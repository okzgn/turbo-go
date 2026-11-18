package server

// Review of 6046dbe (R6), D-09: what had no test of its own. The periodic cleanups of failed logins and denied IPs,
// the copy of Certbot's ACME accounts, the limits of IT, and the deletion of rewrites and aliases.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// R6 D-09: cleanLoginFailures forgets the clients whose window and block ended more than loginLongestBlock ago and
// have no attempt in flight, the trusts that expired, and the wrong current passwords of the sessions that ended.
func TestR6_D09_CleanLoginFailures(t *testing.T) {
	initForTest(t)
	old := time.Now().Add(-loginLongestBlock - time.Minute)
	recent := time.Now().Add(-time.Minute)
	loginFailuresMutex.Lock()
	loginFailuresByIP["203.0.113.1"] = &loginFailures{count: 2, windowEnd: old, blockedUntil: old}
	loginFailuresByIP["203.0.113.2"] = &loginFailures{count: 2, windowEnd: recent, blockedUntil: old}
	loginFailuresByIP["203.0.113.3"] = &loginFailures{inFlight: 1, windowEnd: old, blockedUntil: old}
	loginTrusted["203.0.113.4"] = time.Now().Add(-time.Second)
	loginTrusted["203.0.113.5"] = time.Now().Add(time.Hour)
	sessionPasswordChecks["ended"] = passwordChecks{failures: 1}
	sessionPasswordChecks["live"] = passwordChecks{failures: 1}
	sessionPasswordChecks["ended, checking"] = passwordChecks{inFlight: 1}
	loginFailuresMutex.Unlock()
	withGlobalLock(func() { signedInTokens["live"] = time.Now().Add(time.Hour).Unix() })
	t.Cleanup(func() {
		loginFailuresMutex.Lock()
		for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5"} {
			delete(loginFailuresByIP, ip)
			delete(loginTrusted, ip)
		}
		for _, session := range []string{"ended", "live", "ended, checking"} {
			delete(sessionPasswordChecks, session)
		}
		loginFailuresMutex.Unlock()
		withGlobalLock(func() { delete(signedInTokens, "live") })
	})
	cleanLoginFailures()
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	for ip, kept := range map[string]bool{"203.0.113.1": false, "203.0.113.2": true, "203.0.113.3": true} {
		if _, there := loginFailuresByIP[ip]; there != kept {
			t.Errorf("failed logins of %s: kept %v; expected %v", ip, there, kept)
		}
	}
	for ip, kept := range map[string]bool{"203.0.113.4": false, "203.0.113.5": true} {
		if _, there := loginTrusted[ip]; there != kept {
			t.Errorf("trust of %s: kept %v; expected %v", ip, there, kept)
		}
	}
	for session, kept := range map[string]bool{"ended": false, "live": true, "ended, checking": true} {
		if _, there := sessionPasswordChecks[session]; there != kept {
			t.Errorf("wrong passwords of the session %q: kept %v; expected %v", session, there, kept)
		}
	}
}

// R6 D-09: cleanDeniedIPs forgets the denials whose date passed, and only those.
func TestR6_D09_CleanDeniedIPs(t *testing.T) {
	initForTest(t)
	now := time.Now().Unix()
	setDeniedIPs(func(list map[string]int64) {
		list["203.0.113.10"] = now - 10
		list["203.0.113.11"] = now + 3600
	})
	t.Cleanup(func() {
		setDeniedIPs(func(list map[string]int64) { delete(list, "203.0.113.10"); delete(list, "203.0.113.11") })
	})
	withGlobalLock(cleanDeniedIPs)
	denied := deniedIPsInUse()
	if _, there := denied["203.0.113.10"]; there {
		t.Error("an expired denial is still there")
	}
	if denied["203.0.113.11"] != now+3600 {
		t.Errorf("a denial in force: %v", denied["203.0.113.11"])
	}
}

// R6 D-09: copyACMEAccounts copies the accounts of each ACME server that the folder of a site lacks, private, and
// keeps the one it has; a copy cut halfway is replaced.
func TestR6_D09_CopyACMEAccounts(t *testing.T) {
	from, to := t.TempDir()+"/", t.TempDir()+"/"
	for _, file := range []string{"acme.example/directory/account/regr.json", "acme.example/directory/account/private_key.json", "other.example/kept.json"} {
		os.MkdirAll(filepath.Dir(from+file), 0700)
		os.WriteFile(from+file, []byte(file), 0600)
	}
	os.WriteFile(from+"loose-file", []byte("x"), 0600) // Not a server: not copied
	os.MkdirAll(to+"other.example", 0700)
	os.WriteFile(to+"other.example/own.json", []byte("own"), 0600)
	os.MkdirAll(to+"acme.example.copy", 0700) // What a copy cut halfway left
	os.WriteFile(to+"acme.example.copy/half", []byte("half"), 0600)
	copyACMEAccounts(from, to)
	for _, file := range []string{"acme.example/directory/account/regr.json", "acme.example/directory/account/private_key.json"} {
		if data, err := os.ReadFile(to + file); err != nil || string(data) != file {
			t.Errorf("%s: %q %v", file, data, err)
		}
	}
	if fileExists(to+"other.example/kept.json") || !fileExists(to+"other.example/own.json") {
		t.Error("the accounts that the folder had were replaced")
	}
	if fileExists(to+"loose-file") || fileExists(to+"acme.example.copy/half") || fileExists(to+"acme.example/half") {
		t.Error("a loose file, or the copy cut halfway, is there")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(to + "acme.example/directory/account/private_key.json"); err != nil || info.Mode().Perm() != 0600 {
			t.Errorf("the copied key: %v %v; expected 0600", info, err)
		}
	}
	copyACMEAccounts(t.TempDir()+"/missing/", to) // Without accounts yet: nothing
}

// R6 D-09: IT, the time an idle connection is kept, from 100 ms to 5 minutes, or 0 (that of RT).
func TestR6_D09_IdleTimeoutLimits(t *testing.T) {
	initForTest(t)
	for value, want := range map[string]string{
		"50ms": "Less than 100 milliseconds", "6m": "More than 5 minutes", "x": "Invalid value", "3s": "Idle connection timeout saved",
	} {
		ok, msg := setting("IT", value)
		if msg != want || ok != (want == "Idle connection timeout saved") {
			t.Errorf("IT %s: %v %q; expected %q", value, ok, msg, want)
		}
	}
	if ok, msg := setting("IT", "3s"); ok || msg != "Value unchanged" {
		t.Errorf("IT 3s again: %v %q", ok, msg)
	}
	if ok, msg := setting("IT", "0s"); !ok || serverTimeLimits.Load().IT != 0 { // 0: RT's, as Go does
		t.Errorf("IT 0s: %v %q", ok, msg)
	}
}

// R6 D-09: delRewrite deletes a rewrite by its source as the panel sends it (with the character replacements undone),
// and delAlias an alias of the site, not another site's.
func TestR6_D09_DeleteRewritesAndAliases(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/a#b": "/x"}, true, "localhost", ""); !ok {
		t.Fatalf("rewrite: %q", msg)
	}
	token := charReplacements["#"]
	if ok, msg := subdomainContentDeleters["="](true, map[string]interface{}{"/a" + token + "b": ""}, "localhost", ""); !ok || msg != "Rewrite deleted" {
		t.Errorf("delRewrite with the replacement of #: %v %q", ok, msg)
	}
	if ok, msg := subdomainContentDeleters["="](true, map[string]interface{}{"/a#b": ""}, "localhost", ""); ok || msg != "Rewrite not found" {
		t.Errorf("delRewrite again: %v %q", ok, msg)
	}
	constructSiteWithoutIndex("other.test", "")
	domainAliases["mine.example"], domainAliases["theirs.example"] = "localhost", "other.test"
	defer delete(domainAliases, "theirs.example")
	for alias, want := range map[string]string{"theirs.example": "Alias of another site", "missing.example": "Alias not found", "mine.example": "Alias deleted"} {
		ok, msg := subdomainContentDeleters["&"](true, map[string]interface{}{alias: ""}, "localhost", "")
		if msg != want || ok != (want == "Alias deleted") {
			t.Errorf("delAlias %s: %v %q; expected %q", alias, ok, msg, want)
		}
	}
	if _, there := domainAliases["mine.example"]; there {
		t.Error("the deleted alias is still there")
	}
	if domainAliases["theirs.example"] != "other.test" {
		t.Error("another site's alias was deleted")
	}
}
