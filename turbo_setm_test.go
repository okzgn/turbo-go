package main

// T02 (N2, N16 order, N17, N42): setM always reads the target's turbo.config
// again, checks the password before reading anything, doesn't overlap with the
// periodic reload, doesn't bounce through the pointer of the start directory
// and, with D14 (a), without a turbo.config in the target keeps the settings
// in use.

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setM runs setM through the panel and returns the code and the body.
func setM(t *testing.T, base, tok, dir, password string) (int, string) {
	t.Helper()
	code, body, err := post(base, "/admin:inside:setM?"+url.Values{"a": {dir}, "b": {password}}.Encode(), tok)
	if err != nil {
		t.Fatalf("setM %s: %v", dir, err)
	}
	return code, body
}

// N2: setM to a copy of the directory whose turbo.config has the same date
// applies its configuration: the CGI runs and HTTPS stays on.
func TestN02_SetMToCopyWithSameDate(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"?":{"cgi":"` + filepath.ToSlash(toolPath("cgiecho")) + `"},"!":{"S":"1"}}},".":{"CII":"90"}}`
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("cgi-source"), 0644)
	loadConfig(t, dir, cfg)
	copyDir := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(copyDir+"localhost/@", 0755)
	for _, name := range []string{"localhost/@/index.html", "localhost/@/x.cgi", "localhost/fullchain.pem", "localhost/privkey.pem", "turbo.config"} {
		data, _ := os.ReadFile(dir + name)
		os.WriteFile(copyDir+name, data, 0600)
	}
	info, _ := os.Stat(dir + "turbo.config")
	os.Chtimes(copyDir+"turbo.config", info.ModTime(), info.ModTime())
	base := startServer(t)
	tok := login(t, base)
	if code, body := setM(t, base, tok, copyDir, "Admin"); code != 200 {
		t.Fatalf("setM: %d %s", code, body)
	}
	if code, body, _ := get(base, "/x.cgi", nil); code != 200 || !strings.Contains(body, "QUERY_STRING=") {
		t.Errorf("GET /x.cgi after setM: %d %q; expected the CGI run", code, body)
	}
	globalMutex.RLock()
	https := siteSSLConfig["localhost"]["S"]
	globalMutex.RUnlock()
	if https != 1 {
		t.Error("HTTPS disabled after setM to the copy")
	}
}

// N2: the same directory written another way is "unchanged".
func TestN02_SetMSameDirOtherSpelling(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	spellings := []string{strings.TrimSuffix(dir, "/"), dir + "./", strings.Replace(dir, "/", "//", -1)}
	if runtime.GOOS == "windows" {
		spellings = append(spellings, filepath.FromSlash(dir), strings.ToUpper(dir))
	}
	for _, spelling := range spellings {
		if code, body := setM(t, base, tok, spelling, "Admin"); code != 400 || !strings.Contains(body, "unchanged") {
			t.Errorf("setM %q: %d %q; expected 400 unchanged", spelling, code, body)
		}
	}
}

// N16: with a wrong current password, setM doesn't read the target: it answers
// "Wrong current password", not the error of its turbo.config.
func TestN16_SetMChecksPasswordFirst(t *testing.T) {
	initForTest(t)
	other := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(other+"turbo.config", []byte(`{broken`), 0600)
	base := startServer(t)
	tok := login(t, base)
	if code, body := setM(t, base, tok, other, "Bad"); code != 400 || !strings.Contains(body, "Wrong current password") {
		t.Errorf("setM with a wrong b: %d %q; expected the wrong password", code, body)
	}
}

// N42: setM while the periodic reload runs in a loop: the final state is that
// of the last target, without -race warnings.
func TestN42_SetMDuringReload(t *testing.T) {
	dirA := initForTest(t)
	loadConfig(t, dirA, `{"^":{"v":"2"},".":{"CII":"81"}}`)
	dirB := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(dirB+"b.test/@", 0755)
	os.WriteFile(dirB+"turbo.config", []byte(`{"^":{"v":"2"},".":{"CII":"82"}}`), 0600)
	base := startServer(t)
	tok := login(t, base)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				updateSettings(true)
			}
		}
	}()
	targets := []string{dirB, dirA}
	for i := 0; i < 6; i++ {
		if code, body := setM(t, base, tok, targets[i%2], "Admin"); code != 200 {
			t.Errorf("setM %d: %d %s", i, code, body)
		}
	}
	close(stop)
	wg.Wait()
	if got := sitesDir.Get(); !sameDir(got, dirA) {
		t.Errorf("final directory %q; expected %q", got, dirA)
	}
	if serverRequestLimits.CII.Load() != 81 {
		t.Errorf("final CII %d; expected the target's (81)", serverRequestLimits.CII.Load())
	}
	if _, ok := sitesMap["b.test"]; ok {
		t.Error("the site of the other directory is still active")
	}
}

// N42: a setM that comes while a periodic reload goes through the previous
// directory waits for it to end: the reload doesn't then activate the sites of
// the previous directory over the configuration of the new one.
func TestN42_SetMWaitsForReload(t *testing.T) {
	dirA := initForTest(t)
	loadConfig(t, dirA, `{"^":{"v":"2"},".":{"CII":"81"}}`)
	dirB := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(dirB+"turbo.config", []byte(`{"^":{"v":"2"},".":{"CII":"82"}}`), 0600)
	base := startServer(t)
	tok := login(t, base)
	chosen, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool // Only the periodic reload waits (sync.Once would also hold setM's)
	beforeSitesScan = func() {
		if first.CompareAndSwap(false, true) {
			close(chosen)
			<-release
		}
	}
	t.Cleanup(func() { beforeSitesScan = func() {} })
	configFileModTime = 0 // The periodic reload reads A's turbo.config again
	reloaded := make(chan struct{})
	go func() { updateSettings(true); close(reloaded) }()
	<-chosen
	answered := make(chan int)
	go func() { code, _ := setM(t, base, tok, dirB, "Admin"); answered <- code }()
	time.Sleep(300 * time.Millisecond) // setM comes while the reload goes through A
	close(release)
	<-reloaded
	if code := <-answered; code != 200 {
		t.Fatalf("setM: %d", code)
	}
	globalMutex.RLock()
	_, siteOfA := sitesMap["localhost"]
	globalMutex.RUnlock()
	if got := sitesDir.Get(); !sameDir(got, dirB) || serverRequestLimits.CII.Load() != 82 || siteOfA {
		t.Errorf("after setM during the reload: directory %q, CII %d, A's site active %v; expected only B, with CII 82", got, serverRequestLimits.CII.Load(), siteOfA)
	}
}

// N17: going back to the start directory when it has a pointer: it stays there.
func TestN17_SetMBackToStartWithPointer(t *testing.T) {
	dirA := initForTest(t)
	dirB := filepath.ToSlash(t.TempDir()) + "/"
	base := startServer(t)
	tok := login(t, base)
	if code, body := setM(t, base, tok, dirB, "Admin"); code != 200 {
		t.Fatalf("setM B: %d %s", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:setC?a=&b=Admin", tok); code != 200 {
		t.Fatalf("setC: %d %s", code, body)
	}
	if data, _ := os.ReadFile(dirA + "turbo.config"); !isSitesDirPointer(data) {
		t.Fatalf("no pointer was left in A: %s", data)
	}
	if code, body := setM(t, base, tok, dirA, "Admin"); code != 200 {
		t.Fatalf("setM A: %d %s", code, body)
	}
	if got := sitesDir.Get(); !sameDir(got, dirA) {
		t.Errorf("after going back to A, the directory is %q (it bounced through the pointer)", got)
	}
	updateSettings(true) // The periodic reload doesn't follow it either
	if got := sitesDir.Get(); !sameDir(got, dirA) {
		t.Errorf("after the reload, the directory is %q", got)
	}
	if code, body, _ := post(base, "/admin:inside:setC?a=&b=Admin", tok); code != 200 {
		t.Fatalf("setC in A: %d %s", code, body)
	}
	if raw := savedConfig(t, dirA); raw["localhost"] == nil {
		t.Errorf("saving in A didn't write the whole configuration: %v", raw)
	}
}

// D14 (a): a target without turbo.config keeps PA, the limits, the
// credentials and the lists in use; one with turbo.config is applied whole and
// the response says what changes.
func TestN17_SetMKeepsOrReportsSettings(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"@":{"203.0.113.9":"`+strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)+`"},".":{"PA":"127.0.0.0/8","CII":"83","U":"Other"}}`)
	base := startServer(t)
	tok := loginAs(t, base, "Other", "Admin")
	empty := filepath.ToSlash(t.TempDir()) + "/"
	code, body := setM(t, base, tok, empty, "Admin")
	if code != 200 {
		t.Fatalf("setM to a directory without turbo.config: %d %s", code, body)
	}
	if panelAccess.Load().setting != "127.0.0.0/8" || serverRequestLimits.CII.Load() != 83 || panelUser.Get() != "Other" {
		t.Errorf("without turbo.config the settings weren't kept: PA=%q CII=%d U=%q", panelAccess.Load().setting, serverRequestLimits.CII.Load(), panelUser.Get())
	}
	if _, denied := (*deniedIPs.Load())["203.0.113.9"]; !denied {
		t.Error("without turbo.config the list of denied IPs wasn't kept")
	}
	if !strings.Contains(body, "are kept") {
		t.Errorf("the response doesn't say the settings are kept: %q", body)
	}

	other := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(other+"turbo.config", []byte(`{"^":{"v":"2"},".":{"PA":"127.0.0.1/32","U":"New"}}`), 0600)
	code, body = setM(t, base, tok, other, "Admin")
	if code != 200 {
		t.Fatalf("setM to a directory with turbo.config: %d %s", code, body)
	}
	if panelAccess.Load().setting != "127.0.0.1/32" || panelUser.Get() != "New" {
		t.Errorf("the target's turbo.config wasn't applied: PA=%q U=%q", panelAccess.Load().setting, panelUser.Get())
	}
	for _, want := range []string{"127.0.0.0/8", "127.0.0.1/32", "user"} {
		if !strings.Contains(body, want) {
			t.Errorf("the response doesn't mention %q: %q", want, body)
		}
	}
}

// loginAs signs in to the panel with other credentials.
func loginAs(t *testing.T, base, user, password string) string {
	t.Helper()
	credentials, contentType := multipartCredentials(user, password)
	code, body, _ := loginRequest(t, base, "POST", "/admin:", credentials, contentType)
	if code != 200 || !strings.HasPrefix(body, "ok") {
		t.Fatalf("login %s: %d %q", user, code, body)
	}
	return strings.TrimPrefix(body, "ok")
}

// setupTwoDirs leaves A with a cgi preprocessor and PA, and B with x.cgi and the
// given turbo.config ({B} is its path).
func setupTwoDirs(t *testing.T, targetConfig string) (string, string, string) {
	t.Helper()
	dirA := initForTest(t)
	cfg := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"?":{"cgi":"` + filepath.ToSlash(toolPath("cgiecho")) + `"}}},".":{"PA":"localhost,127.0.0.1"}}`
	loadConfig(t, dirA, cfg)
	dirB := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(dirB+"localhost/@", 0755)
	os.WriteFile(dirB+"localhost/@/x.cgi", []byte("SOURCE-OF-CGI"), 0644)
	os.WriteFile(dirB+"turbo.config", []byte(strings.ReplaceAll(targetConfig, "{B}", dirB)), 0600)
	base := startServer(t)
	return dirA, dirB, base
}

// N63: setM to a directory whose turbo.config can't be applied (a pointer to
// itself, an invalid schema) is rejected before changing anything: it never
// leaves the target's sites without their preprocessors.
func TestN63_SetMToUnusableConfig(t *testing.T) {
	for name, cfg := range map[string]string{
		"selfpointer": `{"^":{"v":"2"},".":{"M":"{B}"}}`,
		"badschema":   `{"^":{"v":"x"},"localhost":{"":{"?":{"cgi":"/nonexistent"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			dirA, dirB, base := setupTwoDirs(t, cfg)
			tok := login(t, base)
			if code, body := setM(t, base, tok, dirB, "Admin"); code != 400 {
				t.Errorf("setM to a turbo.config that can't be used: %d %q; expected 400", code, body)
			}
			globalMutex.RLock()
			now := sitesDir.Get()
			kept := preprocessors["localhost"]["cgi"] != ""
			globalMutex.RUnlock()
			if !sameDir(now, dirA) || !kept {
				t.Errorf("after the rejected setM: directory %s (A=%s), cgi preprocessor kept = %v", now, dirA, kept)
			}
			if _, b, _ := get(base, "/x.cgi", nil); strings.Contains(b, "SOURCE-OF-CGI") {
				t.Errorf("the CGI's source was served after a setM whose configuration wasn't applied")
			}
		})
	}
}

// N65: setM to B, whose turbo.config only points to C, which has no
// turbo.config: as with a direct setM to C, the settings in use (PA and the
// lists) are kept.
func TestN65_SetMPointerToDirWithoutConfig(t *testing.T) {
	dirA := initForTest(t)
	loadConfig(t, dirA, `{"^":{"v":"2"},".":{"PA":"localhost,127.0.0.0/8","CII":"77"},"_":{"~":"-t-"}}`)
	dirC := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(dirC+"localhost/@", 0755)
	dirB := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(dirB+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirC+`"}}`), 0600)
	base := startServer(t)
	tok := login(t, base)
	if code, body := setM(t, base, tok, dirB, "Admin"); code != 200 {
		t.Fatalf("setM to a pointer to a directory without turbo.config: %d %q; expected 200", code, body)
	}
	globalMutex.RLock()
	pa := panelAccess.Load().setting
	_, repl := charReplacements["~"]
	dir := sitesDir.Get()
	globalMutex.RUnlock()
	if !sameDir(dir, dirC) {
		t.Errorf("sites directory %s; expected the pointer's target, %s", dir, dirC)
	}
	if cii := serverRequestLimits.CII.Load(); pa != "localhost,127.0.0.0/8" || !repl || cii != 77 {
		t.Errorf("PA (%q), the replacement (%v) or CII (%d) was lost when following a pointer to a directory without turbo.config", pa, repl, cii)
	}
}
