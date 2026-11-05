package main

// The independent review of v2.4.2 (blocks 6 to 8):
// - the timer that publishes the certificates again overflowed for a certificate valid for centuries, and published
//   and rearmed itself in a loop, holding the global lock;
// - the default password signed in from a loopback address whatever the Host, so a page of another name that the
//   browser of someone on this machine loaded, and whose name then resolved to 127.0.0.1 (DNS rebinding), could
//   sign in with it;
// - a login attempt took its counts again at its end, and a correct login of the same client in between (which
//   trusts it) left its /48 with an attempt in flight forever;
// - the current passwords of a session that were still being checked didn't count, so requests sent at once tried
//   many before the fifth wrong one closed the session;
// - an expired certificate of a name won over a valid wildcard that covers it;
// - a shared ACME account that the server refused (deactivated) was copied into every new site's folder.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRP3_Review_PublishDelayCapped(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		next time.Time
		want time.Duration
	}{
		{now.Add(10 * time.Second), 11 * time.Second},
		{now.Add(48 * time.Hour), 24*time.Hour + time.Second},
		{time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), 24*time.Hour + time.Second}, // RFC 5280: no expiry
	} {
		if got := certificatesPublishDelay(c.next, now); got != c.want {
			t.Errorf("the delay for %v: %v; expected %v", c.next, got, c.want)
		}
	}
}

func TestRP3_Review_DefaultPasswordByAName(t *testing.T) {
	initForTest(t)
	for _, c := range []struct {
		ip, host string
		headers  map[string]string
		local    bool
	}{
		{"127.0.0.1", "localhost", nil, true},
		{"127.0.0.1", "LOCALHOST:8080", nil, true},
		{"127.0.0.1", "127.0.0.1:8080", nil, true},
		{"::1", "[::1]", nil, true},
		{"127.0.0.1", "attacker.test", nil, false}, // A page whose name resolves to 127.0.0.1
		{"127.0.0.1", "attacker.test", map[string]string{"Origin": "http://attacker.test"}, false},
		{"127.0.0.1", "192.0.2.10", nil, false},
		{"127.0.0.1", "localhost", map[string]string{"Via": "1.1 proxy"}, false},
		{"127.0.0.1", "localhost", map[string]string{"X-Forwarded-Host": "example.com"}, false},
		{"127.0.0.1", "localhost", map[string]string{"X-Forwarded-Proto": "https"}, false},
		{"127.0.0.1", "localhost", map[string]string{"CF-Connecting-IP": "203.0.113.9"}, false},
		{"127.0.0.1", "localhost", map[string]string{"True-Client-IP": "203.0.113.9"}, false},
	} {
		rec := loginToHost(c.ip, c.host, "Turbo", "Admin", c.headers)
		if c.local && rec.code != 200 {
			t.Errorf("the default password from %s to %s %v: %d %q; expected 200", c.ip, c.host, c.headers, rec.code, rec.body.String())
		}
		if !c.local && (rec.code != 403 || rec.header.Get("X-Turbo-Login") != "local-only") {
			t.Errorf("the default password from %s to %s %v: %d %q; expected 403 local-only", c.ip, c.host, c.headers, rec.code, rec.body.String())
		}
	}
	// A host of PA, the panel's own, is a name of this machine too (through an SSH tunnel, say): its DNS is the
	// administrator's.
	list, problem := parsePanelAccess("panel.test")
	if problem != "" {
		t.Fatal(problem)
	}
	previous := panelAccess.Load()
	panelAccess.Store(list)
	t.Cleanup(func() { panelAccess.Store(previous) })
	if rec := loginToHost("127.0.0.1", "panel.test", "Turbo", "Admin", nil); rec.code != 200 {
		t.Errorf("the default password from 127.0.0.1 to panel.test, the host of PA: %d %q; expected 200", rec.code, rec.body.String())
	}
	if rec := loginToHost("192.0.2.87", "panel.test", "Turbo", "Admin", nil); rec.code != 403 || rec.header.Get("X-Turbo-Login") != "local-only" {
		t.Errorf("the default password from 192.0.2.87 to panel.test: %d %q; expected 403 local-only", rec.code, rec.body.String())
	}
}

func TestRP3_Review_TrustDuringALogin(t *testing.T) {
	initForTest(t)
	const client = "2001:db8:9:1::1"
	first, retry := startLoginAttempt(client)
	if retry != 0 {
		t.Fatal("the first attempt was refused")
	}
	second, retry := startLoginAttempt(client)
	if retry != 0 {
		t.Fatal("the second attempt was refused")
	}
	finishLoginAttempt(first, false)
	forgetLoginFailures(client) // The first was correct: the client is trusted from now on
	finishLoginAttempt(second, true)
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	if network, found := loginFailuresByIP["2001:db8:9::/48"]; !found || network.inFlight != 0 {
		t.Errorf("the /48 after both attempts ended: %+v; expected no attempt in flight", network)
	}
}

func TestRP3_Review_SessionChecksInFlight(t *testing.T) {
	initForTest(t)
	const ip = "192.0.2.86"
	token := newSession(t, ip)
	verifiedPassword.Store(nil)
	for i := 0; i < cap(passwordHashSlots); i++ { // Every check waits passwordSlotWait for a slot, and gives up
		passwordHashSlots <- struct{}{}
	}
	passwordReservedSlot <- struct{}{}
	t.Cleanup(func() {
		<-passwordReservedSlot
		for i := 0; i < cap(passwordHashSlots); i++ {
			<-passwordHashSlots
		}
	})
	codes := make(chan int, 2*loginMaxFailures)
	var wg sync.WaitGroup
	for i := 0; i < 2*loginMaxFailures; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:closeSessions?b=wrong"+strconv.Itoa(i)).code
		}()
	}
	wg.Wait()
	close(codes)
	counted := map[int]int{}
	for code := range codes {
		counted[code]++
	}
	if counted[429] != loginMaxFailures || counted[503] != loginMaxFailures {
		t.Errorf("%d requests at once with wrong passwords: %v; expected %d checked (503, no slot) and %d refused at once (429)", 2*loginMaxFailures, counted, loginMaxFailures, loginMaxFailures)
	}
}

func TestRP3_Review_ValidWildcardOverAnExpiredName(t *testing.T) {
	initForTest(t)
	scratch := t.TempDir() + "/"
	wildcard := loadTestCertificate(t, scratch+"a/", time.Hour, "example.test", "*.example.test")
	expired := loadTestCertificate(t, scratch+"b/", -time.Minute, "shop.example.test", "old.test")
	withGlobalLock(func() {
		setSiteCertificate("example.test", wildcard)
		setSiteCertificate("shop.example.test", expired)
	})
	if got := certificateFor("shop.example.test"); got != wildcard {
		t.Errorf("shop.example.test: %v; expected the valid wildcard", certificateNames(got))
	}
	if got := certificateFor("old.test"); got != expired { // No valid one covers it
		t.Errorf("old.test: %v; expected the expired one", certificateNames(got))
	}
}

func TestRP3_Review_RefusedACMEAccountReplaced(t *testing.T) {
	useFakeCertbot(t, "ok")
	accountsLog := filepath.ToSlash(filepath.Join(t.TempDir(), "accounts.log"))
	t.Setenv("FAKE_CERTBOT_ACCOUNTS", accountsLog)
	dir := initForTest(t)
	issue := func(site string) interface{} {
		os.MkdirAll(dir+site+"/@", 0755)
		job := certbotJob{names: []string{site}, email: "admin@example.test", webroot: dir + site + "/@", certDir: dir + "turbo.certificates/" + site, destDir: dir + site + "/"}
		return runCertbot(context.Background(), job)
	}
	last := func() string { // The account of the last attempt
		data, _ := os.ReadFile(accountsLog)
		fields := strings.Fields(string(data))
		return fields[len(fields)-1]
	}
	if status := issue("a.test"); status != true {
		t.Fatalf("a.test: %v", status)
	}
	shared := last()
	t.Setenv("FAKE_CERTBOT_REFUSE_ACCOUNT", shared) // The server deactivates it
	if status := issue("b.test"); status == true || !strings.Contains(status.(string), "deactivated") {
		t.Fatalf("b.test with the refused account: %v", status)
	}
	if _, err := os.Stat(acmeAccountsDir("admin@example.test")); err == nil {
		t.Error("the refused account is still shared")
	}
	if status := issue("b.test"); status != true || last() == shared {
		t.Errorf("b.test again: %v, with the account %s; expected a new account", status, last())
	}
	if status := issue("c.test"); status != true {
		t.Errorf("c.test: %v", status)
	}
	data, _ := os.ReadFile(accountsLog)
	if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 4 || !strings.HasPrefix(lines[3], "existing ") || strings.Fields(lines[3])[1] != strings.Fields(lines[2])[1] {
		t.Errorf("the accounts Certbot used:\n%s\nexpected c.test to get the new shared one", data)
	}
}
