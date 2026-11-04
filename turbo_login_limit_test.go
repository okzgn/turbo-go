package main

// A8 (H7, D2): limit of login attempts per IP, cap on the wait in the PBKDF2
// queue, and a warning at startup with the default credentials.

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// countPasswordKeys counts the PBKDF2 derivations until the end of the test.
func countPasswordKeys(t testing.TB) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	previous := derivePasswordKey
	derivePasswordKey = func(password string, salt []byte, iterations int, keyLength int) ([]byte, error) {
		calls.Add(1)
		return previous(password, salt, iterations, keyLength)
	}
	t.Cleanup(func() { derivePasswordKey = previous })
	return &calls
}

// loginFrom sends a login (urlencoded body) from the given IP, without the network.
func loginFrom(handler func(customNetHttp.ResponseWriter, *customNetHttp.Request), ip, user, password string) *responseRecorder {
	body := url.Values{"u": {user}, "p": {password}}.Encode()
	req, _ := customNetHttp.NewRequest("POST", "http://localhost/admin:", strings.NewReader(body))
	req.RequestURI = "/admin:"
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := &responseRecorder{}
	handler(rec, req)
	return rec
}

// H7: after 5 failures from an IP, the sixth attempt gets 429 without computing
// PBKDF2, also with the right password; when the block ends, the right login
// gets in, and a second block lasts longer than the first.
func TestA8_FailedLoginsLimited(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	calls := countPasswordKeys(t)
	for i := 1; i <= 5; i++ {
		if rec := loginFrom(handler, "198.51.100.7", "Turbo", "bad"+strconv.Itoa(i)); rec.code != 403 {
			t.Fatalf("failure %d: %d; expected 403", i, rec.code)
		}
	}
	before := calls.Load()
	for _, password := range []string{"bad6", "Admin"} {
		rec := loginFrom(handler, "198.51.100.7", "Turbo", password)
		retry, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
		if rec.code != 429 || retry < 1 || retry > 60 {
			t.Errorf("attempt with %q after 5 failures: %d, Retry-After %q; expected 429 with up to 60 s", password, rec.code, rec.Header().Get("Retry-After"))
		}
	}
	if n := calls.Load() - before; n != 0 {
		t.Errorf("the blocked attempts computed %d PBKDF2", n)
	}
	if rec := loginFrom(handler, "198.51.100.8", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("another IP: %d; expected 200", rec.code)
	}

	expireLoginBlock(t, "198.51.100.7")
	if rec := loginFrom(handler, "198.51.100.7", "Turbo", "Admin"); rec.code != 200 || !strings.HasPrefix(rec.body.String(), "ok") {
		t.Fatalf("right login after the block: %d %q", rec.code, rec.body.String())
	}

	// A correct login clears the failures; a second block, before they are forgotten, lasts longer.
	for i := 0; i < 5; i++ {
		loginFrom(handler, "198.51.100.7", "Turbo", "bad")
	}
	expireLoginBlock(t, "198.51.100.7")
	for i := 0; i < 5; i++ {
		loginFrom(handler, "198.51.100.7", "Turbo", "bad")
	}
	rec := loginFrom(handler, "198.51.100.7", "Turbo", "Admin")
	if retry, _ := strconv.Atoi(rec.Header().Get("Retry-After")); rec.code != 429 || retry <= 60 || retry > 120 {
		t.Errorf("second block: %d, Retry-After %q; expected 2 minutes", rec.code, rec.Header().Get("Retry-After"))
	}
}

// H57: concurrent attempts from an IP count for the limit while they are
// checked, so a burst doesn't compute more than 5 passwords.
func TestH57_ConcurrentLoginsLimited(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	calls := countPasswordKeys(t)
	// A PBKDF2 slot for each attempt let through, so that none gets 503 (not checked, not counted) waiting for one:
	// with 4 CPUs there are 2, and under -race a PBKDF2 can take longer than passwordSlotWait.
	previousSlots := passwordHashSlots
	passwordHashSlots = make(chan struct{}, loginMaxFailures+1)
	t.Cleanup(func() { passwordHashSlots = previousSlots })
	t.Cleanup(func() {
		loginFailuresMutex.Lock()
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
	})
	var wg sync.WaitGroup
	var forbidden, limited atomic.Int64
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch loginFrom(handler, "198.51.100.20", "Turbo", "bad"+strconv.Itoa(i)).code {
			case 403:
				forbidden.Add(1)
			case 429:
				limited.Add(1)
			}
		}()
	}
	wg.Wait()
	if calls.Load() > loginMaxFailures || forbidden.Load() > loginMaxFailures {
		t.Errorf("60 concurrent logins: %d passwords computed, %d 403 responses, %d 429; expected at most %d computations",
			calls.Load(), forbidden.Load(), limited.Load(), loginMaxFailures)
	}
	if rec := loginFrom(handler, "198.51.100.20", "Turbo", "Admin"); rec.code != 429 {
		t.Errorf("after the burst: %d; expected 429", rec.code)
	}
	if rec := loginFrom(handler, "198.51.100.21", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("another IP after the burst: %d; expected 200", rec.code)
	}
}

// expireLoginBlock ends the login block of an IP.
func expireLoginBlock(t *testing.T, ip string) {
	t.Helper()
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	failures, found := loginFailuresByIP[ip]
	if !found {
		t.Fatalf("%s has no login failures recorded", ip)
	}
	failures.blockedUntil = time.Now().Add(-time.Second)
}

// H7: if the PBKDF2 queue is full for more than 2 s, the login gets 503 with
// Retry-After: 2 instead of waiting without limit.
func TestA8_HashQueueBounded(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	verifiedPassword.Store(nil) // A password already checked doesn't need a slot
	verifiedLogin.Store(nil)
	for i := 0; i < cap(passwordHashSlots); i++ {
		passwordHashSlots <- struct{}{}
	}
	start := time.Now()
	rec := loginFrom(handler, "198.51.100.9", "Turbo", "Admin")
	elapsed := time.Since(start)
	for i := 0; i < cap(passwordHashSlots); i++ {
		<-passwordHashSlots
	}
	if rec.code != 503 || rec.Header().Get("Retry-After") != "2" || elapsed > 3*time.Second {
		t.Fatalf("with the queue full: %d, Retry-After %q, %v; expected 503 with Retry-After: 2 in about 2 s", rec.code, rec.Header().Get("Retry-After"), elapsed)
	}
	if rec := loginFrom(handler, "198.51.100.9", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("with the queue free: %d", rec.code)
	}
}

// H7: with 50 concurrent failed logins from different IPs, the administrator
// gets in within 3 s, or gets 503 and gets in when retrying.
// adminLoginLimit is how long the administrator's login may take during the
// attack: up to passwordSlotWait (2 s) waiting for a PBKDF2 slot and then its
// own PBKDF2, which with -race and a busy CPU takes over 1 s.
var adminLoginLimit = map[bool]time.Duration{false: 3 * time.Second, true: 6 * time.Second}[raceEnabled]

func TestA8_AdminEntersDuringAttack(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	verifiedPassword.Store(nil) // The administrator's login also computes a PBKDF2
	verifiedLogin.Store(nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loginFrom(handler, "203.0.113."+strconv.Itoa(i+1), "Turbo", "bad")
		}()
	}
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	rec := loginFrom(handler, "192.0.2.1", "Turbo", "Admin")
	if rec.code == 503 {
		time.Sleep(2 * time.Second)
		rec = loginFrom(handler, "192.0.2.1", "Turbo", "Admin")
	} else if elapsed := time.Since(start); elapsed > adminLoginLimit {
		t.Errorf("the administrator took %v to get in", elapsed)
	}
	wg.Wait()
	if rec.code != 200 {
		t.Errorf("administrator's login during the attack: %d", rec.code)
	}
}

// D2: at startup with Turbo/Admin, a warning in the log; with another password, none.
func TestA8_DefaultCredentialsWarning(t *testing.T) {
	initForTest(t)
	logs := captureLog(t)
	warnDefaultCredentials()
	if !strings.Contains(logs.String(), "The default credentials") {
		t.Errorf("no warning with Turbo/Admin:\n%s", logs.String())
	}
	setPanelPassword("Another")
	before := len(logs.String())
	warnDefaultCredentials()
	if strings.Contains(logs.String()[before:], "default credentials") {
		t.Error("warning with a changed password")
	}
}

// §11.2: no input signs in without the credentials.
func FuzzLogin(f *testing.F) {
	for _, body := range []string{"u=Turbo&p=Admin", "u=Turbo&p=admin", "u=turbo&p=Admin", "u=Turbo&u=x&p=Admin", "p=Admin", "u=Turbo&p=Admin%00", "u=%54urbo&p=Admin", ""} {
		f.Add(body, false)
		f.Add(body, true)
	}
	initFuzz(f)
	// A hash of few iterations, so that each attempt is fast.
	salt := []byte("0123456789abcdef")
	key, _ := derivePasswordKey("Admin", salt, 1, 32)
	panelPasswordHash.Set("pbkdf2-sha256$1$MDEyMzQ1Njc4OWFiY2RlZg==$" + base64.StdEncoding.EncodeToString(key))
	verifiedPassword.Store(nil)
	verifiedLogin.Store(nil)
	handler := serverHandlerFn("")
	f.Fuzz(func(t *testing.T, body string, multipartBody bool) {
		loginFailuresMutex.Lock()
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
		values, err := url.ParseQuery(body)
		contentType := "application/x-www-form-urlencoded"
		if multipartBody {
			if err != nil {
				return
			}
			var buf strings.Builder
			buf.WriteString("--X\r\n")
			for name, list := range values {
				for _, value := range list {
					buf.WriteString("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n--X\r\n")
				}
			}
			body, contentType = strings.TrimSuffix(buf.String(), "\r\n")+"--\r\n", "multipart/form-data; boundary=X"
		}
		req, _ := customNetHttp.NewRequest("POST", "http://localhost/admin:", strings.NewReader(body))
		req.RequestURI = "/admin:"
		req.RemoteAddr = "198.51.100.200:40000"
		req.Header.Set("Content-Type", contentType)
		rec := &responseRecorder{}
		handler(rec, req)
		valid := err == nil && len(values["u"]) > 0 && values["u"][0] == "Turbo" && len(values["p"]) > 0 && values["p"][0] == "Admin"
		if signedIn := strings.HasPrefix(rec.body.String(), "ok"); signedIn && !valid {
			t.Fatalf("signed in with %q (multipart %v)", body, multipartBody)
		}
	})
}

// Review of 57cbb3c, S12: with TURBO_USER (or another user) and the password still Admin, Turbo warns too; before,
// it only did with the user Turbo.
func TestRL_S12_DefaultPasswordWarningWithAnotherUser(t *testing.T) {
	initForTest(t)
	panelUser.Set("ops")
	logs := captureLog(t)
	warnDefaultCredentials()
	if !strings.Contains(logs.String(), "The default password (Admin)") {
		t.Errorf("no warning with ops/Admin:\n%s", logs.String())
	}
}

// Production review, M-09: the /64s of an IPv6 /48 share a count of failed logins (loginMaxNetworkFailures): beyond
// it, a login from any of them gets 429 without a PBKDF2, the right password too, while another /48 isn't held back.
func TestRP_M09_LoginLimitPer48(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	for failures, network := 0, 1; failures < loginMaxNetworkFailures; network++ {
		for i := 1; i < loginMaxFailures && failures < loginMaxNetworkFailures; i++ { // Below the limit of each /64
			ip := "[2001:db8:5:" + strconv.FormatInt(int64(network), 16) + "::" + strconv.Itoa(i) + "]" // As in RemoteAddr
			if rec := loginFrom(handler, ip, "Turbo", "bad"); rec.code != 403 {
				t.Fatalf("failure %d, from %s: %d; expected 403", failures+1, ip, rec.code)
			}
			failures++
		}
	}
	calls := countPasswordKeys(t)
	if rec := loginFrom(handler, "[2001:db8:5:ffff::1]", "Turbo", "Admin"); rec.code != 429 {
		t.Errorf("a /64 that never failed, in a /48 with %d failures: %d; expected 429", loginMaxNetworkFailures, rec.code)
	}
	if calls.Load() != 0 {
		t.Errorf("the blocked login computed %d PBKDF2", calls.Load())
	}
	if rec := loginFrom(handler, "[2001:db8:6::1]", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("another /48: %d; expected 200", rec.code)
	}
}

// Production review, M-09: a PBKDF2 slot is kept for the current password of a request with a session and for the
// logins from the networks of PA: a flood of logins from elsewhere, which takes the other slots, doesn't keep the
// administrator out.
func TestRP_M09_ReservedPasswordSlot(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	token := newSession(t, "198.51.100.80")
	verifiedPassword.Store(nil) // A password already checked doesn't need a slot
	verifiedLogin.Store(nil)
	fill := func() func() {
		for i := 0; i < cap(passwordHashSlots); i++ {
			passwordHashSlots <- struct{}{}
		}
		return func() {
			for i := 0; i < cap(passwordHashSlots); i++ {
				<-passwordHashSlots
			}
		}
	}
	free := fill()
	if rec := loginFrom(handler, "198.51.100.81", "Turbo", "Admin"); rec.code != 503 {
		t.Errorf("a login with every other slot taken: %d; expected 503", rec.code)
	}
	if rec := apiFrom(handler, "198.51.100.80", token, "/admin:inside:setCII?a=50&b=Admin"); rec.code != 200 {
		t.Errorf("the current password of a session with every other slot taken: %d %q; expected 200", rec.code, rec.body.String())
	}
	free()

	if ok, msg := defaultSettingValidators["."]["PA"]("192.0.2.0/24", internalAuth); !ok {
		t.Fatal(msg)
	}
	verifiedPassword.Store(nil)
	verifiedLogin.Store(nil)
	free = fill()
	defer free()
	if rec := loginFrom(handler, "192.0.2.5", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("a login from a network of PA with every other slot taken: %d; expected 200", rec.code)
	}
}

// Production review, M-09: a new password has 12 to 64 bytes; one already in use keeps working.
func TestRP_M09_NewPasswordLength(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.82"
	token := newSession(t, ip)
	for _, password := range []string{"ElevenBytes", strings.Repeat("x", 65)} {
		if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setP?"+url.Values{"a": {password}, "b": {"Admin"}}.Encode()); rec.code != 400 || rec.body.String() != "The password must have 12 to 64 bytes" {
			t.Errorf("setP with %d bytes: %d %q; expected 400", len(password), rec.code, rec.body.String())
		}
	}
	current := "Admin" // Shorter, already in use: it keeps working
	for _, password := range []string{"TwelveBytes!", strings.Repeat("y", 64)} {
		rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setP?"+url.Values{"a": {password}, "b": {current}}.Encode())
		if rec.code != 200 {
			t.Fatalf("setP with %d bytes: %d %q; expected 200", len(password), rec.code, rec.body.String())
		}
		token, current = rec.Header().Get(sessionHeaderName), password // setP renews the session
	}
	if !passwordMatches(strings.Repeat("y", 64)) {
		t.Error("the password of 64 bytes isn't the one in use")
	}
}
