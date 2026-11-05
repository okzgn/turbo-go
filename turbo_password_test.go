package main

// T07 (N9, N26, I19): the current password of the actions counts for the
// login attempt limit, the login does not reveal whether a password is right
// without the user, and PBKDF2 errors are not ignored.

import (
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// apiFrom sends a panel action from the given IP with the token in the "ok"
// header, without a network.
func apiFrom(handler func(customNetHttp.ResponseWriter, *customNetHttp.Request), ip, token, path string) *responseRecorder {
	req := newPanelRequest(path, ip+":40000")
	req.Header.Set(sessionHeaderName, token)
	rec := &responseRecorder{}
	handler(rec, req)
	return rec
}

// N9, and V14 of the production review: the wrong current passwords count per session, and the fifth closes it, so
// its client signs in again; the IP isn't blocked for them. Counted for the IP, a copy of the session (the same IP)
// spent them and blocked the administrator's closeSessions with 429, while the copy went on.
func TestN09_CurrentPasswordLimited(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	password := useTestPassword(t) // Logins from 198.51.100.30: the default password signs in only from this machine
	const ip = "198.51.100.30"
	token := newSession(t, ip)
	for i := 1; i < loginMaxFailures; i++ {
		rec := apiFrom(handler, ip, token, "/admin:inside:setMUB?a=2000&b=bad"+strconv.Itoa(i))
		if rec.code != 400 || rec.body.String() != "Wrong current password" {
			t.Fatalf("wrong b %d: %d %q", i, rec.code, rec.body.String())
		}
	}
	rec := apiFrom(handler, ip, token, "/admin:inside:setMUB?a=2000&b=bad"+strconv.Itoa(loginMaxFailures))
	if rec.Header().Get("X-Turbo-Login") != "required" {
		t.Errorf("the %dth wrong current password: %d %q; expected the session closed", loginMaxFailures, rec.code, rec.body.String())
	}
	if rec := apiFrom(handler, ip, token, "/admin:inside:setMUB?a=2000&b="+password); rec.Header().Get("X-Turbo-Login") != "required" || maxURILength.Load() == 2000 {
		t.Errorf("the closed session with the right password: %d %q; expected the login", rec.code, rec.body.String())
	}
	rec = loginFrom(handler, ip, "Turbo", password)
	if rec.code != 200 {
		t.Fatalf("login after the session was closed: %d; expected 200 (the IP isn't blocked)", rec.code)
	}
	token = strings.TrimPrefix(rec.body.String(), "ok")
	if rec := apiFrom(handler, ip, token, "/admin:inside:setMUB?a=2000&b="+password); rec.code != 200 {
		t.Errorf("setMUB with the right password in a new session: %d %q", rec.code, rec.body.String())
	}
}

// N26: a wrong user with the right password costs one PBKDF2, like any wrong
// password: the response time does not tell whether the password is right
// without knowing the user.
func TestN26_LoginTimingWithoutUser(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	t.Cleanup(func() {
		loginFailuresMutex.Lock()
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
	})
	if !passwordMatches("Admin") { // Leaves "Admin" as the last password checked
		t.Fatal("the test password is not Admin")
	}
	calls := countPasswordKeys(t)
	if rec := loginFrom(handler, "198.51.100.31", "other", "Admin"); rec.code != 403 {
		t.Fatalf("wrong user: %d", rec.code)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("wrong user with the right password: %d PBKDF2; expected 1", n)
	}
	if rec := loginFrom(handler, "198.51.100.31", "other", "bad"); rec.code != 403 {
		t.Fatalf("wrong user and password: %d", rec.code)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("wrong user and password: %d PBKDF2 in total; expected 2", n)
	}
}

// I19: a PBKDF2 error is not taken for a valid hash: setP answers 500 and
// does not change the password.
func TestI19_PasswordHashError(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	token := newSession(t, "198.51.100.32")
	previous := derivePasswordKey
	t.Cleanup(func() { derivePasswordKey = previous })
	derivePasswordKey = func(password string, salt []byte, iterations int, keyLength int) ([]byte, error) {
		if password == "NewPassword1" {
			return nil, errors.New("pbkdf2 unavailable")
		}
		return previous(password, salt, iterations, keyLength)
	}
	logs := captureLog(t)
	rec := apiFrom(handler, "198.51.100.32", token, "/admin:inside:setP?a=NewPassword1&b=Admin")
	if rec.code != 500 {
		t.Errorf("setP with PBKDF2 failing: %d %q; expected 500", rec.code, rec.body.String())
	}
	if !passwordMatches("Admin") {
		t.Error("the password changed")
	}
	if !strings.Contains(logs.String(), "pbkdf2 unavailable") {
		t.Errorf("the error was not logged:\n%s", logs.String())
	}
	if _, err := hashPassword("NewPassword1"); err == nil {
		t.Error("hashPassword does not return the PBKDF2 error")
	}
}

// I19: with GODEBUG=fips140=only, Turbo starts and checks the password with
// PBKDF2 (a 16-byte salt and a 32-byte key), or, if the error shows up with
// TURBO_PASSWORD, it does not start.
func TestI19_FIPSOnly(t *testing.T) {
	bin := turboBinary(t)
	dir := t.TempDir()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_DIR="+dir, "TURBO_HTTP_ADDR=127.0.0.1:"+freePort(t), "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t), "TURBO_PASSWORD=Admin", "GODEBUG=fips140=only")
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(out.String(), "TURBO_PASSWORD") {
			t.Fatalf("Turbo exited (%v) without explaining the TURBO_PASSWORD failure:\n%s", err, out.String())
		}
		t.Logf("PBKDF2 fails with fips140=only and Turbo does not start:\n%s", out.String())
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Logf("Turbo starts with fips140=only")
	}
}

// Review of 57cbb3c, S11: the salt and the key of a "PH" are bounded (8 to 64 and 16 to 64 bytes): each login
// derives a key of that length, a PBKDF2 per 32 bytes, so a huge one written by hand made every failed login cost
// minutes of CPU.
func TestRL_S11_PasswordHashLengthsBounded(t *testing.T) {
	encoded := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	for _, c := range []struct {
		salt, key int
		ok        bool
	}{{16, 32, true}, {8, 16, true}, {64, 64, true}, {16, 65, false}, {65, 32, false}, {7, 32, false}, {16, 15, false}} {
		if _, _, _, ok := parsePasswordHash("pbkdf2-sha256$1000$" + encoded(c.salt) + "$" + encoded(c.key)); ok != c.ok {
			t.Errorf("salt of %d bytes and key of %d: accepted %v; expected %v", c.salt, c.key, ok, c.ok)
		}
	}
}

// V2 (production review of 775a809): a plain "P" of turbo.config is applied as long as the file accepts it (1 to 64
// bytes). The file took up to 64 bytes but only up to 24 were applied: a longer one left the default password, with
// the file valid and only the warning about the default credentials.
func TestRP2_V2_PlainPasswordUpTo64Bytes(t *testing.T) {
	for _, length := range []int{25, maxPasswordBytes} {
		dir := initForTest(t)
		var defaultHash string
		withReadLock(func() { defaultHash = panelPasswordHash.Get() })
		password := strings.Repeat("correct-horse-", 5)[:length]
		config := `{"^":{"v":"2"},".":{"U":"Operator","P":"` + password + `"}}`
		if err := os.WriteFile(dir+"turbo.config", []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		withGlobalLock(func() { configFileStamp = configStamp{} })
		if err := updateSettings(false); err != nil {
			t.Fatalf("%d bytes: %v", length, err)
		}
		if panelPasswordHash.Get() == defaultHash || !passwordMatches(password) {
			t.Errorf("a plain P of %d bytes isn't applied: the panel keeps the default password", length)
		}
	}
	// One byte more makes the file invalid: the configuration in use stays, with its password.
	dir := initForTest(t)
	var hashBefore string
	withReadLock(func() { hashBefore = panelPasswordHash.Get() })
	config := `{"^":{"v":"2"},".":{"U":"Operator","P":"` + strings.Repeat("x", maxPasswordBytes+1) + `"}}`
	if err := os.WriteFile(dir+"turbo.config", []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	withGlobalLock(func() { configFileStamp = configStamp{} })
	if err := updateSettings(false); err == nil || !strings.Contains(err.Error(), `"P"`) {
		t.Errorf("a plain P of %d bytes: %v; expected the file refused because of P", maxPasswordBytes+1, err)
	}
	if panelUser.Get() == "Operator" || panelPasswordHash.Get() != hashBefore {
		t.Error("a refused turbo.config changed the credentials in use")
	}
}
