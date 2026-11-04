package main

// T07 (N9, N26, I19): the current password of the actions counts for the
// login attempt limit, the login does not reveal whether a password is right
// without the user, and PBKDF2 errors are not ignored.

import (
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

// N9: after 5 wrong current passwords, the sixth gets 429 with Retry-After
// without computing PBKDF2; when the block ends, the login gets in.
func TestN09_CurrentPasswordLimited(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	t.Cleanup(func() {
		loginFailuresMutex.Lock()
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
	})
	const ip = "198.51.100.30"
	rec := loginFrom(handler, ip, "Turbo", "Admin")
	token := strings.TrimPrefix(rec.body.String(), "ok")
	if rec.code != 200 || token == "" {
		t.Fatalf("login: %d %q", rec.code, rec.body.String())
	}
	calls := countPasswordKeys(t)
	for i := 1; i <= 5; i++ {
		rec := apiFrom(handler, ip, token, "/admin:inside:setMUB?a=2000&b=bad"+strconv.Itoa(i))
		if rec.code != 400 || rec.body.String() != "Wrong current password" {
			t.Fatalf("wrong b %d: %d %q", i, rec.code, rec.body.String())
		}
	}
	before := calls.Load()
	for _, password := range []string{"bad6", "Admin"} {
		rec := apiFrom(handler, ip, token, "/admin:inside:setMUB?a=2000&b="+password)
		retry, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
		if rec.code != 429 || retry < 1 || retry > 60 {
			t.Errorf("b=%q after 5 failures: %d, Retry-After %q; expected 429", password, rec.code, rec.Header().Get("Retry-After"))
		}
	}
	if n := calls.Load() - before; n != 0 {
		t.Errorf("the blocked attempts computed %d PBKDF2", n)
	}
	if maxURILength.Load() == 2000 {
		t.Error("MUB changed with the IP blocked")
	}
	if rec := loginFrom(handler, ip, "Turbo", "Admin"); rec.code != 429 {
		t.Errorf("login with the IP blocked: %d; expected 429", rec.code)
	}
	expireLoginBlock(t, ip)
	if rec := loginFrom(handler, ip, "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("login after the block: %d", rec.code)
	}
	if rec := apiFrom(handler, ip, token, "/admin:inside:setMUB?a=2000&b=Admin"); rec.code != 200 {
		t.Errorf("setMUB with the right password after the block: %d %q", rec.code, rec.body.String())
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
	rec := loginFrom(handler, "198.51.100.32", "Turbo", "Admin")
	token := strings.TrimPrefix(rec.body.String(), "ok")
	previous := derivePasswordKey
	t.Cleanup(func() { derivePasswordKey = previous })
	derivePasswordKey = func(password string, salt []byte, iterations int, keyLength int) ([]byte, error) {
		if password == "NewPass" {
			return nil, errors.New("pbkdf2 unavailable")
		}
		return previous(password, salt, iterations, keyLength)
	}
	logs := captureLog(t)
	rec = apiFrom(handler, "198.51.100.32", token, "/admin:inside:setP?a=NewPass&b=Admin")
	if rec.code != 500 {
		t.Errorf("setP with PBKDF2 failing: %d %q; expected 500", rec.code, rec.body.String())
	}
	if !passwordMatches("Admin") {
		t.Error("the password changed")
	}
	if !strings.Contains(logs.String(), "pbkdf2 unavailable") {
		t.Errorf("the error was not logged:\n%s", logs.String())
	}
	if _, err := hashPassword("NewPass"); err == nil {
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
