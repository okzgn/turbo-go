package main

// V13, V16 and R4-08 (production reviews of 2026-11-04): the panel.
// - V13: denying an IPv6 address of ::/64 (::2, ::7f00:1), with the session alone, denied ::1 through its /64,
//   closing the connections of the health checks, a local proxy or an SSH tunnel.
// - V16: the token of the session renewed by setU, setP, setM or closeSessions went in the "ok" header also to a
//   browser, whose page's scripts can read a header (never the cookie, HttpOnly).
// - R4-08: on the panel's host served by a site, a Content-Security-Policy of the site, which the session alone can
//   add, replaced panelCSP.
// - R4-06: a login needs no session, so SameSite didn't guard it: any page could make the administrator's browser log
//   in with wrong credentials five times and lock its IP out of the panel. And a sign-out without the cookie answered
//   with one that deleted it.

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

func TestRP3_V13_LoopbackSlash64NeverDenied(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	for _, ip := range []string{"::2", "::7f00:1", "0:0:0:0:0:0:0:3"} {
		if code, body, _ := post(base, "/admin:inside:addDenied?s="+ip+"&d="+future, tok); code != 400 {
			t.Errorf("addDenied %s: %d %q; expected 400 (its /64 holds ::1)", ip, code, body)
		}
	}
	// A list that has one anyway (written before) doesn't deny ::1, while another /64 is still denied whole.
	until := time.Now().Add(time.Hour).Unix()
	publishDeniedIPs(map[string]int64{"::2": until, "2001:db8::5": until})
	t.Cleanup(func() { publishDeniedIPs(map[string]int64{}) })
	if deniedUntil("::1") != 0 {
		t.Error("a denied ::2 denies ::1 through its /64")
	}
	if deniedUntil("2001:db8::6") == 0 {
		t.Error("a denied 2001:db8::5 no longer denies its /64")
	}
}

func TestRP3_V16_RenewedTokenOnlyToAPIClients(t *testing.T) {
	initForTest(t)
	const ip = "192.0.2.70"
	browser := newSession(t, ip)
	rec := panelFrom("POST", "/admin:inside:setP?a=Another-password-1&b=Admin", ip, map[string]string{
		"Cookie": sessionCookieName + "=" + browser, "Sec-Fetch-Site": "same-origin",
	})
	if rec.code != 200 {
		t.Fatalf("setP from a browser: %d %q", rec.code, rec.body.String())
	}
	if token := rec.header.Get(sessionHeaderName); token != "" {
		t.Error("a browser got the token of its new session in a header, which its page's scripts can read")
	}
	if !strings.Contains(strings.Join(rec.header.Values("Set-Cookie"), "\n"), sessionCookieName+"=") {
		t.Error("a browser didn't get its new session in the cookie")
	}
	// An API client, whose session comes in the header, gets it there.
	rec = loginFrom(serverHandlerFn(""), ip, "Turbo", "Another-password-1")
	client := strings.TrimPrefix(rec.body.String(), "ok")
	rec = panelFrom("POST", "/admin:inside:setP?a=Third-password-1&b=Another-password-1", ip, map[string]string{sessionHeaderName: client})
	if rec.code != 200 || rec.header.Get(sessionHeaderName) == "" {
		t.Errorf("setP from an API client: %d, token in the header %q; expected the new token there", rec.code, rec.header.Get(sessionHeaderName))
	}
}

func TestRP3_R408_SiteCSPAddsToThePanels(t *testing.T) {
	dir := initForTest(t)
	globalMutex.Lock()
	ok, msg := defaultSettingValidators["."]["PA"]("panel.test", internalAuth)
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	if err := os.MkdirAll(dir+"panel.test/@", 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"panel.test/@/index.html", []byte("site"), 0644)
	updateSettings(true) // The panel's host is a site too (Turbo warns about it)
	globalMutex.Lock()
	ok, msg = subdomainContentCheckers["."](true, map[string]interface{}{"Content-Security-Policy": "script-src *"}, false, "panel.test", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	res, _, err := rawGet(base, "panel.test", "/")
	if err != nil {
		t.Fatal(err)
	}
	policies := res.Header.Values("Content-Security-Policy")
	if len(policies) != 2 || policies[0] != panelCSP {
		t.Errorf("the panel's host served by a site with a CSP: %q; expected panelCSP and the site's after it", policies)
	}
}

// loginToHost is a login from ip to host, with the given headers, through the server's handler.
func loginToHost(ip string, host string, user string, password string, headers map[string]string) *responseRecorder {
	body := url.Values{"u": {user}, "p": {password}}.Encode()
	req, _ := customNetHttp.NewRequest("POST", "http://"+host+"/admin:", strings.NewReader(body))
	req.RequestURI = "/admin:"
	req.RemoteAddr = net.JoinHostPort(ip, "40000") // An IPv6 address in brackets
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := &responseRecorder{}
	serverHandlerFn("")(rec, req)
	return rec
}

// loginWith is loginToHost to localhost.
func loginWith(ip string, user string, password string, headers map[string]string) *responseRecorder {
	return loginToHost(ip, "localhost", user, password, headers)
}

func TestRP3_R406_LoginFromAnotherOriginRefused(t *testing.T) {
	initForTest(t)
	const ip = "127.0.0.71" // The default password signs in only from this machine (O4)
	for _, headers := range []map[string]string{{"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}, {"Origin": "http://evil.test"}} {
		if rec := loginWith(ip, "Turbo", "Admin", headers); rec.code != 403 || signedIn(rec) {
			t.Errorf("a login with %v: %d %q; expected 403", headers, rec.code, rec.body.String())
		}
		for i := 0; i < loginMaxFailures+1; i++ { // Wrong ones: not even counted
			loginWith(ip, "Turbo", "wrong", headers)
		}
	}
	for _, headers := range []map[string]string{{"Sec-Fetch-Site": "same-origin"}, {"Origin": "http://localhost"}, {}} {
		if rec := loginWith(ip, "Turbo", "Admin", headers); rec.code != 200 {
			t.Errorf("a login with %v after the refused ones: %d %q; expected 200 (they didn't count as failures)", headers, rec.code, rec.body.String())
		}
	}
}

func TestRP3_R406_SignoutWithoutCookieDeletesNothing(t *testing.T) {
	initForTest(t)
	rec := panelFrom("POST", "/admin:signout", "192.0.2.72", map[string]string{"Sec-Fetch-Site": "cross-site"})
	if cookies := rec.header.Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("a sign-out without the session cookie set %q; expected nothing", cookies)
	}
}

// useTestPassword gives the panel a password other than the default one, which signs in from anywhere (O4), and
// returns it.
func useTestPassword(t *testing.T) string {
	t.Helper()
	const password = "Test-password-12"
	if err := setPanelPassword(password); err != nil {
		t.Fatal(err)
	}
	return password
}

// O4 (decision D2): the default password opens a session only from this machine, without a proxy in front: a Turbo
// just installed, or whose unit lost the file with its credentials, let anyone who reached it in.
func TestRP3_O4_DefaultPasswordOnlyFromThisMachine(t *testing.T) {
	initForTest(t)
	for _, c := range []struct {
		ip      string
		headers map[string]string
	}{
		{"192.0.2.80", nil},
		{"2001:db8::80", nil},
		{"127.0.0.1", map[string]string{"X-Forwarded-For": "203.0.113.9"}},
		{"127.0.0.1", map[string]string{"Forwarded": "for=203.0.113.9"}},
		{"::1", map[string]string{"X-Real-IP": "203.0.113.9"}},
	} {
		for i := 0; i < loginMaxFailures+1; i++ { // Not failures: the IP isn't blocked
			rec := loginWith(c.ip, "Turbo", "Admin", c.headers)
			if rec.code != 403 || rec.header.Get("X-Turbo-Login") != "local-only" || !strings.Contains(rec.body.String(), "only signs in from this machine") || signedIn(rec) {
				t.Fatalf("the default password from %s %v: %d %q; expected 403 local-only", c.ip, c.headers, rec.code, rec.body.String())
			}
		}
	}
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
		if rec := loginWith(ip, "Turbo", "Admin", nil); rec.code != 200 {
			t.Errorf("the default password from %s: %d %q; expected 200", ip, rec.code, rec.body.String())
		}
	}
	password := useTestPassword(t) // Changed: from anywhere
	if rec := loginWith("192.0.2.80", "Turbo", password, nil); rec.code != 200 {
		t.Errorf("another password from 192.0.2.80: %d %q; expected 200", rec.code, rec.body.String())
	}
}

// V14: the wrong current passwords count per session; the fifth closes it, and the IP isn't blocked for them.
func TestRP3_V14_WrongCurrentPasswordsPerSession(t *testing.T) {
	initForTest(t)
	const ip = "192.0.2.81"
	copied, administrator := newSession(t, ip), newSession(t, ip)
	action := func(token string, password string) *responseRecorder {
		return panelFrom("POST", "/admin:inside:closeSessions?b="+password, ip, map[string]string{sessionHeaderName: token})
	}
	for i := 1; i < loginMaxFailures; i++ {
		if rec := action(copied, "wrong"); rec.code != 400 || rec.header.Get("X-Turbo-Login") != "" {
			t.Fatalf("wrong current password %d: %d %q; expected 400", i, rec.code, rec.body.String())
		}
	}
	rec := action(copied, "wrong")
	if rec.code != 400 || rec.header.Get("X-Turbo-Login") != "required" {
		t.Errorf("the %dth wrong current password: %d, X-Turbo-Login %q; expected the session closed", loginMaxFailures, rec.code, rec.header.Get("X-Turbo-Login"))
	}
	if _, alive := sessionExpiry(ip, copied); alive {
		t.Error("the session that spent its attempts is still open")
	}
	if rec := action(administrator, "Admin"); rec.code != 200 {
		t.Errorf("closeSessions of another session of the same IP: %d %q; expected 200 (the IP isn't blocked)", rec.code, rec.body.String())
	}
	// A right one clears the count.
	token := newSession(t, ip)
	for i := 0; i < loginMaxFailures-1; i++ {
		action(token, "wrong")
	}
	if rec := panelFrom("POST", "/admin:inside:setPA?a=&b=Admin", ip, map[string]string{sessionHeaderName: token}); rec.code != 400 || !strings.Contains(rec.body.String(), "unchanged") {
		t.Fatalf("a right current password: %d %q", rec.code, rec.body.String())
	}
	for i := 0; i < loginMaxFailures-1; i++ {
		action(token, "wrong")
	}
	if _, alive := sessionExpiry(ip, token); !alive {
		t.Error("a right current password didn't clear the count of the wrong ones")
	}
}

// V15: a client that signed in correctly in the last 12 hours skips the brake of its IPv6 /48, which its neighbours
// could otherwise hold, though not its own.
func TestRP3_V15_TrustedClientSkipsItsSlash48(t *testing.T) {
	initForTest(t)
	password := useTestPassword(t)
	if rec := loginWith("2001:db8:7:1::1", "Turbo", password, nil); rec.code != 200 {
		t.Fatalf("login: %d %q", rec.code, rec.body.String())
	}
	for i := 0; i < loginMaxNetworkFailures; i++ { // Neighbours of the /48, one /64 each
		loginWith("2001:db8:7:"+strconv.Itoa(100+i)+"::1", "Turbo", "wrong", nil)
	}
	if rec := loginWith("2001:db8:7:200::1", "Turbo", password, nil); rec.code != 429 {
		t.Errorf("a client of the blocked /48 that isn't trusted: %d; expected 429", rec.code)
	}
	if rec := loginWith("2001:db8:7:1::5", "Turbo", password, nil); rec.code != 200 {
		t.Errorf("the trusted client, in the blocked /48: %d %q; expected 200", rec.code, rec.body.String())
	}
	for i := 0; i < loginMaxFailures; i++ { // Its own brake still holds
		loginWith("2001:db8:7:1::5", "Turbo", "wrong", nil)
	}
	if rec := loginWith("2001:db8:7:1::5", "Turbo", password, nil); rec.code != 429 {
		t.Errorf("the trusted client after its own %d failures: %d; expected 429", loginMaxFailures, rec.code)
	}
}

// R4-07: the pages of the panel embedded in the binary run only their own script and style, by their hashes, and
// load only the panel's own files; the panel's other files run no scripts; a page of one's own (turbo.dev/ in the
// sites directory) keeps frame-ancestors only. The panel sends Referrer-Policy: no-referrer.
func TestRP3_R407_StrictPolicyOfThePanelPages(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	inlineHash := func(page string, tag string) string {
		start := strings.Index(page, "<"+tag+">") + len(tag) + 2
		end := strings.Index(page[start:], "</"+tag+">")
		sum := sha256.Sum256([]byte(page[start : start+end]))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	for _, c := range []struct{ name, path, token string }{
		{"turbo.dev/admin/#.html", "/admin:", ""},
		{"turbo.dev/inside/#.html", "/admin:inside:", tok},
	} {
		page, err := fs.ReadFile(embeddedGUI, c.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range []string{"<script", "<style"} { // Only <script> and <style>: their hashes are what runs
			if count, plain := strings.Count(string(page), tag), strings.Count(string(page), tag+">"); count != plain || count != 1 {
				t.Errorf("%s has %d %s elements, %d of them without attributes; expected one, without attributes", c.name, count, tag, plain)
			}
		}
		req, _ := http.NewRequest("GET", base+c.path, nil)
		req.Host = "localhost"
		if c.token != "" {
			req.Header.Set(sessionHeaderName, c.token)
		}
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		policy := res.Header.Get("Content-Security-Policy")
		for _, expected := range []string{"default-src 'none'", "script-src " + inlineHash(string(page), "script"), "style-src 'self' " + inlineHash(string(page), "style"), "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"} {
			if !strings.Contains(policy, expected) {
				t.Errorf("%s: Content-Security-Policy %q; expected %q in it", c.path, policy, expected)
			}
		}
		if res.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: Referrer-Policy %q; expected no-referrer", c.path, res.Header.Get("Referrer-Policy"))
		}
	}
	if res, _, err := rawGet(base, "localhost", "/admin:m.css"); err != nil || res.Header.Get("Content-Security-Policy") != panelCSP {
		t.Errorf("the panel's stylesheet: %v %v; expected panelCSP, without scripts", res, err)
	}
	if err := os.MkdirAll(dir+"turbo.dev/admin", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"turbo.dev/admin/#.html", []byte("<p>mine</p>"), 0644); err != nil {
		t.Fatal(err)
	}
	if res, _, err := rawGet(base, "localhost", "/admin:"); err != nil || res.Header.Get("Content-Security-Policy") != panelPageCSP {
		t.Errorf("a page of one's own in turbo.dev/: %v %v; expected frame-ancestors only", res, err)
	}
}

// V14: setP knows the current password (b), which has just matched: the new one is unchanged only if it is that one,
// with no PBKDF2, and its hash takes a PBKDF2 slot, the one kept for the sessions too, or answers 503. It compared the
// new one with the hash, a PBKDF2 more that waited for a free slot as long as a flood of logins took them.
func TestRP3_V14_SetPasswordCostsOnePBKDF2(t *testing.T) {
	initForTest(t)
	const ip = "192.0.2.82"
	token := newSession(t, ip)
	setP := func(password, current string) *responseRecorder {
		done := make(chan *responseRecorder, 1)
		go func() {
			done <- apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setP?"+url.Values{"a": {password}, "b": {current}}.Encode())
		}()
		select {
		case rec := <-done:
			if renewed := rec.Header().Get(sessionHeaderName); renewed != "" {
				token = renewed
			}
			return rec
		case <-time.After(10 * time.Second):
			t.Fatal("setP still waiting for a PBKDF2 slot after 10 s")
			return nil
		}
	}
	password := useTestPassword(t) // 12 bytes at least, as a new one
	calls := countPasswordKeys(t)
	if rec := setP(password, password); rec.code != 400 || rec.body.String() != "Password unchanged" || calls.Load() != 0 {
		t.Errorf("setP to the same password: %d %q, %d PBKDF2; expected 400 \"Password unchanged\" and none", rec.code, rec.body.String(), calls.Load())
	}
	if rec := setP("First-password-1", password); rec.code != 200 || calls.Load() != 1 {
		t.Errorf("setP to a new password: %d %q, %d PBKDF2; expected 200 and one, its hash", rec.code, rec.body.String(), calls.Load())
	}

	// With every other slot taken, the one kept for the sessions; with that one taken too, 503.
	for i := 0; i < cap(passwordHashSlots); i++ {
		passwordHashSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(passwordHashSlots); i++ {
			<-passwordHashSlots
		}
	}()
	if rec := setP("Second-password-2", "First-password-1"); rec.code != 200 {
		t.Errorf("setP with every other slot taken: %d %q; expected 200", rec.code, rec.body.String())
	}
	passwordReservedSlot <- struct{}{}
	defer func() { <-passwordReservedSlot }()
	hashBefore, start := panelPasswordHash.Get(), time.Now()
	if rec := setP("Third-password-3", "Second-password-2"); rec.code != 503 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("setP with every slot taken: %d %q; expected 503 with Retry-After", rec.code, rec.body.String())
	} else if waited := time.Since(start); waited < passwordSlotWait/2 {
		t.Errorf("setP gave up after %v; expected to wait for a slot about %v", waited, passwordSlotWait)
	}
	if panelPasswordHash.Get() != hashBefore { // Not passwordMatches: with every slot taken, a PBKDF2 would wait
		t.Error("setP without a slot changed the password")
	}
}

// M-02 (decision D3): addMIME and addHeader need the current password in c, and delMIME and delHeader in b: a MIME
// type (text/html for any extension) or a header (Content-Type) can make a site's file run as a page, on the panel's
// origin while PA is empty. Without it, 400 and nothing changes; wrong, 400; right, the action. One session each.
func TestRP3_M02_MIMEAndHeadersNeedPassword(t *testing.T) {
	initForTest(t)
	const ip = "192.0.2.83"
	present := func(name string) bool {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		if name == "addMIME" || name == "delMIME" {
			_, found := mimeTypes["localhost"]["xyz"]
			return found
		}
		_, found := customHeaders["localhost"]["X-Test"]
		return found
	}
	for _, action := range []struct {
		name, param string
		values      url.Values
		after       bool // Whether the entry is there after the action
	}{
		{"addMIME", "c", url.Values{"a": {"xyz"}, "b": {"text/html"}}, true},
		{"addHeader", "c", url.Values{"a": {"X-Test"}, "b": {"1"}}, true},
		{"delMIME", "b", url.Values{"a": {"xyz"}}, false},
		{"delHeader", "b", url.Values{"a": {"X-Test"}}, false},
	} {
		token := newSession(t, ip)
		for _, c := range []struct {
			password string
			code     int
			body     string
		}{{"", 400, "the current password (" + action.param + ")"}, {"WrongPassword", 400, "Wrong current password"}, {"Admin", 200, ""}} {
			values := url.Values{"s": {"localhost"}, "d": {""}}
			for name, value := range action.values {
				values[name] = value
			}
			if c.password != "" {
				values.Set(action.param, c.password)
			}
			rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:"+action.name+"?"+values.Encode())
			if rec.code != c.code || !strings.Contains(rec.body.String(), c.body) {
				t.Errorf("%s with the password %q: %d %q; expected %d %q", action.name, c.password, rec.code, rec.body.String(), c.code, c.body)
			}
			if expected := action.after == (c.code == 200); present(action.name) != expected {
				t.Errorf("%s with the password %q: the entry there %v; expected %v", action.name, c.password, present(action.name), expected)
			}
		}
	}
	// The password is taken as sent, also with a replacement token ("-.-"); the other values still go through them.
	token := newSession(t, ip)
	const password = "abcd-.-efghij"
	if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setP?"+url.Values{"a": {password}, "b": {"Admin"}}.Encode()); rec.code != 200 {
		t.Fatalf("setP: %d %q", rec.code, rec.body.String())
	} else {
		token = rec.Header().Get(sessionHeaderName)
	}
	for _, action := range []string{"addMIME?a=xyz&b=text/plain&c=", "addHeader?a=X-Test&b=1-.-2&c=", "delMIME?a=xyz&b=", "delHeader?a=X-Test&b="} {
		if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:"+action+url.QueryEscape(password)+"&s=localhost&d="); rec.code != 200 {
			t.Errorf("%s with a password that has a token: %d %q; expected 200", strings.SplitN(action, "?", 2)[0], rec.code, rec.body.String())
		}
		if strings.HasPrefix(action, "addHeader") {
			globalMutex.RLock()
			value := customHeaders["localhost"]["X-Test"]
			globalMutex.RUnlock()
			if value != "1;2" {
				t.Errorf("the header's value: %q; expected the token undone, 1;2", value)
			}
		}
	}
}
