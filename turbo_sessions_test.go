package main

// T10 (N25, N27, N30, I16): an expired session isn't valid even if the cleanup
// hasn't run yet; the renewal doesn't undo a sign-out; signing out with the
// cookie requires the same origin; a foreign cookie with the same name doesn't
// block the panel; setP and setU close every session and give the request a
// new one; and only the requests from the same origin renew the session.

import (
	"crypto/tls"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// panelFrom sends a panel request from ip with the given headers, without the network.
func panelFrom(method, path, ip string, headers map[string]string) *responseRecorder {
	req, _ := customNetHttp.NewRequest(method, "http://localhost"+path, customNetHttp.NoBody)
	req.RequestURI = path
	req.RemoteAddr = ip + ":40000"
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := &responseRecorder{}
	serverHandlerFn("")(rec, req)
	return rec
}

// signedIn says whether the request gets into the panel (it isn't redirected to the login).
func signedIn(rec *responseRecorder) bool {
	return rec.code == 200 && !strings.Contains(rec.body.String(), "http-equiv")
}

func newSession(t *testing.T, ip string) string {
	t.Helper()
	rec := loginFrom(serverHandlerFn(""), ip, "Turbo", "Admin")
	if rec.code != 200 {
		t.Fatalf("login: %d", rec.code)
	}
	return strings.TrimPrefix(rec.body.String(), "ok")
}

func sessionExpiry(ip, token string) (int64, bool) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	expiry, found := signedInTokens[sessionKey(ip, token)]
	return expiry, found
}

// N30, I16: an expired session is rejected even if the periodic cleanup hasn't
// removed it, and a panel request doesn't go through the sessions of others.
func TestN30_ExpiredSessionRejected(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.60"
	token := newSession(t, ip)
	other := sessionKey("198.51.100.61", "expired")
	withGlobalLock(func() {
		signedInTokens[sessionKey(ip, token)] = time.Now().Unix() - 1
		signedInTokens[other] = time.Now().Unix() - 1
	})
	if signedIn(panelFrom("GET", "/admin:inside:", ip, map[string]string{"ok": token})) {
		t.Error("an expired session gets into the panel")
	}
	globalMutex.RLock()
	_, kept := signedInTokens[other]
	globalMutex.RUnlock()
	if !kept {
		t.Error("a request to the panel cleaned up the sessions of others (the periodic task does that)")
	}
}

// N25: a request that already saw the session as valid doesn't create it
// again if it is closed in the meantime.
func TestN25_SignoutDuringRequest(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.62"
	token := newSession(t, ip)
	beforeSessionRenewal = func() {
		withGlobalLock(func() { delete(signedInTokens, sessionKey(ip, token)) })
	}
	t.Cleanup(func() { beforeSessionRenewal = func() {} })
	panelFrom("GET", "/admin:inside:", ip, map[string]string{"ok": token})
	if _, found := sessionExpiry(ip, token); found {
		t.Error("the renewal created a closed session again")
	}
}

// N25: signing out with the cookie requires the request to come from the same
// origin; with the "ok" header it isn't needed.
func TestN25_SignoutSameOrigin(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.63"
	token := newSession(t, ip)
	cookie := map[string]string{"Cookie": sessionCookieName + "=" + token, "Sec-Fetch-Site": "same-site"}
	if rec := panelFrom("POST", "/admin:signout:", ip, cookie); rec.code != 403 {
		t.Errorf("signout with the cookie from another origin: %d; expected 403", rec.code)
	}
	if _, found := sessionExpiry(ip, token); !found {
		t.Fatal("the session was closed from another origin")
	}
	cookie["Sec-Fetch-Site"] = "same-origin"
	panelFrom("POST", "/admin:signout:", ip, cookie)
	if _, found := sessionExpiry(ip, token); found {
		t.Error("signout from the same origin did not close the session")
	}
}

// N27: a cookie with the same name set by another subdomain (sent before the
// panel's) doesn't prevent getting in; over TLS, the cookie is __Host-.
func TestN27_ForeignCookieFirst(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.64"
	token := newSession(t, ip)
	rec := panelFrom("GET", "/admin:inside:", ip, map[string]string{"Cookie": sessionCookieName + "=fake; " + sessionCookieName + "=" + token})
	if !signedIn(rec) {
		t.Errorf("with a foreign cookie first: %d %.60q", rec.code, rec.body.String())
	}
	req := newPanelRequest("/admin:", ip+":40000")
	req.TLS = &tls.ConnectionState{}
	if cookie := sessionCookie("x", false, req); !strings.HasPrefix(cookie, "__Host-turbo_session=x;") || !strings.Contains(cookie, "Secure") || strings.Contains(cookie, "Domain") {
		t.Errorf("cookie over TLS: %q; expected __Host-turbo_session with Secure and without Domain", cookie)
	}
	rec = panelFrom("GET", "/admin:inside:", ip, map[string]string{"Cookie": "__Host-turbo_session=" + token})
	if !signedIn(rec) {
		t.Error("the __Host-turbo_session cookie is not accepted")
	}
}

// I16, and production review M-08: setP and setU close every session, the request's own too, and open a new one
// for its client, whose token comes in the answer (the cookie, and the "ok" header): a copy of the old token is
// worth nothing.
func TestI16_PasswordChangeClosesOtherSessions(t *testing.T) {
	initForTest(t)
	for _, change := range []string{"/admin:inside:setP?a=NewPassword1&b=Admin", "/admin:inside:setU?a=Other&b=NewPassword1"} {
		mine := newSessionWith(t, "198.51.100.65")
		other := newSessionWith(t, "198.51.100.66")
		rec := apiFrom(serverHandlerFn(""), "198.51.100.65", mine, change)
		if rec.code != 200 {
			t.Fatalf("%s: %d %q", change, rec.code, rec.body.String())
		}
		renewed := rec.Header().Get(sessionHeaderName)
		if _, found := sessionExpiry("198.51.100.66", other); found {
			t.Errorf("%s: the other session is still open", change)
		}
		if _, found := sessionExpiry("198.51.100.65", mine); found {
			t.Errorf("%s: the old token of the request still works", change)
		}
		if _, found := sessionExpiry("198.51.100.65", renewed); renewed == "" || !found {
			t.Errorf("%s: no new session in the answer (ok: %q)", change, renewed)
		}
		if cookies := strings.Join(rec.Header()["Set-Cookie"], " | "); !strings.Contains(cookies, sessionCookieName+"="+renewed+";") {
			t.Errorf("%s: the cookie doesn't carry the new token: %q", change, cookies)
		}
	}
}

// newSessionWith signs in with the credentials in use (they change during the test).
func newSessionWith(t *testing.T, ip string) string {
	t.Helper()
	for _, credentials := range [][2]string{{"Turbo", "Admin"}, {"Turbo", "NewPassword1"}, {"Other", "NewPassword1"}} {
		if rec := loginFrom(serverHandlerFn(""), ip, credentials[0], credentials[1]); rec.code == 200 {
			return strings.TrimPrefix(rec.body.String(), "ok")
		}
	}
	t.Fatal("none of the credentials get in")
	return ""
}

// I16: a request from another origin (a resource another page loads) doesn't
// renew the session; one from the same origin does.
func TestI16_RenewOnlySameOrigin(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.67"
	token := newSession(t, ip)
	withGlobalLock(func() { signedInTokens[sessionKey(ip, token)] = time.Now().Unix() + 100 })
	panelFrom("GET", "/admin:inside:", ip, map[string]string{"Cookie": sessionCookieName + "=" + token, "Sec-Fetch-Site": "same-site"})
	if expiry, _ := sessionExpiry(ip, token); expiry > time.Now().Unix()+100 {
		t.Error("a request from another origin renewed the session")
	}
	panelFrom("GET", "/admin:inside:", ip, map[string]string{"Cookie": sessionCookieName + "=" + token, "Sec-Fetch-Site": "same-origin"})
	if expiry, _ := sessionExpiry(ip, token); expiry < time.Now().Unix()+500 {
		t.Error("a request from the same origin did not renew the session")
	}
}

// N76: when the credentials change by setM (those of the other directory's
// turbo.config) or by a reload of the file, the sessions opened with the old
// ones are closed, as with setU and setP; the client that did setM gets a new
// one (production review, M-08).
func TestN76_SessionsEndWhenCredentialsChange(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	first, second := login(t, base), login(t, base)
	hash, err := hashPassword("Another")
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(other+"turbo.config", []byte(`{"^":{"v":"2"},".":{"U":"Turbo","PH":"`+hash+`"}}`), 0600)
	code, body, renewed, _ := postSession(base, "/admin:inside:setM?"+url.Values{"a": {other}, "b": {"Admin"}}.Encode(), first)
	if code != 200 {
		t.Fatalf("setM: %d %q", code, body)
	}
	alive := func(token string) bool { // Without a session, the response is the HTML redirect to the login
		code, body, _ := post(base, "/admin:inside:sites", token)
		return code == 200 && strings.HasPrefix(body, "{")
	}
	if renewed == first || !alive(renewed) || alive(first) || alive(second) {
		t.Errorf("after setM with other credentials: the new session of the one that did it is alive = %v, its old token = %v, the other one = %v; expected true, false and false", alive(renewed), alive(first), alive(second))
	}
	first = renewed
	// A reload that changes the user closes them all
	os.WriteFile(other+"turbo.config", []byte(`{"^":{"v":"2"},".":{"U":"Other","PH":"`+hash+`"}}`), 0600)
	future := time.Now().Add(time.Minute)
	os.Chtimes(other+"turbo.config", future, future)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if alive(first) {
		t.Error("the session is still alive after a reload that changes the user")
	}
}

// Production review, M-08: closeSessions, with the password, closes every session, the request's own too (a copy of
// its token, taken from the same IP, is worth nothing), and gives its client a new one; without the password, a
// stolen session can't close the administrator's.
func TestRP_M08_CloseEverySession(t *testing.T) {
	initForTest(t)
	mine := newSession(t, "198.51.100.76")
	other := newSession(t, "198.51.100.77")
	for _, c := range []struct {
		query string
		code  int
		body  string
	}{{"", 400, "the current password (b)"}, {"?b=WrongPassword", 400, "Wrong current password"}} {
		if rec := apiFrom(serverHandlerFn(""), "198.51.100.76", mine, "/admin:inside:closeSessions"+c.query); rec.code != c.code || !strings.Contains(rec.body.String(), c.body) {
			t.Errorf("closeSessions%s: %d %q; expected %d %q", c.query, rec.code, rec.body.String(), c.code, c.body)
		}
	}
	if _, found := sessionExpiry("198.51.100.77", other); !found {
		t.Fatal("closeSessions without the password closed a session")
	}
	rec := apiFrom(serverHandlerFn(""), "198.51.100.76", mine, "/admin:inside:closeSessions?b=Admin")
	if rec.code != 200 {
		t.Fatalf("closeSessions: %d %q", rec.code, rec.body.String())
	}
	renewed := rec.Header().Get(sessionHeaderName)
	_, mineAlive := sessionExpiry("198.51.100.76", mine)
	_, otherAlive := sessionExpiry("198.51.100.77", other)
	_, renewedAlive := sessionExpiry("198.51.100.76", renewed)
	if mineAlive || otherAlive || renewed == "" || !renewedAlive {
		t.Errorf("after closeSessions: old token alive %v, other session alive %v, new token %q alive %v; expected only the new one", mineAlive, otherAlive, renewed, renewedAlive)
	}
	if cookies := strings.Join(rec.Header()["Set-Cookie"], " | "); !strings.Contains(cookies, sessionCookieName+"="+renewed+";") {
		t.Errorf("the cookie doesn't carry the new token: %q", cookies)
	}
}

// Production review, M-08: a session can't be renewed past sessionMaxLifetime from its login.
func TestRP_M08_SessionMaxLifetime(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.78"
	token := newSession(t, ip)
	key := sessionKey(ip, token)
	now := time.Now().Unix()
	globalMutex.RLock()
	deadline := sessionDeadlines[key]
	globalMutex.RUnlock()
	if deadline < now+sessionMaxLifetime-60 || deadline > now+sessionMaxLifetime+60 {
		t.Fatalf("deadline of a new session: %d s from now; expected %d", deadline-now, sessionMaxLifetime)
	}
	withGlobalLock(func() { sessionDeadlines[key] = now + 3 }) // Its login was almost sessionMaxLifetime ago
	if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:sites"); rec.code != 200 || !strings.HasPrefix(rec.body.String(), "{") {
		t.Fatalf("sites: %d %.80q", rec.code, rec.body.String())
	}
	if expiry, _ := sessionExpiry(ip, token); expiry > now+3 {
		t.Errorf("a request renewed the session %d s past its deadline", expiry-(now+3))
	}
}
