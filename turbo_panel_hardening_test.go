package main

// Review of 6046dbe (R6): the panel's credentials, sessions, uploads and what the session alone may do.

import (
	"crypto/tls"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// R6 P-01: while TURBO_PASSWORD or TURBO_USER set the credential, setP and setU are refused. They answered "changed",
// the new one was saved, and the next start brought the one of the environment back.
func TestR6_P01_CredentialsOfTheEnvironmentAreNotChanged(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	userFromEnv, passwordFromEnv = true, true // As main() leaves them with TURBO_USER and TURBO_PASSWORD
	t.Cleanup(func() { userFromEnv, passwordFromEnv = false, false })
	for action, variable := range map[string]string{
		"/admin:inside:setP?" + url.Values{"a": {"AnotherPassword12"}, "b": {"Admin"}}.Encode(): "TURBO_PASSWORD",
		"/admin:inside:setU?" + url.Values{"a": {"Other"}, "b": {"Admin"}}.Encode():             "TURBO_USER",
	} {
		code, body, _, _ := postSession(base, action, tok)
		if code != 400 || !strings.Contains(body, variable) {
			t.Errorf("%s with %s set: %d %q; expected 400 naming the variable", action, variable, code, body)
		}
	}
	if !passwordMatches("Admin") || passwordMatches("AnotherPassword12") || panelUser.Get() != "Turbo" {
		t.Error("the credentials changed")
	}
	// Without them, both still change
	userFromEnv, passwordFromEnv = false, false
	if code, body, _, _ := postSession(base, "/admin:inside:setP?"+url.Values{"a": {"AnotherPassword12"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Errorf("setP without TURBO_PASSWORD: %d %q", code, body)
	}
}

// R6 P-09: a subdomain can't be called as the certificate files of its site, whose folder would take their place.
func TestR6_P09_SubdomainNamedAsACertificateFile(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, name := range []string{certFileName, keyFileName, certFileName + ".new", keyFileName + ".new"} {
		code, body, _ := post(base, "/admin:inside:addSubdomain?"+url.Values{"s": {"localhost"}, "d": {name}}.Encode(), tok)
		if code != 400 || !strings.Contains(body, "reserved") {
			t.Errorf("addSubdomain %s: %d %q; expected 400", name, code, body)
		}
		if _, err := os.Stat(dir + "localhost/" + name); err == nil {
			t.Errorf("the folder localhost/%s was created", name)
		}
	}
	// One found on disk isn't activated either
	os.MkdirAll(dir+"localhost/"+keyFileName+"/@", 0755)
	updateSettings(true)
	if siteExists("localhost", keyFileName) {
		t.Errorf("the folder localhost/%s was activated as a subdomain", keyFileName)
	}
	if code, body, _ := post(base, "/admin:inside:addSubdomain?s=localhost&d=blog", tok); code != 200 {
		t.Errorf("addSubdomain blog: %d %q", code, body)
	}
}

// R6 P-10: the message of a turbo.config that is broken at its "P" or "PH" never shows their value, also when the
// colon is missing or the key isn't written as JSON asks.
func TestR6_P10_PasswordHiddenInABrokenKey(t *testing.T) {
	dir := t.TempDir() + "/"
	for _, content := range []string{
		`{".":{"P" "hunter2hunter2"}}`,
		`{".":{"PH" "hunter2hunter2"}}`,
		`{".":{'P': "hunter2hunter2"}}`,
		`{".":{P: "hunter2hunter2"}}`,
		`{".":{"U":"Turbo","P":"hunter2hunter2",}}`,
		`{".":{"P":"hunter2hunter2" "U":"Turbo"}}`,
	} {
		os.WriteFile(dir+configFileName, []byte(content), 0600)
		_, err := parseSiteConfig(dir + configFileName)
		if err == nil {
			t.Errorf("%s was read without an error", content)
			continue
		}
		if message := configErrorMessage(err, true); strings.Contains(message, "hunter2") {
			t.Errorf("the message of %s shows the password:\n%s", content, message)
		}
	}
	// What isn't the password stays in the message
	os.WriteFile(dir+configFileName, []byte(`{".":{"PA" "panel.test"}}`), 0600)
	if _, err := parseSiteConfig(dir + configFileName); err == nil || !strings.Contains(configErrorMessage(err, true), "panel.test") {
		t.Errorf("the value of PA was hidden too: %v", err)
	}
}

// R6 P-11: the cookie of HTTP, which has no Secure, is no session over TLS; the one of TLS is, and by HTTP nothing
// changes.
func TestR6_P11_PlainCookieIsNoSessionOverTLS(t *testing.T) {
	initForTest(t)
	const ip = "127.0.0.1"
	token := newSession(t, ip)
	request := func(cookieName string, overTLS bool) *customNetHttp.Request {
		req := newPanelRequest("/admin:inside:", ip+":40000")
		if overTLS {
			req.TLS = &tls.ConnectionState{}
		}
		req.AddCookie(&customNetHttp.Cookie{Name: cookieName, Value: token})
		return req
	}
	for _, c := range []struct {
		cookie  string
		overTLS bool
		session bool
	}{
		{sessionCookieName, false, true},
		{sessionCookieName, true, false},
		{sessionCookieNameTLS, true, true},
		{sessionCookieNameTLS, false, true},
	} {
		if key, _, _ := panelSession(request(c.cookie, c.overTLS), ip); (key != "") != c.session {
			t.Errorf("cookie %s, TLS=%v: session=%v; expected %v", c.cookie, c.overTLS, key != "", c.session)
		}
	}
	// The token in the "ok" header, which an API client sends, is a session by either
	req := newPanelRequest("/admin:inside:", ip+":40000")
	req.TLS = &tls.ConnectionState{}
	req.Header.Set(sessionHeaderName, token)
	if key, viaCookie, _ := panelSession(req, ip); key == "" || viaCookie {
		t.Error("the token in the header isn't a session over TLS")
	}
}

// R6 V-03: a fixed replacement can't be replaced by writing its character with blanks around it.
func TestR6_V03_FixedReplacementWithBlanks(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, char := range []string{" ;", "; ", "\u00a0;", " # ", "& "} {
		code, body, _ := post(base, "/admin:inside:addCharsReplace?"+url.Values{"s": {char}, "d": {"zz"}, "b": {"Admin"}}.Encode(), tok)
		if code != 400 || body != "Fixed replacement" {
			t.Errorf("addCharsReplace %q: %d %q; expected 400 \"Fixed replacement\"", char, code, body)
		}
	}
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	if charReplacements[";"] != "-.-" || charReplacements["#"] != "-,-" || charReplacements["&"] != "-_-" {
		t.Errorf("the fixed replacements changed: %v", charReplacements)
	}
}

// R6 P-14: an uploaded file whose name has control characters or isn't valid UTF-8 is discarded: no request could
// ever name it.
func TestR6_P14_UploadedNamesThatCanNotBeServed(t *testing.T) {
	for name, accepted := range map[string]bool{
		"site/a b.txt":      true,
		"site/ñ/é.txt":      true,
		"site/a\x7fb.txt":   false,
		"site/a\x01b.txt":   false,
		"site/a\xffb.txt":   false,
		"site/dir\x00/a.js": false,
	} {
		if _, ok := uploadedFilePath(name); ok != accepted {
			t.Errorf("uploadedFilePath(%q) accepted=%v; expected %v", name, ok, accepted)
		}
	}
}

// R6 P-03: what takes a site down or sends its visitors away needs the current password, not the session alone: a
// rewrite to another address, denying an IP, and turning a site's HTTPS off. What stays inside the site, or only
// restores, still needs only the session.
func TestR6_P03_ActionsThatNeedTheCurrentPassword(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	base := startServer(t)
	tok := login(t, base)
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	site := url.Values{"s": {"localhost"}, "d": {""}}
	with := func(values url.Values, more ...string) string {
		all := url.Values{}
		for name, value := range values {
			all[name] = value
		}
		for i := 0; i+1 < len(more); i += 2 {
			all.Set(more[i], more[i+1])
		}
		return all.Encode()
	}
	if code, body, _ := post(base, "/admin:inside:cfgS?"+with(site, "a", "1"), tok); code != 200 {
		t.Fatalf("cfgS a=1 with the session alone: %d %q", code, body)
	}
	for name, action := range map[string]struct {
		path, param string
		values      url.Values
	}{
		"a rewrite to https://":            {"addRewrite", "c", url.Values{"s": {"localhost"}, "d": {""}, "a": {"/"}, "b": {"https://other.test/"}}},
		"a rewrite to HTTP:// in capitals": {"addRewrite", "c", url.Values{"s": {"localhost"}, "d": {""}, "a": {"/shop"}, "b": {"HTTP://other.test"}}},
		"a rewrite with a host keyword":    {"addRewrite", "c", url.Values{"s": {"localhost"}, "d": {""}, "a": {"/away"}, "b": {"https://{DOMAIN}.other.test/"}}},
		"denying an IP":                    {"addDenied", "b", url.Values{"s": {"203.0.113.7"}, "d": {future}}},
		"turning HTTPS off":                {"cfgS", "b", url.Values{"s": {"localhost"}, "d": {""}, "a": {"0"}}},
	} {
		path := "/admin:inside:" + action.path + "?"
		if code, body, _ := post(base, path+action.values.Encode(), tok); code != 400 || !strings.Contains(body, "current password") {
			t.Errorf("%s with the session alone: %d %q; expected 400 asking for the current password", name, code, body)
		}
		if code, body, _ := post(base, path+with(action.values, action.param, "Wrong-password-1"), tok); code == 200 {
			t.Errorf("%s with a wrong password: %d %q", name, code, body)
		}
		if code, body, _ := post(base, path+with(action.values, action.param, "Admin"), tok); code != 200 {
			t.Errorf("%s with the current password: %d %q; expected 200", name, code, body)
		}
	}
	// With the session alone, as before: a rewrite inside the site, and what gives back what those take
	for name, path := range map[string]string{
		"a rewrite inside the site": "/admin:inside:addRewrite?" + url.Values{"s": {"localhost"}, "d": {""}, "a": {"/old"}, "b": {"/new.html"}}.Encode(),
		"turning HTTPS on":          "/admin:inside:cfgS?" + with(site, "a", "1"),
		"allowing an IP again":      "/admin:inside:delDenied?s=203.0.113.7",
		"deleting a rewrite":        "/admin:inside:delRewrite?" + with(site, "a", "/shop"),
	} {
		if code, body, _ := post(base, path, tok); code != 200 {
			t.Errorf("%s with the session alone: %d %q; expected 200", name, code, body)
		}
	}
}

// R6 P-03: the target of a rewrite is read for the password as its validator reads it, with the character
// replacements undone: one that only spells "https://" once they are undone is a rewrite to another address too.
func TestR6_P03_ExternalRewriteThroughAReplacement(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addCharsReplace?"+url.Values{"s": {":"}, "d": {"-c-"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("addCharsReplace: %d %q", code, body)
	}
	values := url.Values{"s": {"localhost"}, "d": {""}, "a": {"/"}, "b": {"https-c-//other.test/"}}
	if code, body, _ := post(base, "/admin:inside:addRewrite?"+values.Encode(), tok); code != 400 || !strings.Contains(body, "current password") {
		t.Errorf("a rewrite to https-c-// (https:// with its replacement) with the session alone: %d %q; expected 400", code, body)
	}
	globalMutex.RLock()
	_, saved := sitesMap["localhost"][""]["/"]
	globalMutex.RUnlock()
	if saved {
		t.Error("the rewrite was saved without the password")
	}
}
