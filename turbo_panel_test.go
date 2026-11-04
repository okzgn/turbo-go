package main

// Panel and API (#28, #29, #38, #49, #50, #52).

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// The documentation says "/admin"; the panel answers on "/admin:".
func TestW_AdminURL(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	res, body, err := rawGet(base, "localhost", "/admin:")
	if err != nil || res.StatusCode != 200 || !strings.Contains(body, "data-signin") {
		t.Fatalf("/admin: doesn't serve the login: %v %v", res, err)
	}
	for _, p := range []string{"/admin", "/admin/"} {
		res, body, err := rawGet(base, "localhost", p)
		if err != nil {
			t.Fatalf("%s -> %v", p, err)
		}
		if strings.Contains(body, "data-signin") {
			t.Errorf("%s serves the login", p)
		}
		t.Logf("%s -> %d", p, res.StatusCode)
	}
}

// #50: with a partial turbo.dev, what is missing is served from the embedded copy.
func TestW_TurboDevPartial(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"turbo.dev/admin", 0755)
	os.WriteFile(dir+"turbo.dev/admin/#.html", []byte("<html>dev</html>"), 0644)
	base := startServer(t)
	for _, p := range []string{"/admin:", "/admin:m.css", "/admin:i.png"} {
		res, body, err := rawGet(base, "localhost", p)
		if err != nil || res.StatusCode != 200 {
			t.Errorf("%s -> %v %v; expected 200", p, res, err)
			continue
		}
		if strings.Contains(body, dir) || strings.Contains(body, strings.ReplaceAll(dir, "/", `\`)) {
			t.Errorf("%s reveals the server's path", p)
		}
	}
}

// #52: two logins give different tokens; the session lasts 600 s of inactivity.
func TestW_SessionLifetime(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	globalMutex.RLock()
	exp := signedInTokens[sessionKey("127.0.0.1", tok)]
	globalMutex.RUnlock()
	if d := exp - time.Now().Unix(); d < 595 || d > 600 {
		t.Errorf("expiry = now + %d s; expected 600", d)
	}
	if tok2 := login(t, base); tok2 == tok {
		t.Error("two logins from the same IP share a token")
	}
}

// #49: the general settings require the current password (b).
func TestW_SettingsWithoutPassword(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, p := range []string{"/admin:inside:setRT?a=7s", "/admin:inside:setRT?a=8s&b=wrong", "/admin:inside:setC?a=x"} {
		code, body, err := post(base, p, tok)
		if err != nil || code != 400 {
			t.Errorf("%s -> %d %q %v; expected 400", p, code, body, err)
		}
	}
}

// #28, #72: the panel works with the session cookie (HttpOnly, SameSite=Strict)
// without a token in the URL; without the cookie, the login page shows; signing
// out deletes it; a CGI on the same host doesn't get it.
func TestW_SessionCookie(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	base := startServer(t)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("u", "Turbo")
	w.WriteField("p", "Admin")
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	setCookie := res.Header.Get("Set-Cookie")
	t.Logf("Set-Cookie: %s", setCookie)
	for _, attr := range []string{"turbo_session=", "Path=/", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(setCookie, attr) {
			t.Fatalf("%q missing in Set-Cookie", attr)
		}
	}
	cookie := strings.SplitN(setCookie, ";", 2)[0]

	panel := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Host = "localhost"
		if cookie != "" {
			req.Header.Set("Cookie", cookie+"; other=1")
		}
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := panel("/admin:inside:"); code != 200 || strings.Contains(body, "<meta http-equiv") {
		t.Fatalf("panel with cookie: %d %.80q", code, body)
	}
	if code, body := panel("/admin:inside:"); code != 200 || strings.Contains(body, "<meta http-equiv") {
		t.Fatalf("panel reload with cookie: %d %.80q", code, body)
	}
	if _, body := panel("/x.cgi"); strings.Contains(body, "turbo_session") || !strings.Contains(body, "HTTP_COOKIE=other=1\n") {
		t.Fatalf("the CGI must get only the other cookies:\n%s", body)
	}
	saved := cookie
	cookie = ""
	if _, body := panel("/admin:inside:"); !strings.Contains(body, "<meta http-equiv") {
		t.Fatalf("panel without cookie: expected the redirect to the login, %.80q", body)
	}
	cookie = saved
	req, _ = http.NewRequest("POST", base+"/admin:signout:", nil)
	req.Host = "localhost"
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Sec-Fetch-Site", "same-origin") // As the panel's page sends it: with the cookie, signout needs it
	res, err = (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if sc := res.Header.Get("Set-Cookie"); !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("signing out doesn't delete the cookie: %q", sc)
	}
	if _, body := panel("/admin:inside:"); !strings.Contains(body, "<meta http-equiv") {
		t.Fatal("the session is still valid after signing out")
	}
}

// #28: the session token must not appear in turbo.visits.
func TestP28_TokenInVisitsLog(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false) // the periodic reload opens the log
	base := startServer(t)
	tok := login(t, base)
	get(base, "/admin:inside:", map[string]string{"Cookie": "turbo_session=" + tok}) // as the panel does after T1.6
	get(base, "/index.html", nil)
	serverSetLogState(visitsLogName, nil)
	b, _ := os.ReadFile(dir + "turbo.visits")
	if strings.Contains(string(b), tok) {
		t.Fatalf("the token appears in turbo.visits:\n%s", b)
	}
}

// #29: "Save configuration" saves the user and the password hash, never the
// password in plain text.
func TestP29_CredentialsNotPersisted(t *testing.T) {
	dir := initForTest(t)
	defaultSettingValidators["."]["P"]("NewPassword", "Admin")
	if ok, msg := defaultSettingValidators["."]["C"]("", "NewPassword"); !ok {
		t.Fatalf("setC: %q", msg)
	}
	b, _ := os.ReadFile(dir + "turbo.config")
	s := string(b)
	if strings.Contains(s, "NewPassword") {
		t.Error("plain-text password in turbo.config")
	}
	if !strings.Contains(s, `"PH"`) || !strings.Contains(s, `"U"`) {
		t.Errorf("U or PH missing in turbo.config: %s", s)
	}
	// Restart: the state goes back to Turbo/Admin and turbo.config is read.
	resetTestState(dir)
	updateSettings(false)
	if !passwordMatches("NewPassword") || passwordMatches("Admin") {
		t.Errorf("after restarting: NewPassword=%v Admin=%v; expected only NewPassword", passwordMatches("NewPassword"), passwordMatches("Admin"))
	}
}

// TURBO_USER and TURBO_PASSWORD take priority over U and PH of turbo.config.
func TestC_CredentialsEnvPriority(t *testing.T) {
	dir := initForTest(t)
	defaultSettingValidators["."]["U"]("Other", "Admin")
	defaultSettingValidators["."]["P"]("FromFile", "Admin")
	saveDefaultConfig() // Takes the locks itself (T20)
	resetTestState(dir)
	setPanelPassword("FromEnv")
	userFromEnv, passwordFromEnv = true, true
	updateSettings(false)
	if panelUser.Get() != "Turbo" || !passwordMatches("FromEnv") || passwordMatches("FromFile") {
		t.Errorf("U=%q FromEnv=%v FromFile=%v; expected the credentials from the environment", panelUser.Get(), passwordMatches("FromEnv"), passwordMatches("FromFile"))
	}
}

// #58: after changing the sites directory (M) and saving, a restart serves the
// new directory with its configuration.
func TestC_SitesDirPersisted(t *testing.T) {
	start := initForTest(t)
	other := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(other+"other.test/@", 0755)
	if ok, msg := defaultSettingValidators["."]["M"](other, "Admin"); !ok {
		t.Fatalf("setM: %q", msg)
	}
	resetSettings()
	updateSettings(true)
	if ok, msg := defaultSettingValidators["."]["C"]("", "Admin"); !ok {
		t.Fatalf("setC: %q", msg)
	}
	resetTestState(start) // restart in the working directory
	updateSettings(false)
	if sitesDir.Get() != other {
		t.Fatalf("directory after restarting: %q; expected %q", sitesDir.Get(), other)
	}
	if _, ok := sitesMap["other.test"]; !ok {
		t.Error("the site of the new directory wasn't loaded")
	}
}

// A root key that isn't a host name ("^", the schema version key of §5.1)
// isn't mistaken for a site.
func TestC_UnknownRootKey(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"^":{"v":"2"},"version":"x","localhost":{"":{"-":{"index.html":""}}}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileModTime = 0
	updateSettings(false)
	if _, ok := sitesMap["^"]; ok {
		t.Fatal("the key '^' is treated as a site")
	}
	if _, ok := sitesMap["localhost"]; !ok {
		t.Fatal("localhost wasn't loaded")
	}
}

// #29: plain-text U and P in turbo.config are migrated to U and PH when saving.
func TestC_CredentialsFromConfig(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{"-":{"index.html":""}}},".":{"U":"Operator","P":"Secret1","CIL":"1000"}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileModTime = 0
	updateSettings(false)
	if panelUser.Get() != "Operator" {
		t.Errorf("U=%q", panelUser.Get())
	}
	saveDefaultConfig()
	b, _ := os.ReadFile(dir + "turbo.config")
	s := string(b)
	if strings.Contains(s, "Secret1") || !strings.Contains(s, `"PH"`) || !strings.Contains(s, `"^"`) {
		t.Errorf("turbo.config after saving: %s", s)
	}
	if !passwordMatches("Secret1") || passwordMatches("Admin") {
		t.Error("the password of P isn't applied")
	}
}

// #30, #38: hardUpload empties all of @, subfolders included, and lists the
// discarded names.
func TestP_HardUpload(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/old", 0755)
	os.WriteFile(dir+"localhost/@/old/keep.txt", []byte("x"), 0644)
	base := startServer(t)
	tok := login(t, base)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("s", "localhost")
	w.WriteField("d", "")
	w.WriteField("b", "Admin")
	names := []string{"assets/img/logo.png", "../../evil1.txt", "a/../../evil2.txt", `..\..\evil3.txt`, "/abs/evil4.txt", "x/y/../z.txt"}
	for _, n := range names {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f"; filename="%s"`, n))
		p, _ := w.CreatePart(h)
		p.Write([]byte("content " + n))
	}
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload?s=localhost&d=", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	t.Logf("response: %d %q", res.StatusCode, b)
	if fileExists(dir + "localhost/@/old/keep.txt") {
		t.Error("old/keep.txt is still there")
	}
	if !strings.Contains(string(b), "evil1.txt") {
		t.Error("the response doesn't list the discarded files")
	}
	for _, f := range []string{"evil1.txt", "evil2.txt", "evil3.txt"} {
		if fileExists(dir+f) || fileExists(dir+"localhost/"+f) {
			t.Errorf("%s written outside @", f)
		}
	}
}

// DP13: hardUpload never mixes new files with those that couldn't be deleted.
// The upload is written separately and replaces @ in one go: on Windows, an
// open file prevents replacing @, which stays as it was; on Unix, @ is replaced
// and what can't be deleted from the previous content stays outside @ (before,
// the upload was rejected if @ couldn't be emptied).
func TestP_HardUploadUndeletable(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("root can delete in a folder without write permission")
	}
	dir := initForTest(t)
	locked := dir + "localhost/@/locked"
	os.MkdirAll(locked, 0755)
	os.WriteFile(locked+"/old.txt", []byte("x"), 0644)
	if runtime.GOOS == "windows" {
		f, err := os.Open(locked + "/old.txt") // Windows doesn't delete an open file
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
	} else {
		os.Chmod(locked, 0500) // no write permission: its entries can't be deleted
		defer os.Chmod(locked, 0755)
	}
	base := startServer(t)
	tok := login(t, base)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("b", "Admin")
	p, _ := w.CreateFormFile("f", "folder/new.txt")
	p.Write([]byte("new"))
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload?s=localhost&d=", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if runtime.GOOS == "windows" {
		if res.StatusCode != 400 || fileExists(dir+"localhost/@/new.txt") || !fileExists(locked+"/old.txt") {
			t.Fatalf("response %d %q, new.txt written=%v; expected 400 and @ as it was",
				res.StatusCode, b, fileExists(dir+"localhost/@/new.txt"))
		}
		return
	}
	moved, _ := filepath.Glob(dir + "localhost/@.previous-*/locked") // What couldn't be deleted, outside @
	for _, folder := range moved {
		os.Chmod(folder, 0755)
	}
	if res.StatusCode != 200 || !fileExists(dir+"localhost/@/new.txt") || dirExists(dir+"localhost/@/locked") {
		t.Fatalf("response %d %q; expected 200 and @ with only new.txt", res.StatusCode, b)
	}
}

// #70: a value with an encoded "+" arrives intact (the panel no longer turns
// "+" into a space).
func TestW_AddMIMEPlus(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:addMIME?s=localhost&d=&a=svg&b=image%2Fsvg%2Bxml", tok)
	if err != nil || code != 200 {
		t.Fatalf("addMIME: %d %q %v", code, body, err)
	}
	globalMutex.RLock()
	got := mimeTypes["localhost"]["svg"]
	globalMutex.RUnlock()
	if got != "image/svg+xml" {
		t.Fatalf("MIME saved %q; expected image/svg+xml", got)
	}
}

// #38: s and d are also accepted in the multipart body, without the URL.
func TestP_HardUploadBodyParams(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("s", "localhost")
	w.WriteField("d", "")
	w.WriteField("b", "Admin")
	p, _ := w.CreateFormFile("f", "folder/new.txt")
	p.Write([]byte("new"))
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !fileExists(dir+"localhost/@/new.txt") || fileExists(dir+"localhost/@/index.html") {
		t.Fatalf("response %d %q; expected @ with only new.txt", res.StatusCode, b)
	}
}

// #68: the panel can't be embedded in an iframe and isn't cached, in the
// login, in the panel and in the API responses.
func TestW_PanelHeaders(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	check := func(name string, h http.Header) {
		t.Helper()
		if h.Get("X-Frame-Options") != "DENY" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: X-Frame-Options=%q CSP=%q Cache-Control=%q", name, h.Get("X-Frame-Options"), h.Get("Content-Security-Policy"), h.Get("Cache-Control"))
		}
	}
	res, _, err := rawGet(base, "localhost", "/admin:")
	if err != nil {
		t.Fatal(err)
	}
	check("login", res.Header)
	for _, p := range []string{"/admin:inside:", "/admin:inside:sites"} {
		req, _ := http.NewRequest("POST", base+p, nil)
		req.Host = "localhost"
		req.Header.Set("ok", tok)
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		check(p, res.Header)
	}
}

// DP7: with PA, /admin: answers only on the hosts or networks of the list (404
// elsewhere); empty or "*" doesn't restrict; PA is validated and saved.
func TestW_PanelAccessHosts(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	adminCode := func(host string) int {
		res, _, err := rawGet(base, host, "/admin:")
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	if c := adminCode("other.test"); c != 200 {
		t.Fatalf("without PA, /admin: on other.test -> %d; expected 200", c)
	}
	for _, bad := range []string{"10.0.0.0/33", "not valid", "a..b"} {
		if ok, _ := defaultSettingValidators["."]["PA"](bad, "Admin"); ok {
			t.Errorf("PA %q accepted", bad)
		}
	}
	// A7 (D3): with hosts and networks, a request needs both.
	if ok, msg := defaultSettingValidators["."]["PA"]("admin.test, 192.0.2.0/24", "Admin"); !ok {
		t.Fatalf("PA: %q", msg)
	}
	if c := adminCode("admin.test"); c != 404 {
		t.Errorf("/admin: on admin.test from outside 192.0.2.0/24 -> %d; expected 404", c)
	}
	if ok, msg := defaultSettingValidators["."]["PA"]("admin.test, 127.0.0.0/8", "Admin"); !ok {
		t.Fatalf("PA: %q", msg)
	}
	if c := adminCode("admin.test"); c != 200 {
		t.Errorf("/admin: on admin.test -> %d; expected 200", c)
	}
	if c := adminCode("other.test"); c != 404 {
		t.Errorf("/admin: on other.test -> %d; expected 404", c)
	}
	if code, _, _ := get(base, "/", nil); code != 200 {
		t.Errorf("the site stopped answering: %d", code)
	}
	if ok, msg := defaultSettingValidators["."]["PA"]("127.0.0.0/8", "Admin"); !ok { // by the client's IP
		t.Fatalf("PA: %q", msg)
	}
	if c := adminCode("other.test"); c != 200 {
		t.Errorf("/admin: from 127.0.0.1 with PA=127.0.0.0/8 -> %d; expected 200", c)
	}
	saveDefaultConfig() // Takes the locks itself (T20)
	if raw := savedConfig(t, dir); raw["."]["PA"] != "127.0.0.0/8" {
		t.Errorf("PA saved = %v", raw["."]["PA"])
	}
	resetTestState(dir) // restart: PA is read from turbo.config
	updateSettings(false)
	if s := panelAccess.Load().setting; s != "127.0.0.0/8" {
		t.Errorf("PA after restarting = %q", s)
	}
	if ok, msg := defaultSettingValidators["."]["PA"]("*", "Admin"); !ok {
		t.Fatalf("PA *: %q", msg)
	}
	if c := adminCode("other.test"); c != 200 {
		t.Errorf("with PA=* -> %d; expected 200", c)
	}
}

// #72 (review of T1.6): when turbo_session is removed, the rest of the Cookie
// header reaches the CGI unchanged (quotes, spaces, commas, non-ASCII, no
// value).
func TestW_CGICookiesUnchanged(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	base := startServer(t)
	for header, want := range map[string]string{
		`a=b c; turbo_session=secret; x="y"; d=1,2; name=café; novalue`: `a=b c; x="y"; d=1,2; name=café; novalue`,
		`turbo_session=secret; a=1`:                                     `a=1`,
		`a=b c; x="y"`:                                                  `a=b c; x="y"`,
	} {
		_, body, err := get(base, "/x.cgi", map[string]string{"Cookie": header})
		if err != nil || !strings.Contains(body, "HTTP_COOKIE="+want+"\n") {
			t.Errorf("Cookie %q -> err=%v; expected HTTP_COOKIE=%s\n%s", header, err, want, body)
		}
	}
}

// #72 (review of T1.6): a panel action authenticated with the cookie is only
// accepted from the same origin (CSRF from another subdomain of the same
// site); with the ok header it isn't needed.
func TestW_PanelCSRF(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	n := 0
	action := func(hdr map[string]string) int {
		n++ // a different header in each request
		req, _ := http.NewRequest("POST", base+"/admin:inside:addHeader?s=localhost&d=&a=X-Csrf-"+strconv.Itoa(n)+"&b=1", nil)
		req.Host = "localhost"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	cookie := "turbo_session=" + tok
	for name, hdr := range map[string]map[string]string{
		"Origin from another subdomain": {"Cookie": cookie, "Origin": "http://evil.localhost"},
		"Sec-Fetch-Site same-site":      {"Cookie": cookie, "Sec-Fetch-Site": "same-site", "Origin": "http://localhost"},
		"no Origin":                     {"Cookie": cookie},
	} {
		if code := action(hdr); code != 403 {
			t.Errorf("%s -> %d; expected 403", name, code)
		}
	}
	for name, hdr := range map[string]map[string]string{
		"own Origin":                 {"Cookie": cookie, "Origin": "http://localhost"},
		"Sec-Fetch-Site same-origin": {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"},
		"ok header":                  {"ok": tok},
	} {
		if code := action(hdr); code != 200 {
			t.Errorf("%s -> %d; expected 200", name, code)
		}
	}
}

// Review of T1.7: PBKDF2 checks of wrong passwords use no more than the slots
// of passwordHashSlots; with all of them taken, the check waits.
func TestW_PasswordHashSlots(t *testing.T) {
	initForTest(t)
	for i := 0; i < cap(passwordHashSlots); i++ {
		passwordHashSlots <- struct{}{}
	}
	done := make(chan bool)
	go func() { done <- passwordMatches("wrong") }()
	select {
	case <-done:
		t.Fatal("a PBKDF2 was computed with all the slots taken")
	case <-time.After(300 * time.Millisecond):
	}
	for i := 0; i < cap(passwordHashSlots); i++ {
		<-passwordHashSlots
	}
	if <-done {
		t.Fatal("wrong password accepted")
	}
	if !passwordMatches("Admin") {
		t.Fatal("the right password isn't accepted")
	}
}

// T2.6 (#21): the embedded GUI is the one in turbo.dev/ (a single copy), it is
// served file by file and doesn't leave each panel's folder.
func TestT26_EmbeddedGUI(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	for _, c := range []struct{ path, file, contentType string }{
		{"/admin:", "turbo.dev/admin/#.html", "text/html"},
		{"/admin:m.css", "turbo.dev/admin/m.css", "text/css"},
		{"/admin:i.png", "turbo.dev/admin/i.png", "image/png"},
		{"/admin:r.ttf", "turbo.dev/admin/r.ttf", "font/ttf"},
		{"/admin:b.ttf", "turbo.dev/admin/b.ttf", "font/ttf"},
	} {
		res, body, err := rawGet(base, "localhost", c.path)
		if err != nil || res.StatusCode != 200 {
			t.Errorf("%s -> %v %v; expected 200", c.path, res, err)
			continue
		}
		onDisk, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		if body != string(onDisk) {
			t.Errorf("%s is not %s", c.path, c.file)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, c.contentType) {
			t.Errorf("%s: Content-Type %q; expected %s", c.path, ct, c.contentType)
		}
	}
	for _, p := range []string{"/admin:../inside/%23.html", "/admin:inside/%23.html", "/admin:nothing.css"} {
		if res, _, err := rawGet(base, "localhost", p); err != nil || res.StatusCode != 404 {
			t.Errorf("%s -> %v %v; expected 404", p, res, err)
		}
	}
}

// The GUI sends the API parameters in the body of the POST, so the current
// password (b) of the set* actions doesn't reach turbo.visits; the server
// accepts them in the body as in the URL.
func TestW_SettingsInBodyNotLogged(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false)
	previous := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = previous }) }) })
	base := startServer(t)
	tok := login(t, base)
	req, _ := http.NewRequest("POST", base+"/admin:inside:setRT", strings.NewReader("a=7s&b=Admin"))
	req.Host = "localhost"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || serverTimeLimits.Load().RT != 7*time.Second {
		t.Fatalf("setRT in the body: %d %q, RT = %v", res.StatusCode, body, serverTimeLimits.Load().RT)
	}
	serverSetLogState(visitsLogName, nil)
	b, _ := os.ReadFile(dir + "turbo.visits")
	if !strings.Contains(string(b), "setRT") || strings.Contains(string(b), "Admin") {
		t.Fatalf("turbo.visits:\n%s", b)
	}
}

// addDenied rejects the IP the panel is used from: the administrator would
// lock themselves out.
func TestW_DenyCurrentIP(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	code, body, err := post(base, "/admin:inside:addDenied?s=127.0.0.1&d="+future, tok)
	if err != nil || code != 400 || body != "Current IP" {
		t.Fatalf("addDenied of the current IP: %d %q %v; expected 400 \"Current IP\"", code, body, err)
	}
	if code, body, _ := post(base, "/admin:inside:addDenied?s=203.0.113.5&d="+future, tok); code != 200 {
		t.Fatalf("addDenied of another IP: %d %q", code, body)
	}
	for _, c := range []struct {
		ip, remote string
		want       bool
	}{
		{"203.0.113.5", "203.0.113.5:4000", true},
		{" 203.0.113.5 ", "203.0.113.5:4000", true},
		{"203.0.113.6", "203.0.113.5:4000", false},
		{"2001:db8:0::1", "[2001:db8::1]:443", true},
		{"no-ip", "203.0.113.5:4000", false},
	} {
		if got := isClientIP(c.ip, &customNetHttp.Request{RemoteAddr: c.remote}); got != c.want {
			t.Errorf("isClientIP(%q, %q) = %v", c.ip, c.remote, got)
		}
	}
}

// The del* actions for a subdomain's content without all their parameters
// answer 400, like the rest of the API, instead of an empty 200.
func TestW_DeleteWithoutParams(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, action := range []string{"Index", "Alias", "Preprocessor", "Header", "MIME", "Rewrite"} {
		for _, query := range []string{"", "?s=localhost&d=", "?s=localhost&a=x", "?d=&a=x"} {
			code, body, err := post(base, "/admin:inside:del"+action+query, tok)
			if err != nil || code != 400 || body != msgMissingData {
				t.Errorf("del%s%s: %d %q %v; expected 400 %q", action, query, code, body, err, msgMissingData)
			}
		}
	}
}

// setU and setP reject a value equal to the current one, like the rest of the settings.
func TestW_CredentialsUnchanged(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, c := range []struct{ path, want string }{
		{"/admin:inside:setU?a=Turbo&b=Admin", "User unchanged"},
		{"/admin:inside:setP?a=Admin&b=Admin", "Password unchanged"},
	} {
		if code, body, err := post(base, c.path, tok); err != nil || code != 400 || body != c.want {
			t.Errorf("%s: %d %q %v; expected 400 %q", c.path, code, body, err, c.want)
		}
	}
	if code, body, _ := post(base, "/admin:inside:setU?a=Turbo2&b=Admin", tok); code != 200 {
		t.Errorf("setU with another user: %d %q", code, body)
	}
}

// The 404 of /admin: outside PA carries the same security headers as the rest
// of the panel's responses.
func TestW_PanelAccessDeniedHeaders(t *testing.T) {
	initForTest(t)
	if ok, msg := defaultSettingValidators["."]["PA"]("admin.test", "Admin"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	res, _, err := rawGet(base, "localhost", "/admin:")
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("/admin: outside PA -> %v %v; expected 404", res, err)
	}
	// The 404 is the error template: no scripts (N89)
	for k, v := range map[string]string{"X-Frame-Options": "DENY", "Content-Security-Policy": panelCSP, "Cache-Control": "no-store"} {
		if got := res.Header.Get(k); got != v {
			t.Errorf("%s = %q; expected %q", k, got, v)
		}
	}
}

// N98: the panel's files come only from turbo.dev/<panel>/ (or the embedded copy). A path that would leave it,
// also through what Windows reads differently (a "/" start, which cleaning took for a network path, "\", a ":"
// that names a stream), and a device name get 404 without opening anything: before, on Windows, the path
// "/../secret.txt" read turbo.dev/secret.txt (HTTP/1 stops it earlier, the function didn't), and "nul" was
// opened as a file.
func TestN98_PanelFilesStayInTheirFolder(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	os.MkdirAll(dir+"turbo.dev/admin", 0755)
	os.WriteFile(dir+"turbo.dev/secret.txt", []byte("secret"), 0644)
	os.WriteFile(dir+"secret.txt", []byte("secret"), 0644)
	os.WriteFile(dir+"turbo.dev/admin/own.txt", []byte("own"), 0644)
	for _, path := range []string{"/../secret.txt", "//../secret.txt", "/../../secret.txt", `\..\secret.txt`, `..\..\secret.txt`, "x:/../../secret.txt", "/../x:secret.txt", "..%5Csecreto.txt", "%2F..%2Fsecreto.txt", "nul", "con.txt", "CONIN$", "own.txt::$DATA"} {
		recorder := &responseRecorder{}
		request := &customNetHttp.Request{Method: "GET", Header: customNetHttp.Header{}, URL: &url.URL{Path: "/"}, RequestURI: "/admin:" + path}
		consoleFiles(adminPathPrefix, path, recorder, request)
		if recorder.code != 404 || strings.Contains(recorder.body.String(), "secret") || strings.Contains(recorder.body.String(), "page not found") {
			t.Errorf("%q: %d %q; expected the panel's 404, without opening anything", path, recorder.code, recorder.body.String())
		}
	}
	if res, body, err := rawGet(base, "localhost", "/admin:nul"); err != nil || res.StatusCode != 404 || strings.Contains(body, "page not found") {
		t.Errorf("/admin:nul: %v %q %v; expected the panel's 404, without opening anything", res, body, err)
	}
	if res, body, err := rawGet(base, "localhost", "/admin:own.txt"); err != nil || res.StatusCode != 200 || body != "own" {
		t.Errorf("a file of turbo.dev/admin: %v %q %v", res, body, err)
	}
	if res, body, err := rawGet(base, "localhost", "/admin:m.css"); err != nil || res.StatusCode != 200 || body == "" {
		t.Errorf("an embedded file of the panel: %v %v", res, err)
	}
}
