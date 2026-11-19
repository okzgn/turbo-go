package server

// The tests of the panel's findings of the review of v2.5 (_revision/INFORME_REVISION_4cb626c.md, block 1): each
// failed before its fix.

import (
	"bytes"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// reviewPanelPost posts an action of the panel with the token tok and the extra headers, and returns its status (401 when
// the answer asks to sign in again), its body and its headers.
func reviewPanelPost(t *testing.T, base string, path string, tok string, headers map[string]string) (int, string, http.Header) {
	t.Helper()
	request, _ := http.NewRequest("POST", base+path, nil)
	request.Host = "localhost"
	if tok != "" {
		request.Header.Set("ok", tok)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := (&http.Client{Timeout: clientTimeout()}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.Header.Get("X-Turbo-Login") == "required" {
		return 401, string(body), response.Header
	}
	return response.StatusCode, string(body), response.Header
}

// V2.5 review S-2 (decision D5): with PA of networks only, the panel answers on the IP addresses and on localhost, so
// a new site * (which serves the IP addresses), a new site localhost and a new alias localhost are refused from the
// panel; those that turbo.config has are kept, and the log warns of them.
func TestV25R_S2_NetworksOnlyKeepsTheSitesOffThePanelsHosts(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addSite?s=app.test", tok); code != 200 {
		t.Fatalf("addSite app.test: %d %q", code, body)
	}
	if ok, message := setting("PA", "127.0.0.0/8"); !ok {
		t.Fatalf("PA: %q", message)
	}
	if code, body, _ := post(base, "/admin:inside:delSite?s=localhost&d=&b=Admin", tok); code != 200 {
		t.Fatalf("delSite localhost: %d %q", code, body)
	}
	for name, path := range map[string]string{
		"a site *":           "/admin:inside:addSite?s=*",
		"a site localhost":   "/admin:inside:addSite?s=localhost",
		"an alias localhost": "/admin:inside:addAlias?s=app.test&d=&a=localhost",
	} {
		if code, body, _ := post(base, path, tok); code != 400 || !strings.Contains(body, "where the panel answers") && !strings.Contains(body, "The panel answers on") {
			t.Errorf("%s with PA of networks only: %d %q; expected 400", name, code, body)
		}
	}
	globalMutex.RLock()
	_, wildcard := sitesMap["*"]
	_, aliased := domainAliases["localhost"]
	globalMutex.RUnlock()
	if wildcard || aliased {
		t.Errorf("after the refusals: site * %v, alias localhost %v", wildcard, aliased)
	}
	// Other names are still accepted
	if code, body, _ := post(base, "/admin:inside:addAlias?s=app.test&d=&a=other.test", tok); code != 200 {
		t.Errorf("addAlias other.test: %d %q", code, body)
	}
	// From turbo.config, a site * is kept, with a warning
	logs := captureLog(t)
	os.MkdirAll(dir+"#/@", 0755)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"PA":"127.0.0.0/8"},"*":{}}`)
	globalMutex.RLock()
	_, wildcard = sitesMap["*"]
	globalMutex.RUnlock()
	if !wildcard || !strings.Contains(logs.String(), "serves the IP addresses, where the panel answers") {
		t.Errorf("a site * of turbo.config with PA of networks only: kept %v; log:\n%s", wildcard, logs.String())
	}
}

// V2.5 review S-3: an action is checked against its session again once its body has arrived: one closed meanwhile
// (Close every session, new credentials) applies nothing.
func TestV25R_S3_ASessionClosedWhileTheBodyCameAppliesNothing(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	previous := beforeSessionRenewal
	beforeSessionRenewal = func() { withGlobalLock(func() { closeOtherSessions("") }) } // After the session was found, before the body is read
	t.Cleanup(func() { beforeSessionRenewal = previous })
	code, body, _ := reviewPanelPost(t, base, "/admin:inside:addAlias?s=localhost&d=&a=closed.test", tok, nil)
	beforeSessionRenewal = previous
	globalMutex.RLock()
	_, aliased := domainAliases["closed.test"]
	globalMutex.RUnlock()
	if code != 401 || aliased {
		t.Errorf("an action whose session closed before its body was read: %d %q, applied %v; expected to sign in again, and nothing applied", code, body, aliased)
	}
}

// V2.5 review S-5: a certificate isn't deleted while Certbot issues or renews it: its files would come back, or be put
// in use without them.
func TestV25R_S5_NoDeletionWhileCertbotWorks(t *testing.T) {
	useFakeCertbot(t, "ok")
	t.Setenv("FAKE_CERTBOT_DELAY", "1500")
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:cfgE?s=localhost&d=&a="+url.QueryEscape("admin@example.test"), tok); code != 200 {
		t.Fatalf("cfgE: %d %q", code, body)
	}
	writeTestCertificate(t, dir+"localhost/", 24*time.Hour, "localhost") // Due for renewal
	os.MkdirAll(dir+"turbo.certificates/localhost", 0700)
	renewCertificates()
	globalMutex.RLock()
	working := currentCertDomain == "localhost"
	globalMutex.RUnlock()
	if !working {
		t.Fatal("the renewal didn't start: the test proves nothing")
	}
	code, body, _ := post(base, "/admin:inside:cfgC?s=localhost&d=&a=0&x=1&b=Admin", tok)
	if code != 400 || !strings.Contains(body, "being issued or renewed") {
		t.Errorf("Delete SSL while Certbot renews it: %d %q; expected 400", code, body)
	}
	if !fileExists(dir + "localhost/" + certFileName) {
		t.Error("the certificate's files were deleted")
	}
	waitIdle()
	// Once Certbot is done, it can be deleted
	if code, body, _ := post(base, "/admin:inside:cfgC?s=localhost&d=&a=0&x=1&b=Admin", tok); code != 200 {
		t.Errorf("Delete SSL after the renewal: %d %q", code, body)
	}
}

// V2.5 review S-6: the panel's errors are plain text, whatever their message starts with: the type is set before the
// status, which fixes the headers (after it, the server guessed it from the text).
func TestV25R_S6_PanelErrorsArePlainText(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		switch r.URL.Path {
		case "/bad":
			badReq(w, r, "<html><body>a message</body></html>")
		case "/large":
			formRejected(w, r, &customNetHttp.MaxBytesError{Limit: 1})
		}
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	for path, code := range map[string]int{"/bad": 400, "/large": 413} {
		response, err := http.Get("http://" + listener.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != code || response.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s: %d %q; expected %d as plain text", path, response.StatusCode, response.Header.Get("Content-Type"), code)
		}
	}
}

// V2.5 review S-7: the folders of an upload are made inside its folder only: one removed meanwhile (with its site,
// deleted during the upload) makes the upload fail, instead of making the site's folder again, empty.
func TestV25R_S7_UploadFoldersOnlyInsideTheUploadFolder(t *testing.T) {
	site := t.TempDir() + "/site/"
	base := site + "upload/"
	if err := os.MkdirAll(base, 0755); err != nil {
		t.Fatal(err)
	}
	if err := mkdirUnder(base, "a/b/c"); err != nil || !dirExists(base+"a/b/c") {
		t.Fatalf("mkdirUnder in a folder that exists: %v", err)
	}
	if err := mkdirUnder(base, "a/b"); err != nil {
		t.Errorf("mkdirUnder of folders already there: %v", err)
	}
	os.RemoveAll(site)
	if err := mkdirUnder(base, "a/b"); err == nil {
		t.Error("mkdirUnder in a folder removed meanwhile: no error")
	}
	if _, err := os.Stat(site); err == nil {
		t.Error("the removed folder was made again")
	}
}

// V2.5 review S-8: what carries a session of the panel never reaches a CGI nor a worker: the "ok" header, which API
// clients send with the token, as the session cookie.
func TestV25R_S8_ThePanelsTokenDoesntReachScripts(t *testing.T) {
	const token = "the-token-of-an-api-client"
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	if code, body, _ := get(base, "/x.cgi?env=HTTP_OK", map[string]string{"ok": token}); code != 200 || strings.Contains(body, token) {
		t.Errorf("a CGI: %d, the token reached it %v", code, strings.Contains(body, token))
	}
	_, dxBase := setupDX(t, toolPath("dxecho"))
	if code, body := dxRequest(t, "GET", dxBase, "/x.dx", nil, map[string]string{"ok": token}); code != 200 || strings.Contains(body, token) {
		t.Errorf("a worker: %d, the token reached it %v", code, strings.Contains(body, token))
	}
}

// V2.5 review S-9 (decision D9): what stops a certificate from being renewed needs the current password, as deleting
// it: removing a site's e-mail, and changing the DNS adapter of a site (cfgA, or y of cfgC) or of the panel (y of
// cfgPC). Setting an e-mail, or sending the adapter saved, doesn't.
func TestV25R_S9_StoppingTheRenewalNeedsThePassword(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	base := startServer(t)
	tok := login(t, base)
	asksForThePassword := func(code int, body string) bool { return code == 400 && strings.Contains(body, "current password") }
	steps := []struct {
		name, path string
		password   bool // Whether it needs it
	}{
		{"setting an e-mail", "/admin:inside:cfgE?s=localhost&d=&a=" + url.QueryEscape("admin@example.test"), false},
		{"removing the e-mail", "/admin:inside:cfgE?s=localhost&d=&a=", true},
		{"setting an adapter", "/admin:inside:cfgA?s=localhost&d=&a=dns-route53", true},
		{"the same adapter", "/admin:inside:cfgA?s=localhost&d=&a=dns-route53", false},
		{"another adapter in Create SSL", "/admin:inside:cfgC?s=localhost&d=&a=1&y=dns-other", true},
		{"the saved adapter in Create SSL", "/admin:inside:cfgC?s=localhost&d=&a=1&y=dns-other", false},
		{"no adapter in Create SSL", "/admin:inside:cfgC?s=localhost&d=&a=1&y=", false},
		{"back to webroot", "/admin:inside:cfgA?s=localhost&d=&a=", true},
		{"an adapter for the panel", "/admin:inside:cfgPC?a=1&y=dns-route53", true},
	}
	// T-5 (c): the adapter is taken as sent, as every cfg<KEY>: one that arrives URL-encoded isn't decoded again
	if code, body, _ := post(base, "/admin:inside:cfgA?s=localhost&d=&a=dns%252Dxx&b=Admin", tok); code != 400 || !strings.Contains(body, "Invalid adapter") {
		t.Errorf("an adapter that arrives as dns%%2Dxx: %d %q; expected it refused", code, body)
	}
	for _, step := range steps {
		code, body, _ := post(base, step.path, tok)
		if asksForThePassword(code, body) != step.password {
			t.Errorf("%s with the session alone: %d %q; needs the password %v", step.name, code, body, step.password)
		}
		if step.password {
			if code, body, _ = post(base, step.path+"&b=Wrong-password-1", tok); code == 200 {
				t.Errorf("%s with a wrong password: %d %q", step.name, code, body)
			}
			if code, body, _ = post(base, step.path+"&b=Admin", tok); asksForThePassword(code, body) || strings.Contains(body, "Wrong current password") {
				t.Errorf("%s with the current password: %d %q", step.name, code, body)
			}
		}
	}
	globalMutex.RLock()
	settings := siteSSLConfig["localhost"]
	email, adapter, panelAdapter := settings.email, settings.adapter, panelCertAdapter
	globalMutex.RUnlock()
	if email != "" || adapter != "" || panelAdapter != "dns-route53" {
		t.Errorf("at the end: e-mail %q, adapter %q, panel adapter %q", email, adapter, panelAdapter)
	}
}

// V2.5 review S-10 (decision D10): the login gives the token in its body only to API clients: the panel's page (a
// browser's request, with Sec-Fetch-Site) gets "ok" alone, and its session in the cookie, which its scripts can't read.
func TestV25R_S10_TheLoginTokenOnlyForAPIClients(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	signIn := func(headers map[string]string) (string, bool) {
		var buf bytes.Buffer
		form := multipart.NewWriter(&buf)
		form.WriteField("u", "Turbo")
		form.WriteField("p", "Admin")
		form.Close()
		request, _ := http.NewRequest("POST", base+"/admin:", &buf)
		request.Host = "localhost"
		request.Header.Set("Content-Type", form.FormDataContentType())
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := (&http.Client{Timeout: clientTimeout()}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return string(body), strings.Contains(response.Header.Get("Set-Cookie"), sessionCookieName)
	}
	if body, cookie := signIn(map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}); body != "ok" || !cookie {
		t.Errorf("the panel's page: %q, cookie %v; expected \"ok\" and the cookie", body, cookie)
	}
	if body, cookie := signIn(nil); !regexp.MustCompile(`^ok[0-9a-f]{64}$`).MatchString(body) || !cookie {
		t.Errorf("an API client: %q, cookie %v; expected \"ok\" and the token", body, cookie)
	}
	// Second pass, P-2: a browser sends Sec-Fetch-Site only to a secure context; the page of a panel reached by HTTP
	// on another host than localhost comes with its Origin alone, and got the token.
	if body, cookie := signIn(map[string]string{"Origin": "http://localhost"}); body != "ok" || !cookie {
		t.Errorf("the panel's page by HTTP, with its Origin and no Sec-Fetch-Site: %q, cookie %v; expected \"ok\" and the cookie", body, cookie)
	}
}

// reviewUpload uploads to localhost a body that write makes (the current password first), and returns its status (401
// when the server asks to sign in again) and its answer.
func reviewUpload(t *testing.T, base string, tok string, write func(form *multipart.Writer)) (int, string) {
	t.Helper()
	reader, writer := io.Pipe()
	form := multipart.NewWriter(writer)
	go func() {
		form.WriteField("b", "Admin")
		write(form)
		form.Close()
		writer.Close()
	}()
	request, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload?s=localhost&d=", reader)
	request.Host = "localhost"
	request.Header.Set("Content-Type", form.FormDataContentType())
	request.Header.Set("ok", tok)
	response, err := (&http.Client{Timeout: clientTimeout()}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.Header.Get("X-Turbo-Login") == "required" {
		return 401, string(body)
	}
	return response.StatusCode, string(body)
}

// V2.5 review S-3, for an upload (second pass, P-7): its session is checked again once its files have arrived.
func TestV25R_S3_AnUploadWhoseSessionClosedAppliesNothing(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	previous := beforeSessionRenewal
	beforeSessionRenewal = func() { withGlobalLock(func() { closeOtherSessions("") }) } // After the session was found, before the body is read
	t.Cleanup(func() { beforeSessionRenewal = previous })
	code, body := reviewUpload(t, base, tok, func(form *multipart.Writer) {
		file, _ := form.CreateFormFile("f", "site/index.html")
		file.Write([]byte("uploaded"))
	})
	beforeSessionRenewal = previous
	if content, _ := os.ReadFile(dir + "localhost/@/index.html"); code != 401 || string(content) == "uploaded" {
		t.Errorf("an upload whose session closed before its files were read: %d %q, index.html %q; expected to sign in again, and nothing changed", code, body, content)
	}
}

// V2.5 review, second pass, P-3: an upload renews its session while its files arrive: one that took longer than a
// session lasts idle was dropped, once whole, since the session is checked again at its end (S-3).
func TestV25R_P3_AnUploadKeepsItsSessionWhileItArrives(t *testing.T) {
	dir := initForTest(t)
	if ok, message := setting("RT", "30s"); !ok {
		t.Fatal(message)
	}
	base := startServer(t)
	tok := login(t, base)
	previous := uploadSessionRenewal
	uploadSessionRenewal = 50 * time.Millisecond
	t.Cleanup(func() { uploadSessionRenewal = previous })
	code, body := reviewUpload(t, base, tok, func(form *multipart.Writer) {
		file, _ := form.CreateFormFile("f", "site/index.html")
		file.Write([]byte("up"))
		time.Sleep(300 * time.Millisecond) // The request has arrived, and renewed its session as any other
		withGlobalLock(func() {
			for key := range signedInTokens {
				signedInTokens[key] = time.Now().Unix() + 1 // A second left of it, as after ten minutes of an upload
			}
		})
		for piece := 0; piece < 25; piece++ { // And the rest of the file takes longer than that, within MBB
			file.Write(bytes.Repeat([]byte("x"), 24<<10)) // More than the form reader keeps before it reads again
			time.Sleep(100 * time.Millisecond)
		}
	})
	if content, _ := os.ReadFile(dir + "localhost/@/index.html"); code != 200 || !strings.HasPrefix(string(content), "up") {
		t.Errorf("an upload that took longer than its session had left: %d %q, index.html %.10q; expected it applied", code, body, content)
	}
}

// V2.5 review, second pass, P-4: a site deleted while the files of an upload are written answers as a site that isn't
// there, as one deleted once they are written: it answered 500, an error writing, and logged an error of the server.
func TestV25R_P4_ASiteDeletedWhileAnUploadIsWritten(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	logs := captureLog(t)
	previous := afterUploadFolderMade
	afterUploadFolderMade = func() {
		os.RemoveAll(dir + "localhost/")
		deleteSite("localhost", "")
	}
	t.Cleanup(func() { afterUploadFolderMade = previous })
	code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/css/a.css", "css"}})
	afterUploadFolderMade = previous
	if code != 400 || body != "Site not found" || strings.Contains(logs.String(), "can't write the file") || dirExists(dir+"localhost") {
		t.Errorf("an upload whose site was deleted while it was written: %d %q, its folder there %v; expected 400 \"Site not found\", no error logged, and no folder:\n%s", code, body, dirExists(dir+"localhost"), logs.String())
	}
}
