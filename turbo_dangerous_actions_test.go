package main

// T28 (I17, D28 (a)): addPreprocessor, hardUpload, delSite and cfgC a=0 ask
// for the current password besides the session (in c for addPreprocessor,
// whose b is the executable; in b for the others). Without it, 400; wrong, it
// counts for the session, which the fifth closes.

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func TestI17_DangerousActionsNeedPassword(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	upload := func(password string) int {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if password != "" {
			w.WriteField("b", password)
		}
		p, _ := w.CreateFormFile("f", "site/index.html")
		p.Write([]byte("new"))
		w.Close()
		req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload?s=localhost&d=", &buf)
		req.Host = "localhost"
		req.Header.Set("ok", tok)
		req.Header.Set("Content-Type", w.FormDataContentType())
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	actions := []struct {
		name   string
		path   string
		passed func(password string) int
	}{
		{"addPreprocessor", "/admin:inside:addPreprocessor?s=localhost&d=&a=cgi&b=" + toolPath("cgiecho"), nil},
		{"cfgC a=0", "/admin:inside:cfgC?s=localhost&d=&a=0", nil},
		{"hardUpload", "", upload},
		{"delSite", "/admin:inside:delSite?s=localhost&d=", nil},
	}
	param := map[string]string{"addPreprocessor": "c"}
	send := func(name, path string, run func(string) int, password string) int {
		if run != nil {
			return run(password)
		}
		key := param[name]
		if key == "" {
			key = "b"
		}
		if password != "" {
			path += "&" + key + "=" + password
		}
		code, _, err := post(base, path, tok)
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	for _, action := range actions {
		if code := send(action.name, action.path, action.passed, ""); code != 400 {
			t.Errorf("%s without a password: %d; expected 400", action.name, code)
		}
	}
	for i := 0; i < loginMaxFailures; i++ { // Five wrong ones: the session is closed, and the IP isn't blocked (V14)
		action := actions[i%len(actions)]
		send(action.name, action.path, action.passed, "Bad")
	}
	if code, _, _, _ := postSession(base, "/admin:inside:sites", tok); code != 401 {
		t.Errorf("the session after five wrong current passwords: %d; expected it closed (401)", code)
	}
	if attempt, retry := startLoginAttempt("127.0.0.1"); retry != 0 {
		t.Error("five wrong current passwords blocked the IP's logins")
	} else {
		finishLoginAttempt(attempt, false)
	}
	tok = login(t, base)
	for _, action := range actions[:3] {
		// cfgC a=0 answers 400 "No certificate" here: what matters is that the reason is no longer the password
		if code := send(action.name, action.path, action.passed, "Admin"); code == 400 && action.name != "cfgC a=0" {
			t.Errorf("%s with the password: 400", action.name)
		}
	}
	if code, body, _ := post(base, "/admin:inside:cfgC?s=localhost&d=&a=0&b=Admin", tok); code == 429 || strings.Contains(body, "password") {
		t.Errorf("cfgC a=0 with the password: %d %q", code, body)
	}
	if code := send("delSite", actions[3].path, nil, "Admin"); code != 200 {
		t.Errorf("delSite with the password: %d", code)
	}
	if code, body, _ := post(base, "/admin:inside:sites", tok); code != 200 || strings.Contains(body, `"localhost"`) {
		t.Errorf("the site is still there after delSite: %d", code)
	}
}

// The current password of the dangerous actions is used as it arrives, like
// that of the settings: a password with a replacement token ("-.-") works the
// same in addPreprocessor (c), cfgC a=0 and delSite (b).
func TestI17_DangerousActionsPasswordKeepsTokens(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	const password = "abcd-.-efghij"
	code, body, tok, _ := postSession(base, "/admin:inside:setP?a="+password+"&b=Admin", tok)
	if code != 200 {
		t.Fatalf("setP: %d %q", code, body)
	}
	for _, path := range []string{
		"/admin:inside:addPreprocessor?s=localhost&d=&a=cgi&b=" + toolPath("cgiecho") + "&c=" + password,
		"/admin:inside:cfgC?s=localhost&d=&a=0&b=" + password,
		"/admin:inside:delSite?s=localhost&d=&b=" + password,
	} {
		if code, body, _ := post(base, path, tok); code == 429 || strings.Contains(body, "assword") {
			t.Errorf("%s: %d %q; the password with the token wasn't accepted", strings.SplitN(path, "?", 2)[0], code, body)
		}
	}
}

// Deleting the panel certificate (cfgPC a=0) is like deleting a site's
// (cfgC a=0): it asks for the current password in b, used as it arrives.
func TestI17_PanelCertificateDeleteNeedsPassword(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:cfgPC?a=0", tok); code != 400 || !strings.Contains(body, "current password (b)") {
		t.Errorf("cfgPC a=0 without a password: %d %q; expected 400 for the missing password", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:cfgPC?a=0&b=Bad", tok); code != 400 || !strings.Contains(body, "Wrong current password") {
		t.Errorf("cfgPC a=0 with a wrong password: %d %q", code, body)
	}
	// With the password, the reason is no longer the password: without a certificate, "No panel certificate"
	if code, body, _ := post(base, "/admin:inside:cfgPC?a=0&b=Admin", tok); code == 429 || strings.Contains(body, "assword") {
		t.Errorf("cfgPC a=0 with the password: %d %q", code, body)
	}
}

// N96: without its preprocessor, an extension's files are served as text, their source included (the keys of a
// database, for example). Deleting one needs the current password (b), as adding one: without it, 400; wrong,
// it counts for the session and the preprocessor stays.
func TestN96_DeletePreprocessorNeedsPassword(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addPreprocessor?s=localhost&d=&a=cgi&b="+toolPath("cgiecho")+"&c=Admin", tok); code != 200 {
		t.Fatalf("addPreprocessor: %d %q", code, body)
	}
	present := func() bool {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		_, ok := preprocessors["localhost"]["cgi"]
		return ok
	}
	if code, body, _ := post(base, "/admin:inside:delPreprocessor?s=localhost&d=&a=cgi", tok); code != 400 || !strings.Contains(body, "current password (b)") || !present() {
		t.Errorf("delPreprocessor without a password: %d %q, still there %v; expected 400 and that it stayed", code, body, present())
	}
	if code, body, _ := post(base, "/admin:inside:delPreprocessor?s=localhost&d=&a=cgi&b=Bad", tok); code != 400 || !strings.Contains(body, "Wrong current password") || !present() {
		t.Errorf("delPreprocessor with a wrong password: %d %q, still there %v", code, body, present())
	}
	if code, body, _ := post(base, "/admin:inside:delPreprocessor?s=localhost&d=&a=cgi&b=Admin", tok); code != 200 || present() {
		t.Errorf("delPreprocessor with the password: %d %q, still there %v", code, body, present())
	}
}
