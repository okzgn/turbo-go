package main

// T09 (N4, D15 (a)): the certificate of the panel's own host is issued and
// renewed from the panel (cfgPC) with Certbot, for all the hosts of PA, with
// the ACME challenge served from turbo.panel/webroot on those hosts only.

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// panelCertSetup leaves PA with two hosts of its own and the simulated Certbot.
func panelCertSetup(t *testing.T, mode string) (dir, base, token, certbotLog string) {
	t.Helper()
	certbotLog = useFakeCertbot(t, mode)
	dir = initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"PA":"panel.test,admin.panel.test"}}`)
	base = startServer(t)
	credentials, contentType := multipartCredentials("Turbo", "Admin")
	req, _ := http.NewRequest("POST", base+"/admin:", credentials)
	req.Host = "panel.test"
	req.Header.Set("Content-Type", contentType)
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if !strings.HasPrefix(string(body), "ok") {
		t.Fatalf("login on panel.test: %d %q", res.StatusCode, body)
	}
	return dir, base, strings.TrimPrefix(string(body), "ok"), certbotLog
}

func TestN04_PanelCertificateIssued(t *testing.T) {
	dir, base, token, certbotLog := panelCertSetup(t, "ok")
	code, body := postHost(t, base, "panel.test", "/admin:inside:cfgPC?"+url.Values{"a": {"1"}, "z": {"admin@example.com"}}.Encode(), token)
	if code != 202 || !strings.Contains(body, "WAIT") {
		t.Fatalf("cfgPC a=1: %d %q; expected 202 WAIT", code, body)
	}
	waitIdle()
	for _, host := range []string{"panel.test", "admin.panel.test"} {
		if certificateFor(host) == nil {
			t.Errorf("no certificate for %s after issuing it", host)
		}
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		if _, err := os.Stat(dir + "turbo.panel/" + name); err != nil {
			t.Errorf("turbo.panel/%s: %v", name, err)
		}
	}
	logged, _ := os.ReadFile(certbotLog)
	for _, want := range []string{`"-d" "admin.panel.test"`, `"-d" "panel.test"`, `"--webroot-path" "` + dir + `turbo.panel/webroot"`, `"admin@example.com"`} {
		if !strings.Contains(string(logged), want) {
			t.Errorf("Certbot without %s:\n%s", want, logged)
		}
	}
	if code, body = postHost(t, base, "panel.test", "/admin:inside:cfgPC?a=1", token); code != 200 || !strings.Contains(body, "active") {
		t.Errorf("cfgPC a=1 with the certificate in use: %d %q", code, body)
	}
	if code, body = postHost(t, base, "panel.test", "/admin:inside:sites", token); !strings.Contains(body, `"PCE":"admin@example.com"`) || !strings.Contains(body, `"PCC":true`) {
		t.Errorf("sites without PCE or PCC: %d %s", code, body)
	}
	saveDefaultConfig()
	if raw := savedConfig(t, dir); raw["."]["PCE"] != "admin@example.com" || raw["."]["PCC"] != nil {
		t.Errorf("saved: PCE=%v PCC=%v; expected the e-mail and no state", raw["."]["PCE"], raw["."]["PCC"])
	}
	if code, body = postHost(t, base, "panel.test", "/admin:inside:cfgPC?a=0&b=Admin", token); code != 200 || certificateFor("panel.test") != nil {
		t.Errorf("cfgPC a=0: %d %q; the certificate is still in use: %v", code, body, certificateFor("panel.test") != nil)
	}
}

// Without an e-mail, or without hosts of its own in PA, nothing is issued.
func TestN04_PanelCertificateRefused(t *testing.T) {
	_, base, token, certbotLog := panelCertSetup(t, "ok")
	if code, body := postHost(t, base, "panel.test", "/admin:inside:cfgPC?a=1", token); code != 400 || !strings.Contains(body, "E-mail") {
		t.Errorf("without an e-mail: %d %q", code, body)
	}
	panelAccess.Store(&panelAccessList{})
	if code, body := postHost(t, base, "localhost", "/admin:inside:cfgPC?a=1&z=admin%40example.com", token); code != 400 || !strings.Contains(body, "host of its own") {
		t.Errorf("without hosts in PA: %d %q", code, body)
	}
	if logged, _ := os.ReadFile(certbotLog); len(logged) != 0 {
		t.Errorf("Certbot ran:\n%s", logged)
	}
}

// Certbot's error is answered once.
func TestN04_PanelCertificateFailure(t *testing.T) {
	_, base, token, _ := panelCertSetup(t, "fail")
	postHost(t, base, "panel.test", "/admin:inside:cfgPC?a=1&z=admin%40example.com", token)
	waitIdle()
	if code, body := postHost(t, base, "panel.test", "/admin:inside:cfgPC?a=1", token); code != 400 || !strings.Contains(body, "Simulated failure") {
		t.Errorf("after the failure: %d %q; expected Certbot's error", code, body)
	}
}

// The ACME challenge is served only on the hosts of PA, only a token and only
// files.
func TestN04_PanelACMEChallenge(t *testing.T) {
	dir, base, _, _ := panelCertSetup(t, "ok")
	challengeDir := dir + "turbo.panel/webroot/.well-known/acme-challenge/"
	os.MkdirAll(challengeDir+"folder", 0755)
	os.WriteFile(challengeDir+"tok_en-1", []byte("acme-response"), 0644)
	if res, body, err := rawGet(base, "panel.test", "/.well-known/acme-challenge/tok_en-1"); err != nil || res.StatusCode != 200 || body != "acme-response" {
		t.Errorf("challenge on panel.test: %v %q %v", res, body, err)
	}
	for _, c := range []struct{ host, path string }{
		{"localhost", "/.well-known/acme-challenge/tok_en-1"},
		{"panel.test", "/.well-known/acme-challenge/folder"},
		{"panel.test", "/.well-known/acme-challenge/../../privkey.pem"},
		{"panel.test", "/.well-known/acme-challenge/%2e%2e%2fx"},
		{"panel.test", "/.well-known/acme-challenge/missing"},
		{"panel.test", "/privkey.pem"},
	} {
		if res, body, err := rawGet(base, c.host, c.path); err == nil && (res.StatusCode == 200 || strings.Contains(body, "acme-response")) {
			t.Errorf("Host %s %s -> %d %q", c.host, c.path, res.StatusCode, body)
		}
	}
}

// With only the panel certificate (no site with HTTPS), HTTPS opens: at
// startup and when the certificate comes later.
func TestN04_PanelCertificateOpensHTTPS(t *testing.T) {
	dir := initForTest(t)
	previousAddr, previousServer := httpsAddr, servers[0]
	t.Cleanup(func() {
		httpsAddr, servers[0] = previousAddr, previousServer
		httpsListening.Store(false)
	})
	listening := func() bool {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if httpsListening.Load() {
				return true
			}
		}
		return false
	}
	os.MkdirAll(dir+"turbo.panel", 0755)
	writeTestCertificate(t, dir+"turbo.panel/", time.Hour, "panel.test")
	updateSettings(true)
	httpsAddr = "127.0.0.1:" + freePort(t)
	var server *customNetHttp.Server
	withGlobalLock(func() { server = createSafeServer(tlsConfig) })
	if !listening() {
		t.Error("starting with only the panel certificate, HTTPS didn't open")
	}
	server.Close()
	httpsListening.Store(false)

	os.Remove(dir + "turbo.panel/fullchain.pem")
	updateSettings(true)
	httpsAddr = "127.0.0.1:" + freePort(t)
	servers[0] = newHTTPSServer(tlsConfig)
	defer servers[0].Close()
	writeTestCertificate(t, dir+"turbo.panel/", time.Hour, "panel.test")
	updateSettings(true)
	if !listening() {
		t.Error("when the panel certificate came, HTTPS didn't open")
	}
}

// The daily renewal also renews the panel certificate.
func TestN04_PanelCertificateRenewal(t *testing.T) {
	dir, _, _, certbotLog := panelCertSetup(t, "ok")
	os.MkdirAll(dir+"turbo.panel", 0700)
	os.MkdirAll(dir+"turbo.certificates/turbo.panel", 0700)
	writeTestCertificate(t, dir+"turbo.panel/", 10*24*time.Hour, "panel.test", "admin.panel.test")
	withGlobalLock(func() { panelCertEmail = "admin@example.com" })
	updateSettings(true)
	renewCertificates()
	waitIdle()
	if logged, _ := os.ReadFile(certbotLog); !strings.Contains(string(logged), `"-d" "panel.test"`) {
		t.Errorf("Certbot wasn't called to renew:\n%s", logged)
	}
	if cert := certificateFor("panel.test"); cert == nil || cert.Leaf != nil && time.Until(cert.Leaf.NotAfter) < 30*24*time.Hour {
		t.Error("the renewed certificate isn't in use")
	}
}

// N68: when the panel certificate is deleted over HTTPS, the response withdraws
// HSTS (max-age=0): without a certificate, the browser must be able to come back
// to the panel over HTTP, which is no longer redirected.
func TestN68_PanelCertificateDeleteClearsHSTS(t *testing.T) {
	_, base := panelHTTPSSetup(t)
	httpsListening.Store(false) // The login, over HTTP on panel.test, without the redirect
	credentials, contentType := multipartCredentials("Turbo", "Admin")
	loginRequest, _ := http.NewRequest("POST", base+"/admin:", credentials)
	loginRequest.Host = "panel.test"
	loginRequest.Header.Set("Content-Type", contentType)
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.HasPrefix(string(body), "ok") {
		t.Fatalf("login on panel.test: %d %q", res.StatusCode, body)
	}
	token := strings.TrimPrefix(string(body), "ok")
	httpsListening.Store(true)
	request, _ := customNetHttp.NewRequest("POST", "https://panel.test/admin:inside:cfgPC?a=0&b=Admin", customNetHttp.NoBody)
	request.RequestURI = "/admin:inside:cfgPC?a=0&b=Admin"
	request.RemoteAddr = "127.0.0.1:5000"
	request.Header.Set("ok", token)
	request.TLS = &tls.ConnectionState{}
	recorder := &responseRecorder{}
	console(recorder, request)
	if recorder.code != 0 && recorder.code != 200 || certificateFor("panel.test") != nil {
		t.Fatalf("cfgPC a=0: %d %q; certificate in use: %v", recorder.code, recorder.body.String(), certificateFor("panel.test") != nil)
	}
	if got := recorder.Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Errorf("HSTS when deleting the panel certificate: %q; expected \"max-age=0\"", got)
	}
}
