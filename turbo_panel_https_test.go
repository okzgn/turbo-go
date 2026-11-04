package main

// T08 (N4, D15 (a), D16 (a)): the panel on its own host has HTTPS: it loads
// the certificate of <sites>/turbo.panel/, redirects to HTTPS when a
// certificate covers the host and HTTPS is open (301 for GET and HEAD, 308
// for the rest) and sends HSTS over HTTPS on the hosts of PA. Nothing of
// turbo.panel/ is served or activated as a site.

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// panelHTTPSSetup leaves a certificate of panel.test in turbo.panel/ and PA
// with panel.test and other.test (without a certificate), with HTTPS open.
func panelHTTPSSetup(t *testing.T) (string, string) {
	t.Helper()
	dir := initForTest(t)
	os.MkdirAll(dir+"turbo.panel", 0755)
	writeTestCertificate(t, dir+"turbo.panel/", time.Hour, "panel.test")
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"PA":"panel.test,other.test"}}`)
	httpsListening.Store(true)
	t.Cleanup(func() { httpsListening.Store(false) })
	return dir, startServer(t)
}

// panelHTTP makes a request without following redirects.
func panelHTTP(t *testing.T, base, method, host, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, nil)
	req.Host = host
	client := &http.Client{Timeout: clientTimeout(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s %s: %v", method, host, path, err)
	}
	res.Body.Close()
	return res
}

func TestN04_PanelRedirectsToHTTPS(t *testing.T) {
	_, base := panelHTTPSSetup(t)
	res := panelHTTP(t, base, "GET", "panel.test", "/admin:")
	if want := "https://panel.test" + httpsPortSuffix() + "/admin:"; res.StatusCode != 301 || res.Header.Get("Location") != want {
		t.Errorf("GET http://panel.test/admin: -> %d %q; expected 301 to %q", res.StatusCode, res.Header.Get("Location"), want)
	}
	if res = panelHTTP(t, base, "POST", "panel.test", "/admin:inside:sites"); res.StatusCode != 308 {
		t.Errorf("POST over HTTP -> %d; expected 308", res.StatusCode)
	}
	if res = panelHTTP(t, base, "GET", "other.test", "/admin:"); res.StatusCode != 200 {
		t.Errorf("no certificate for the host -> %d; expected 200 without a redirect", res.StatusCode)
	}
	if res.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS over HTTP")
	}
	httpsListening.Store(false)
	if res = panelHTTP(t, base, "GET", "panel.test", "/admin:"); res.StatusCode != 200 {
		t.Errorf("with HTTPS closed -> %d; expected 200 without a redirect", res.StatusCode)
	}
}

// The TLS handshake with SNI panel.test delivers the panel certificate.
func TestN04_PanelCertificateHandshake(t *testing.T) {
	panelHTTPSSetup(t)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	go tls.Server(serverConn, tlsConfig).Handshake()
	client := tls.Client(clientConn, &tls.Config{ServerName: "panel.test", InsecureSkipVerify: true}) // #nosec G402 -- self-signed test certificate
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake with SNI panel.test: %v", err)
	}
	if names := client.ConnectionState().PeerCertificates[0].DNSNames; len(names) != 1 || names[0] != "panel.test" {
		t.Errorf("certificate delivered for %v", names)
	}
}

// HSTS only over HTTPS and on a host in PA.
func TestN04_PanelHSTS(t *testing.T) {
	panelHTTPSSetup(t)
	serve := func(host string) customNetHttp.Header {
		recorder := &responseRecorder{}
		request := &customNetHttp.Request{Method: "GET", Host: host, RequestURI: "/admin:", RemoteAddr: "127.0.0.1:5000", Header: customNetHttp.Header{}, TLS: &tls.ConnectionState{}}
		console(recorder, request)
		return recorder.Header()
	}
	if got := serve("panel.test").Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HSTS over HTTPS on the host in PA: %q", got)
	}
	panelAccess.Store(&panelAccessList{}) // Without a host of its own, the panel answers on a site's
	if got := serve("localhost").Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS on a host that is not in PA: %q", got)
	}
}

// Nothing of turbo.panel/ is served, not even if it has an @ folder.
func TestN04_PanelCertificateNotServed(t *testing.T) {
	dir, base := panelHTTPSSetup(t)
	os.MkdirAll(dir+"turbo.panel/@", 0755)
	os.WriteFile(dir+"turbo.panel/@/privkey.pem", []byte("x"), 0600)
	updateSettings(true)
	globalMutex.RLock()
	_, activated := sitesMap["turbo.panel"]
	globalMutex.RUnlock()
	if activated {
		t.Error("turbo.panel was activated as a site")
	}
	for _, host := range []string{"localhost", "turbo.panel", "panel.test"} {
		for _, path := range []string{"/turbo.panel/privkey.pem", "/../turbo.panel/privkey.pem", "/%2e%2e/turbo.panel/privkey.pem", "/privkey.pem"} {
			res, body, err := rawGet(base, host, path)
			if err == nil && (res.StatusCode == 200 || strings.Contains(body, "PRIVATE KEY")) {
				t.Errorf("Host %s %s -> %d", host, path, res.StatusCode)
			}
		}
	}
}

// The certificate is removed if its files are deleted.
func TestN04_PanelCertificateRemoved(t *testing.T) {
	dir, _ := panelHTTPSSetup(t)
	if certificateFor("panel.test") == nil {
		t.Fatal("panel certificate not loaded")
	}
	os.Remove(dir + "turbo.panel/fullchain.pem")
	os.Remove(dir + "turbo.panel/privkey.pem")
	updateSettings(true)
	if certificateFor("panel.test") != nil {
		t.Error("the panel certificate is still in use after deleting its files")
	}
}
