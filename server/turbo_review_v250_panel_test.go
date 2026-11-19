package server

// The tests of the findings about the panel of the review of v2.5.0: each failed before its fix.

import (
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"turbo/customNetHttp"
)

// r250PanelTLS signs in on panel.test (over HTTP, without the redirection) and returns how to send a panel action as
// one that came over TLS on that host.
func r250PanelTLS(t *testing.T, base string) func(uri string) *responseRecorder {
	t.Helper()
	httpsListening.Store(false)
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
		t.Fatalf("the login on panel.test: %d %q", res.StatusCode, body)
	}
	token := strings.TrimPrefix(string(body), "ok")
	httpsListening.Store(true)
	return func(uri string) *responseRecorder {
		request, _ := customNetHttp.NewRequest("POST", "https://panel.test"+uri, customNetHttp.NoBody)
		request.RequestURI = uri
		request.RemoteAddr = "127.0.0.1:5000"
		request.Header.Set("ok", token)
		request.TLS = &tls.ConnectionState{}
		recorder := &responseRecorder{}
		console(recorder, request)
		if renewed := recorder.Header().Get("ok"); renewed != "" {
			token = renewed
		}
		return recorder
	}
}

// V2.5.0 review PA-1: setM over HTTPS to a directory without turbo.panel leaves the panel's host without a
// certificate, and its answer says so to the browser (max-age=0): it carried the year of HSTS decided before the
// action, with no HTTPS left to come back to.
func TestR250_PA1_SetMThatDropsThePanelCertificateClearsHSTS(t *testing.T) {
	_, base := panelHTTPSSetup(t)
	send := r250PanelTLS(t, base)
	if before := send("/admin:inside:sites"); before.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("with the panel's certificate: HSTS %q", before.Header().Get("Strict-Transport-Security"))
	}
	newDir := strings.ReplaceAll(t.TempDir(), "\\", "/") + "/"
	setM := send("/admin:inside:setM?a=" + newDir + "&b=Admin")
	if setM.code != 200 || certificateFor("panel.test") != nil {
		t.Fatalf("setM: %d %q, certificate in use %v", setM.code, setM.body.String(), certificateFor("panel.test") != nil)
	}
	if got := setM.Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Errorf("the answer of the setM that left the host without its certificate: HSTS %q; expected max-age=0", got)
	}
	if got := send("/admin:inside:sites").Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Errorf("the next request on the connection still open: HSTS %q; expected max-age=0", got)
	}
}

// V2.5.0 review PA-1: cfgPC a=0 once the files of the panel's certificate were removed by hand answers that there is
// none, stops using it, and its answer clears HSTS too.
func TestR250_PA1_NoPanelCertificateClearsHSTS(t *testing.T) {
	dir, base := panelHTTPSSetup(t)
	send := r250PanelTLS(t, base)
	for _, name := range []string{"turbo.panel/fullchain.pem", "turbo.panel/privkey.pem"} {
		if err := siteFileRemove(dir + name); err != nil {
			t.Fatal(err)
		}
	}
	answer := send("/admin:inside:cfgPC?a=0&b=Admin")
	if answer.code != 400 || certificateFor("panel.test") != nil {
		t.Fatalf("cfgPC a=0 without its files: %d %q, certificate in use %v", answer.code, answer.body.String(), certificateFor("panel.test") != nil)
	}
	if got := answer.Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Errorf("its answer: HSTS %q; expected max-age=0", got)
	}
}

// V2.5.0 review PA-2: whether a cfg action needs the current password is judged again as it is applied. cfgC with the
// adapter that was saved needs none; if the adapter is changed (cfgA, with the password) while that request looks at
// the disk, it is refused instead of putting the old adapter back.
func TestR250_PA2_ThePasswordIsJudgedAgainWhenACfgActionApplies(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	token := login(t, base)
	withGlobalLock(func() { siteSSLConfig["localhost"].adapter = "dns-aa" })
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if strings.HasSuffix(name, "localhost/fullchain.pem") {
			select {
			case entered <- struct{}{}:
				<-release
			default:
			}
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
	type answer struct {
		code int
		body string
	}
	done := make(chan answer)
	go func() { // The session alone: y is the adapter saved, and no b
		code, body, _ := post(base, "/admin:inside:cfgC?s=localhost&d=&a=1&y=dns-aa", token)
		done <- answer{code, body}
	}()
	<-entered
	if code, body, _ := post(base, "/admin:inside:cfgA?s=localhost&d=&a=dns-bb&b=Admin", token); code != 200 {
		t.Fatalf("cfgA with the password: %d %q", code, body)
	}
	close(release)
	if got := <-done; got.code != 400 || !strings.Contains(got.body, "the current password (b)") {
		t.Errorf("the cfgC that came without the password: %d %q; expected it to be asked for", got.code, got.body)
	}
	adapter := ""
	withReadLock(func() { adapter = siteSSLConfig["localhost"].adapter })
	if adapter != "dns-bb" {
		t.Errorf("the adapter saved at the end: %q; expected the one set with the password, dns-bb", adapter)
	}
}
