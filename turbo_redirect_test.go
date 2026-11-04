package main

// C1 (H24): the redirect to HTTPS goes to the port of TURBO_HTTPS_ADDR, and the
// www and root ones (W, R) keep the port of the Host.

import (
	"crypto/tls"
	"testing"

	"turbo/customNetHttp"
)

func TestC1_RedirectPorts(t *testing.T) {
	initForTest(t)
	previous := httpsAddr
	t.Cleanup(func() { httpsAddr = previous })
	globalMutex.Lock()
	siteSSLConfig["localhost"]["S"] = 1 // HTTPS on, with a certificate that covers localhost
	certificatesByName.Store(&map[string]*tls.Certificate{"localhost": {}})
	globalMutex.Unlock()
	httpsListening.Store(true) // As if Turbo's HTTPS were open: nothing is redirected to one that isn't
	t.Cleanup(func() { certificatesByName.Store(&map[string]*tls.Certificate{}); httpsListening.Store(false) })

	location := func(hostHeader string) string {
		req, _ := customNetHttp.NewRequest("GET", "http://"+hostHeader+"/x?y=1", nil)
		req.RequestURI = "/x?y=1"
		req.RemoteAddr = "192.0.2.20:40000"
		rec := &responseRecorder{}
		serverHandlerFn("")(rec, req)
		return rec.Header().Get("Location")
	}
	for addr, want := range map[string]string{
		":443":           "https://localhost/x?y=1",
		":8443":          "https://localhost:8443/x?y=1",
		"127.0.0.1:8443": "https://localhost:8443/x?y=1",
	} {
		httpsAddr = addr
		if got := location("localhost:8080"); got != want {
			t.Errorf("TURBO_HTTPS_ADDR=%s: Location %q; expected %q", addr, got, want)
		}
	}

	globalMutex.Lock()
	siteSSLConfig["localhost"]["S"] = 0
	siteSSLConfig["localhost"]["W"] = true
	globalMutex.Unlock()
	if got := location("localhost:8080"); got != "http://www.localhost:8080/x?y=1" {
		t.Errorf("W with Host localhost:8080: Location %q; expected http://www.localhost:8080/x?y=1", got)
	}
	if got := location("localhost"); got != "http://www.localhost/x?y=1" {
		t.Errorf("W with Host localhost: Location %q", got)
	}
}
