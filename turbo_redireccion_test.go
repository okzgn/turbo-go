package main

// C1 (H24): la redirección a HTTPS va al puerto de TURBO_HTTPS_ADDR, y las de
// www y raíz (W, R) conservan el puerto del Host.

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
	t.Cleanup(func() { certificatesByName.Store(&map[string]*tls.Certificate{}) })

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
			t.Errorf("TURBO_HTTPS_ADDR=%s: Location %q; se esperaba %q", addr, got, want)
		}
	}

	globalMutex.Lock()
	siteSSLConfig["localhost"]["S"] = 0
	siteSSLConfig["localhost"]["W"] = true
	globalMutex.Unlock()
	if got := location("localhost:8080"); got != "http://www.localhost:8080/x?y=1" {
		t.Errorf("W con Host localhost:8080: Location %q; se esperaba http://www.localhost:8080/x?y=1", got)
	}
	if got := location("localhost"); got != "http://www.localhost/x?y=1" {
		t.Errorf("W con Host localhost: Location %q", got)
	}
}
