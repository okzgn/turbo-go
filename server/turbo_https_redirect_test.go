package server

// Review of 6046dbe (R6), O-6: an HTTP request to a site without HTTPS is not asked for the port of its Host to decide
// that it isn't redirected. Reading it made an error for each Host without a port, which is how most come.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// memoryCertificate is a self-signed certificate for names, never written to disk.
func memoryCertificate(tb testing.TB, names ...string) *tls.Certificate {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// R6 O-6: the redirection to HTTPS is decided as before, for a site with HTTPS and for one without, with :443 open
// and closed, and for a Host with a port; and for a site without HTTPS it costs no allocation.
func TestR6_O6_HTTPSRedirectReadsTheHostWhenItCounts(t *testing.T) {
	initForTest(t)
	listening := httpsListening.Load()
	httpsListening.Store(true) // As with :443 open
	t.Cleanup(func() { httpsListening.Store(listening) })
	certificate := memoryCertificate(t, "secure.test", "www.secure.test")
	withGlobalLock(func() { // secure.test with HTTPS and its certificate, example.test without
		for _, site := range [][2]string{{"example.test", ""}, {"secure.test", ""}, {"secure.test", "www"}} {
			constructSiteWithoutIndex(site[0], site[1])
		}
		for _, siteKey := range []string{"secure.test", "www.secure.test"} {
			siteSSLConfig[siteKey].https = true
			setSiteCertificate(siteKey, certificate)
		}
	})
	redirection := func(siteKey, hostHeader string) (bool, string) {
		recorder := &responseRecorder{}
		request := benchRequest(hostHeader, "/page?x=1", "203.0.113.9:40000")
		var redirected bool
		withReadLock(func() { redirected = httpsRedirect(siteKey, recorder, request) })
		return redirected, recorder.header.Get("Location")
	}
	for _, c := range []struct {
		siteKey, hostHeader string
		expected            string
	}{
		{"secure.test", "secure.test", "https://secure.test/page?x=1"},
		{"secure.test", "secure.test:8080", "https://secure.test/page?x=1"},
		{"www.secure.test", "www.secure.test", "https://www.secure.test/page?x=1"},
		{"secure.test", "alias-without-certificate.test", ""}, // HTTPS on, and no certificate for that name
		{"example.test", "example.test", ""},
		{"example.test", "secure.test", ""}, // A certificate for the name, and a site without HTTPS
		{"unknown.test", "unknown.test", ""},
	} {
		if redirected, location := redirection(c.siteKey, c.hostHeader); redirected != (c.expected != "") || location != c.expected {
			t.Errorf("site %s, Host %s: redirected %v to %q; expected %q", c.siteKey, c.hostHeader, redirected, location, c.expected)
		}
	}
	httpsListening.Store(false)
	if redirected, location := redirection("secure.test", "secure.test"); redirected || location != "" {
		t.Errorf("with :443 closed: redirected to %q", location)
	}
	httpsListening.Store(true)
	if raceEnabled {
		return // The race detector allocates on its own
	}
	request := benchRequest("example.test", "/page", "203.0.113.9:40000")
	recorder := &responseRecorder{}
	withReadLock(func() {
		if allocations := testing.AllocsPerRun(100, func() { httpsRedirect("example.test", recorder, request) }); allocations != 0 {
			t.Errorf("a site without HTTPS: %.0f allocations to decide that it isn't redirected; expected none", allocations)
		}
	})
}
