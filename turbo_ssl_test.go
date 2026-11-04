package main

// Certbot, certificates and TLS with the simulated Certbot (#10, #16, #41,
// #43, #44, #45, #54).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// #10, #54: the adapter accepts valid Certbot names and rejects arbitrary
// options, both in cfgA and in the y parameter of cfgC.
func TestP10_AdapterValidator(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := siteSSLSettingCheckers["A"](false, "dns-route53", "localhost", ""); !ok {
		t.Errorf("cfgA dns-route53 -> %q; expected accepted", msg)
	}
	for _, v := range []string{"pre-hook=x", "pre-hook=reboot", "webroot"} {
		if ok, msg := siteSSLSettingCheckers["A"](false, v, "localhost", ""); ok {
			t.Errorf("cfgA %q -> %q; expected rejected", v, msg)
		}
		if ok, msg := siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@example.com", v); ok || siteSSLConfig["localhost"]["A"] == v {
			t.Errorf("cfgC y=%q -> %v %q; expected rejected", v, ok, msg)
		}
	}
}

// #43: Certbot is not launched on its own at startup or when sites are
// detected.
func TestW_SSL_AutoAttempt(t *testing.T) {
	logf := useFakeCertbot(t, "fail")
	initForTest(t)
	updateSettings(true)
	time.Sleep(1 * time.Second)
	waitIdle()
	b, _ := os.ReadFile(logf)
	if len(b) != 0 {
		t.Fatalf("certbot invocations without pressing anything:\n%s", b)
	}
}

// #43: "Delete SSL" without a certificate doesn't launch Certbot.
func TestW_SSL_DeleteWithoutFiles(t *testing.T) {
	logf := useFakeCertbot(t, "fail")
	initForTest(t)
	time.Sleep(1 * time.Second)
	waitIdle()
	os.WriteFile(logf, nil, 0644)
	globalMutex.Lock()
	siteSSLConfig["localhost"]["C"] = false // The normal state of a site without a certificate
	ok, msg := siteSSLSettingCheckers["C"](false, "0", "localhost", "", "", "")
	globalMutex.Unlock()
	time.Sleep(1 * time.Second)
	waitIdle()
	if ok || msg != "No certificate" {
		t.Errorf("cfgC a=0 without files: %v %q; expected \"No certificate\"", ok, msg)
	}
	if b, _ := os.ReadFile(logf); len(b) != 0 {
		t.Fatalf("certbot invoked:\n%s", b)
	}
}

// #43: "Create SSL" without an e-mail doesn't launch Certbot.
func TestW_SSL_EmailRequired(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	initForTest(t)
	waitIdle()
	os.WriteFile(logf, nil, 0644)
	globalMutex.Lock()
	siteSSLConfig["localhost"]["C"] = false
	ok, msg := siteSSLSettingCheckers["C"](false, "1", "localhost", "", "", "")
	globalMutex.Unlock()
	waitIdle()
	b, _ := os.ReadFile(logf)
	if ok || !strings.Contains(msg, "E-mail") || len(b) != 0 {
		t.Fatalf("cfgC a=1 without an e-mail -> %v %q; certbot:\n%s", ok, msg, b)
	}
}

// Full flow: simulated issuance on request, loading into TLS, redirect to
// HTTPS, versions and suites, and SNI.
func TestW_SSL_TLSFlow(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	sites := []string{"a.test", "b.test", "c.test"}
	for _, s := range sites {
		os.MkdirAll(dir+s+"/@", 0755)
		os.WriteFile(dir+s+"/@/index.html", []byte("site "+s), 0644)
	}
	updateSettings(false)
	time.Sleep(500 * time.Millisecond)
	waitIdle()
	autoLog, _ := os.ReadFile(logf)
	os.WriteFile(logf, nil, 0644)

	// Issuance at the administrator's request, with an e-mail.
	for _, s := range sites {
		globalMutex.Lock()
		addIndex(s, "index.html")
		globalMutex.Unlock()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			globalMutex.Lock()
			ok, msg := siteSSLSettingCheckers["C"](false, "1", s, "", "admin@"+s, "")
			globalMutex.Unlock()
			if ok {
				break
			}
			t.Logf("cfgC %s: %q", s, msg)
			time.Sleep(300 * time.Millisecond)
		}
		if !fileExists(dir + s + "/fullchain.pem") {
			t.Fatalf("no certificate for %s; certbot:\n%s", s, func() []byte { b, _ := os.ReadFile(logf); return b }())
		}
	}
	waitIdle()
	globalMutex.Lock()
	subdomainContentCheckers["&"](true, map[string]interface{}{"alias-a.test": false}, false, "a.test", "")
	for _, s := range sites {
		if ok, msg := siteSSLSettingCheckers["S"](false, "1", s, ""); !ok {
			t.Fatalf("cfgS %s: %q", s, msg)
		}
	}
	globalMutex.Unlock()

	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(serverHandlerFn("s")), TLSConfig: tlsConfig, ConnState: connHandler}
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	// This listener stands for Turbo's HTTPS: nothing is redirected to an HTTPS that isn't open.
	httpsListening.Store(true)
	t.Cleanup(func() { srv.Close(); httpsListening.Store(false) })
	addr := l.Addr().String()
	handshake := func(sni string, cfg *tls.Config) (string, error) {
		if cfg == nil {
			cfg = &tls.Config{}
		}
		cfg.ServerName = sni
		cfg.InsecureSkipVerify = true
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: clientTimeout()}, "tcp", addr, cfg)
		if err != nil {
			return "", err
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
	}
	base := startServer(t)

	t.Run("HTTPRedirect", func(t *testing.T) {
		res, _, err := rawGet(base, "b.test", "/x?y=1")
		if err != nil || res.StatusCode != 301 || res.Header.Get("Location") != "https://b.test/x?y=1" {
			t.Fatalf("HTTP b.test -> %v %v; expected 301 to https://b.test/x?y=1", res, err)
		}
	})

	t.Run("Versions", func(t *testing.T) {
		rejected := map[string]*tls.Config{
			"TLS 1.0": {MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10},
			"TLS 1.1": {MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11},
			"3DES":    {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}},
			"RSA kex": {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}},
		}
		for name, cfg := range rejected {
			if cn, err := handshake("b.test", cfg); err == nil {
				t.Errorf("%s accepted (%s)", name, cn)
			}
		}
		accepted := map[string]*tls.Config{
			"TLS 1.2": {MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
			"TLS 1.3": {MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
		}
		for name, cfg := range accepted {
			if _, err := handshake("b.test", cfg); err != nil {
				t.Errorf("%s rejected: %v", name, err)
			}
		}
	})

	t.Run("IssuanceOnRequest", func(t *testing.T) {
		if len(autoLog) != 0 {
			t.Fatalf("certbot invoked without pressing anything:\n%s", autoLog)
		}
		requested, _ := os.ReadFile(logf)
		for _, want := range []string{`"-m" "admin@b.test"`, `"--work-dir"`, `"--logs-dir"`} {
			if !strings.Contains(string(requested), want) {
				t.Errorf("%s missing in the certbot invocations:\n%s", want, requested)
			}
		}
	})

	t.Run("SNI", func(t *testing.T) {
		for _, s := range sites {
			if cn, err := handshake(s, nil); err != nil || cn != s {
				t.Errorf("SNI %s -> %q %v", s, cn, err)
			}
		}
		for _, s := range []string{"unknown.test", "alias-a.test", ""} {
			if cn, err := handshake(s, nil); err == nil {
				t.Errorf("SNI %q accepted with the certificate of %s", s, cn)
			}
		}
		res, _, err := rawGet(base, "alias-a.test", "/")
		if err != nil || res.StatusCode != 200 || res.Header.Get("Location") != "" {
			t.Errorf("HTTP alias-a.test -> %v %v; expected 200 without a redirect", res, err)
		}
		globalMutex.Lock()
		ok, msg := siteSSLSettingCheckers["S"](false, "0", "a.test", "")
		globalMutex.Unlock()
		if !ok {
			t.Fatalf("cfgS a.test=0: %q", msg)
		}
		for _, s := range sites[1:] {
			if cn, err := handshake(s, nil); err != nil || cn != s {
				t.Errorf("after disabling a.test, SNI %s -> %q %v", s, cn, err)
			}
		}
		if cn, err := handshake("a.test", nil); err == nil {
			t.Errorf("after disabling it, SNI a.test accepted with the certificate of %s", cn)
		}
	})

}

// writeTestCertificate leaves in folder a self-signed fullchain.pem and
// privkey.pem for the given names, valid for validFor.
func writeTestCertificate(t *testing.T, folder string, validFor time.Duration, names ...string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(folder+"fullchain.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(folder+"privkey.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
}

// #16, #45 (DP11), §5.2: a wildcard certificate covers the subdomains one
// level down; an old "S" with a certificate index ("3") is loaded as enabled
// and saved as "1".
func TestW_SSL_WildcardAndLegacyS(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"w.test/@", 0755)
	writeTestCertificate(t, dir+"w.test/", 90*24*time.Hour, "w.test", "*.w.test")
	resetSettings()
	loadConfig(t, dir, `{"w.test":{"":{"!":{"S":"3"}}}}`)
	globalMutex.RLock()
	s := siteSSLConfig["w.test"]["S"]
	globalMutex.RUnlock()
	if s != 1 {
		t.Fatalf("loaded S = %v; expected 1", s)
	}
	for name, want := range map[string]bool{"w.test": true, "a.w.test": true, "A.W.TEST.": true, "b.a.w.test": false, "other.test": false, "": false} {
		if got := certificateFor(name) != nil; got != want {
			t.Errorf("certificateFor(%q) = %v; expected %v", name, got, want)
		}
	}
	saveDefaultConfig() // Takes the locks itself (T20)
	raw := savedConfig(t, dir)
	if got := raw["w.test"][""].(map[string]interface{})["!"].(map[string]interface{})["S"]; got != "1" {
		t.Errorf("saved S = %v; expected \"1\"", got)
	}
}

// DP5: the daily renewal asks Certbot for a new certificate only for those
// issued by Turbo that expire in less than 30 days, and puts it in use
// without restarting.
func TestW_SSL_Renewal(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	sites := map[string]time.Duration{"soon.test": 10 * 24 * time.Hour, "later.test": 60 * 24 * time.Hour, "external.test": 5 * 24 * time.Hour}
	for s, validFor := range sites {
		os.MkdirAll(dir+s+"/@", 0755)
		writeTestCertificate(t, dir+s+"/", validFor, s)
	}
	updateSettings(false)
	globalMutex.Lock()
	for s := range sites {
		if s != "external.test" { // Issued by Turbo: with an e-mail and a folder in turbo.certificates
			siteSSLSettingCheckers["E"](false, "admin@"+s, s, "")
			os.MkdirAll(dir+"turbo.certificates/"+s, 0700)
		}
		if ok, msg := siteSSLSettingCheckers["S"](false, "1", s, ""); !ok {
			t.Fatalf("cfgS %s: %q", s, msg)
		}
	}
	before := certificateFor("soon.test")
	globalMutex.Unlock()
	os.WriteFile(logf, nil, 0644)

	renewCertificates()
	time.Sleep(500 * time.Millisecond)
	waitIdle()

	calls, _ := os.ReadFile(logf)
	t.Logf("certbot:\n%s", calls)
	if !strings.Contains(string(calls), `"-d" "soon.test"`) {
		t.Error("soon.test was not renewed")
	}
	for _, s := range []string{"later.test", "external.test"} {
		if strings.Contains(string(calls), `"-d" "`+s+`"`) {
			t.Errorf("%s was renewed", s)
		}
	}
	if expiry, err := certificateExpiry(dir + "soon.test/fullchain.pem"); err != nil || time.Until(expiry) < 80*24*time.Hour {
		t.Errorf("fullchain of soon.test expires %v (%v); expected the renewed one", expiry, err)
	}
	if after := certificateFor("soon.test"); after == nil || after == before {
		t.Error("the renewed certificate is not in use")
	}
}

// Review of T1.17: each site has its folder in turbo.certificates. A
// subdomain with a certificate put in by hand is not renewed because Turbo
// issued the root's; one issued before in the domain's folder is.
func TestW_SSL_RenewalSubdomains(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	os.MkdirAll(dir+"r.test/@", 0755)
	for _, sub := range []string{"manual", "old"} {
		os.MkdirAll(dir+"r.test/"+sub+"/@", 0755)
		writeTestCertificate(t, dir+"r.test/"+sub+"/", 10*24*time.Hour, sub+".r.test")
	}
	writeTestCertificate(t, dir+"r.test/", 60*24*time.Hour, "r.test")
	os.MkdirAll(dir+"turbo.certificates/r.test/archive/old.r.test", 0700) // Issued before, in the domain's folder
	updateSettings(false)
	globalMutex.Lock()
	for _, sub := range []string{"", "manual", "old"} {
		siteSSLSettingCheckers["E"](false, "admin@r.test", "r.test", sub)
	}
	globalMutex.Unlock()
	os.WriteFile(logf, nil, 0644)
	renewCertificates()
	time.Sleep(500 * time.Millisecond)
	waitIdle()
	calls, _ := os.ReadFile(logf)
	if strings.Contains(string(calls), `"-d" "manual.r.test"`) {
		t.Errorf("the certificate put in by hand was renewed:\n%s", calls)
	}
	if !strings.Contains(string(calls), `"-d" "old.r.test"`) {
		t.Errorf("the one issued before in the domain's folder was not renewed:\n%s", calls)
	}
	if !strings.Contains(string(calls), "turbo.certificates/old.r.test") {
		t.Errorf("the renewal does not use the subdomain's own folder:\n%s", calls)
	}
}
