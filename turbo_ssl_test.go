package main

// Certbot, certificados y TLS con el Certbot simulado (#10, #16, #41, #43,
// #44, #45, #54).

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

// #10, #54: el adaptador acepta nombres válidos de Certbot y rechaza opciones
// arbitrarias, tanto en cfgA como en el parámetro y de cfgC.
func TestP10_AdapterValidator(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := siteSSLSettingCheckers["A"](false, "dns-route53", "localhost", ""); !ok {
		t.Errorf("cfgA dns-route53 -> %q; se esperaba aceptado", msg)
	}
	for _, v := range []string{"pre-hook=x", "pre-hook=reboot", "webroot"} {
		if ok, msg := siteSSLSettingCheckers["A"](false, v, "localhost", ""); ok {
			t.Errorf("cfgA %q -> %q; se esperaba rechazado", v, msg)
		}
		if ok, msg := siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@example.com", v); ok || siteSSLConfig["localhost"]["A"] == v {
			t.Errorf("cfgC y=%q -> %v %q; se esperaba rechazado", v, ok, msg)
		}
	}
}

// #43: Certbot no se lanza solo al arrancar ni al detectar sitios.
func TestW_SSL_AutoAttempt(t *testing.T) {
	logf := useFakeCertbot(t, "fail")
	initForTest(t)
	updateSettings(true)
	time.Sleep(1 * time.Second)
	waitIdle()
	b, _ := os.ReadFile(logf)
	if len(b) != 0 {
		t.Fatalf("invocaciones de certbot sin pulsar nada:\n%s", b)
	}
}

// #43: "Borrar SSL" sin certificado no lanza Certbot.
func TestW_SSL_DeleteWithoutFiles(t *testing.T) {
	logf := useFakeCertbot(t, "fail")
	initForTest(t)
	time.Sleep(1 * time.Second)
	waitIdle()
	os.WriteFile(logf, nil, 0644)
	globalMutex.Lock()
	siteSSLConfig["localhost"]["C"] = false // estado normal de un sitio sin certificado
	ok, msg := siteSSLSettingCheckers["C"](false, "0", "localhost", "", "", "")
	globalMutex.Unlock()
	time.Sleep(1 * time.Second)
	waitIdle()
	b, _ := os.ReadFile(logf)
	t.Logf("cfgC a=0 sin archivos -> %v %q", ok, msg)
	if len(b) != 0 {
		t.Fatalf("certbot invocado:\n%s", b)
	}
}

// #43: "Crear SSL" sin email no lanza Certbot.
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
		t.Fatalf("cfgC a=1 sin email -> %v %q; certbot:\n%s", ok, msg, b)
	}
}

// Flujo completo: emisión simulada a petición, carga en TLS, redirección a
// HTTPS, versiones y suites, y SNI.
func TestW_SSL_TLSFlow(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	sites := []string{"a.test", "b.test", "c.test"}
	for _, s := range sites {
		os.MkdirAll(dir+s+"/@", 0755)
		os.WriteFile(dir+s+"/@/index.html", []byte("sitio "+s), 0644)
	}
	updateSettings(false)
	time.Sleep(500 * time.Millisecond)
	waitIdle()
	autoLog, _ := os.ReadFile(logf)
	os.WriteFile(logf, nil, 0644)

	// Emisión a petición del administrador, con email.
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
			t.Fatalf("sin certificado para %s; certbot:\n%s", s, func() []byte { b, _ := os.ReadFile(logf); return b }())
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
	t.Cleanup(func() { srv.Close() })
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

	t.Run("RedireccionHTTP", func(t *testing.T) {
		res, _, err := rawGet(base, "b.test", "/x?y=1")
		if err != nil || res.StatusCode != 301 || res.Header.Get("Location") != "https://b.test/x?y=1" {
			t.Fatalf("HTTP b.test -> %v %v; se esperaba 301 a https://b.test/x?y=1", res, err)
		}
	})

	t.Run("Versiones", func(t *testing.T) {
		rejected := map[string]*tls.Config{
			"TLS 1.0": {MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10},
			"TLS 1.1": {MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11},
			"3DES":    {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}},
			"RSA kex": {MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}},
		}
		for name, cfg := range rejected {
			if cn, err := handshake("b.test", cfg); err == nil {
				t.Errorf("%s aceptado (%s)", name, cn)
			}
		}
		accepted := map[string]*tls.Config{
			"TLS 1.2": {MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12},
			"TLS 1.3": {MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
		}
		for name, cfg := range accepted {
			if _, err := handshake("b.test", cfg); err != nil {
				t.Errorf("%s rechazado: %v", name, err)
			}
		}
	})

	t.Run("EmisionAPeticion", func(t *testing.T) {
		if len(autoLog) != 0 {
			t.Fatalf("certbot invocado sin pulsar nada:\n%s", autoLog)
		}
		requested, _ := os.ReadFile(logf)
		for _, want := range []string{`"-m" "admin@b.test"`, `"--work-dir"`, `"--logs-dir"`} {
			if !strings.Contains(string(requested), want) {
				t.Errorf("falta %s en las invocaciones de certbot:\n%s", want, requested)
			}
		}
	})

	t.Run("SNI", func(t *testing.T) {
		for _, s := range sites {
			if cn, err := handshake(s, nil); err != nil || cn != s {
				t.Errorf("SNI %s -> %q %v", s, cn, err)
			}
		}
		for _, s := range []string{"desconocido.test", "alias-a.test", ""} {
			if cn, err := handshake(s, nil); err == nil {
				t.Errorf("SNI %q aceptado con el certificado de %s", s, cn)
			}
		}
		res, _, err := rawGet(base, "alias-a.test", "/")
		if err != nil || res.StatusCode != 200 || res.Header.Get("Location") != "" {
			t.Errorf("HTTP alias-a.test -> %v %v; se esperaba 200 sin redirección", res, err)
		}
		globalMutex.Lock()
		ok, msg := siteSSLSettingCheckers["S"](false, "0", "a.test", "")
		globalMutex.Unlock()
		if !ok {
			t.Fatalf("cfgS a.test=0: %q", msg)
		}
		for _, s := range sites[1:] {
			if cn, err := handshake(s, nil); err != nil || cn != s {
				t.Errorf("tras desactivar a.test, SNI %s -> %q %v", s, cn, err)
			}
		}
		if cn, err := handshake("a.test", nil); err == nil {
			t.Errorf("tras desactivarlo, SNI a.test aceptado con el certificado de %s", cn)
		}
	})

}

// writeTestCertificate deja en folder un fullchain.pem y un privkey.pem
// autofirmados para los nombres dados, válidos durante validFor.
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

// #16, #45 (DP11), §5.2: un certificado comodín cubre los subdominios de un
// nivel; un "S" antiguo con índice de certificado ("3") se carga como activado
// y se guarda como "1".
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
		t.Fatalf("S cargado = %v; se esperaba 1", s)
	}
	for name, want := range map[string]bool{"w.test": true, "a.w.test": true, "A.W.TEST.": true, "b.a.w.test": false, "otro.test": false, "": false} {
		if got := certificateFor(name) != nil; got != want {
			t.Errorf("certificateFor(%q) = %v; se esperaba %v", name, got, want)
		}
	}
	globalMutex.Lock()
	saveDefaultConfig()
	globalMutex.Unlock()
	raw := savedConfig(t, dir)
	if got := raw["w.test"][""].(map[string]interface{})["!"].(map[string]interface{})["S"]; got != "1" {
		t.Errorf("S guardado = %v; se esperaba \"1\"", got)
	}
}

// DP5: la renovación diaria pide a Certbot un certificado nuevo solo para los
// emitidos por Turbo que caducan en menos de 30 días, y lo pone en uso sin
// reiniciar.
func TestW_SSL_Renewal(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	sites := map[string]time.Duration{"pronto.test": 10 * 24 * time.Hour, "lejos.test": 60 * 24 * time.Hour, "ajeno.test": 5 * 24 * time.Hour}
	for s, validFor := range sites {
		os.MkdirAll(dir+s+"/@", 0755)
		writeTestCertificate(t, dir+s+"/", validFor, s)
	}
	updateSettings(false)
	globalMutex.Lock()
	for s := range sites {
		if s != "ajeno.test" { // emitidos por Turbo: con e-mail y carpeta en turbo.certificates
			siteSSLSettingCheckers["E"](false, "admin@"+s, s, "")
			os.MkdirAll(dir+"turbo.certificates/"+s, 0700)
		}
		if ok, msg := siteSSLSettingCheckers["S"](false, "1", s, ""); !ok {
			t.Fatalf("cfgS %s: %q", s, msg)
		}
	}
	before := certificateFor("pronto.test")
	globalMutex.Unlock()
	os.WriteFile(logf, nil, 0644)

	renewCertificates()
	time.Sleep(500 * time.Millisecond)
	waitIdle()

	calls, _ := os.ReadFile(logf)
	t.Logf("certbot:\n%s", calls)
	if !strings.Contains(string(calls), `"-d" "pronto.test"`) {
		t.Error("no se renovó pronto.test")
	}
	for _, s := range []string{"lejos.test", "ajeno.test"} {
		if strings.Contains(string(calls), `"-d" "`+s+`"`) {
			t.Errorf("se renovó %s", s)
		}
	}
	if expiry, err := certificateExpiry(dir + "pronto.test/fullchain.pem"); err != nil || time.Until(expiry) < 80*24*time.Hour {
		t.Errorf("fullchain de pronto.test caduca %v (%v); se esperaba el renovado", expiry, err)
	}
	if after := certificateFor("pronto.test"); after == nil || after == before {
		t.Error("el certificado renovado no está en uso")
	}
}

// Revisión de T1.17: cada sitio tiene su carpeta en turbo.certificates. Un
// subdominio con certificado puesto a mano no se renueva porque la raíz lo
// emitiera Turbo; uno emitido antes en la carpeta del dominio, sí.
func TestW_SSL_RenewalSubdomains(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	os.MkdirAll(dir+"r.test/@", 0755)
	for _, sub := range []string{"manual", "antiguo"} {
		os.MkdirAll(dir+"r.test/"+sub+"/@", 0755)
		writeTestCertificate(t, dir+"r.test/"+sub+"/", 10*24*time.Hour, sub+".r.test")
	}
	writeTestCertificate(t, dir+"r.test/", 60*24*time.Hour, "r.test")
	os.MkdirAll(dir+"turbo.certificates/r.test/archive/antiguo.r.test", 0700) // emitido antes, en la carpeta del dominio
	updateSettings(false)
	globalMutex.Lock()
	for _, sub := range []string{"", "manual", "antiguo"} {
		siteSSLSettingCheckers["E"](false, "admin@r.test", "r.test", sub)
	}
	globalMutex.Unlock()
	os.WriteFile(logf, nil, 0644)
	renewCertificates()
	time.Sleep(500 * time.Millisecond)
	waitIdle()
	calls, _ := os.ReadFile(logf)
	if strings.Contains(string(calls), `"-d" "manual.r.test"`) {
		t.Errorf("se renovó el certificado puesto a mano:\n%s", calls)
	}
	if !strings.Contains(string(calls), `"-d" "antiguo.r.test"`) {
		t.Errorf("no se renovó el emitido antes en la carpeta del dominio:\n%s", calls)
	}
	if !strings.Contains(string(calls), "turbo.certificates/antiguo.r.test") {
		t.Errorf("la renovación no usa la carpeta propia del subdominio:\n%s", calls)
	}
}
