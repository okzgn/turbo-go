// Simulated certbot: it logs each invocation to $FAKE_CERTBOT_LOG and, with
// FAKE_CERTBOT_MODE=ok, generates a self-signed certificate where certbot would leave it.
// With FAKE_CERTBOT_DELAY=<ms>, it takes that long to issue it (to try the GUI by hand;
// the test suite doesn't use it).
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if lp := os.Getenv("FAKE_CERTBOT_LOG"); lp != "" {
		f, _ := os.OpenFile(lp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		fmt.Fprintf(f, "%q\n", os.Args[1:])
		f.Close()
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--version" {
		fmt.Println("certbot 9.9.9 (simulated)")
		return
	}
	var domains []string // Every -d; the first names the lineage, as in Certbot
	var cfgDir string
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-d":
			domains = append(domains, args[i+1])
		case "--config-dir":
			cfgDir = args[i+1]
		}
	}
	if delay, err := time.ParseDuration(os.Getenv("FAKE_CERTBOT_DELAY") + "ms"); err == nil {
		time.Sleep(delay)
	}
	if os.Getenv("FAKE_CERTBOT_MODE") != "ok" {
		fmt.Println("Simulated failure: Requested domain is not a FQDN")
		os.Exit(1)
	}
	if len(domains) == 0 {
		fmt.Println("Simulated failure: no -d")
		os.Exit(1)
	}
	domain := domains[0]
	dir := filepath.Join(cfgDir, "archive", strings.ReplaceAll(domain, "*", "_"))
	os.MkdirAll(dir, 0700)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb := x509.MarshalPKCS1PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "fullchain1.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	os.WriteFile(filepath.Join(dir, "privkey1.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: kb}), 0600)
	fmt.Println("Successfully received certificate (simulated).")
}
