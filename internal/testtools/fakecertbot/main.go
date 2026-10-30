// certbot simulado: registra cada invocación en $FAKE_CERTBOT_LOG y, con
// FAKE_CERTBOT_MODE=ok, genera un certificado autofirmado donde certbot lo dejaría.
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
		fmt.Println("certbot 9.9.9 (simulado)")
		return
	}
	var domain, cfgDir string
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-d":
			domain = args[i+1]
		case "--config-dir":
			cfgDir = args[i+1]
		}
	}
	if os.Getenv("FAKE_CERTBOT_MODE") != "ok" {
		fmt.Println("Simulated failure: Requested domain is not a FQDN")
		os.Exit(1)
	}
	dir := filepath.Join(cfgDir, "archive", strings.ReplaceAll(domain, "*", "_"))
	os.MkdirAll(dir, 0700)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kb := x509.MarshalPKCS1PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "fullchain1.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	os.WriteFile(filepath.Join(dir, "privkey1.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: kb}), 0600)
	fmt.Println("Successfully received certificate (simulado).")
}
