//go:build unix

package main

// P15 (A1): the certificates are read without the global lock. fullchain.pem is
// a FIFO, which can't be read until someone writes to it: a really slow disk,
// without replacing any function.

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// fifoCertificate turns the fullchain.pem of folder (written by writeTestCertificate) into a FIFO, and returns a
// function that writes the certificate into it, which ends any read waiting on it.
func fifoCertificate(t *testing.T, folder string) func() {
	t.Helper()
	pemData, err := os.ReadFile(folder + certFileName)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(folder + certFileName)
	if err := syscall.Mkfifo(folder+certFileName, 0600); err != nil {
		t.Skip("can't create a FIFO:", err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		go func() { // Opening a FIFO to write waits for a reader
			if f, err := os.OpenFile(folder+certFileName, os.O_WRONLY, 0); err == nil {
				f.Write(pemData)
				f.Close()
			}
		}()
	}
	t.Cleanup(release)
	return release
}

func TestP15_CertificateLoadedWithoutGlobalLock(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	base := startServer(t)
	tok := login(t, base)
	release := fifoCertificate(t, dir+"localhost/")
	time.AfterFunc(1500*time.Millisecond, release)
	var code int
	var body string
	elapsed := requestWhileLockWaits(t, base, func() { code, body, _ = post(base, "/admin:inside:cfgS?s=localhost&d=&a=1", tok) })
	if elapsed > 150*time.Millisecond {
		t.Errorf("cfgS reading a slow certificate: a request meanwhile took %v; expected less than 150 ms", elapsed)
	}
	if code != 200 {
		t.Errorf("cfgS: %d %q", code, body)
	}
}

func TestP15_RenewalReadsWithoutGlobalLock(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	os.MkdirAll(dir+certificatesDirName+"/localhost", 0700) // Issued by Turbo
	globalMutex.Lock()
	siteSSLConfig["localhost"]["E"] = "a@b.co"
	globalMutex.Unlock()
	base := startServer(t)
	release := fifoCertificate(t, dir+"localhost/")
	time.AfterFunc(1500*time.Millisecond, release)
	if elapsed := requestWhileLockWaits(t, base, renewCertificates); elapsed > 150*time.Millisecond {
		t.Errorf("the renewal reading a slow certificate: a request meanwhile took %v; expected less than 150 ms", elapsed)
	}
}
