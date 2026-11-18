package server

// Review of 6046dbe (R6): certificate files that can't be loaded, deleted halfway or installed from another volume,
// and the opening of the HTTPS address.

import (
	"bytes"
	"crypto/tls"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// placeCertificateFile writes a certificate file with a fixed date, so that a later version of the same size has
// the same stamp (date and size), as a file whose owner or permissions change.
func placeCertificateFile(t *testing.T, path string, data []byte, moment time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, moment, moment); err != nil {
		t.Fatal(err)
	}
}

// panelCertificateInUse is the panel's certificate in use, or nil.
func panelCertificateInUse() *tls.Certificate {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return panelCertificate
}

// R6 V-05: the certificate files of a site that couldn't be loaded are read again at the next look, also when what
// makes them usable changes neither their date nor their size (a key that a renewal hook copies and then gives to
// Turbo's user). They were taken as read, and the site kept its previous certificate until it expired.
func TestR6_V05_UnloadableSiteCertificateIsReadAgain(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	globalMutex.Lock()
	ok, msg := siteSSLSettingCheckers["S"](false, "1", "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("S: %s", msg)
	}
	first := certificateFor("localhost")
	if first == nil {
		t.Fatal("no certificate in use")
	}
	refreshSiteCertificates()
	scratch := t.TempDir() + "/"
	renewed := loadTestCertificate(t, scratch, time.Hour, "localhost")
	chain, _ := os.ReadFile(scratch + certFileName)
	key, _ := os.ReadFile(scratch + keyFileName)
	moment := time.Now().Add(-time.Minute).Truncate(time.Second)
	placeCertificateFile(t, dir+"localhost/"+certFileName, chain, moment)
	placeCertificateFile(t, dir+"localhost/"+keyFileName, bytes.Repeat([]byte("x"), len(key)), moment) // Not a key yet
	logs := captureLog(t)
	for i := 0; i < 3; i++ {
		refreshSiteCertificates()
	}
	if certificateFor("localhost") != first {
		t.Error("the pair that can't be loaded replaced the certificate in use")
	}
	if warnings := strings.Count(logs.String(), "can't be loaded"); warnings != 1 {
		t.Errorf("%d warnings for the same files in three looks; expected 1:\n%s", warnings, logs.String())
	}
	placeCertificateFile(t, dir+"localhost/"+keyFileName, key, moment) // The key, with the same date and size
	refreshSiteCertificates()
	if got := certificateFor("localhost"); !sameCertificate(got, renewed) {
		t.Error("the pair, once it can be loaded, isn't in use")
	}
	refreshSiteCertificates() // And it is not loaded again
	if got := certificateFor("localhost"); !sameCertificate(got, renewed) {
		t.Error("the certificate changed at the look after it was loaded")
	}
}

// R6 V-05: the same for the panel's certificate, whose certificate in use was dropped (the panel left without
// HTTPS) when its files changed to a pair that couldn't be loaded.
func TestR6_V05_UnloadablePanelCertificateKeepsTheOneInUse(t *testing.T) {
	dir := initForTest(t)
	panelDir := dir + panelCertDirName + "/"
	os.MkdirAll(panelDir, 0755)
	writeTestCertificate(t, panelDir, time.Hour, "panel.test")
	withGlobalLock(func() { loadPanelCertificate(dir) })
	var first = panelCertificateInUse()
	if first == nil {
		t.Fatal("the panel's certificate wasn't loaded")
	}
	scratch := t.TempDir() + "/"
	renewed := loadTestCertificate(t, scratch, time.Hour, "panel.test")
	chain, _ := os.ReadFile(scratch + certFileName)
	key, _ := os.ReadFile(scratch + keyFileName)
	moment := time.Now().Add(-time.Minute).Truncate(time.Second)
	placeCertificateFile(t, panelDir+certFileName, chain, moment)
	placeCertificateFile(t, panelDir+keyFileName, bytes.Repeat([]byte("x"), len(key)), moment)
	logs := captureLog(t)
	for i := 0; i < 3; i++ {
		withGlobalLock(func() { loadPanelCertificate(dir) })
	}
	if panelCertificateInUse() != first {
		t.Error("the pair that can't be loaded took the panel's certificate out of use")
	}
	if warnings := strings.Count(logs.String(), "can't be loaded"); warnings != 1 {
		t.Errorf("%d warnings for the same files in three looks; expected 1:\n%s", warnings, logs.String())
	}
	placeCertificateFile(t, panelDir+keyFileName, key, moment)
	withGlobalLock(func() { loadPanelCertificate(dir) })
	if got := panelCertificateInUse(); !sameCertificate(got, renewed) {
		t.Error("the panel's pair, once it can be loaded, isn't in use")
	}
	// Without a certificate in use, an invalid pair is still only warned about, once, and read again
	withGlobalLock(func() { panelCertificate, panelCertificateStamp = nil, "" })
	placeCertificateFile(t, panelDir+keyFileName, bytes.Repeat([]byte("x"), len(key)), moment)
	logs.Reset()
	for i := 0; i < 2; i++ {
		withGlobalLock(func() { loadPanelCertificate(dir) })
	}
	if warnings := strings.Count(logs.String(), "invalid or incomplete"); warnings != 1 || panelCertificateInUse() != nil {
		t.Errorf("an invalid pair with none in use: %d warnings, in use %v; expected 1 and none", warnings, panelCertificateInUse() != nil)
	}
	placeCertificateFile(t, panelDir+keyFileName, key, moment)
	withGlobalLock(func() { loadPanelCertificate(dir) })
	if got := panelCertificateInUse(); !sameCertificate(got, renewed) {
		t.Error("the panel's first pair, once it can be loaded, isn't in use")
	}
}

// R6 V-06: "Delete SSL" also deletes what a deletion that failed halfway left. With only the key there, the answer
// was "No certificate", and the panel could no longer delete it.
func TestR6_V06_DeleteSSLAfterAHalfDeletion(t *testing.T) {
	dir := initForTest(t)
	deleteSSL := func() (bool, string) {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		return siteSSLSettingCheckers["C"](false, "0", "localhost", "", "", "")
	}
	for _, left := range []string{keyFileName, certFileName} {
		writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
		for _, name := range []string{certFileName, keyFileName} {
			if name != left {
				os.Remove(dir + "localhost/" + name)
			}
		}
		if ok, msg := deleteSSL(); !ok || msg != "SSL certificate deleted" {
			t.Errorf("Delete SSL with only %s there: %v %q; expected it deleted", left, ok, msg)
		}
		if fileExists(dir + "localhost/" + left) {
			t.Errorf("%s is still there", left)
		}
	}
	if ok, msg := deleteSSL(); ok || msg != "No certificate" {
		t.Errorf("Delete SSL without files: %v %q; expected \"No certificate\"", ok, msg)
	}
}

// R6 V-06: "Delete SSL" leaves the certificate in use, so that replacing a certificate leaves no gap, unless it is
// asked to stop using it too (x=1, which the panel asks about). The site is then left as a restart would leave it:
// with HTTPS on and no certificate, until another one reaches its folder.
func TestR6_V06_DeleteSSLAndTheCertificateInUse(t *testing.T) {
	dir := initForTest(t)
	site := dir + "localhost/"
	writeTestCertificate(t, site, time.Hour, "localhost")
	globalMutex.Lock()
	ok, msg := siteSSLSettingCheckers["S"](false, "1", "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("S: %s", msg)
	}
	first := certificateFor("localhost")
	if first == nil {
		t.Fatal("no certificate in use")
	}
	base := startServer(t)
	tok := login(t, base)
	deleteSSL := func(extra string) (int, string) {
		t.Helper()
		code, body, err := post(base, "/admin:inside:cfgC?s=localhost&d=&a=0&b=Admin"+extra, tok)
		if err != nil {
			t.Fatal(err)
		}
		return code, body
	}
	filesLeft := func() bool { return fileExists(site+certFileName) || fileExists(site+keyFileName) }
	kept := func() (inUse bool, httpsOn bool) {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		_, inUse = siteCertificates["localhost"]
		return inUse, httpsEnabled("localhost")
	}

	// A value of x that isn't one: nothing is deleted
	if code, body := deleteSSL("&x=yes"); code != 400 || !strings.Contains(body, "Invalid value for x") || !filesLeft() || certificateFor("localhost") != first {
		t.Errorf("x=yes: %d %q, files left %v; expected 400 and nothing deleted", code, body, filesLeft())
	}
	// Without x: the files go, and the certificate in use stays
	if code, body := deleteSSL(""); code != 200 || body != "SSL certificate deleted" || filesLeft() || certificateFor("localhost") != first {
		t.Errorf("without x: %d %q, files left %v, in use %v; expected the files deleted and the certificate in use", code, body, filesLeft(), certificateFor("localhost") == first)
	}
	if code, body := deleteSSL("&x=0"); code != 400 || body != "No certificate" || certificateFor("localhost") != first {
		t.Errorf("x=0 without files: %d %q; expected \"No certificate\" and the certificate in use", code, body)
	}
	// x=1 for the one that a deletion left in use
	logs := captureLog(t)
	if code, body := deleteSSL("&x=1"); code != 200 || body != "SSL certificate no longer in use" || certificateFor("localhost") != nil {
		t.Errorf("x=1 with a certificate in use and no files: %d %q, in use %v; expected it out of use", code, body, certificateFor("localhost") != nil)
	}
	if inUse, httpsOn := kept(); inUse || !httpsOn {
		t.Errorf("after x=1: in use %v, HTTPS on %v; expected no certificate, with the site's HTTPS still on", inUse, httpsOn)
	}
	if !strings.Contains(logs.String(), "no longer in use") {
		t.Errorf("the log doesn't say that the certificate is out of use:\n%s", logs.String())
	}
	if code, body := deleteSSL("&x=1"); code != 400 || body != "No certificate" {
		t.Errorf("x=1 with nothing to delete: %d %q; expected \"No certificate\"", code, body)
	}
	if res, body := requestTo(t, base, "GET", "/"); res.StatusCode != 200 || body != "hello" {
		t.Errorf("GET / by HTTP without the certificate: %d %q; expected the site", res.StatusCode, body)
	}
	// The next certificate that reaches the folder is put in use, and x=1 deletes it and takes it out of use at once
	next := loadTestCertificate(t, site, time.Hour, "localhost")
	loadPendingCertificates()
	if got := certificateFor("localhost"); !sameCertificate(got, next) {
		t.Fatal("the certificate that reached the folder afterwards isn't in use")
	}
	if code, body := deleteSSL("&x=1"); code != 200 || body != "SSL certificate deleted, and no longer in use" || filesLeft() || certificateFor("localhost") != nil {
		t.Errorf("x=1: %d %q, files left %v, in use %v; expected deleted and out of use", code, body, filesLeft(), certificateFor("localhost") != nil)
	}
	if inUse, httpsOn := kept(); inUse || !httpsOn {
		t.Errorf("after x=1: in use %v, HTTPS on %v; expected no certificate, with the site's HTTPS still on", inUse, httpsOn)
	}
	// With the site's HTTPS off there is none in use: only the files are deleted
	globalMutex.Lock()
	ok, msg = siteSSLSettingCheckers["S"](false, "0", "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("S off: %s", msg)
	}
	writeTestCertificate(t, site, time.Hour, "localhost")
	if code, body := deleteSSL("&x=1"); code != 200 || body != "SSL certificate deleted" || filesLeft() {
		t.Errorf("x=1 with HTTPS off: %d %q, files left %v; expected the files deleted", code, body, filesLeft())
	}
	// As a setting of turbo.config, or of a site found on disk, nothing is ever deleted
	writeTestCertificate(t, site, time.Hour, "localhost")
	globalMutex.Lock()
	siteSSLSettingCheckers["C"](true, "0", "localhost", "", "", "", "1")
	globalMutex.Unlock()
	if !fileExists(site+certFileName) || !fileExists(site+keyFileName) {
		t.Error("the setting read from a file deleted the certificate")
	}
}

// R6 V-07: a new certificate reaches the folder of a site that is in another volume than Certbot's, where a rename
// can't: its files are copied. The installation failed there, and every attempt issued another certificate.
func TestR6_V07_CertificateInstalledAcrossVolumes(t *testing.T) {
	scratch := t.TempDir() + "/"
	site := scratch + "site/"
	loadTestCertificate(t, site, time.Hour, "localhost")
	loadTestCertificate(t, scratch+"new/", time.Hour, "localhost")
	newChain, _ := os.ReadFile(scratch + "new/" + certFileName)
	newKey, _ := os.ReadFile(scratch + "new/" + keyFileName)
	previous := renameFile
	t.Cleanup(func() { renameFile = previous })
	renameFile = func(from, to string) error {
		if strings.HasPrefix(from, scratch+"new/") { // From Certbot's folder: another volume
			return errors.New("invalid cross-device link")
		}
		return previous(from, to)
	}
	if status := installCertificate(scratch+"new/"+certFileName, scratch+"new/"+keyFileName, site); status != true {
		t.Fatalf("installation across volumes: %v", status)
	}
	chainNow, _ := os.ReadFile(site + certFileName)
	keyNow, _ := os.ReadFile(site + keyFileName)
	if !bytes.Equal(chainNow, newChain) || !bytes.Equal(keyNow, newKey) {
		t.Error("the new pair isn't in the folder of the site")
	}
	for _, leftover := range []string{site + certFileName + ".new", site + keyFileName + ".new", scratch + "new/" + certFileName, scratch + "new/" + keyFileName} {
		if fileExists(leftover) {
			t.Errorf("%s left behind", leftover)
		}
	}
	// A file that can't be copied either is still an installation that fails
	loadTestCertificate(t, scratch+"new/", time.Hour, "localhost")
	os.Remove(scratch + "new/" + keyFileName)
	if status := installCertificate(scratch+"new/"+certFileName, scratch+"new/"+keyFileName, site); status == true {
		t.Error("installed without the key")
	}
	if now, _ := os.ReadFile(site + certFileName); !bytes.Equal(now, newChain) {
		t.Error("the failed installation changed the chain in the folder")
	}
}

// R6 M-06: opening the HTTPS address while it is already open, or being opened, does nothing. The second attempt
// found the address taken, logged it as an error and left a retry waiting.
func TestR6_M06_HTTPSAddressOpenedOnce(t *testing.T) {
	initForTest(t)
	previousAddr := httpsAddr
	httpsAddr = "127.0.0.1:" + freePort(t)
	server := newHTTPSServer(selfSignedTLS(t))
	t.Cleanup(func() {
		server.Close()
		eventually(2*time.Second, func() bool { return !httpsListening.Load() })
		httpsAddr = previousAddr
	})
	logs := captureLog(t)
	safeServerStart(server, server.TLSConfig)
	if !httpsListening.Load() {
		t.Fatalf("the HTTPS address wasn't opened:\n%s", logs.String())
	}
	safeServerStart(server, server.TLSConfig)
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() { safeServerStart(server, server.TLSConfig); done <- struct{}{} }()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	if strings.Contains(logs.String(), "Can't open the HTTPS address") || httpsRetrying.Load() {
		t.Errorf("opening it again logged an error or left a retry waiting (%v):\n%s", httpsRetrying.Load(), logs.String())
	}
}
