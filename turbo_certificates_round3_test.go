package main

// R3-05, R5-07, R5-05, R2-04, R2-03 and R5-08 (production reviews of 2026-11-04): the certificates, and the
// message of an invalid turbo.config.
// - R3-05: the certificate of each name went by the alphabetical order of the sites: an expired one of a site that
//   also covered another site's name was served there instead of that site's own, valid one.
// - R5-07: a site's certificate was read only when turbo.config was applied: a renewal outside Turbo wasn't seen
//   until it restarted.
// - R5-05: a new certificate was put in place with two renames, and when the second failed the folder kept the new
//   chain with the old key.
// - R2-04: an issuance whose Certbot ended well, but left its output open (a hook), counted as failed.
// - R2-03: each site's Certbot folder made an ACME account of its own.
// - R5-08: the message of an invalid turbo.config of one long line took hundreds of MB, and placed the error of a
//   key at the first key of that name in the file.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// loadTestCertificate writes a certificate for names in folder (writeTestCertificate) and loads it.
func loadTestCertificate(t *testing.T, folder string, validFor time.Duration, names ...string) *tls.Certificate {
	t.Helper()
	if err := os.MkdirAll(folder, 0755); err != nil {
		t.Fatal(err)
	}
	writeTestCertificate(t, folder, validFor, names...)
	cert, err := tls.LoadX509KeyPair(folder+certFileName, folder+keyFileName)
	if err != nil {
		t.Fatal(err)
	}
	return &cert
}

// R3-05: the panel's names first; then each site's own valid certificate for the site's name; then the other names
// of the valid ones; then those still free of the expired ones. When one expires, the names are published again.
func TestRP3_R305_CertificatePriority(t *testing.T) {
	initForTest(t)
	scratch := t.TempDir() + "/"
	expired := loadTestCertificate(t, scratch+"a/", -time.Minute, "example.test", "shop.example.test", "old.example.test")
	shop := loadTestCertificate(t, scratch+"b/", time.Hour, "shop.example.test")
	other := loadTestCertificate(t, scratch+"c/", time.Hour, "other.test")
	later := loadTestCertificate(t, scratch+"f/", time.Hour, "zz.test", "old.example.test") // Valid, after example.test
	logs := captureLog(t)
	withGlobalLock(func() {
		setSiteCertificate("example.test", expired)
		setSiteCertificate("shop.example.test", shop)
		setSiteCertificate("www.other.test", other) // A certificate that doesn't cover its site's name
		setSiteCertificate("zz.test", later)
	})
	for name, want := range map[string]*tls.Certificate{"shop.example.test": shop, "example.test": expired, "old.example.test": later, "other.test": other} {
		if got := certificateFor(name); got != want {
			t.Errorf("%s: %v; expected %v", name, certificateNames(got), certificateNames(want))
		}
	}
	if !strings.Contains(logs.String(), "doesn't cover its name") || !strings.Contains(logs.String(), "www.other.test") {
		t.Errorf("no warning about a certificate that doesn't cover its site:\n%s", logs.String())
	}

	// A site's own certificate that expires gives its name to another valid one that covers it.
	brief := loadTestCertificate(t, scratch+"d/", 2*time.Second, "b.test")
	wide := loadTestCertificate(t, scratch+"e/", time.Hour, "a.test", "b.test")
	withGlobalLock(func() {
		setSiteCertificate("b.test", brief)
		setSiteCertificate("a.test", wide)
	})
	if got := certificateFor("b.test"); got != brief {
		t.Fatalf("b.test while its own certificate is valid: %v", certificateNames(got))
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && certificateFor("b.test") != wide {
		time.Sleep(100 * time.Millisecond)
	}
	if certificateFor("b.test") != wide {
		t.Error("b.test after its own certificate expired: still the expired one; expected a.test's, valid")
	}
}

// R5-07: a site's certificate files that change on disk are read again; a pair that can't be loaded (a new chain
// whose key hasn't come yet) leaves the one in use.
func TestRP3_R507_SiteCertificateReadAgain(t *testing.T) {
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
	refreshSiteCertificates() // The first look: the same files
	if certificateFor("localhost") != first {
		t.Fatal("the first look changed the certificate in use")
	}
	scratch := t.TempDir() + "/"
	renewed := loadTestCertificate(t, scratch, time.Hour, "localhost")
	copyFile := func(name string) {
		data, err := os.ReadFile(scratch + name)
		if err == nil {
			err = os.WriteFile(dir+"localhost/"+name, data, 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	copyFile(certFileName) // The new chain, with the old key
	logs := captureLog(t)
	refreshSiteCertificates()
	if certificateFor("localhost") != first {
		t.Error("a new chain with the old key replaced the certificate in use")
	}
	if !strings.Contains(logs.String(), "can't be loaded") {
		t.Errorf("no warning about the files that can't be loaded:\n%s", logs.String())
	}
	copyFile(keyFileName)
	refreshSiteCertificates()
	if got := certificateFor("localhost"); !sameCertificate(got, renewed) {
		t.Error("the renewed certificate isn't in use after its key came")
	}
}

// R5-05: a new certificate goes in place key first and chain after it; if the chain can't follow, the previous key
// comes back, and without a previous certificate none is left.
func TestRP3_R505_CertificateInstalledAsAPair(t *testing.T) {
	scratch := t.TempDir() + "/"
	site := scratch + "site/"
	loadTestCertificate(t, site, time.Hour, "localhost")
	oldChain, _ := os.ReadFile(site + certFileName)
	oldKey, _ := os.ReadFile(site + keyFileName)
	archive := func(name string) (string, string) {
		loadTestCertificate(t, scratch+name+"/", time.Hour, "localhost")
		return scratch + name + "/" + certFileName, scratch + name + "/" + keyFileName
	}
	previous := renameFile
	t.Cleanup(func() { renameFile = previous })
	renameFile = func(from, to string) error {
		if strings.HasSuffix(to, "/"+certFileName) { // The chain, last: it can't be put in place
			return os.ErrPermission
		}
		return previous(from, to)
	}
	chain, key := archive("new1")
	if status := installCertificate(chain, key, site); status == true {
		t.Fatal("installed although the chain couldn't be put in place")
	}
	chainNow, _ := os.ReadFile(site + certFileName)
	keyNow, _ := os.ReadFile(site + keyFileName)
	if !bytes.Equal(chainNow, oldChain) || !bytes.Equal(keyNow, oldKey) {
		t.Error("a failed installation left the folder with other files than the previous pair")
	}
	if _, err := tls.LoadX509KeyPair(site+certFileName, site+keyFileName); err != nil {
		t.Errorf("the folder's pair after a failed installation: %v", err)
	}
	for _, name := range []string{certFileName + ".new", keyFileName + ".new"} {
		if fileExists(site + name) {
			t.Errorf("%s left behind", name)
		}
	}
	empty := scratch + "empty/"
	os.MkdirAll(empty, 0755)
	chain, key = archive("new2")
	if status := installCertificate(chain, key, empty); status == true || fileExists(empty+keyFileName) || fileExists(empty+certFileName) {
		t.Errorf("a failed first installation: %v, and files left in the folder", status)
	}
	renameFile = previous
	chain, key = archive("new3")
	newChain, _ := os.ReadFile(chain)
	if status := installCertificate(chain, key, site); status != true {
		t.Fatalf("installation: %v", status)
	}
	if chainNow, _ := os.ReadFile(site + certFileName); !bytes.Equal(chainNow, newChain) {
		t.Error("the new chain isn't in place")
	}
	if _, err := tls.LoadX509KeyPair(site+certFileName, site+keyFileName); err != nil {
		t.Errorf("the installed pair: %v", err)
	}
}

// R2-04: Certbot ended well, and a child of it kept its output open past certbotWaitDelay: the certificate is used.
func TestRP3_R204_CertbotOutputHeldOpen(t *testing.T) {
	useFakeCertbot(t, "ok")
	t.Setenv("FAKE_CERTBOT_HOLD", "1500")
	previous := certbotWaitDelay
	certbotWaitDelay = 300 * time.Millisecond
	t.Cleanup(func() { certbotWaitDelay = previous })
	dir := initForTest(t)
	job := certbotJob{names: []string{"localhost"}, email: "admin@localhost.test", webroot: dir + "localhost/@", certDir: dir + "turbo.certificates/localhost", destDir: dir + "localhost/"}
	if status := runCertbot(context.Background(), job); status != true {
		t.Fatalf("an issuance whose Certbot ended well: %v", status)
	}
	if _, err := tls.LoadX509KeyPair(dir+"localhost/"+certFileName, dir+"localhost/"+keyFileName); err != nil {
		t.Errorf("the certificate issued: %v", err)
	}
	time.Sleep(1500 * time.Millisecond) // The child ends before the folders are removed
}

// R2-03: the sites' Certbot folders share the ACME account of their e-mail: three sites, one new account; another
// e-mail, its own.
func TestRP3_R203_OneACMEAccountPerEmail(t *testing.T) {
	useFakeCertbot(t, "ok")
	accountsLog := filepath.ToSlash(filepath.Join(t.TempDir(), "accounts.log"))
	t.Setenv("FAKE_CERTBOT_ACCOUNTS", accountsLog)
	dir := initForTest(t)
	issue := func(site, email string) {
		os.MkdirAll(dir+site+"/@", 0755)
		job := certbotJob{names: []string{site}, email: email, webroot: dir + site + "/@", certDir: dir + "turbo.certificates/" + site, destDir: dir + site + "/"}
		if status := runCertbot(context.Background(), job); status != true {
			t.Fatalf("%s: %v", site, status)
		}
	}
	for _, site := range []string{"a.test", "b.test", "c.test"} {
		issue(site, "admin@example.test")
	}
	issue("d.test", "other@example.test")
	data, _ := os.ReadFile(accountsLog)
	lines := strings.Fields(strings.ReplaceAll(string(data), "\n", " "))
	if len(lines) != 8 || lines[0] != "new" || lines[2] != "existing" || lines[4] != "existing" || lines[6] != "new" ||
		lines[1] != lines[3] || lines[1] != lines[5] || lines[7] == lines[1] {
		t.Errorf("the accounts Certbot used:\n%s\nexpected a new one, the same twice more, and a new one for the other e-mail", data)
	}
	if runtime.GOOS != "windows" {
		shared := acmeAccountsDir("admin@example.test")
		if info, err := os.Stat(shared + "acme-v02.api.letsencrypt.org"); err != nil || info.Mode().Perm() != 0700 {
			t.Errorf("the shared account's folder: %v %v; expected 0700", info, err)
		}
	}
}

// R5-08: describing the error of a turbo.config saved in one line, of 5 MB with a typo, made a string per character
// of the line: hundreds of MB. Only a window around the error is rendered.
func TestRP3_R508_ErrorOfABigOneLineConfig(t *testing.T) {
	var builder strings.Builder
	builder.WriteString(`{"^":{"v":"2"},"@":{`)
	for i := 0; builder.Len() < 5<<20; i++ {
		builder.WriteString(`"10.0.` + strconv.Itoa(i/250) + `.` + strconv.Itoa(i%250) + `":1,`)
		if i == 120000 {
			builder.WriteString(`"typo" 1,`) // The error: a missing ':'
		}
	}
	builder.WriteString(`"10.255.255.255":1}}`)
	data := []byte(builder.String())
	var parsed map[string]interface{}
	err := json.Unmarshal(data, &parsed)
	if err == nil {
		t.Fatal("the file isn't broken")
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	message := describeConfigError("turbo.config", data, err)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
		t.Errorf("describing the error allocated %d MB; expected less than 32", allocated>>20)
	}
	column := bytes.Index(data, []byte(`"typo" 1`)) + len(`"typo" `) + 1
	if !strings.Contains(message, "Line 1, column "+strconv.Itoa(column)+":") {
		t.Errorf("the message doesn't place the error at line 1, column %d:\n%s", column, message)
	}
	lines := strings.Split(message, "\n")
	for i, line := range lines {
		if strings.Contains(line, `"typo" 1`) {
			if !strings.HasPrefix(line, "    ...") || !strings.HasSuffix(line, "...") || len(line) > 140 {
				t.Errorf("the fragment: %q; expected about 120 characters, cut on both sides", line)
			}
			if i+1 >= len(lines) || len(lines[i+1]) < 5 || line[len(lines[i+1])-1:len(lines[i+1])] != "1" {
				t.Errorf("the mark %q isn't under the error of %q", lines[i+1], line)
			}
		}
	}
}

// R5-08: the error of a setting or of a site's list is placed at its key, not at the first key of that name in the
// file (a header "PA" of a site, for the "PA" of ".").
func TestRP3_R508_ErrorAtItsKey(t *testing.T) {
	for _, c := range []struct{ config, at string }{
		{`{"^":{"v":"2"},"a.test":{"":{".":{"PA":"x"}}},".":{"PA":5}}`, `"PA":5`},
		{`{"^":{"v":"2"},"a.test":{"":{".":{"?":"1"},"?":5}}}`, `"?":5`},
	} {
		dir := initForTest(t)
		if err := os.WriteFile(dir+"turbo.config", []byte(c.config), 0600); err != nil {
			t.Fatal(err)
		}
		withGlobalLock(func() { configFileStamp = configStamp{} })
		err := updateSettings(false)
		if err == nil {
			t.Fatalf("%s: accepted", c.config)
		}
		column := strings.Index(c.config, c.at) + 1
		if !strings.Contains(err.Error(), "Line 1, column "+strconv.Itoa(column)+":") {
			t.Errorf("%s: the error isn't placed at column %d:\n%s", c.config, column, err.Error())
		}
		if first, second := err.Error(), err.Error(); first != second {
			t.Error("the message changes from one call to the next")
		}
	}
}
