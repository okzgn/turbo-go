package server

// Review of 6046dbe (R6), V-08 and P-12: the panel's actions that change files (a site's folder, a certificate's files,
// the folders of the certificates) and the load of a certificate just issued don't touch the disk holding the global
// lock, so a slow or network disk doesn't stop every request while they run.

import (
	"crypto/tls"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// slowDiskWork makes each removal of a certificate file, each folder made, each certificate file read and each pair
// loaded take 600 ms, as on a slow network disk.
func slowDiskWork(t *testing.T) {
	t.Helper()
	remove, makeDir, read, load := siteFileRemove, siteDirMake, certificateFileRead, certificatePairLoad
	pause := func() { time.Sleep(600 * time.Millisecond) }
	siteFileRemove = func(path string) error { pause(); return remove(path) }
	siteDirMake = func(path string, mode os.FileMode) error { pause(); return makeDir(path, mode) }
	certificateFileRead = func(path string) ([]byte, error) { pause(); return read(path) }
	certificatePairLoad = func(chain, key string) (tls.Certificate, error) { pause(); return load(chain, key) }
	t.Cleanup(func() {
		siteFileRemove, siteDirMake, certificateFileRead, certificatePairLoad = remove, makeDir, read, load
	})
}

// slowDiskMargin is how long a request may take while a panel action works on a slow disk (600 ms per operation,
// slowDiskWork): one held by the global lock waits at least 400 ms, as it starts 200 ms into the action. At 150 ms,
// a request that nothing held went over it now and then on a busy machine (154 ms).
const slowDiskMargin = 300 * time.Millisecond

func dirThere(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// R6 V-08: adding a site or a subdomain, deleting a site's certificate and asking for one, with a slow disk.
func TestR6_V08_SiteActionsWithASlowDisk(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	useFakeCertbot(t, "fail")
	base := startServer(t)
	tok := login(t, base)
	slowDiskWork(t)
	for _, action := range []struct {
		path string
		code int
		done func() bool
	}{
		{"addSite?s=new.test", 200, func() bool { return dirThere(dir+"new.test/@") && siteExistsLocked("new.test", "") }},
		{"addSubdomain?s=localhost&d=sub", 200, func() bool { return dirThere(dir+"localhost/sub/@") && siteExistsLocked("localhost", "sub") }},
		{"cfgC?s=localhost&d=&a=0&b=Admin", 200, func() bool {
			return !fileExists(dir+"localhost/"+certFileName) && !fileExists(dir+"localhost/"+keyFileName)
		}},
		{"cfgC?s=localhost&d=&a=1&z=" + url.QueryEscape("a@b.co"), 202, func() bool { return dirThere(dir + certificatesDirName) }},
	} {
		var code int
		var body string
		elapsed := requestWhileLockWaits(t, base, func() { code, body, _ = post(base, "/admin:inside:"+action.path, tok) })
		if elapsed > slowDiskMargin {
			t.Errorf("%s with a slow disk: a request meanwhile took %v; expected less than %v", action.path, elapsed, slowDiskMargin)
		}
		if code != action.code || !action.done() {
			t.Errorf("%s: %d %q; expected %d and the change made", action.path, code, body, action.code)
		}
		waitIdle()
	}
}

// siteExistsLocked is siteExists with the read lock.
func siteExistsLocked(domain, subdomain string) bool {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return siteExists(domain, subdomain)
}

// R6 P-12: the panel's certificate, looked at (its expiry) and deleted, with a slow disk.
func TestR6_P12_PanelCertificateWithASlowDisk(t *testing.T) {
	dir, base, token, _ := panelCertSetup(t, "ok")
	if code, body := postHost(t, base, "panel.test", "/admin:inside:cfgPC?"+url.Values{"a": {"1"}, "z": {"admin@example.com"}}.Encode(), token); code != 202 {
		t.Fatalf("cfgPC a=1: %d %q", code, body)
	}
	waitIdle()
	if certificateFor("panel.test") == nil {
		t.Fatal("the panel's certificate wasn't issued")
	}
	slowDiskWork(t)
	for _, action := range []struct {
		path, answer string
	}{
		{"cfgPC?a=1", "Panel certificate active"},
		{"cfgPC?a=0&b=Admin", "Panel certificate deleted"},
	} {
		var code int
		var body string
		elapsed := requestWhileLockWaits(t, base, func() { code, body = postHost(t, base, "panel.test", "/admin:inside:"+action.path, token) })
		if elapsed > slowDiskMargin {
			t.Errorf("%s with a slow disk: a request meanwhile took %v; expected less than %v", action.path, elapsed, slowDiskMargin)
		}
		if code != 200 || body != action.answer {
			t.Errorf("%s: %d %q; expected %q", action.path, code, body, action.answer)
		}
	}
	if fileExists(dir+panelCertDirName+"/"+certFileName) || certificateFor("panel.test") != nil {
		t.Error("the panel's certificate is still there, or in use")
	}
}

// R6 V-08: a certificate just issued is read before taking the global lock that puts it in use.
func TestR6_V08_IssuedCertificateLoadedWithoutTheGlobalLock(t *testing.T) {
	dir := initForTest(t)
	useFakeCertbot(t, "ok")
	base := startServer(t)
	withGlobalLock(func() { siteSSLConfig["localhost"].email, siteSSLConfig["localhost"].https = "a@b.co", true })
	entered := make(chan struct{})
	var once sync.Once
	load := certificatePairLoad
	certificatePairLoad = func(chain, key string) (tls.Certificate, error) { // The first load: the certificate issued
		once.Do(func() { close(entered); time.Sleep(time.Second) })
		return load(chain, key)
	}
	t.Cleanup(func() { certificatePairLoad = load })
	withGlobalLock(func() { obtainCertificate("localhost", dir+certificatesDirName+"/localhost", dir+"localhost/") })
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the certificate issued wasn't loaded")
	}
	elapsed := requestWhileLockWaits(t, base, func() {})
	if elapsed > 300*time.Millisecond {
		t.Errorf("a request while the certificate issued is loaded took %v; expected less than 300 ms", elapsed)
	}
	waitIdle()
	if certificateFor("localhost") == nil {
		t.Error("the certificate issued isn't in use")
	}
}

// R6 V-08: a deletion whose files can't be removed changes nothing: the certificate stays in use, and the state of the
// site's or the panel's certificate is as it was.
func TestR6_V08_DeletionThatFailsChangesNothing(t *testing.T) {
	dir, base, token, _ := panelCertSetup(t, "ok")
	if code, body := postHost(t, base, "panel.test", "/admin:inside:cfgPC?"+url.Values{"a": {"1"}, "z": {"admin@example.com"}}.Encode(), token); code != 202 {
		t.Fatalf("cfgPC a=1: %d %q", code, body)
	}
	waitIdle()
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	globalMutex.Lock()
	ok, msg := siteSSLSettingCheckers["S"](false, "1", "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("S: %s", msg)
	}
	site, panel := certificateFor("localhost"), certificateFor("panel.test")
	if site == nil || panel == nil {
		t.Fatal("no certificate in use")
	}
	remove := siteFileRemove
	siteFileRemove = func(path string) error {
		if strings.HasSuffix(path, certFileName) {
			return errors.New("permission denied")
		}
		return remove(path)
	}
	t.Cleanup(func() { siteFileRemove = remove })
	if code, body := postHost(t, base, "panel.test", "/admin:inside:cfgC?s=localhost&d=&a=0&x=1&b=Admin", token); code != 400 || body != "Error deleting the SSL files" {
		t.Errorf("cfgC a=0 whose file can't be removed: %d %q", code, body)
	}
	if certificateFor("localhost") != site || !fileExists(dir+"localhost/"+certFileName) {
		t.Error("the failed deletion took the site's certificate out of use, or removed its file")
	}
	if code, body := postHost(t, base, "panel.test", "/admin:inside:cfgPC?a=0&b=Admin", token); code != 400 || body != "Error deleting the panel certificate files" {
		t.Errorf("cfgPC a=0 whose file can't be removed: %d %q", code, body)
	}
	if certificateFor("panel.test") != panel || !fileExists(dir+panelCertDirName+"/"+certFileName) {
		t.Error("the failed deletion took the panel's certificate out of use, or removed its file")
	}
	if code, body := postHost(t, base, "panel.test", "/admin:inside:cfgPC?a=1", token); code != 200 || body != "Panel certificate active" {
		t.Errorf("cfgPC a=1 after the failed deletion: %d %q", code, body)
	}
}

// R6 R-0: adding a site from the panel keeps the subdomains that its domain already has without their root (a folder
// whose root was refused while another site had its key, and whose subdomain was activated). The check that addSite
// makes before the folder is made undid the site with deleteSiteLocked, which for a root deletes the whole domain:
// those subdomains lost their preprocessors, headers and aliases, and their scripts would be served as text.
func TestR6_V08_AddSiteKeepsSubdomainsWithoutRoot(t *testing.T) {
	dir := initForTest(t)
	rootless := func(domain string) {
		t.Helper()
		if err := os.MkdirAll(dir+domain+"/x/@", 0755); err != nil {
			t.Fatal(err)
		}
		globalMutex.Lock()
		defer globalMutex.Unlock()
		constructSiteWithoutIndex(domain, "x") // As a reload leaves it: the root refused, its subdomain active
		for kind, entry := range map[string]map[string]interface{}{
			"?": {"cgi": toolPath("cgiecho")}, ".": {"X-Kept": "1"}, "&": {"alias-of-" + domain: ""},
		} {
			if ok, msg := subdomainContentCheckers[kind](true, entry, false, domain, "x"); !ok {
				t.Fatalf("%s of x.%s: %q", kind, domain, msg)
			}
		}
	}
	kept := func(domain string) bool {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		key := "x." + domain
		return siteExists(domain, "x") && preprocessors[key]["cgi"] != "" && customHeaders[key]["X-Kept"] == "1" && domainAliases["alias-of-"+domain] == key
	}
	rootless("c.a.test")
	if ok, msg := addSiteFromPanel("c.a.test", ""); !ok {
		t.Fatalf("addSite c.a.test: %q", msg)
	}
	if !siteExistsLocked("c.a.test", "") || !kept("c.a.test") {
		t.Error("adding the root of a domain that had a subdomain lost the subdomain or its settings")
	}
	// The same when the site is refused once built: it would serve the panel's host
	rootless("panel.b.test")
	list, problem := parsePanelAccess("panel.b.test")
	if problem != "" {
		t.Fatal(problem)
	}
	previous := panelAccess.Load()
	panelAccess.Store(list)
	t.Cleanup(func() { panelAccess.Store(previous) })
	if ok, msg := addSiteFromPanel("panel.b.test", ""); ok || !strings.Contains(msg, "panel host") {
		t.Fatalf("addSite of the panel's host: %v %q; expected it refused", ok, msg)
	}
	if siteExistsLocked("panel.b.test", "") || !kept("panel.b.test") {
		t.Error("a site refused for the panel's host stayed, or took the subdomain of its domain with it")
	}
	// And a site whose domain had nothing leaves nothing when it is refused
	list, _ = parsePanelAccess("only.c.test")
	panelAccess.Store(list)
	if ok, _ := addSiteFromPanel("only.c.test", ""); ok {
		t.Fatal("addSite of the panel's host accepted")
	}
	globalMutex.RLock()
	_, left := sitesMap["only.c.test"]
	_, settings := customHeaders["only.c.test"]
	globalMutex.RUnlock()
	if left || settings {
		t.Error("a refused site left its domain or its settings behind")
	}
}

// R6 R-1: asking for the panel's certificate with its folders already there makes none, and looks at none with the
// global lock held. They were made before the lock only when they were missing; there, MkdirAll looked at them again
// under it.
func TestR6_P12_PanelCertificateFoldersAlreadyThere(t *testing.T) {
	dir, base, token, _ := panelCertSetup(t, "ok")
	for _, folder := range []string{certificatesDirName, panelCertDirName + "/" + acmeWebrootDirName} {
		if err := os.MkdirAll(dir+folder, 0700); err != nil {
			t.Fatal(err)
		}
	}
	makeDir := siteDirMake
	made := 0
	siteDirMake = func(path string, mode os.FileMode) error { // Only this: what is read before the lock is fast here
		made++
		time.Sleep(600 * time.Millisecond)
		return makeDir(path, mode)
	}
	t.Cleanup(func() { siteDirMake = makeDir })
	var code int
	var body string
	elapsed := requestWhileLockWaits(t, base, func() {
		code, body = postHost(t, base, "panel.test", "/admin:inside:cfgPC?"+url.Values{"a": {"1"}, "z": {"admin@example.com"}}.Encode(), token)
	})
	if elapsed > slowDiskMargin || made != 0 {
		t.Errorf("cfgPC a=1 with its folders there: a request meanwhile took %v, and %d folders were made; expected less than %v and none", elapsed, made, slowDiskMargin)
	}
	if code != 202 {
		t.Errorf("cfgPC a=1: %d %q; expected 202", code, body)
	}
	waitIdle()
	if certificateFor("panel.test") == nil {
		t.Error("the panel's certificate wasn't issued")
	}
}

// R6 R-2: "Create SSL" makes the folder of the certificates only when Certbot is going to run. It was made for every
// request with an e-mail, also for a site that already had its certificate.
func TestR6_V08_CertificatesFolderOnlyForCertbot(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	useFakeCertbot(t, "fail")
	base := startServer(t)
	tok := login(t, base)
	ask := "/admin:inside:cfgC?s=localhost&d=&a=1&z=" + url.QueryEscape("a@b.co")
	if code, body, _ := post(base, ask, tok); code != 200 || body != "SSL certificate active" {
		t.Fatalf("Create SSL with a certificate in its time: %d %q", code, body)
	}
	if dirThere(dir + certificatesDirName) {
		t.Error("the folder of the certificates was made for a site that already has its certificate")
	}
	os.Remove(dir + "localhost/" + certFileName)
	os.Remove(dir + "localhost/" + keyFileName)
	if code, body, _ := post(base, ask, tok); code != 202 {
		t.Fatalf("Create SSL without a certificate: %d %q; expected 202", code, body)
	}
	if !dirThere(dir + certificatesDirName) {
		t.Error("the folder of the certificates wasn't made for Certbot")
	}
	waitIdle()
	// The error of that attempt waits to be answered: it is, and nothing is made for it
	os.RemoveAll(dir + certificatesDirName)
	if code, body, _ := post(base, ask, tok); code != 400 || strings.Contains(body, "WAIT") {
		t.Errorf("the error of the last attempt: %d %q; expected it answered with 400", code, body)
	}
	if dirThere(dir + certificatesDirName) {
		t.Error("the folder of the certificates was made to answer the error of the last attempt")
	}
	waitIdle()
}
