package main

// V4, V5 and V12 (production review of 775a809): what Turbo keeps of a site without its folder.
// - V4: creating such a site, or subdomain, from the panel is refused. With the session alone, it dropped what was
//   kept of it and of its subdomains, and their folders came back with the defaults, their scripts served as text.
// - V5: deleting it from "Sites without their folder" forgets what is kept of that one entry and deletes no folder:
//   it ran RemoveAll on its folder, which may be there (only its @, or that of its site, missing), with the content of
//   its subdomains, its certificates and anything outside @.
// - V12: delSite waits for a reload in progress, which could bring the site back with the defaults afterwards.

import (
	"io/fs"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// keptSitesSetup gives localhost its settings (configureLocalhost) and a subdomain www with a preprocessor for "cgi"
// and a script, and then takes away the @ of localhost (a deploy in progress): localhost and www are kept without
// their folder, with www's own folder intact.
func keptSitesSetup(t *testing.T) (dir, base, tok string) {
	t.Helper()
	dir = initForTest(t)
	base = startServer(t)
	tok = login(t, base)
	configureLocalhost(t, dir)
	if err := os.MkdirAll(dir+"localhost/www/@", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"localhost/www/@/script.cgi", []byte("SOURCE OF THE WWW SCRIPT"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"localhost/outside-public.txt", []byte("outside @"), 0644); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "www")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	globalMutex.RLock()
	_, rootKept := dormantSites["localhost"][""]
	_, wwwKept := dormantSites["localhost"]["www"]
	globalMutex.RUnlock()
	if !rootKept || !wwwKept {
		t.Fatalf("setup: kept localhost %v, www %v", rootKept, wwwKept)
	}
	return dir, base, tok
}

// wwwScript is what www.localhost/script.cgi gives.
func wwwScript(t *testing.T, base string) string {
	t.Helper()
	_, body, err := rawGet(base, "www.localhost", "/script.cgi")
	if err != nil {
		return err.Error()
	}
	return body
}

func TestRP2_V4_CreatingKeptSiteRefused(t *testing.T) {
	dir, base, tok := keptSitesSetup(t)
	code, body, err := post(base, "/admin:inside:addSite?s=localhost", tok)
	if err != nil || code != 400 || !strings.Contains(body, "is kept, with its settings") {
		t.Errorf("addSite of localhost, kept without its folder: %d %q %v; expected 400", code, body, err)
	}
	globalMutex.RLock()
	_, rootKept := dormantSites["localhost"][""]
	_, wwwKept := dormantSites["localhost"]["www"]
	globalMutex.RUnlock()
	if !rootKept || !wwwKept {
		t.Errorf("after addSite: kept localhost %v, www %v; expected both kept", rootKept, wwwKept)
	}
	// The deploy ends: both come back with their settings.
	if err := os.Rename(dir+"localhost/@.away", dir+"localhost/@"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	checkLocalhostKept(t, base, "localhost back")
	if body := wwwScript(t, base); strings.Contains(body, "SOURCE") {
		t.Errorf("www.localhost/script.cgi after the deploy: %.60q; expected the output of its preprocessor", body)
	}
}

func TestRP2_V4_CreatingKeptSubdomainRefused(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if err := os.MkdirAll(dir+"localhost/www/@", 0755); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "www")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	if err := os.Rename(dir+"localhost/www/@", dir+"localhost/www/@.away"); err != nil { // www's deploy in progress
		t.Fatal(err)
	}
	updateSettings(true)
	code, body, err := post(base, "/admin:inside:addSubdomain?s=localhost&d=www", tok)
	if err != nil || code != 400 || !strings.Contains(body, "is kept, with its settings") {
		t.Errorf("addSubdomain of www, kept without its folder: %d %q %v; expected 400", code, body, err)
	}
	// The deploy ends: www comes back with its preprocessor.
	os.RemoveAll(dir + "localhost/www/@")
	if err := os.Rename(dir+"localhost/www/@.away", dir+"localhost/www/@"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"localhost/www/@/script.cgi", []byte("SOURCE OF THE WWW SCRIPT"), 0644); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if body := wwwScript(t, base); strings.Contains(body, "SOURCE") {
		t.Errorf("www.localhost/script.cgi after the deploy: %.60q; expected the output of its preprocessor", body)
	}
}

func TestRP2_V5_ForgettingKeptSiteDeletesNoFolder(t *testing.T) {
	dir, base, tok := keptSitesSetup(t)
	listed := func() (root, www bool) {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		_, root = dormantSites["localhost"][""]
		_, www = dormantSites["localhost"]["www"]
		return root, www
	}
	if code, _, _ := post(base, "/admin:inside:delSite?s=localhost&d=&b=wrong-password", tok); code == 200 {
		t.Error("delSite without the current password answered 200")
	}
	// While their folders are there (only the @ of localhost is missing), the settings stay: forgotten, the folders
	// would come back as new sites with the defaults, their scripts served as text.
	for _, d := range []string{"www", ""} {
		code, body, err := post(base, "/admin:inside:delSite?s=localhost&d="+d+"&b=Admin", tok)
		if err != nil || code != 400 || !strings.Contains(body, "still has its folder") {
			t.Errorf("forgetting %q while its folder is there: %d %q %v; expected 400", d, code, body, err)
		}
	}
	if root, www := listed(); !root || !www {
		t.Fatalf("after the refusals: kept localhost %v, www %v; expected both", root, www)
	}
	// The folder of localhost goes (moved out of the sites directory): forgetting localhost forgets www too, whose
	// folder went with it, and deletes nothing.
	away := t.TempDir() + "/localhost"
	if err := os.Rename(dir+"localhost", away); err != nil {
		t.Fatal(err)
	}
	code, body, err := post(base, "/admin:inside:delSite?s=localhost&d=&b=Admin", tok)
	if err != nil || code != 200 || !strings.Contains(body, "no folder is deleted") {
		t.Fatalf("forgetting localhost without its folder: %d %q %v", code, body, err)
	}
	if root, www := listed(); root || www {
		t.Errorf("after forgetting localhost: kept localhost %v, www %v; expected none", root, www)
	}
	for _, name := range []string{"/outside-public.txt", "/@.away/script.cgi", "/www/@/script.cgi"} {
		if !fileExists(away + name) {
			t.Errorf("forgetting localhost deleted %s", name)
		}
	}
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	if _, saved := savedConfig(t, dir)["localhost"]; saved {
		t.Error("localhost, forgotten from the panel, is still in turbo.config")
	}
}

// A subdomain whose own folder is gone is forgotten alone: its site stays as it is.
func TestRP2_V5_ForgettingKeptSubdomain(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	configureLocalhost(t, dir)
	if err := os.MkdirAll(dir+"localhost/www/@", 0755); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if err := os.RemoveAll(dir + "localhost/www"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	code, body, err := post(base, "/admin:inside:delSite?s=localhost&d=www&b=Admin", tok)
	if err != nil || code != 200 {
		t.Fatalf("forgetting www without its folder: %d %q %v", code, body, err)
	}
	globalMutex.RLock()
	_, wwwKept := dormantSites["localhost"]["www"]
	globalMutex.RUnlock()
	if wwwKept {
		t.Error("www is still kept")
	}
	checkLocalhostKept(t, base, "after forgetting its subdomain")
}

// A site kept without its folder isn't forgotten while its folder can't be looked at (permissions, I/O): it may be
// there. Its settings stay until it can.
func TestRP2_V5_ForgettingNeedsAFolderThatCanBeLookedAt(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	configureLocalhost(t, dir)
	if err := os.Rename(dir+"localhost", t.TempDir()+"/localhost"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true) // Kept without its folder
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if strings.Contains(name, "localhost") {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
	code, body, err := post(base, "/admin:inside:delSite?s=localhost&d=&b=Admin", tok)
	if err != nil || code != 400 || !strings.Contains(body, "can't be looked at") {
		t.Errorf("forgetting localhost while its folder can't be looked at: %d %q %v; expected 400", code, body, err)
	}
	globalMutex.RLock()
	_, kept := dormantSites["localhost"][""]
	globalMutex.RUnlock()
	if !kept {
		t.Error("the settings of localhost were forgotten")
	}
}

// V12: a reload that has looked at the disk, and is about to activate the sites it found, is waited for by delSite:
// otherwise it brought the site back, with the defaults, after delSite had deleted it.
func TestRP2_V12_DelSiteWaitsForReload(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if err := os.MkdirAll(dir+"other.test/@", 0755); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	scanned, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	beforeSitesScan = func() {
		if first.CompareAndSwap(false, true) {
			close(scanned)
			<-release
		}
	}
	t.Cleanup(func() { beforeSitesScan = func() {} })
	reloaded := make(chan struct{})
	go func() { updateSettings(true); close(reloaded) }()
	<-scanned // The reload has seen other.test on the disk
	answered := make(chan int)
	go func() {
		code, _, _ := post(base, "/admin:inside:delSite?s=other.test&d=&b=Admin", tok)
		answered <- code
	}()
	select {
	case code := <-answered:
		close(release)
		<-reloaded
		t.Fatalf("delSite answered %d during the reload; expected it to wait", code)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	<-reloaded
	if code := <-answered; code != 200 {
		t.Fatalf("delSite: %d", code)
	}
	updateSettings(true)
	globalMutex.RLock()
	_, active := sitesMap["other.test"]
	_, kept := dormantSites["other.test"]
	globalMutex.RUnlock()
	if active || kept || fileExists(dir+"other.test") {
		t.Errorf("after delSite during a reload: active %v, kept %v, folder there %v; expected the site gone", active, kept, fileExists(dir+"other.test"))
	}
}

// V12, after the independent review: the folder of a deleted site is put aside while the reloads are held, and
// removed once they aren't: deleting a large site held every reload, and Turbo's stop, for as long as it took.
func TestRP2_V12_FolderRemovedWithoutHoldingReloads(t *testing.T) {
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"other.test/@", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"other.test/@/index.html", []byte("other"), 0644); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	deleted, message, moved := deleteSiteFromPanel("other.test", "")
	if !deleted || moved == "" {
		t.Fatalf("deleteSiteFromPanel: %v %q, folder put aside in %q", deleted, message, moved)
	}
	if !settingsUpdateMutex.TryLock() {
		t.Fatal("the reloads are still held while the folder is removed")
	}
	settingsUpdateMutex.Unlock()
	if fileExists(dir+"other.test") || !fileExists(moved+"/@/index.html") {
		t.Errorf("the folder of other.test: still there %v, put aside %v", fileExists(dir+"other.test"), fileExists(moved+"/@/index.html"))
	}
	updateSettings(true) // A look at the disk doesn't take the folder put aside for a site
	globalMutex.RLock()
	for name := range sitesMap {
		if strings.Contains(name, "turbo-deleted") {
			t.Errorf("the folder put aside became the site %s", name)
		}
	}
	globalMutex.RUnlock()
	if err := os.RemoveAll(moved); err != nil {
		t.Fatal(err)
	}
}
