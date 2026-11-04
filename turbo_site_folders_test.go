package main

// Review of 57cbb3c, A1: a site whose folder (or its @) is gone, for a moment or for longer, keeps its settings.
// It is deactivated, and when the folder comes back it is activated with them, not with the defaults, with which
// its scripts were served as text. Only "doesn't exist" counts: another error of the disk leaves the site as it
// is, and a sites directory that can't be read deactivates nothing. Saving meanwhile keeps the site in
// turbo.config, and a site of turbo.config whose folder isn't there when the file is read gets its settings when
// the folder appears. A site deleted from the panel, also one without its folder, doesn't come back.

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// configureLocalhost gives localhost a preprocessor for "cgi" and a header, the settings that must come back, and
// a script whose source must never be served.
func configureLocalhost(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(dir+"localhost/@/script.cgi", []byte("SOURCE OF THE SCRIPT"), 0644); err != nil {
		t.Fatal(err)
	}
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", ""); !ok {
		t.Fatal(msg)
	}
	if ok, msg := subdomainContentCheckers["."](true, map[string]interface{}{"X-Kept": "1"}, false, "localhost", ""); !ok {
		t.Fatal(msg)
	}
}

// localhostState is whether localhost is active, its preprocessor for "cgi" and its header X-Kept.
func localhostState() (active bool, preprocessor string, header string) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return siteExists("localhost", ""), preprocessors["localhost"]["cgi"], customHeaders["localhost"]["X-Kept"]
}

// checkLocalhostKept checks that localhost is active with its settings and that its script runs.
func checkLocalhostKept(t *testing.T, base string, when string) {
	t.Helper()
	if active, preprocessor, header := localhostState(); !active || preprocessor == "" || header != "1" {
		t.Errorf("%s: active %v, preprocessor %q, header %q; expected the site with its settings", when, active, preprocessor, header)
	}
	code, body, err := get(base, "/script.cgi", nil)
	if err != nil || code != 200 || strings.Contains(body, "SOURCE OF THE SCRIPT") {
		t.Errorf("%s: /script.cgi gives %d %.80q (%v); expected the output of its preprocessor", when, code, body, err)
	}
}

func TestRA1_SiteFolderBackWithItsSettings(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	configureLocalhost(t, dir)

	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if active, _, _ := localhostState(); active {
		t.Fatal("localhost without its @: still active")
	}
	// Saving meanwhile keeps the site in turbo.config, with its settings.
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	site, _ := savedConfig(t, dir)["localhost"][""].(map[string]interface{})
	if preprocessorsSaved, _ := site["?"].(map[string]interface{}); preprocessorsSaved["cgi"] != toolPath("cgiecho") {
		t.Errorf("turbo.config saved while localhost has no @: %v; expected the site with its preprocessor", site)
	}

	if err := os.Rename(dir+"localhost/@.away", dir+"localhost/@"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	checkLocalhostKept(t, base, "@ back")
}

// Turbo started (or turbo.config read again) while the folder isn't there: its section of turbo.config is kept,
// saved again, and applied when the folder appears.
func TestRA1_ConfigSiteWithoutFolderAppliesWhenItAppears(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	configureLocalhost(t, dir)
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	if err := os.Rename(dir+"localhost", dir+"localhost.away"); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	resetTestState(dir) // As a new start
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if active, _, _ := localhostState(); active {
		t.Fatal("localhost without its folder: active")
	}
	if !strings.Contains(logs.String(), "folder isn't there") {
		t.Errorf("no log line for the site of turbo.config without its folder: %s", logs.String())
	}
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	if _, saved := savedConfig(t, dir)["localhost"]; !saved {
		t.Error("saving without the folder of localhost dropped it from turbo.config")
	}

	if err := os.Rename(dir+"localhost.away", dir+"localhost"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	checkLocalhostKept(t, base, "folder appeared after reading turbo.config")
}

// An error of the disk that isn't "doesn't exist" (permissions, I/O, a network disk) deactivates nothing, and
// neither does a sites directory that can't be read.
func TestRA1_DiskErrorsDeactivateNothing(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	configureLocalhost(t, dir)

	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if strings.Contains(name, "localhost") {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
		}
		return previous(name)
	}
	updateSettings(true)
	siteDirStat = previous
	checkLocalhostKept(t, base, "after a reload where the disk didn't answer for localhost")

	// A sites directory that can't be read (here, one that isn't there): before, the folders of the sites were
	// looked at first, and every site was deactivated.
	sitesDir.Set(dir + "unreadable/")
	err := updateSettings(true)
	sitesDir.Set(dir)
	var dirErr *sitesDirError
	if !errors.As(err, &dirErr) {
		t.Errorf("reload with a sites directory that can't be read: %v; expected a *sitesDirError", err)
	}
	checkLocalhostKept(t, base, "after a reload that couldn't read the sites directory")
}

// delSite deletes, from the panel, also a site without its folder (what Turbo keeps of it), and a folder with its
// name, later, is a new site.
func TestRA1_PanelDeletesSiteWithoutFolder(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	configureLocalhost(t, dir)
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if code, body, err := post(base, "/admin:inside:delSite?s=localhost&d=&b=Admin", tok); err != nil || code != 200 {
		t.Fatalf("delSite of localhost without its @: %d %q %v", code, body, err)
	}
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	if _, saved := savedConfig(t, dir)["localhost"]; saved {
		t.Error("localhost deleted from the panel is still in turbo.config")
	}
	if err := os.MkdirAll(dir+"localhost/@", 0755); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if active, preprocessor, header := localhostState(); !active || preprocessor != "" || header != "" {
		t.Errorf("a new folder localhost after deleting the site: active %v, preprocessor %q, header %q; expected a new site", active, preprocessor, header)
	}
}

// Production review, B3: turbo.config read (at the start, or again) while the folder of a site can't be looked at
// (permissions, I/O, a network disk): its section is kept, as for a folder that isn't there, saving keeps it, and it
// applies when the folder can be used. Before, the site came from the disk later with the defaults, its scripts
// served as text.
func TestRP_B3_ConfigReadWhileFolderUnreadable(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	configureLocalhost(t, dir)
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if strings.Contains(name, "localhost") {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrPermission}
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
	resetTestState(dir) // As a new start
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if code, body, err := get(base, "/script.cgi", nil); err != nil || strings.Contains(body, "SOURCE OF THE SCRIPT") {
		t.Errorf("/script.cgi while localhost can't be looked at: %d %.80q %v; expected never the source", code, body, err)
	}
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	site, _ := savedConfig(t, dir)["localhost"][""].(map[string]interface{})
	if saved, _ := site["?"].(map[string]interface{}); saved["cgi"] != toolPath("cgiecho") {
		t.Errorf("turbo.config saved while localhost can't be looked at: %v; expected the site with its preprocessor", site)
	}

	siteDirStat = previous // The disk answers again
	updateSettings(true)
	checkLocalhostKept(t, base, "the folder readable again")
}

// Production review, M-05: the sites kept without their folder are listed apart in the answer of sites ("~"), where
// the panel shows them and can delete them; deleted, they are no longer listed.
func TestRP_M05_SitesListsThoseWithoutFolder(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	configureLocalhost(t, dir)
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	withoutFolder := func() (kept []interface{}, active bool) {
		t.Helper()
		code, body, err := post(base, "/admin:inside:sites", tok)
		var sites map[string]interface{}
		if err != nil || code != 200 || json.Unmarshal([]byte(body), &sites) != nil {
			t.Fatalf("sites: %d %.200q %v", code, body, err)
		}
		dormant, _ := sites["~"].(map[string]interface{})
		kept, _ = dormant["localhost"].([]interface{})
		_, active = sites["localhost"]
		return kept, active
	}
	if kept, active := withoutFolder(); len(kept) != 1 || kept[0] != "" || active {
		t.Errorf("localhost without its @ in sites: kept %v, active %v; expected it in \"~\" only", kept, active)
	}
	if code, body, err := post(base, "/admin:inside:delSite?s=localhost&d=&b=Admin", tok); err != nil || code != 200 {
		t.Fatalf("delSite: %d %q %v", code, body, err)
	}
	if kept, active := withoutFolder(); len(kept) != 0 || active {
		t.Errorf("localhost deleted: kept %v, active %v; expected it gone from sites", kept, active)
	}
}
