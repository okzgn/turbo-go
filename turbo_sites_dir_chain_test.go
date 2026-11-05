package main

// V8, V9, R1-09 and R1-10 (production reviews of 2026-11-04): following "M" to another sites directory.
// - V8: the chain was checked, the configuration in use emptied, and the directory it leads to read again: a change
//   of its turbo.config in between left the defaults in use, and requests saw no sites meanwhile. Now nothing changes
//   until the configuration of that directory applies, with the move, at once.
// - V9: a reload counted the directories it followed from the one in use, and the start from the start directory: a
//   chain that a reload accepted was refused at the next start. Both count from the start directory now.
// - R1-09: two whole turbo.config files that name each other with "M" are refused.
// - R1-10: a whole turbo.config whose "M" names a directory with a turbo.config of its own was applied first, looking
//   at the disk under the lock, for nothing: it is followed like a pointer now, its credentials kept.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chainDir is a new sites directory with the site site (index.html "site") and turbo.config config.
func chainDir(t *testing.T, site string, config string) string {
	t.Helper()
	dir := filepath.ToSlash(t.TempDir()) + "/"
	if err := os.MkdirAll(dir+site+"/@", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+site+"/@/index.html", []byte(site), 0644); err != nil {
		t.Fatal(err)
	}
	if config != "" {
		if err := os.WriteFile(dir+configFileName, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// reloadChanged reads the turbo.config of the sites directory in use, as changed since it was read.
func reloadChanged() error {
	withGlobalLock(func() { configFileStamp = configStamp{kind: stampFile, modTime: 3} })
	return updateSettings(true)
}

func TestRP3_V8_FollowAppliesWhatWasChecked(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, localhostWithPreprocessor())
	target := chainDir(t, "b.test", `{"^":{"v":"2"},"b.test":{"":{"-":{"index.html":"1"}}}}`)
	if err := os.WriteFile(dir+configFileName, []byte(`{"^":{"v":"2"},".":{"M":"`+target+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	beforeFollowing = func(string) { os.WriteFile(target+configFileName, []byte(`{"^":`), 0600) } // An editor halfway
	t.Cleanup(func() { beforeFollowing = func(string) {} })
	if err := reloadChanged(); err == nil {
		t.Error("a reload whose target broke after the check applied it")
	}
	localhostInUse(t, dir, "after the target broke")
	// Fixed, and the pointer touched: it is followed then.
	beforeFollowing = func(string) {}
	if err := os.WriteFile(target+configFileName, []byte(`{"^":{"v":"2"},"b.test":{"":{"-":{"index.html":"1"}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reloadChanged(); err != nil {
		t.Fatal(err)
	}
	globalMutex.RLock()
	_, served := sitesMap["b.test"]
	_, left := sitesMap["localhost"]
	globalMutex.RUnlock()
	if !sameDir(sitesDir.Get(), target) || !served || left {
		t.Errorf("after following: sites directory %s, b.test %v, localhost %v; expected the target with its site only", sitesDir.Get(), served, left)
	}
}

func TestRP3_V8_NoMomentWithoutSites(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	target := chainDir(t, "b.test", `{"^":{"v":"2"},"b.test":{"":{"-":{"index.html":"1"}}}}`)
	if err := os.WriteFile(dir+configFileName, []byte(`{"^":{"v":"2"},".":{"M":"`+target+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	var answers []string
	beforeSitesScan = func() { // Every time a reload is about to apply: the sites in use are still served
		code, body, err := get(base, "/", nil)
		if err != nil {
			answers = append(answers, err.Error())
			return
		}
		if code != 200 || body != "hello" {
			answers = append(answers, strings.TrimSpace(body))
		}
	}
	t.Cleanup(func() { beforeSitesScan = func() {} })
	if err := reloadChanged(); err != nil {
		t.Fatal(err)
	}
	if len(answers) != 0 {
		t.Errorf("while following M, localhost answered %q; expected hello until the target applied", answers)
	}
	if !sameDir(sitesDir.Get(), target) {
		t.Errorf("sites directory %s; expected %s", sitesDir.Get(), target)
	}
}

func TestRP3_V9_HopsCountedFromTheStart(t *testing.T) {
	start := initForTest(t)
	dirD := chainDir(t, "d.test", `{"^":{"v":"2"},"d.test":{"":{"-":{"index.html":"1"}}}}`)
	dirC := chainDir(t, "c.test", `{"^":{"v":"2"},"c.test":{"":{"-":{"index.html":"1"}}}}`)
	dirB := chainDir(t, "b.test", `{"^":{"v":"2"},"b.test":{"":{"-":{"index.html":"1"}}}}`)
	if err := os.WriteFile(start+configFileName, []byte(`{"^":{"v":"2"},".":{"M":"`+dirB+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	resetTestState(start)
	if err := updateSettings(false); err != nil || !sameDir(sitesDir.Get(), dirB) {
		t.Fatalf("start: %v, sites directory %s", err, sitesDir.Get())
	}
	// B now leads to C, and C to D: three directories from the start, which the next start refuses.
	os.WriteFile(dirB+configFileName, []byte(`{"^":{"v":"2"},".":{"M":"`+dirC+`"}}`), 0600)
	os.WriteFile(dirC+configFileName, []byte(`{"^":{"v":"2"},".":{"M":"`+dirD+`"},"c.test":{"":{}}}`), 0600)
	if err := reloadChanged(); err == nil || !strings.Contains(err.Error(), "counted from the start directory") {
		t.Errorf("a reload in B that leads to C and D: %v; expected it refused", err)
	}
	if !sameDir(sitesDir.Get(), dirB) {
		t.Errorf("sites directory %s after the refused reload; expected B", sitesDir.Get())
	}
	resetTestState(start)
	if err := updateSettings(false); err == nil || !strings.Contains(err.Error(), "counted from the start directory") {
		t.Errorf("the start with the same chain: %v; expected the same refusal", err)
	}
	// Only to C: two directories from the start, which the reload and the start both follow.
	os.WriteFile(dirC+configFileName, []byte(`{"^":{"v":"2"},"c.test":{"":{"-":{"index.html":"1"}}}}`), 0600)
	resetTestState(start)
	if err := updateSettings(false); err != nil || !sameDir(sitesDir.Get(), dirC) {
		t.Errorf("start to C: %v, sites directory %s", err, sitesDir.Get())
	}
}

func TestRP3_R109_TwoWholeConfigsNamingEachOther(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, localhostWithPreprocessor())
	other := chainDir(t, "b.test", withM(`{"^":{"v":"2"},"b.test":{"":{"-":{"index.html":"1"}}}}`, dir))
	if err := os.WriteFile(dir+configFileName, []byte(withM(localhostWithPreprocessor(), other)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := reloadChanged(); err == nil || !strings.Contains(err.Error(), "leads back") {
		t.Errorf("two whole turbo.config files that name each other: %v; expected them refused", err)
	}
	localhostInUse(t, dir, "after the loop")
}

func TestRP3_R110_WholeConfigFollowedLikePointer(t *testing.T) {
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"a.test/@", 0755); err != nil {
		t.Fatal(err)
	}
	target := chainDir(t, "b.test", `{"^":{"v":"2"},".":{"CII":"55"},"b.test":{"":{"-":{"index.html":"1"}}}}`)
	whole := `{"^":{"v":"2"},".":{"U":"inherited","CII":"44","M":"` + target + `"},"a.test":{"":{".":{"X-A":"1"}}}}`
	var underLock []string
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if lookedDisk != nil { // Within the reload's withDiskLook
			underLock = append(underLock, name)
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
	loadConfig(t, dir, whole)
	siteDirStat = previous
	globalMutex.RLock()
	_, aSite := sitesMap["a.test"]
	_, bSite := sitesMap["b.test"]
	globalMutex.RUnlock()
	if !sameDir(sitesDir.Get(), target) || !bSite || aSite {
		t.Errorf("sites directory %s, a.test %v, b.test %v; expected the target with its own site", sitesDir.Get(), aSite, bSite)
	}
	if panelUser.Get() != "inherited" || serverRequestLimits.CII.Load() != 55 {
		t.Errorf("user %q and CII %d; expected the user of the first turbo.config and the CII of the target's", panelUser.Get(), serverRequestLimits.CII.Load())
	}
	if len(underLock) != 0 {
		t.Errorf("looked at under the global lock: %s; expected nothing", strings.Join(underLock, ", "))
	}
}
