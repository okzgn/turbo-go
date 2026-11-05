package main

// V11, R1-07 and R1-08 (production reviews of 2026-11-04): how Turbo tells that a site's folder is gone or back.
// - V11: on a system whose file names ignore case (Windows, macOS), the folder of a site kept without it that came
//   back with other capitals stayed unused until a restart. Now it brings the site back; any other site folder with
//   capitals is logged once (no host has them).
// - R1-07: on Windows, a network share that stops answering gives "not found" for every folder, and the sites were
//   deactivated; and the second look at a missing site, under the global lock, could wait for the share's time limit
//   with every request held. A folder is gone only if its parent folder, listed, doesn't have it, and the second
//   look is made without the lock.
// - R1-08: an alias of a site that comes back, whose host is now a site's, was dropped without a word; and a site of
//   turbo.config whose folder isn't there was logged as kept when there was nothing to keep.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// namesIgnoreCaseIn reports whether the file system of dir takes a name with other capitals for the same file.
func namesIgnoreCaseIn(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "case-probe")
	if err := os.Mkdir(probe, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	lower, errLower := os.Stat(probe)
	upper, errUpper := os.Stat(filepath.Join(dir, "CASE-PROBE"))
	return errLower == nil && errUpper == nil && os.SameFile(lower, upper)
}

func TestRP3_V11_KeptSiteBackWithOtherCapitals(t *testing.T) {
	dir := initForTest(t)
	configureLocalhost(t, dir)
	away := filepath.Join(t.TempDir(), "localhost")
	if err := os.Rename(dir+"localhost", away); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if active, _, _ := localhostState(); active {
		t.Fatal("localhost is still active without its folder")
	}
	if err := os.Rename(away, dir+"LocalHost"); err != nil { // Back, with other capitals
		t.Fatal(err)
	}
	logs := captureLog(t)
	updateSettings(true)
	updateSettings(true)
	active, _, header := localhostState()
	if namesIgnoreCaseIn(t, dir) {
		if !active || header != "1" {
			t.Errorf("its folder back as LocalHost, on a file system that ignores case: localhost active %v, header %q; expected it back with its settings", active, header)
		}
		return
	}
	if active {
		t.Error("a folder LocalHost, on a file system that tells capitals apart, brought localhost back")
	}
	if count := strings.Count(logs.String(), "LocalHost"); count != 1 {
		t.Errorf("the folder LocalHost was logged %d times; expected once:\n%s", count, logs.String())
	}
}

func TestRP3_V11_FolderWithCapitalsLoggedOnce(t *testing.T) {
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"Other.test/@", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir+"localhost/WWW/@", 0755); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	updateSettings(true)
	updateSettings(true)
	globalMutex.RLock()
	_, other := sitesMap["other.test"]
	_, www := sitesMap["localhost"]["www"]
	globalMutex.RUnlock()
	if other || www {
		t.Errorf("folders with capitals, not kept: other.test active %v, www.localhost %v; expected neither", other, www)
	}
	for _, folder := range []string{"Other.test", "WWW"} {
		if count := strings.Count(logs.String(), folder); count != 1 {
			t.Errorf("the folder %s was logged %d times; expected once:\n%s", folder, count, logs.String())
		}
	}
}

// stattingAs makes siteDirStat answer for path what answer says, for the rest of the test.
func stattingAs(t *testing.T, answer func(path string) error) {
	t.Helper()
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if err := answer(name); err != nil {
			return nil, err
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
}

func TestRP3_R107_NotFoundButListedStays(t *testing.T) {
	dir := initForTest(t)
	stattingAs(t, func(path string) error {
		if path == dir+"localhost/"+publicDirName { // A network share's error, which Windows gives as "not found"
			return &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
		}
		return nil
	})
	checkSites()
	if active, _, _ := localhostState(); !active {
		t.Error("a site whose @ stat says isn't there, but its folder lists, was deactivated")
	}
}

func TestRP3_R107_ParentUnreadableStays(t *testing.T) {
	dir := initForTest(t)
	stattingAs(t, func(path string) error {
		if strings.HasPrefix(path, dir+"localhost") {
			return &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
		}
		return nil
	})
	previous := siteDirRead
	siteDirRead = func(name string) ([]os.DirEntry, error) { return nil, errors.New("the share doesn't answer") }
	t.Cleanup(func() { siteDirRead = previous })
	checkSites()
	if active, _, _ := localhostState(); !active {
		t.Error("a site whose folder can't be told apart from a share that doesn't answer was deactivated")
	}
}

// Nothing of the disk is looked at holding the global lock: on a share that doesn't answer, each look can take its
// time limit, with every request waiting. (No one else takes the lock in this test, so TryRLock fails only while
// checkSites holds it.)
func TestRP3_R107_NoLookUnderTheLock(t *testing.T) {
	dir := initForTest(t)
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	var underLock []string
	held := func(name string) {
		if !globalMutex.TryRLock() {
			underLock = append(underLock, name)
			return
		}
		globalMutex.RUnlock()
	}
	stattingAs(t, func(path string) error { held(path); return nil })
	previous := siteDirRead
	siteDirRead = func(name string) ([]os.DirEntry, error) { held(name); return previous(name) }
	t.Cleanup(func() { siteDirRead = previous })
	checkSites()
	if len(underLock) != 0 {
		t.Errorf("checkSites looked at the disk holding the global lock: %s", strings.Join(underLock, ", "))
	}
	if active, _, _ := localhostState(); active {
		t.Error("a site whose @ is gone is still active")
	}
}

func TestRP3_R107_SwapMeanwhileKeepsTheSite(t *testing.T) {
	dir := initForTest(t)
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	beforeMissingSitesDeleted = func() { publicSwaps.Add(1) } // As hardUpload swapping an @ meanwhile
	t.Cleanup(func() { beforeMissingSitesDeleted = func() {} })
	checkSites()
	if active, _, _ := localhostState(); !active {
		t.Error("a site was deactivated by a look made while an @ was being swapped")
	}
	beforeMissingSitesDeleted = func() {}
	checkSites()
	if active, _, _ := localhostState(); active {
		t.Error("the next look didn't deactivate the site whose @ is gone")
	}
}

func TestRP3_R108_AliasOfSiteThatComesBackLogged(t *testing.T) {
	dir := initForTest(t)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["&"](true, map[string]interface{}{"b.test": true}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	if err := os.Rename(dir+"localhost/@", dir+"localhost/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true) // localhost is kept without its folder, with its alias
	if err := os.MkdirAll(dir+"b.test/@", 0755); err != nil {
		t.Fatal(err)
	}
	updateSettings(true) // b.test is a site now
	if err := os.Rename(dir+"localhost/@.away", dir+"localhost/@"); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	updateSettings(true) // localhost comes back: its alias is b.test's host
	if !strings.Contains(logs.String(), "Alias discarded") || !strings.Contains(logs.String(), "b.test") {
		t.Errorf("the alias b.test of localhost, now a site's host, was dropped without a word:\n%s", logs.String())
	}
}

func TestRP3_R108_NothingToKeepNothingLogged(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"}}},"gone.test":{},"kept.test":{"":{".":{"X-A":"1"}}}}`)
	if strings.Contains(logs.String(), "gone.test") {
		t.Errorf("a site of turbo.config without its folder, with nothing to keep, was logged:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "kept.test") {
		t.Errorf("a site of turbo.config without its folder, with settings to keep, wasn't logged:\n%s", logs.String())
	}
}
