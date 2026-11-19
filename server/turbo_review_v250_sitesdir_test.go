package server

// The tests of the findings about the sites directory and saving of the review of v2.5.0: each failed before its fix.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// V2.5.0 review CF-2: setM to a directory whose turbo.config leads back to the directory in use (a copy of this one,
// whose "M" still names it) is refused: followed, the reload came back here and answered "Sites directory set".
func TestR250_CF2_SetMToADirectoryThatLeadsBackIsRefused(t *testing.T) {
	dirA := initForTest(t)
	loadConfig(t, dirA, `{"^":{"v":"2"},".":{"M":"`+dirA+`","CII":"40"},"_":{}}`)
	dirB := filepath.ToSlash(t.TempDir()) + "/"
	if err := os.MkdirAll(dirB+"siteb/@", 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dirB+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirA+`","CII":"50"},"_":{}}`), 0600)
	ok, message := setSitesDir(dirB, "")
	if ok || !strings.Contains(message, "leads back to the sites directory in use") {
		t.Errorf("setM to a directory that leads back: %v, %q", ok, message)
	}
	if !sameDir(sitesDir.Get(), dirA) || sitesDirHops != 0 || serverRequestLimits.CII.Load() != 40 {
		t.Errorf("after the refusal: directory %q, hops %d, CII %d; expected nothing changed", sitesDir.Get(), sitesDirHops, serverRequestLimits.CII.Load())
	}
	// Without that "M", the directory is set, with its configuration
	os.WriteFile(dirB+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirB+`","CII":"50"},"_":{}}`), 0600)
	if ok, message = setSitesDir(dirB, ""); !ok || !sameDir(sitesDir.Get(), dirB) || serverRequestLimits.CII.Load() != 50 {
		t.Errorf("setM to a directory with its own turbo.config: %v, %q, directory %q", ok, message, sitesDir.Get())
	}
}

// The realistic case of CF-2: Turbo runs in its sites folder with the turbo.config that every save writes ("M":
// "{TURBO_CURRENT_DIR}"), the folder is copied, and M is set to the copy.
func TestR250_CF2_SetMToACopyOfTheFolder(t *testing.T) {
	dirA := initForTest(t)
	old, _ := os.Getwd()
	if err := os.Chdir(dirA); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	resetTestState(dirA)
	sitesDirValue.Set("{TURBO_CURRENT_DIR}")
	updateSettings(false)
	if !saveDefaultConfig() {
		t.Fatal("the configuration wasn't saved")
	}
	saved, _ := os.ReadFile(dirA + "turbo.config")
	dirB := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(dirB+"localhost/@", 0755)
	os.WriteFile(dirB+"turbo.config", saved, 0600)
	if ok, message := setSitesDir(dirB, ""); ok || !strings.Contains(message, "leads back to the sites directory in use") {
		t.Errorf("setM to the copy: %v, %q; expected it refused", ok, message)
	}
	if !sameDir(sitesDir.Get(), dirA) {
		t.Errorf("the sites directory is %q", sitesDir.Get())
	}
}

// V2.5.0 review CF-3: saving doesn't replace a turbo.config that is there and can't be read: no copy of it could be
// kept, and what someone wrote in it was lost while the answer said "Configuration saved".
func TestR250_CF3_AnUnreadableConfigIsNotOverwritten(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a file that its owner can't read: Unix, without root")
	}
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"CII":"40"},"_":{}}`)
	os.Remove(dir + "turbo.config")
	edited := `{"^":{"v":"2"},".":{"CII":"77","PA":"admin.example.com"},"_":{}}`
	if err := os.WriteFile(dir+"turbo.config", []byte(edited), 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir+"turbo.config", 0600) })
	logs := captureLog(t)
	if saveDefaultConfig() {
		t.Error("the configuration was saved over a turbo.config that can't be read")
	}
	if !strings.Contains(logs.String(), "can't be read to keep a copy of it") {
		t.Errorf("no line in the log: %s", logs.String())
	}
	os.Chmod(dir+"turbo.config", 0600)
	if data, _ := os.ReadFile(dir + "turbo.config"); string(data) != edited {
		t.Errorf("the file was replaced: %s", data)
	}
}

// V2.5.0 review CF-4: a turbo.config whose "M" names a directory that isn't there yet (a disk not mounted) is tried
// again in the next reloads, and followed once the directory is there, as its message asks; the error is logged once.
func TestR250_CF4_AnMThatWaitsForItsDirectoryIsTriedAgain(t *testing.T) {
	dirA := initForTest(t)
	loadConfig(t, dirA, `{"^":{"v":"2"},".":{"M":"`+dirA+`","CII":"40"},"_":{}}`)
	dirB := filepath.ToSlash(t.TempDir()) + "/later/"
	os.WriteFile(dirA+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirB+`","CII":"50"},"_":{}}`), 0600)
	logs := captureLog(t)
	t.Cleanup(func() { logConfigError(nil) })
	for i := 0; i < 3; i++ {
		err := updateSettings(true)
		if err == nil {
			t.Fatalf("reload %d with the directory missing: no error", i)
		}
		logConfigError(err)
	}
	if lines := strings.Count(logs.String(), "level=ERROR"); lines != 1 {
		t.Errorf("the same error of the chain was logged %d times; expected once: %s", lines, logs.String())
	}
	if !sameDir(sitesDir.Get(), dirA) || serverRequestLimits.CII.Load() != 40 {
		t.Errorf("while the directory is missing: %q, CII %d; expected the configuration in use kept", sitesDir.Get(), serverRequestLimits.CII.Load())
	}
	if err := os.MkdirAll(dirB+"siteb/@", 0755); err != nil { // The disk is mounted
		t.Fatal(err)
	}
	err := updateSettings(true)
	logConfigError(err)
	if err != nil || !sameDir(sitesDir.Get(), dirB) {
		t.Errorf("with the directory there: %v, sites directory %q; expected it followed", err, sitesDir.Get())
	}
}

// V2.5.0 review CF-5: with TURBO_DIR, the "M": "{TURBO_CURRENT_DIR}" that a save wrote when Turbo was started from its
// sites folder isn't followed to the working directory of the service: the directory of TURBO_DIR stays, with its
// sites, and the log says so.
func TestR250_CF5_CurrentDirInMWithTurboDirIsNotFollowed(t *testing.T) {
	dirA := initForTest(t)
	os.MkdirAll(dirA+"example.com/@", 0755)
	os.WriteFile(dirA+"turbo.config", []byte(`{"^":{"v":"2"},"example.com":{"":{"-":{"index.html":"1"}}},".":{"M":"{TURBO_CURRENT_DIR}","CII":"40"},"_":{}}`), 0600)
	cwd := filepath.ToSlash(t.TempDir()) + "/" // The working directory of the service
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	resetTestState(dirA) // As TURBO_DIR sets it
	sitesDirFromEnv = true
	t.Cleanup(func() { sitesDirFromEnv = false })
	logs := captureLog(t)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if !sameDir(sitesDir.Get(), dirA) {
		t.Errorf("the sites directory moved to %q", sitesDir.Get())
	}
	globalMutex.RLock()
	active := sitesMap["example.com"] != nil
	globalMutex.RUnlock()
	if !active || serverRequestLimits.CII.Load() != 40 {
		t.Errorf("the site is active: %v, CII %d; expected the turbo.config of TURBO_DIR applied there", active, serverRequestLimits.CII.Load())
	}
	if !strings.Contains(logs.String(), "which with TURBO_DIR is another directory") {
		t.Errorf("no warning: %s", logs.String())
	}
	// Without TURBO_DIR it is followed, as always
	sitesDirFromEnv = false
	resetTestState(dirA)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if !sameDir(sitesDir.Get(), cwd) {
		t.Errorf("without TURBO_DIR: the sites directory is %q; expected the working directory", sitesDir.Get())
	}
}

// V2.5.0 review CF-6: the port of TURBO_HTTPS_ADDR is kept as a number writes it: "+443" or "0443" listened on 443,
// and went as they came into the redirections to HTTPS.
func TestR250_CF6_ThePortOfAListeningAddressIsNormalized(t *testing.T) {
	for value, want := range map[string]string{"+443": ":443", "0443": ":443", "127.0.0.1:08443": "127.0.0.1:8443", "8443": ":8443", ":443": ":443"} {
		t.Setenv("TURBO_HTTPS_ADDR", value)
		if got, err := listenAddress("TURBO_HTTPS_ADDR", ":443"); err != nil || got != want {
			t.Errorf("%q: %q, %v; expected %q", value, got, err, want)
		}
	}
	t.Setenv("TURBO_HTTPS_ADDR", "70000")
	if _, err := listenAddress("TURBO_HTTPS_ADDR", ":443"); err == nil {
		t.Error("a port out of range was accepted")
	}
}
