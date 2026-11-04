package main

// V3 and V10 (production review of 775a809): the "M" of turbo.config is read the same way everywhere
// (configSitesDir), and a turbo.config that only points to another directory, with an "M" that isn't a directory
// name, can't be used: applied as an empty configuration, it left the default credentials, the panel on any host and
// the sites without their preprocessors, their scripts served as text.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unusableSitesDirSetup gives localhost a whole configuration with credentials, PA and a preprocessor for .cgi, and
// returns its sites directory and the base URL of a server.
func unusableSitesDirSetup(t *testing.T, hash string) (dir, base string) {
	t.Helper()
	dir = initForTest(t)
	base = startServer(t)
	if err := os.WriteFile(dir+"localhost/@/script.cgi", []byte("SOURCE OF THE SCRIPT"), 0644); err != nil {
		t.Fatal(err)
	}
	whole := `{"^":{"v":"2"},".":{"U":"admin2","PH":"` + hash + `","PA":"127.0.0.0/8"},"localhost":{"":{"?":{"cgi":"` + toolPath("cgiecho") + `"},"-":{"index.html":"1"}}}}`
	loadConfig(t, dir, whole)
	if panelUser.Get() != "admin2" {
		t.Fatalf("setup: user %q", panelUser.Get())
	}
	return dir, base
}

// checkWholeConfigInUse fails if the configuration of unusableSitesDirSetup isn't the one in use.
func checkWholeConfigInUse(t *testing.T, base, what string) {
	t.Helper()
	code, body, _ := get(base, "/script.cgi", nil)
	if user, pa := panelUser.Get(), panelAccess.Load().setting; user != "admin2" || pa != "127.0.0.0/8" || strings.Contains(body, "SOURCE") {
		t.Errorf("%s: the configuration in use changed: user %q, PA %q, /script.cgi %d %.40q", what, user, pa, code, body)
	}
}

func TestRP2_V3_PointerWithUnusableM(t *testing.T) {
	hash, err := hashPassword("Another-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{`""`, `null`, `true`, `1.5`, `{}`, `[]`} {
		dir, base := unusableSitesDirSetup(t, hash)
		pointer := `{"^":{"v":"2"},".":{"M":` + m + `}}`
		if err := os.WriteFile(dir+"turbo.config", []byte(pointer), 0600); err != nil {
			t.Fatal(err)
		}
		// A reload keeps the configuration in use.
		withGlobalLock(func() { configFileStamp = configStamp{kind: stampFile, modTime: 3} })
		if err := updateSettings(true); err == nil || !strings.Contains(err.Error(), "must be a non-empty string") {
			t.Errorf("M=%s: a reload applies the pointer: %v", m, err)
		}
		checkWholeConfigInUse(t, base, "M="+m+", reload")
		// A start refuses it (Turbo exits with the message).
		resetTestState(dir)
		if err := updateSettings(false); err == nil || !strings.Contains(err.Error(), "must be a non-empty string") {
			t.Errorf("M=%s: Turbo starts with the pointer: %v (user %q, PA %q)", m, err, panelUser.Get(), panelAccess.Load().setting)
		}
	}
}

// The same with the pointer one step further: a pointer to a directory whose turbo.config is such a pointer.
func TestRP2_V3_UnusableMOnTheWay(t *testing.T) {
	hash, err := hashPassword("Another-password")
	if err != nil {
		t.Fatal(err)
	}
	dir, base := unusableSitesDirSetup(t, hash)
	other := filepath.ToSlash(t.TempDir()) + "/"
	if err := os.WriteFile(other+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":""}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+other+`"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	withGlobalLock(func() { configFileStamp = configStamp{kind: stampFile, modTime: 3} })
	if err := updateSettings(true); err == nil || !strings.Contains(err.Error(), "must be a non-empty string") {
		t.Errorf("a pointer to a pointer with an empty M is followed: %v", err)
	}
	checkWholeConfigInUse(t, base, "pointer on the way")
}

// Without "M" ({} or only "^"), a turbo.config is still an empty configuration (N115).
func TestRP2_V3_WithoutMStillEmpty(t *testing.T) {
	for _, config := range []string{`{}`, `{"^":{"v":"2"}}`, `{"^":{"v":"2"},".":{}}`} {
		dir := initForTest(t)
		if err := os.WriteFile(dir+"turbo.config", []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		resetTestState(dir)
		if err := updateSettings(false); err != nil {
			t.Errorf("%s: %v; expected an empty configuration", config, err)
		}
	}
}

// V10: a numeric "M" names a directory as the setting reads it (its digits), and it is checked and followed like a
// string: before, it was applied without checking where it led, and a turbo.config there that couldn't be used, or
// none at all, emptied the configuration in use.
func TestRP2_V10_NumericM(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work) // "M": 7 is the folder 7 of the working directory
	dir := initForTest(t)
	if err := os.MkdirAll(work+"/7/localhost/@", 0755); err != nil {
		t.Fatal(err)
	}
	before := `{"^":{"v":"2"},".":{"U":"before"},"localhost":{"":{"-":{"index.html":"1"}}}}`
	loadConfig(t, dir, before)
	if panelUser.Get() != "before" {
		t.Fatalf("setup: user %q", panelUser.Get())
	}
	numeric := `{"^":{"v":"2"},".":{"U":"numeric","M":7},"localhost":{"":{"-":{"index.html":"1"}}}}`

	// A turbo.config there that can't be used: refused, and the configuration in use stays.
	if err := os.WriteFile(work+"/7/turbo.config", []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"turbo.config", []byte(numeric), 0600); err != nil {
		t.Fatal(err)
	}
	withGlobalLock(func() { configFileStamp = configStamp{kind: stampFile, modTime: 3} })
	if err := updateSettings(true); err == nil {
		t.Error(`"M": 7 with an unusable turbo.config there is followed`)
	}
	if !sameDir(sitesDir.Get(), dir) || panelUser.Get() != "before" {
		t.Errorf("the configuration in use changed: sites directory %s, user %q", sitesDir.Get(), panelUser.Get())
	}

	// Without a turbo.config there, the whole configuration applies there, as with "M": "7".
	if err := os.Remove(work + "/7/turbo.config"); err != nil {
		t.Fatal(err)
	}
	withGlobalLock(func() { configFileStamp = configStamp{kind: stampFile, modTime: 3} })
	if err := updateSettings(true); err != nil {
		t.Fatalf(`"M": 7 without a turbo.config there: %v`, err)
	}
	if !sameDir(sitesDir.Get(), work+"/7") || panelUser.Get() != "numeric" {
		t.Errorf("the whole configuration doesn't apply in 7: sites directory %s, user %q", sitesDir.Get(), panelUser.Get())
	}
}
