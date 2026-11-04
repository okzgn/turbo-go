package main

// turbo.config compatibility across schemas (§5, §10).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// loadConfig writes turbo.config in dir and forces it to be read.
func loadConfig(t *testing.T, dir, cfg string) {
	t.Helper()
	if err := os.WriteFile(dir+"turbo.config", []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	configFileStamp = configStamp{}
	updateSettings(false)
}

// savedConfig returns the turbo.config of dir (with or without the final slash), already parsed.
func savedConfig(t *testing.T, dir string) map[string]map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("saved turbo.config is not valid JSON: %v\n%s", err, b)
	}
	return raw
}

// A turbo.config of v2.3.rc3 (schema 1, without "^") loads with CIL and
// CIS migrated to milliseconds; saving creates turbo.config.v1.bak with the
// original and writes "^"; the saved file isn't migrated again.
func TestC_ConfigMigrationV1(t *testing.T) {
	dir := initForTest(t)
	orig, err := os.ReadFile("testdata/config/v1-example.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(orig), "{TURBO_CURRENT_DIR}", dir, 1)
	loadConfig(t, dir, cfg)
	if configSchemaRead != 1 {
		t.Errorf("schema read %d; expected 1", configSchemaRead)
	}
	if sitesDir.Get() != dir {
		t.Errorf("M = %q; expected %q", sitesDir.Get(), dir)
	}
	if d := time.Duration(serverRequestLimits.CIL.Load()); d != 10*time.Second {
		t.Errorf("CIL = %v; expected 10s (1000 units of 10 ms)", d)
	}
	if d := time.Duration(serverRequestLimits.CIS.Load()); d != time.Second {
		t.Errorf("CIS = %v; expected 1s (100 units of 10 ms)", d)
	}
	if serverRequestLimits.CII.Load() != 100 {
		t.Errorf("CII = %d; expected 100", serverRequestLimits.CII.Load())
	}

	ok := saveDefaultConfig() // Takes the locks itself (T20)
	if !ok {
		t.Fatal("could not save")
	}
	bak, err := os.ReadFile(dir + "turbo.config.v1.bak")
	if err != nil || string(bak) != cfg {
		t.Fatalf(".bak copy: err=%v content=%q", err, bak)
	}
	if fi, _ := os.Stat(dir + "turbo.config.v1.bak"); runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
		t.Errorf("permissions of the copy: %v; expected 0600", fi.Mode().Perm())
	}
	raw := savedConfig(t, dir)
	if raw["^"]["v"] != "2" || raw["."]["CIL"] != "10000" || raw["."]["CIS"] != "1000" || raw["."]["CII"] != "100" {
		t.Fatalf("saved: ^=%v .=%v", raw["^"], raw["."])
	}

	b, _ := os.ReadFile(dir + "turbo.config")
	loadConfig(t, dir, string(b))
	if configSchemaRead != configSchema {
		t.Errorf("schema read after saving: %d", configSchemaRead)
	}
	if d := time.Duration(serverRequestLimits.CIL.Load()); d != 10*time.Second {
		t.Errorf("CIL after reloading = %v; expected 10s (not migrated twice)", d)
	}
}

// A turbo.config of a later schema loads without migrating, and "Save
// configuration" doesn't overwrite it without explicit confirmation.
func TestC_ConfigFutureSchema(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"^":{"v":"3"},"localhost":{"":{}},".":{"CIL":"5000","NEW":"x"}}`
	loadConfig(t, dir, cfg)
	if d := time.Duration(serverRequestLimits.CIL.Load()); d != 5*time.Second {
		t.Errorf("CIL = %v; expected 5s", d)
	}
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:setC?a=&b=Admin", tok)
	if err != nil || code != 400 {
		t.Fatalf("setC without confirmation: code=%d body=%q err=%v; expected 400", code, body, err)
	}
	if b, _ := os.ReadFile(dir + "turbo.config"); string(b) != cfg {
		t.Fatalf("turbo.config overwritten without confirmation: %s", b)
	}
	code, body, err = post(base, "/admin:inside:setC?a=overwrite&b=Admin", tok)
	if err != nil || code != 200 {
		t.Fatalf("setC with confirmation: code=%d body=%q err=%v", code, body, err)
	}
	if raw := savedConfig(t, dir); raw["^"]["v"] != "2" {
		t.Fatalf("saved with confirmation: ^=%v", raw["^"])
	}
}

// §5.1, #58 (review of T1.7): when the minimal turbo.config with M is left in
// the startup directory, the original is first copied to
// turbo.config.v<schema>.bak; a pointer already written isn't copied again.
func TestC_SitesDirPointerBackup(t *testing.T) {
	start := initForTest(t)
	original := `{"localhost":{"":{}},".":{"CIL":"1000"}}`
	resetSettings()
	loadConfig(t, start, original)
	other := t.TempDir() + "/"
	os.MkdirAll(other+"other.test/@", 0755)
	if ok, msg := defaultSettingValidators["."]["M"](other, "Admin"); !ok {
		t.Fatalf("setM: %q", msg)
	}
	resetSettings()
	updateSettings(true)
	for i := 0; i < 2; i++ { // the second save finds the pointer
		if ok, msg := defaultSettingValidators["."]["C"]("", "Admin"); !ok {
			t.Fatalf("setC: %q", msg)
		}
	}
	bak, err := os.ReadFile(start + "turbo.config.v1.bak")
	if err != nil || string(bak) != original {
		t.Fatalf("copy in the startup directory: err=%v content=%q", err, bak)
	}
	if fi, _ := os.Stat(start + "turbo.config.v1.bak"); runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
		t.Errorf("permissions of the copy: %v", fi.Mode().Perm())
	}
	if raw := savedConfig(t, start); raw["."]["M"] == nil || len(raw) != 2 {
		t.Errorf("pointer in the startup directory: %v", raw)
	}
}

// T44 (N61): the turbo.config example, now in testdata (git ignores it at the
// root), is still a valid file of the current schema.
func TestN61_ExampleConfigValid(t *testing.T) {
	config, err := parseSiteConfig("testdata/config/v2-example.json")
	if err != nil {
		t.Fatalf("the example is not valid: %v", err)
	}
	if config.schema != configSchema || config.raw["localhost"] == nil {
		t.Errorf("the example: schema %d, site localhost %v", config.schema, config.raw["localhost"] != nil)
	}
}
