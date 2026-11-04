package main

// T25 (N22): the schema version is read as a number or as an integer string,
// a "^" that isn't understood makes the file invalid, the migration from v1
// neither brings back discarded indexes nor overwrites an earlier backup, and
// the v1 rewrites with "%" are decoded.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestN22_SchemaVersionNumber(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":2},".":{"CIL":"5000","CIS":"500"}}`)
	if configSchemaRead != 2 {
		t.Errorf("schema read with \"v\":2: %d", configSchemaRead)
	}
	if d := time.Duration(serverRequestLimits.CIL.Load()); d != 5*time.Second {
		t.Errorf("CIL = %v; expected 5s (not multiplied by 10)", d)
	}
}

func TestN22_SchemaVersionInvalid(t *testing.T) {
	for _, version := range []string{`"x"`, `"2.0"`, `0`, `-1`, `2.5`, `null`, `{}`} {
		dir := initForTest(t)
		os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":`+version+`},".":{"CIL":"5000"}}`), 0600)
		configFileStamp = configStamp{}
		err := updateSettings(false)
		if err == nil {
			t.Errorf("\"v\":%s was accepted (schema %d); expected an invalid file", version, configSchemaRead)
			continue
		}
		if !strings.Contains(configErrorMessage(err, true), "Turbo does not start") {
			t.Errorf("\"v\":%s: message without the cause:\n%s", version, configErrorMessage(err, true))
		}
	}
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.config", []byte(`{"^":{},".":{}}`), 0600)
	configFileStamp = configStamp{}
	if err := updateSettings(false); err == nil {
		t.Error("\"^\" without \"v\" was accepted")
	}
}

func TestN22_V1IndexWithControlChars(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"v1.test/@", 0755) // A site of its own: localhost already has index.html
	loadConfig(t, dir, `{"v1.test":{"":{"-":{"index.php":"","in\u0001dex.html":"","index.html":""}}}}`)
	globalMutex.RLock()
	indexes := orderedIndexes("v1.test")
	globalMutex.RUnlock()
	for _, name := range indexes {
		if !textAllowed(name, false) {
			t.Errorf("index with control characters after migrating: %q", name)
		}
	}
	if len(indexes) != 2 || indexes[0] != "index.php" || indexes[1] != "index.html" {
		t.Errorf("indexes: %q; expected index.php, index.html", indexes)
	}
}

func TestN22_SecondV1Backup(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.config.v1.bak", []byte("first"), 0600)
	original := `{"localhost":{"":{}},".":{"CIL":"1000"}}`
	loadConfig(t, dir, original)
	ok := saveDefaultConfig() // It takes the locks itself (T20)
	if !ok {
		t.Fatal("couldn't save")
	}
	if data, _ := os.ReadFile(dir + "turbo.config.v1.bak"); string(data) != "first" {
		t.Errorf("the earlier backup was overwritten: %q", data)
	}
	backups, _ := filepath.Glob(dir + "turbo.config.v1.*.bak")
	if len(backups) != 1 {
		t.Fatalf("new backups: %v", backups)
	}
	if data, _ := os.ReadFile(backups[0]); string(data) != original {
		t.Errorf("the new backup isn't the original: %q", data)
	}
}

func TestN22_V1RewriteDecoded(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/target.html", []byte("target"), 0644)
	logs := captureLog(t)
	loadConfig(t, dir, `{"localhost":{"":{"=":{"/a%20b":"/target.html","/bad%zz":"/target.html","/c%2Fd":"/target.html"}}}}`)
	base := startServer(t)
	if code, body, _ := get(base, "/a%20b", nil); code != 200 || body != "target" {
		t.Errorf("GET /a%%20b: %d %q; expected the rewrite's target", code, body)
	}
	globalMutex.RLock()
	_, bad := sitesMap["localhost"][""]["/bad%zz"]
	_, slash := sitesMap["localhost"][""]["/c%2Fd"]
	globalMutex.RUnlock()
	if bad || slash {
		t.Errorf("v1 rewrites that can't be decoded are still loaded: %%zz=%v %%2F=%v", bad, slash)
	}
	if !strings.Contains(logs.String(), "/bad%zz") {
		t.Errorf("no warning of the discarded rewrite:\n%s", logs.String())
	}
}

// Review of 57cbb3c, F7: the rewrite sources of a v1 turbo.config are decoded once each, always with the same
// result. Before, a decoded source added while the map was being walked could be decoded again, or not, depending on
// the order of the map: /a%2541 ended up as /a%41 or as /aA.
func TestRL_F7_V1RewriteSourcesDecodedOnce(t *testing.T) {
	for i := 0; i < 50; i++ {
		var raw map[string]map[string]interface{}
		if err := json.Unmarshal([]byte(`{"localhost":{"":{"=":{"/a%2541":"/x","/b%41":"/y"}}}}`), &raw); err != nil {
			t.Fatal(err)
		}
		decodeV1RewriteSources(raw)
		site, _ := raw["localhost"][""].(map[string]interface{})
		rewrites, _ := site["="].(map[string]interface{})
		if got := sortedKeys(rewrites); !reflect.DeepEqual(got, []string{"/a%41", "/bA"}) {
			t.Fatalf("attempt %d: sources %v; expected [/a%%41 /bA]", i, got)
		}
	}
}
