package main

// T03 (N3, I15): saving turbo.config doesn't make the periodic reload apply it
// again and undo what was changed afterwards; the write uses a temporary file
// of its own.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// N3: after setC, what is changed in the panel stays in use after the
// periodic reload: the password, PA, a limit, HTTPS and a denied IP.
func TestN03_SaveDoesNotReload(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	base := startServer(t)
	tok := login(t, base)
	steps := []string{
		"/admin:inside:cfgS?a=1&s=localhost&d=",
		"/admin:inside:addDenied?s=203.0.113.9&d=" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
		"/admin:inside:setC?a=&b=Admin",
		"/admin:inside:setP?a=NewPass&b=Admin",
		"/admin:inside:setPA?a=127.0.0.0/8&b=NewPass",
		"/admin:inside:setCII?a=50&b=NewPass",
		"/admin:inside:cfgS?a=0&s=localhost&d=",
		"/admin:inside:delDenied?s=203.0.113.9",
	}
	for _, step := range steps {
		if code, body, err := post(base, step, tok); err != nil || code != 200 {
			t.Fatalf("%s: %d %q %v", step, code, body, err)
		}
	}
	if err := updateSettings(true); err != nil { // The periodic reload
		t.Fatal(err)
	}
	if !passwordMatches("NewPass") {
		t.Error("the new password stopped working after the reload")
	}
	if got := panelAccess.Load().setting; got != "127.0.0.0/8" {
		t.Errorf("PA after the reload: %q", got)
	}
	if serverRequestLimits.CII.Load() != 50 {
		t.Errorf("CII after the reload: %d", serverRequestLimits.CII.Load())
	}
	globalMutex.RLock()
	https := httpsEnabled("localhost")
	globalMutex.RUnlock()
	if https {
		t.Error("HTTPS was enabled again after the reload")
	}
	if _, denied := deniedIPList()["203.0.113.9"]; denied {
		t.Error("the denied IP came back after the reload")
	}
}

// N3: a hand edit after saving does apply on the reload.
func TestN03_HandEditAfterSaveApplies(t *testing.T) {
	dir := initForTest(t)
	ok := saveDefaultConfig() // It takes the locks itself (T20)
	if !ok {
		t.Fatal("couldn't save")
	}
	data, _ := os.ReadFile(dir + "turbo.config")
	edited := strings.Replace(string(data), `"CII":"100"`, `"CII":"40"`, 1)
	if edited == string(data) {
		t.Fatalf("CII isn't in the saved file:\n%s", data)
	}
	os.WriteFile(dir+"turbo.config", []byte(edited), 0600)
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(dir+"turbo.config", later, later)
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	if serverRequestLimits.CII.Load() != 40 {
		t.Errorf("CII after editing by hand: %d; expected 40", serverRequestLimits.CII.Load())
	}
}

// I15: a turbo.config.tmp that already exists (a file or a link) isn't used as
// the temporary file: it is neither overwritten nor followed.
func TestI15_SaveIgnoresExistingTmp(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.config.tmp", []byte("foreign"), 0600)
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("outside"), 0600)
	link := filepath.Join(t.TempDir(), "turbo.config")
	linked := os.Symlink(outside, link+".tmp") == nil
	ok := saveDefaultConfig() // It takes the locks itself (T20)
	if !ok {
		t.Fatal("couldn't save")
	}
	if data, _ := os.ReadFile(dir + "turbo.config.tmp"); string(data) != "foreign" {
		t.Errorf("turbo.config.tmp overwritten: %q", data)
	}
	if linked {
		if err := writeFileAtomic(link, []byte("{}")); err != nil {
			t.Fatal(err)
		}
		if data, _ := os.ReadFile(outside); string(data) != "outside" {
			t.Errorf("the turbo.config.tmp link was followed: %q", data)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if name := entry.Name(); strings.HasSuffix(name, ".tmp") && name != "turbo.config.tmp" {
			t.Errorf("the temporary file %s is left", name)
		}
	}
}

// N94: after the first save of a Turbo started without turbo.config, the file holds the configuration in use: if it
// disappears later, that configuration stays, as with one read at start, instead of the defaults.
func TestN94_FirstSaveThenConfigRemoved(t *testing.T) {
	dir := initForTest(t)
	resetTestState(dir)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	list, _ := parsePanelAccess("127.0.0.0/8")
	withGlobalLock(func() { panelAccess.Store(list) }) // As setPA
	if !saveDefaultConfig() {
		t.Fatal("it wasn't saved")
	}
	if err := os.Remove(dir + "turbo.config"); err != nil {
		t.Fatal(err)
	}
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if access := panelAccess.Load().setting; access != "127.0.0.0/8" {
		t.Errorf("turbo.config deleted after the first save: PA %q; expected it to stay 127.0.0.0/8", access)
	}
}

// N95: saving from the panel over a turbo.config edited by hand since Turbo read or wrote it (a reload hasn't
// applied it yet, it was rejected, or a later Turbo wrote it) first copies that edit to a .bak.
func TestN95_SaveKeepsHandEdit(t *testing.T) {
	for _, scenario := range []string{"not reloaded", "rejected", "later schema"} {
		dir := initForTest(t)
		os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"U":"admin2"}}`), 0600)
		resetTestState(dir)
		if err := updateSettings(false); err != nil {
			t.Fatal(err)
		}
		edit := map[string]string{
			"not reloaded": `{"^":{"v":"2"},".":{"U":"admin3"}}`,
			"rejected":     `{"^":{"v":"2"},".":{"U":"admin3","PA":"not a network"}}`,
			"later schema": `{"^":{"v":"99"},".":{"U":"admin3"}}`,
		}[scenario]
		os.WriteFile(dir+"turbo.config", []byte(edit), 0600)
		later := time.Now().Add(time.Minute)
		os.Chtimes(dir+"turbo.config", later, later)
		if scenario != "not reloaded" {
			updateSettings(false) // Rejected: what is in use stays
		}
		saveDefaultConfig()
		kept := false
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			if data, err := os.ReadFile(dir + entry.Name()); err == nil && strings.HasSuffix(entry.Name(), ".bak") && string(data) == edit {
				kept = true
			}
		}
		if !kept {
			t.Errorf("%s: saving overwrote the hand edit without copying it to a .bak", scenario)
		}
	}
}
