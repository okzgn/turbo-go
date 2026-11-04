package main

// T06 (N6, I14, DOC3): an I/O error doesn't lead to the defaults: an unreadable
// sites folder, or a turbo.config that exists but can't be read, keeps Turbo
// from starting; a turbo.config that disappears while Turbo runs doesn't
// change the configuration in use, and the error message doesn't show the PH.

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// N6: a directory named turbo.config, or a broken link, is a turbo.config that
// can't be read: at startup, an error (Turbo does not start).
func TestN06_UnreadableConfigFile(t *testing.T) {
	dir := initForTest(t)
	os.Mkdir(dir+"turbo.config", 0755)
	configFileStamp = configStamp{}
	if err := updateSettings(false); err == nil {
		t.Error("a turbo.config directory was taken for a missing file")
	}
	os.Remove(dir + "turbo.config")
	if err := os.Symlink(dir+"missing", dir+"turbo.config"); err != nil {
		t.Skipf("no symbolic links on this system: %v", err)
	}
	configFileStamp = configStamp{}
	if err := updateSettings(false); err == nil {
		t.Error("a broken turbo.config link was taken for a missing file")
	}
}

// N6: a sites folder that can't be read keeps Turbo from starting.
func TestN06_UnreadableSitesDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("folder permissions: checked on Linux without root")
	}
	dir := initForTest(t)
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0755) })
	configFileStamp = configStamp{}
	err := updateSettings(false)
	if err == nil || !strings.Contains(err.Error(), strings.TrimSuffix(dir, "/")) {
		t.Errorf("unreadable sites folder: %v; expected an error with the path", err)
	}
}

// N6: if turbo.config disappears while Turbo runs, the configuration in use
// stays (PA and the limits).
func TestN06_ConfigFileRemovedWhileRunning(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"PA":"panel.test","CII":"40"}}`)
	os.Remove(dir + "turbo.config")
	updateSettings(true)
	updateSettings(true)
	if got := panelAccess.Load().setting; got != "panel.test" {
		t.Errorf("PA after deleting turbo.config: %q", got)
	}
	if serverRequestLimits.CII.Load() != 40 {
		t.Errorf("CII after deleting turbo.config: %d", serverRequestLimits.CII.Load())
	}
	if n := strings.Count(logs.String(), "turbo.config has disappeared"); n != 1 {
		t.Errorf("%d warnings that turbo.config disappeared; expected 1:\n%s", n, logs.String())
	}
}

// I14: the fragment of a turbo.config error hides the value of PH and of P.
func TestI14_ConfigErrorHidesHash(t *testing.T) {
	data := []byte(`{".":{"PH":"pbkdf2-sha256$600000$c2FsdA==$Y2xhdmU=","P":"secret" x}}`)
	err := parseConfig(data, &map[string]map[string]interface{}{})
	message := describeConfigError("turbo.config", data, err)
	if strings.Contains(message, "c2FsdA") || strings.Contains(message, "secret") {
		t.Errorf("the message shows the password or its hash:\n%s", message)
	}
}
