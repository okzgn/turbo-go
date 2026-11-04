package main

// T05, point 2 (N5, D17 (a)): a PA, U or PH (or P without PH) that can't be
// used makes turbo.config invalid, like broken JSON: at startup, Turbo doesn't
// start and gives the key and the reason; on a reload, the configuration in use
// is kept. Their default values would open the panel or bring back Turbo/Admin.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var invalidPanelSettings = map[string]string{
	"PA-port":      `"PA":"admin.x:8443"`,
	"PA-null":      `"PA":null`,
	"PA-array":     `"PA":[]`,
	"PA-33":        `"PA":"` + strings.TrimSuffix(strings.Repeat("10.0.0.0/8,", 33), ",") + `"`,
	"U-empty":      `"U":""`,
	"U-long":       `"U":"` + strings.Repeat("u", 25) + `"`,
	"U-number":     `"U":5`,
	"U-control":    `"U":"Boss\u0007"`,
	"PH-broken":    `"PH":"x"`,
	"P-without-PH": `"P":""`,
	"PH-not-text":  `"PH":{}`,
}

// At startup: code 1 and a message with the key.
func TestN05_InvalidPanelSettingStopsStart(t *testing.T) {
	for name, setting := range invalidPanelSettings {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "localhost", "@"), 0755)
			os.WriteFile(filepath.Join(dir, "turbo.config"), []byte(`{"^":{"v":"2"},".":{`+setting+`}}`), 0600)
			p := startTurbo(t, dir)
			err, ended := p.exited()
			if !ended {
				t.Fatalf("Turbo started with %s\n%s", setting, p.out.String())
			}
			if exitErr, isExit := err.(*exec.ExitError); !isExit || exitErr.ExitCode() != 1 {
				t.Errorf("it ended with %v; expected code 1", err)
			}
			key := strings.SplitN(name, "-", 2)[0]
			if out := p.out.String(); !strings.Contains(out, "Turbo does not start") || !strings.Contains(out, `"`+key+`"`) {
				t.Errorf("the message doesn't say it doesn't start, or doesn't give the key %s:\n%s", key, out)
			}
		})
	}
}

// On a reload: the configuration in use is kept and the error is logged.
func TestN05_InvalidPanelSettingKeptOnReload(t *testing.T) {
	for name, setting := range invalidPanelSettings {
		t.Run(name, func(t *testing.T) {
			dir := initForTest(t)
			loadConfig(t, dir, `{"^":{"v":"2"},".":{"PA":"127.0.0.0/8","U":"Other","CII":"77"}}`)
			hash := panelPasswordHash.Get()
			os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{`+setting+`,"CII":"78"}}`), 0600)
			configFileStamp = configStamp{}
			if err := updateSettings(false); err == nil {
				t.Errorf("the reload with %s doesn't report the error", setting)
			}
			if panelAccess.Load().setting != "127.0.0.0/8" || panelUser.Get() != "Other" || panelPasswordHash.Get() != hash || serverRequestLimits.CII.Load() != 77 {
				t.Errorf("the reload with %s didn't keep the configuration: PA=%q U=%q CII=%d", setting, panelAccess.Load().setting, panelUser.Get(), serverRequestLimits.CII.Load())
			}
		})
	}
}

// setM to a directory whose turbo.config has an invalid PA: 400, unchanged.
func TestN05_SetMRefusesInvalidPanelSetting(t *testing.T) {
	dir := initForTest(t)
	other := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(other+"turbo.config", []byte(`{"^":{"v":"2"},".":{"PA":null}}`), 0600)
	base := startServer(t)
	tok := login(t, base)
	if code, body := setM(t, base, tok, other, "Admin"); code != 400 || !strings.Contains(body, `"PA"`) {
		t.Errorf("setM: %d %q; expected 400 with the key", code, body)
	}
	if !sameDir(sitesDir.Get(), dir) {
		t.Errorf("the directory changed to %q", sitesDir.Get())
	}
}
