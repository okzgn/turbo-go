package main

// T21 (N18, DOC8): the conditions between settings (CIS/CII ≤ 66, CII ≤ CIS
// and RHT ≤ RT/2) hold whichever setting is changed, and also when
// turbo.config is loaded.

import (
	"strings"
	"testing"
	"time"
)

// setting applies a global setting as the API does after checking b.
func setting(key, value string) (bool, string) {
	return lockedCheck(func() (bool, string) { return defaultSettingValidators["."][key](value, internalAuth) })
}

func TestN18_LimitInvariantsFromPanel(t *testing.T) {
	initForTest(t)
	steps := []struct {
		key, value string
		ok         bool
	}{
		{"CII", "100", false},   // Unchanged
		{"CIS", "50000", false}, // 50000/100 > 66
		{"CIS", "6600", true},   // Exactly 66
		{"CIS", "6601", false},  // 66.01: integer division let it through
		{"CII", "99", false},    // 6600/99 > 66
		{"CIS", "1000", true},
		{"CII", "1001", false}, // CII > CIS
		{"RT", "15m", true},
		{"RHT", "7m", true},
		{"RT", "1s", false}, // RHT would be more than half of RT
		{"RT", "14m", true}, // Exactly twice RHT
		{"RT", "13m59s", false},
		{"RT", "0s", true}, // No limit: nothing to be half of
	}
	for _, step := range steps {
		if ok, msg := setting(step.key, step.value); ok != step.ok {
			t.Errorf("set%s %s: %v %q; expected %v", step.key, step.value, ok, msg, step.ok)
		}
	}
	if cis, cii := serverRequestLimits.CIS.Load()/int64(time.Millisecond), serverRequestLimits.CII.Load(); cis > 66*cii || cii > cis {
		t.Errorf("CIS=%d CII=%d do not meet the conditions", cis, cii)
	}
}

// A turbo.config that does not meet them is loaded with the dependent value
// corrected and a warning, whatever the order of the keys.
func TestN18_LimitInvariantsFromFile(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"CII":"10","CIS":"50000","RHT":"7m","RT":"1s"}}`)
	cis, cii := serverRequestLimits.CIS.Load()/int64(time.Millisecond), serverRequestLimits.CII.Load()
	if cis > 66*cii || cii > cis {
		t.Errorf("CIS=%d CII=%d after loading", cis, cii)
	}
	limits := serverTimeLimits.Load()
	if limits.RT != time.Second || (limits.RHT != 0 && 2*limits.RHT > limits.RT) {
		t.Errorf("RT=%v RHT=%v after loading; expected RT 1s and RHT at most half of it", limits.RT, limits.RHT)
	}
	for _, key := range []string{"CII", "RHT"} {
		if !strings.Contains(logs.String(), key) {
			t.Errorf("no warning about %s:\n%s", key, logs.String())
		}
	}

	// A file that meets them loads as it is, whatever the order of its keys.
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"CII":"1000","CIS":"50000","RHT":"7m","RT":"15m"}}`)
	if cis, cii := serverRequestLimits.CIS.Load()/int64(time.Millisecond), serverRequestLimits.CII.Load(); cis != 50000 || cii != 1000 {
		t.Errorf("CIS=%d CII=%d; expected 50000 and 1000", cis, cii)
	}
	if limits := serverTimeLimits.Load(); limits.RT != 15*time.Minute || limits.RHT != 7*time.Minute {
		t.Errorf("RT=%v RHT=%v; expected 15m and 7m", limits.RT, limits.RHT)
	}
}
