package main

// T05 (N5, N15, I18): the global and "!" settings that turbo.config can't
// apply are logged, JSON integers are valid where a numeric string is
// expected, a "C" key saves nothing and a turbo.config that isn't an object
// isn't applied.

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestN05_JSONNumbersAccepted(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"MBB":5242880,"CGL":100},"localhost":{"":{"!":{"S":1}}}}`)
	if got := maxBodySize.Load(); got != 5242880 {
		t.Errorf("MBB as a JSON number: %d; expected 5242880", got)
	}
	if got := globalRequestLimit.Load(); got != 100 {
		t.Errorf("CGL as a JSON number: %d; expected 100", got)
	}
	globalMutex.RLock()
	https := httpsEnabled("localhost")
	globalMutex.RUnlock()
	if !https {
		t.Error(`"S":1 doesn't enable HTTPS`)
	}
}

func TestN05_DiscardedValuesLogged(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"MBB":"many","CIL":1.5,"RT":"99h","MUB":[]},"localhost":{"":{"!":{"R":"7"}}}}`)
	for _, key := range []string{"MBB", "CIL", "RT", "MUB"} {
		if !strings.Contains(logs.String(), key) {
			t.Errorf("no warning for the discarded value of %s:\n%s", key, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "localhost") || !strings.Contains(logs.String(), `"R"`) && !strings.Contains(logs.String(), "R=") && !strings.Contains(logs.String(), "setting=R") {
		t.Errorf("no warning for the site's R setting:\n%s", logs.String())
	}
	if got := maxBodySize.Load(); got != 1048576 {
		t.Errorf("MBB after an invalid value: %d; expected the default value", got)
	}
}

// N15: a "C" key in "." doesn't save the configuration when it is loaded.
func TestN15_CKeyIgnored(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	config := `{"^":{"v":"2"},".":{"C":"1","CII":"50"},"localhost":{"":{"=":{"/a":"/index.html"}}}}`
	loadConfig(t, dir, config)
	if data, _ := os.ReadFile(dir + "turbo.config"); string(data) != config {
		t.Errorf("turbo.config rewritten when loading a C key:\n%s", data)
	}
	if !strings.Contains(logs.String(), `"C"`) && !strings.Contains(logs.String(), "key=C") {
		t.Errorf("no warning for the C key:\n%s", logs.String())
	}
}

// I18: a turbo.config that isn't a JSON object isn't applied.
func TestI18_NotAnObject(t *testing.T) {
	for _, content := range []string{"null", "[]", "5", `"x"`} {
		dir := initForTest(t)
		os.WriteFile(dir+"turbo.config", []byte(content), 0600)
		configFileStamp = configStamp{}
		if err := updateSettings(false); err == nil {
			t.Errorf("turbo.config %s was applied; expected an invalid file", content)
		}
	}
}

// N85: R and W at their default (0) in a subdomain, which Turbo writes when saving (and v2.3.rc3 did too), load
// without a warning; a value that would do something there is still discarded with one.
func TestN85_SubdomainRedirectDefaultsLoadQuietly(t *testing.T) {
	dir := initForTest(t)
	globalMutex.Lock()
	ok, msg := addSubdomain("localhost", "sub")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	if !saveDefaultConfig() { // Takes the locks itself
		t.Fatal("turbo.config wasn't saved")
	}
	saved, err := os.ReadFile(dir + "turbo.config")
	if err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	loadConfig(t, dir, string(saved))
	if strings.Contains(logs.String(), "discarded") {
		t.Errorf("the turbo.config Turbo just saved gives warnings when loaded:\n%s", logs.String())
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{},"sub":{"!":{"R":"1"}}}}`)
	if !strings.Contains(logs.String(), "setting=R") {
		t.Errorf("R=1 in a subdomain was discarded without a warning:\n%s", logs.String())
	}
}
