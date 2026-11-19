package server

// The tests of the findings about turbo.config and the sites directory of the review of v2.5.0: each failed before
// its fix.

import (
	"os"
	"strings"
	"testing"
)

// V2.5.0 review CF-1: a key of the section of a site that is no list of a site ("? " for "?", "Preprocessors") makes
// the file invalid, as a list written outside its section: skipped, as it was, the site lost its preprocessors
// without a word in the log, and its scripts were served as text. A reload keeps the configuration in use.
func TestR250_CF1_AnUnknownListMakesTheFileInvalid(t *testing.T) {
	dir := v25ReviewCGI(t)
	base := startServer(t)
	echo := toolPath("cgiecho")
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"`+echo+`"}}}}`)
	if code, body, _ := get(base, "/x.cgi", nil); code != 200 || strings.Contains(body, "<?php") {
		t.Fatalf("with a valid turbo.config: %d, source served %v", code, strings.Contains(body, "<?php"))
	}
	for _, key := range []string{"? ", "Preprocessors", "？", "preprocessors", " ?"} {
		config := `{"^":{"v":"2"},"localhost":{"":{"` + key + `":{"cgi":"` + echo + `"},"-":{"index.html":"1"}}}}`
		if err := os.WriteFile(dir+"turbo.config", []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := parseSiteConfig(dir + "turbo.config")
		if siteErr := (configSiteError{}); err == nil || !asConfigSiteError(err, &siteErr) || siteErr.unknown != key {
			t.Errorf("list %q: %v; expected the file refused for that key", key, err)
			continue
		}
		if message := configErrorMessage(err, true); !strings.Contains(message, "is no list of a site") {
			t.Errorf("list %q: the message %q", key, message)
		}
		loadConfig(t, dir, config)
		if code, body, _ := get(base, "/x.cgi", nil); code != 200 || strings.Contains(body, "<?php") {
			t.Errorf("after reading the list %q: %d, source served %v; expected the configuration in use kept", key, code, strings.Contains(body, "<?php"))
		}
	}
	// The same key in a subdomain's section
	subdomain := `{"^":{"v":"2"},"localhost":{"":{},"www":{"Rewrites":{}}}}`
	os.WriteFile(dir+"turbo.config", []byte(subdomain), 0600)
	if _, err := parseSiteConfig(dir + "turbo.config"); err == nil {
		t.Error("an unknown list in a subdomain's section was accepted")
	}
	// A file of a later schema may have lists this version doesn't know: they are ignored, with a warning
	logs := captureLog(t)
	later := `{"^":{"v":"3"},"localhost":{"":{"+":{"x":"y"},"?":{"cgi":"` + echo + `"}}}}`
	os.WriteFile(dir+"turbo.config", []byte(later), 0600)
	if _, err := parseSiteConfig(dir + "turbo.config"); err != nil {
		t.Errorf("a list of a later schema: %v", err)
	}
	if !strings.Contains(logs.String(), "a list of a site that this version doesn't know is ignored") {
		t.Errorf("no warning for the list of a later schema: %s", logs.String())
	}
	// What Turbo writes, and its examples, are still valid
	for _, example := range []string{"testdata/config/v2-example.json", "testdata/config/v1-example.json"} {
		if _, statErr := os.Stat(example); statErr != nil {
			continue
		}
		if _, err := parseSiteConfig(example); err != nil {
			t.Errorf("%s: %v", example, err)
		}
	}
}

// V2.5.0 review CF-1: a setting of a site, or a global one, written with a name that no setting has ("s" for "S",
// "pa" for "PA") is reported in the log, by its name alone: it was lost without a word, and its default applied.
func TestR250_CF1_ASettingWithAnUnknownNameIsReported(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"!":{"s":"1","S":"0"}}},".":{"pa":"secret.example","WT":"10s","U":"Turbo"}}`)
	output := logs.String()
	if !strings.Contains(output, "turbo.config site setting ignored: no setting of a site has that name") || !strings.Contains(output, "setting=s") {
		t.Errorf("no warning for the site setting \"s\": %s", output)
	}
	if !strings.Contains(output, "turbo.config setting ignored: no setting has that name") || !strings.Contains(output, "key=pa") {
		t.Errorf("no warning for the setting \"pa\": %s", output)
	}
	if strings.Contains(output, "secret.example") {
		t.Errorf("the value of an unknown setting is in the log: %s", output)
	}
	if strings.Contains(output, "key=WT") || strings.Contains(output, "key=U ") || strings.Contains(output, "setting=S ") {
		t.Errorf("a known setting was reported: %s", output)
	}
}
