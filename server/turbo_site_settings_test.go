package server

// Review of 6046dbe (R6), 7.2: the settings of a site are a struct with a field for each, not a map of any value
// by a letter, where "C" was a bool or the text of a failure and "S" a number. What turbo.config and the panel get
// of them is, byte by byte, what it was.

import (
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// mapSiteSettingsList is how the "!" member of a site's JSON was written from the map of its settings.
func mapSiteSettingsList(settings map[string]interface{}) string {
	var jsonBuilder strings.Builder
	jsonBuilder.WriteString("{")
	delimiter := ""
	for _, settingName := range sortedKeys(settings) {
		var encodedValue string
		switch value := settings[settingName].(type) {
		case bool:
			encodedValue = "0"
			if value {
				encodedValue = "1"
			}
		case int:
			encodedValue = strconv.Itoa(value)
		case string:
			encodedValue = url.QueryEscape(value)
		default:
			continue
		}
		jsonBuilder.WriteString(delimiter + jsonString(settingName) + ":" + jsonString(encodedValue))
		delimiter = ","
	}
	jsonBuilder.WriteString("}")
	return "\"!\":" + jsonBuilder.String()
}

// R6 7.2: for every combination of settings, the section that the checker of turbo.config gets and the "!" that
// turbo.config and the panel get are what the map gave.
func TestR6_M72_SiteSettingsWrittenAsBefore(t *testing.T) {
	initForTest(t)
	certificates := []struct {
		state certificateState
		value interface{} // What "C" held
	}{
		{certificateState{}, false}, {certificateState{active: true}, true},
		{certificateState{failed: true, failure: `Certbot said: "no" & <stop> ñ`}, `Certbot said: "no" & <stop> ñ`},
		{certificateState{failed: true}, ""},
	}
	combinations := 0
	for _, https := range []bool{false, true} {
		for _, certificate := range certificates {
			for _, redirect := range []string{"", "R", "W", "RW"} {
				for _, email := range []string{"", "admin+certs@example.com"} {
					for _, adapter := range []string{"", "dns-example"} {
						settings := siteSettings{
							https: https, certificate: certificate.state, wwwToRoot: strings.Contains(redirect, "R"), rootToWWW: strings.Contains(redirect, "W"),
							email: email, adapter: adapter, precompressed: adapter != "" && https,
						}
						asMap := map[string]interface{}{"S": 0, "C": certificate.value, "R": settings.wwwToRoot, "W": settings.rootToWWW, "E": email, "A": adapter, "Z": settings.precompressed}
						if https {
							asMap["S"] = 1
						}
						var section map[string]interface{}
						var written string
						withGlobalLock(func() {
							*siteSSLConfig["localhost"] = settings
							section, written = siteSSLConfig["localhost"].asSection(), createSiteSettingsList("localhost")
						})
						if !reflect.DeepEqual(section, asMap) {
							t.Errorf("%+v as a section: %#v; the map was %#v", settings, section, asMap)
						}
						if expected := mapSiteSettingsList(asMap); written != expected {
							t.Errorf("%+v written: %s; from the map it was %s", settings, written, expected)
						}
						combinations++
					}
				}
			}
		}
	}
	withReadLock(func() {
		if written, expected := createSiteSettingsList("not-a-site.test"), mapSiteSettingsList(nil); written != expected {
			t.Errorf("a site without settings: %s; it was %s", written, expected)
		}
		var none *siteSettings
		if section := none.asSection(); section != nil || settingsOf("not-a-site.test") != (siteSettings{}) || httpsEnabled("not-a-site.test") {
			t.Errorf("a site without settings: the section %v, the settings %+v", section, settingsOf("not-a-site.test"))
		}
	})
	if combinations != 128 {
		t.Errorf("%d combinations", combinations)
	}
}

// R6 7.2: what an attempt of Certbot leaves in "C", and how the next "Create SSL" answers a failure: once, with its
// text, as when "C" held that text in place of its bool.
func TestR6_M72_CertificateStateOfAnAttempt(t *testing.T) {
	for _, c := range []struct {
		status   interface{}
		expected certificateState
	}{
		{true, certificateState{active: true}}, {false, certificateState{}},
		{"Certbot is not installed", certificateState{failed: true, failure: "Certbot is not installed"}},
		{"", certificateState{failed: true}}, {42, certificateState{failed: true, failure: "Invalid certificate response"}},
	} {
		if state := certificateStateOf(c.status); state != c.expected {
			t.Errorf("certificateStateOf(%#v) = %+v; expected %+v", c.status, state, c.expected)
		}
	}
	initForTest(t)
	create := func() (bool, string) {
		return lockedCheck(func() (bool, string) { return siteSSLSettingCheckers["C"](false, "1", "localhost", "") })
	}
	withGlobalLock(func() { siteSSLConfig["localhost"].certificate = certificateStateOf("Certbot failed: rate limited") })
	withReadLock(func() {
		if written := createSiteSettingsList("localhost"); !strings.Contains(written, `"C":"Certbot+failed%3A+rate+limited"`) {
			t.Errorf("with a failure to answer, the panel gets %s", written)
		}
	})
	if applied, answer := create(); applied || answer != "Certbot failed: rate limited" {
		t.Errorf("Create SSL after a failure: %v %q; expected the failure", applied, answer)
	}
	if applied, answer := create(); applied || answer != "E-mail required to create the certificate" {
		t.Errorf("Create SSL again: %v %q; expected the failure answered only once", applied, answer)
	}
	withReadLock(func() {
		if state := siteSSLConfig["localhost"].certificate; state != (certificateState{}) {
			t.Errorf("the state after the failure was answered: %+v", state)
		}
	})
}
