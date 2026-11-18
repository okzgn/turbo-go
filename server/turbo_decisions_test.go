package server

// Review of 6046dbe (R6), 7.1: what the code decides by the answer of a validator. The answers that mean "nothing to
// do" (a value that is already the one in use, a fixed replacement, a denial that has ended) and the one that means
// "wait" (a certificate that Certbot is working on) are named once, where they are given and where they are looked
// for: a text edited in one place and not in the other changed what Turbo does without a word.

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// R6 7.1: loading a turbo.config, the entries that only repeat what is in use, the fixed replacement and the denial
// that has ended are no mistakes of the file, and the log says nothing of them; the ones that are mistakes are each
// in the log, and a setting that is one is left at its default.
func TestR6_M71_ConfigEntriesThatAreNoMistake(t *testing.T) {
	dir := initForTest(t)
	logged := captureLog(t)
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	loadConfig(t, dir, `{"^":{"v":"2"},
		"_":{";":"-.-", "~":"-tilde-", " ~":"-tilde-", "abcde":"-long-"},
		"@":{"203.0.113.5":"`+future+`", "::ffff:203.0.113.5":"`+future+`", "203.0.113.6":"1", "not-an-ip":"`+future+`"},
		"#":{"404":"gone", "0404":"gone", "200":"fine"},
		".":{"CII":"100", "CGL":"5"}}`)
	log := logged.String()
	for _, expected := range []string{
		`character replacement discarded" character=abcde`, `denied IP discarded" ip=not-an-ip`,
		`response discarded" code=200`, `the default value is used" key=CGL`,
	} {
		if strings.Count(log, expected) != 1 {
			t.Errorf("the log has %d times %q; expected once:\n%s", strings.Count(log, expected), expected, log)
		}
	}
	if count := strings.Count(log, "discarded"); count != 4 {
		t.Errorf("%d entries discarded in the log; expected the 4 that are mistakes:\n%s", count, log)
	}
	withReadLock(func() {
		if charReplacements["~"] != "-tilde-" || charReplacements[";"] != "-.-" {
			t.Errorf("the replacements: %v", charReplacements)
		}
		if (*httpResponses.Load())[404] != "gone" {
			t.Errorf("the response of 404: %q", (*httpResponses.Load())[404])
		}
	})
	if deniedUntil(clientOf("203.0.113.5")) == 0 || deniedUntil(clientOf("203.0.113.6")) != 0 {
		t.Errorf("the denied IPs: %v", deniedIPsInUse())
	}
	if serverRequestLimits.CII.Load() != 100 || globalRequestLimit.Load() != 0 {
		t.Errorf("CII %d and CGL %d; expected 100, and the default 0", serverRequestLimits.CII.Load(), globalRequestLimit.Load())
	}
}

// R6 7.1: the validators answer with the texts that the API has always given for those cases.
func TestR6_M71_AnswersThatTheCodeLooksFor(t *testing.T) {
	initForTest(t)
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	for name, step := range map[string]struct {
		run      func() (bool, string)
		expected string
	}{
		"a setting as it is":        {func() (bool, string) { return defaultSettingValidators["."]["CII"]("100", internalAuth) }, "Value unchanged"},
		"a fixed replacement added": {func() (bool, string) { return adminAddHandlers["_"](";", "-other-") }, "Fixed replacement"},
		"a fixed one removed":       {func() (bool, string) { return adminDeleteHandlers["_"](";") }, "Fixed replacement"},
		"a denial that ended":       {func() (bool, string) { return adminAddHandlers["@"]("203.0.113.9", "1") }, "Expired UNIX date"},
		"a response as it is":       {func() (bool, string) { adminAddHandlers["#"]("404", "x"); return adminAddHandlers["#"]("404", "x") }, "Response unchanged"},
		"a replacement as it is":    {func() (bool, string) { adminAddHandlers["_"]("~", "-t-"); return adminAddHandlers["_"]("~", "-t-") }, "Replacement unchanged"},
		"a denial as it is": {func() (bool, string) {
			adminAddHandlers["@"]("203.0.113.8", future)
			return adminAddHandlers["@"]("203.0.113.8", future)
		}, "Denied IP unchanged"},
	} {
		if applied, message := lockedCheck(step.run); applied || message != step.expected {
			t.Errorf("%s: %v %q; expected %q, refused", name, applied, message, step.expected)
		}
	}
	for message, expected := range map[string]bool{
		certificateWait("Please wait, certificate in process"):                       true,
		`{"message":"Please wait, certificate busy on example.com","status":"WAIT"}`: true,
		"E-mail required to create the certificate":                                  false,
		"": false,
	} {
		if isCertificateWait(message) != expected {
			t.Errorf("isCertificateWait(%q) = %v", message, !expected)
		}
	}
	if wait := certificateWait("Please wait, certificate in process"); wait != `{"message":"Please wait, certificate in process","status":"WAIT"}` {
		t.Errorf("certificateWait: %s", wait)
	}
}

// R6 7.1: every action on the content or the settings of a site answers the same for a site that isn't one, and for
// a subdomain that isn't one of a site that is.
func TestR6_M71_ActionsOnASiteThatIsNotThere(t *testing.T) {
	initForTest(t)
	content := map[string]map[string]interface{}{
		"=": {"/a": "/b"}, "$": {"css": "text/css"}, ".": {"X-A": "b"}, "?": {"cgi": toolPath("cgiecho")}, "-": {"index.html": "1"},
	}
	settings := map[string]string{"E": "a@example.com", "A": "dns-example", "C": "0", "S": "0"}
	for _, site := range []struct{ domain, subdomain, expected string }{
		{"missing.test", "", "Site not found"}, {"missing.test", "sub", "Subdomain not found"}, {"localhost", "sub", "Subdomain not found"},
	} {
		for kind, entry := range content {
			if applied, answer := lockedCheck(func() (bool, string) {
				return subdomainContentCheckers[kind](true, entry, false, site.domain, site.subdomain)
			}); applied || answer != site.expected {
				t.Errorf("%q for %q/%q: %v %q; expected %q", kind, site.subdomain, site.domain, applied, answer, site.expected)
			}
		}
		for key, value := range settings {
			if applied, answer := lockedCheck(func() (bool, string) {
				return siteSSLSettingCheckers[key](false, value, site.domain, site.subdomain)
			}); applied || answer != site.expected {
				t.Errorf("setting %s for %q/%q: %v %q; expected %q", key, site.subdomain, site.domain, applied, answer, site.expected)
			}
		}
	}
	for _, key := range []string{"R", "W"} { // Of the domain only
		if applied, answer := lockedCheck(func() (bool, string) { return siteSSLSettingCheckers[key](false, "0", "missing.test", "") }); applied || answer != "Site not found" {
			t.Errorf("setting %s for missing.test: %v %q", key, applied, answer)
		}
	}
}
