package main

// B9 (H17-H21): the API does what its specification says.

import (
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// H17 (D7): R (www → root) and W (root → www) are set at the root of the
// site, which is where they apply; on a subdomain they are rejected.
func TestB9_RootRedirectsOnlyAtRoot(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/www/@", 0755)
	updateSettings(true)
	base := startServer(t)
	tok := login(t, base)
	for _, path := range []string{"/admin:inside:cfgR?s=localhost&d=www&a=1", "/admin:inside:cfgW?s=localhost&d=www&a=1"} {
		if code, body, _ := post(base, path, tok); code != 400 || !strings.Contains(body, "site's root") {
			t.Errorf("%s: %d %q; expected 400 because it isn't the root", path, code, body)
		}
	}
	if code, body, _ := post(base, "/admin:inside:cfgR?s=localhost&d=&a=1", tok); code != 200 {
		t.Fatalf("cfgR at the root: %d %q", code, body)
	}
	res, _, err := rawGet(base, "www.localhost", "/x")
	if err != nil || res.StatusCode != 301 || res.Header.Get("Location") != "http://localhost/x" {
		t.Errorf("www.localhost with R at the root: %v %v; expected 301 to http://localhost/x", res, err)
	}
}

// H18 (D8): "Create SSL" with the issuance in progress answers 202 with the
// wait JSON, not 400.
func TestB9_CertificateWaitIs202(t *testing.T) {
	useFakeCertbot(t, "ok")
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	globalMutex.Lock()
	currentCertDomain = "localhost"
	globalMutex.Unlock()
	t.Cleanup(func() { withGlobalLock(func() { currentCertDomain = "" }) })
	code, body, _ := post(base, "/admin:inside:cfgC?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"1"}, "z": {"admin@localhost.test"}}.Encode(), tok)
	if code != 202 || !strings.Contains(body, `"status":"WAIT"`) {
		t.Errorf("cfgC with the issuance in progress: %d %q; expected 202 with status WAIT", code, body)
	}
}

// H19: with RT = 0 (no limit), RHT accepts any value in its range.
func TestB9_RHTWithoutRT(t *testing.T) {
	initForTest(t)
	previous := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = previous }) }) })
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := defaultSettingValidators["."]["RT"]("0s", internalAuth); !ok {
		t.Fatalf("RT=0: %q", msg)
	}
	if ok, msg := defaultSettingValidators["."]["RHT"]("2s", internalAuth); !ok {
		t.Errorf("RHT=2s with RT=0: %q; expected accepted", msg)
	}
}

// H20: "Delete SSL" deletes the certificate even when it is older than 75 days.
func TestB9_DeleteOldCertificate(t *testing.T) {
	dir := initForTest(t)
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		os.WriteFile(dir+"localhost/"+name, []byte("x"), 0600)
		old := time.Now().Add(-80 * 24 * time.Hour)
		os.Chtimes(dir+"localhost/"+name, old, old)
	}
	globalMutex.Lock()
	ok, msg := siteSSLSettingCheckers["C"](false, "0", "localhost", "")
	globalMutex.Unlock()
	if !ok || msg != "SSL certificate deleted" || fileExists(dir+"localhost/fullchain.pem") || fileExists(dir+"localhost/privkey.pem") {
		t.Errorf("cfgC a=0 with an 80-day-old certificate: %v %q; expected deleted", ok, msg)
	}
}

// H21: every text parameter goes through the character replacement (§2.1),
// also the response template and the name of a header.
func TestB9_AllTextParametersReplaced(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	// Production review, B2: the replacements, which need the password now, apply to the actions that need only
	// the session; those that take the password, and the replacements and the responses themselves, take their
	// values as sent.
	if code, body, _ := post(base, "/admin:inside:addCharsReplace?"+url.Values{"s": {"|"}, "d": {"zz"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("addCharsReplace: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:addHttpCodeResponse?"+url.Values{"s": {"404"}, "d": {"-,- does not exist"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("addHttpCodeResponse: %d %q", code, body)
	}
	if got := (*httpResponses.Load())[404]; got != "-,- does not exist" {
		t.Errorf("saved template %q; expected it as sent, \"-,- does not exist\"", got)
	}
	if code, body, _ := post(base, "/admin:inside:addHeader?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-Test"}, "b": {"1zz2"}}.Encode(), tok); code != 200 {
		t.Fatalf("addHeader: %d %q", code, body)
	}
	globalMutex.RLock()
	value := customHeaders["localhost"]["X-Test"]
	globalMutex.RUnlock()
	if value != "1|2" {
		t.Errorf("the header value 1zz2 was saved as %q; expected 1|2", value)
	}
	if code, body, _ := post(base, "/admin:inside:delHeader?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-Test"}}.Encode(), tok); code != 200 {
		t.Errorf("delHeader X-Test: %d %q", code, body)
	}
}

// CAL8: a MIME or a preprocessor written with the leading dot (".css") is the
// same one as without it: if it already exists with the same value, the answer
// is "unchanged"; if the value changes, "changed", never "created".
func TestCAL8_ExtensionWithDot(t *testing.T) {
	servingFixture(t)
	check := func(kind string, value string) (bool, string) {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		return subdomainContentCheckers[kind](true, map[string]interface{}{".zzq": value}, false, "localhost", "")
	}
	if ok, msg := check("$", "text/x-one"); !ok || msg != "MIME created" {
		t.Fatalf("first MIME .zzq: %v %q", ok, msg)
	}
	if ok, msg := check("$", "text/x-one"); ok || msg != "MIME unchanged" {
		t.Errorf("same MIME .zzq again: %v %q; expected \"MIME unchanged\"", ok, msg)
	}
	if ok, msg := check("$", "text/x-two"); !ok || msg != "MIME changed" {
		t.Errorf("another MIME for .zzq: %v %q; expected \"MIME changed\"", ok, msg)
	}
}
