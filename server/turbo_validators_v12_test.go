package server

// Review of 6046dbe (R6), V-12: the minor points of the validators. An e-mail that can't be removed, headers that only
// HTTP sets, ports that don't exist, a header deleted only in its own case, MIME types and index positions of
// turbo.config, messages of "unchanged" that compared what wasn't normalized yet, sites named as an IP address, the
// time of Certbot with a DNS adapter, and a way to change the sites directory that production doesn't use.

import (
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// R6 V-12a: cfgE with an empty value removes the e-mail of a site: its certificate stays, and is no longer renewed.
// No empty e-mail was accepted, so the only way to stop the renewal was to delete the certificate.
func TestR6_V12a_EmptyEmailStopsTheRenewal(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	send := func(path string) (int, string) {
		t.Helper()
		code, body, err := post(base, path, tok)
		if err != nil {
			t.Fatal(err)
		}
		return code, body
	}
	if code, body := send("/admin:inside:cfgE?s=localhost&d=&a=" + url.QueryEscape("admin@example.test")); code != 200 || body != "E-mail saved" {
		t.Fatalf("cfgE with an e-mail: %d %q", code, body)
	}
	// With the e-mail, a certificate issued by Turbo that expires in less than 30 days is renewed
	writeTestCertificate(t, dir+"localhost/", 24*time.Hour, "localhost")
	os.MkdirAll(dir+"turbo.certificates/localhost", 0700)
	renewCertificates()
	waitIdle()
	calls := func() int {
		data, _ := os.ReadFile(logf)
		return strings.Count(string(data), "\n")
	}
	before := calls()
	if before == 0 {
		t.Fatal("the certificate wasn't renewed with the e-mail: the test proves nothing")
	}
	if code, body := send("/admin:inside:cfgE?s=localhost&d=&a="); code != 200 || body != "E-mail removed" {
		t.Errorf("cfgE with an empty value: %d %q; expected 200 \"E-mail removed\"", code, body)
	}
	globalMutex.RLock()
	email := siteSSLConfig["localhost"].asSection()["E"]
	globalMutex.RUnlock()
	if email != "" {
		t.Errorf("the e-mail after removing it: %q", email)
	}
	if code, body := send("/admin:inside:cfgE?s=localhost&d=&a="); code != 400 || body != "E-mail unchanged" {
		t.Errorf("cfgE with an empty value, without an e-mail: %d %q; expected 400 \"E-mail unchanged\"", code, body)
	}
	writeTestCertificate(t, dir+"localhost/", 24*time.Hour, "localhost")
	renewCertificates()
	waitIdle()
	if after := calls(); after != before {
		t.Errorf("Certbot ran %d more times after the e-mail was removed; expected none", after-before)
	}
	if !fileExists(dir + "localhost/" + certFileName) {
		t.Error("removing the e-mail deleted the certificate")
	}
	// "Create SSL" still needs one
	os.Remove(dir + "localhost/" + certFileName)
	os.Remove(dir + "localhost/" + keyFileName)
	if code, body := send("/admin:inside:cfgC?s=localhost&d=&a=1"); code != 400 || body != "E-mail required to create the certificate" {
		t.Errorf("Create SSL without an e-mail: %d %q", code, body)
	}
}

// R6 V-12b: a site can't set the headers that HTTP itself sets for the connection and the length of the body, which
// could cut or join responses. From turbo.config, they are discarded with a warning.
func TestR6_V12b_HeadersThatHTTPSets(t *testing.T) {
	dir := initForTest(t)
	add := func(name string) (bool, string) {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		return subdomainContentCheckers["."](true, map[string]interface{}{name: "x"}, false, "localhost", "")
	}
	for _, name := range []string{"Content-Length", "transfer-encoding", "Connection", "Keep-Alive", "Proxy-Connection", "TE", "Trailer", "Upgrade"} {
		if ok, msg := add(name); ok || msg != "Header reserved" {
			t.Errorf("addHeader %s: %v %q; expected \"Header reserved\"", name, ok, msg)
		}
	}
	if ok, msg := add("X-Test"); !ok {
		t.Errorf("addHeader X-Test: %q", msg)
	}
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{".":{"Connection":"close","X-Ok":"1"}}}}`)
	globalMutex.RLock()
	headers := customHeaders["localhost"]
	globalMutex.RUnlock()
	if _, kept := headers["Connection"]; kept || headers["X-Ok"] != "1" {
		t.Errorf("the headers of turbo.config: %v; expected X-Ok without Connection", headers)
	}
	if !strings.Contains(logs.String(), "Header reserved") {
		t.Errorf("no warning for the header discarded:\n%s", logs.String())
	}
}

// R6 V-12c: a port above 65535 isn't a host. It was taken as one, and a request with it was served.
func TestR6_V12c_PortsThatDontExist(t *testing.T) {
	for host, want := range map[string]string{"localhost:65535": "localhost:65535", "[::1]:443": "[::1]:443", "localhost:00080": "localhost:00080"} {
		if got, ok := canonicalHost(host); !ok || got != want {
			t.Errorf("canonicalHost(%q) = %q, %v; expected %q", host, got, ok, want)
		}
	}
	for _, host := range []string{"localhost:65536", "localhost:99999", "[::1]:70000", "127.0.0.1:65536"} {
		if got, ok := canonicalHost(host); ok {
			t.Errorf("canonicalHost(%q) = %q; expected it refused", host, got)
		}
	}
	initForTest(t)
	addr := strings.TrimPrefix(startServer(t), "http://")
	for host, code := range map[string]int{"localhost:99999": 400, "localhost:65535": 200} {
		if res, body := sendRaw(t, addr, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); res.StatusCode != code {
			t.Errorf("Host %q: %d %q; expected %d", host, res.StatusCode, body, code)
		}
	}
}

// R6 V-12d: delHeader deletes a header written in other capitals, as addHeader replaces it. It answered "Header not
// found" for "x-test" when the site had "X-Test".
func TestR6_V12d_DelHeaderIgnoresCase(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := subdomainContentCheckers["."](true, map[string]interface{}{"X-Test": "1"}, false, "localhost", ""); !ok {
		t.Fatalf("addHeader: %q", msg)
	}
	if ok, msg := subdomainContentDeleters["."](true, map[string]interface{}{"x-test": ""}, "localhost", ""); !ok || msg != "Header deleted" {
		t.Errorf("delHeader x-test of X-Test: %v %q; expected \"Header deleted\"", ok, msg)
	}
	if len(customHeaders["localhost"]) != 0 {
		t.Errorf("headers left: %v", customHeaders["localhost"])
	}
	if ok, msg := subdomainContentDeleters["."](true, map[string]interface{}{"X-Missing": ""}, "localhost", ""); ok || msg != "Header not found" {
		t.Errorf("delHeader of a header that isn't there: %v %q", ok, msg)
	}
}

// R6 V-12e: an extension written twice in the MIME types of a site of turbo.config (".HTML" and "html" are the same)
// keeps the first one, with a warning, as the headers do. The second replaced the first without a word.
func TestR6_V12e_ExtensionTwiceInTurboConfig(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"$":{".HTML":"text/html; charset=utf-8","html":"text/plain"}}}}`)
	globalMutex.RLock()
	got := mimeTypes["localhost"]["html"]
	globalMutex.RUnlock()
	if got != "text/html; charset=utf-8" {
		t.Errorf("the MIME type of html: %q; expected the first one", got)
	}
	if !strings.Contains(logs.String(), "MIME repeated in turbo.config") {
		t.Errorf("no warning for the extension written twice:\n%s", logs.String())
	}
}

// R6 V-12f: the position of an index in turbo.config can also be a JSON number. Only text was read: "b.html": 1
// went last.
func TestR6_V12f_IndexPositionAsANumber(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"b.html":1,"a.html":"2","c.html":3}}}}`)
	globalMutex.RLock()
	got := orderedIndexes("localhost")
	globalMutex.RUnlock()
	if want := []string{"b.html", "a.html", "c.html"}; !reflect.DeepEqual(got, want) {
		t.Errorf("indexes: %v; expected %v", got, want)
	}
}

// R6 V-12g: "unchanged" is decided on the values as they are kept, not as they were written: a date with a leading
// zero, a rewrite to another host, and a CIL whose milliseconds overflowed into the value in use.
func TestR6_V12g_UnchangedAfterNormalizing(t *testing.T) {
	initForTest(t)
	until := time.Now().Add(time.Hour).Unix()
	date := strconv.FormatInt(until, 10)
	addDenied := func(when string) (bool, string) {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		return adminAddHandlers["@"]("203.0.113.5", when)
	}
	if ok, msg := addDenied(date); !ok || msg != "Denied IP added" {
		t.Fatalf("addDenied: %v %q", ok, msg)
	}
	if ok, msg := addDenied("0" + date); ok || msg != "Denied IP unchanged" {
		t.Errorf("addDenied with the same date written with a leading zero: %v %q; expected \"Denied IP unchanged\"", ok, msg)
	}
	addRewrite := func(target string) (bool, string) {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		return subdomainContentCheckers["="](true, map[string]interface{}{"/ext": target}, false, "localhost", "")
	}
	if ok, msg := addRewrite("https://example.com/x"); !ok || msg != "Rewrite created" {
		t.Fatalf("addRewrite: %v %q", ok, msg)
	}
	for _, same := range []string{"https://example.com/x", "HTTPS://example.com/x"} {
		if ok, msg := addRewrite(same); ok || msg != "Rewrite unchanged" {
			t.Errorf("addRewrite of the same target %q: %v %q; expected \"Rewrite unchanged\"", same, ok, msg)
		}
	}
	if ok, msg := addRewrite("example.com/x"); ok || msg == "Rewrite unchanged" {
		t.Errorf("addRewrite of a target without a scheme or /: %v %q; expected the reason it is refused", ok, msg)
	}
	if ok, msg := addRewrite("http://example.com/x"); !ok || msg != "Rewrite changed" {
		t.Errorf("addRewrite to http: %v %q; expected \"Rewrite changed\"", ok, msg)
	}
	// 10000 + 2^58 milliseconds overflow, in nanoseconds, into the 10 s in use
	globalMutex.Lock()
	ok, msg := defaultSettingValidators["."]["CIL"]("288230376151721744", "Admin")
	globalMutex.Unlock()
	if ok || msg != "More than 800000 milliseconds" {
		t.Errorf("CIL far out of range: %v %q; expected \"More than 800000 milliseconds\"", ok, msg)
	}
}

// R6 V-12h: only the site "*" serves an IP address, so a site named as one is never reached. addSite refuses it;
// a folder or a site of turbo.config named so is activated, as before, with a warning, once.
func TestR6_V12h_SiteNamedAsAnIPAddress(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, name := range []string{"192.168.1.10", "10.0.0.1"} {
		code, body, err := post(base, "/admin:inside:addSite?s="+name, tok)
		if err != nil || code != 400 || !strings.Contains(body, "Only the site * serves an IP address") {
			t.Errorf("addSite %s: %d %q %v; expected 400", name, code, body, err)
		}
	}
	if code, body, _ := post(base, "/admin:inside:addSite?s=10.0.0.1.example", tok); code != 200 {
		t.Errorf("addSite of a name that only starts as an IP address: %d %q", code, body)
	}
	logs := captureLog(t)
	os.MkdirAll(dir+"10.0.0.2/@", 0755)
	for i := 0; i < 2; i++ {
		updateSettings(true)
	}
	globalMutex.RLock()
	active := siteExists("10.0.0.2", "")
	globalMutex.RUnlock()
	if !active {
		t.Error("the folder named as an IP address isn't activated")
	}
	if warnings := strings.Count(logs.String(), "named as an IP address"); warnings != 1 {
		t.Errorf("%d warnings in two reloads; expected 1:\n%s", warnings, logs.String())
	}
	logs.Reset()
	os.MkdirAll(dir+"10.0.0.3/@", 0755)
	loadConfig(t, dir, `{"^":{"v":"2"},"10.0.0.3":{"":{}}}`)
	globalMutex.RLock()
	active = siteExists("10.0.0.3", "")
	globalMutex.RUnlock()
	if !active || !strings.Contains(logs.String(), "named as an IP address") {
		t.Errorf("a site of turbo.config named as an IP address: active %v; log:\n%s", active, logs.String())
	}
}

// R6 V-12i: Certbot has 10 minutes with a DNS adapter, which waits for the records to propagate, and 3 without one.
// It had 3 in both cases.
func TestR6_V12i_CertbotTimeWithADNSAdapter(t *testing.T) {
	if certbotTimeLimit != 3*time.Minute || certbotDNSTimeLimit != 10*time.Minute {
		t.Errorf("the times of Certbot: %v and %v with an adapter; expected 3 and 10 minutes", certbotTimeLimit, certbotDNSTimeLimit)
	}
	if certbotTimeLimitFor(certbotJob{}) != certbotTimeLimit || certbotTimeLimitFor(certbotJob{adapter: "dns-route53"}) != certbotDNSTimeLimit {
		t.Error("certbotTimeLimitFor doesn't give the time of the adapter")
	}
	useFakeCertbot(t, "ok")
	t.Setenv("FAKE_CERTBOT_DELAY", "1500")
	webroot, dns := certbotTimeLimit, certbotDNSTimeLimit
	certbotTimeLimit, certbotDNSTimeLimit = 300*time.Millisecond, 30*time.Second
	t.Cleanup(func() { certbotTimeLimit, certbotDNSTimeLimit = webroot, dns })
	dir := initForTest(t)
	issue := func(adapter string) interface{} {
		t.Helper()
		done := make(chan interface{}, 1)
		job := certbotJob{names: []string{"localhost"}, email: "admin@localhost.test", adapter: adapter, webroot: dir + "localhost/@", certDir: dir + "turbo.certificates/localhost", destDir: dir + "localhost/"}
		withGlobalLock(func() {
			startCertbot("localhost", func() (certbotJob, bool) { return job, true }, func(status interface{}) { done <- status })
		})
		select {
		case status := <-done:
			return status
		case <-time.After(60 * time.Second):
			t.Fatal("no result from Certbot")
		}
		return nil
	}
	if status := issue(""); status == true {
		t.Error("without an adapter, a Certbot slower than its time ended well")
	}
	if status := issue("dns-test"); status != true {
		t.Errorf("with an adapter, a Certbot within its time: %v", status)
	}
}

// R6 V-12j: the sites directory changes only with setM (setSitesDir), which follows it with its configuration. The
// validator of "M" also changed it, outside a reload, without reading anything there: only tests used that way.
func TestR6_V12j_SitesDirectoryOnlyWithSetM(t *testing.T) {
	dir := initForTest(t)
	other := filepath.ToSlash(t.TempDir()) + "/"
	globalMutex.Lock()
	ok, _ := defaultSettingValidators["."]["M"](other, "Admin")
	globalMutex.Unlock()
	if ok || sitesDir.Get() != dir {
		t.Errorf("the validator of M outside a reload: %v, sites directory %q; expected %q unchanged", ok, sitesDir.Get(), dir)
	}
	if ok, msg := setSitesDir(other, ""); !ok || sitesDir.Get() != other {
		t.Errorf("setSitesDir: %v %q, sites directory %q", ok, msg, sitesDir.Get())
	}
}
