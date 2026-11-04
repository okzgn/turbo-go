package main

// File serving, rewrites, CGI and redirects (#12, #27, #32, #41,
// #46, #47, #48, #51).

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// #12: a preprocessor without an executable must not serve the source code.
func TestP12_PreprocessorFailOpen(t *testing.T) {
	dir := initForTest(t)
	exe := dir + "fake-cgi.exe"
	os.WriteFile(exe, []byte("x"), 0755)
	os.WriteFile(dir+"localhost/@/a.php", []byte("<?php $secret = 'key'; ?>"), 0644)
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"php": exe}, false, "localhost", ""); !ok {
		t.Fatalf("adding the preprocessor: %q", msg)
	}
	os.Remove(exe)
	base := startServer(t)
	code, body, err := get(base, "/a.php", nil)
	if err != nil || code != 500 || strings.Contains(body, "secret") {
		t.Fatalf("GET /a.php without the executable -> code=%d body=%q err=%v; expected 500 without the content", code, body, err)
	}
}

// #27: a failure to start the CGI answers 500 without the system error.
func TestP27_CGIErrorDisclosure(t *testing.T) {
	dir := initForTest(t)
	exe := dir + "not-executable.txt" // It exists, but it isn't executable
	os.WriteFile(exe, []byte("text"), 0644)
	os.WriteFile(dir+"localhost/@/b.cgi", []byte("x"), 0644)
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": exe}, false, "localhost", ""); !ok {
		t.Fatalf("adding the preprocessor: %q", msg)
	}
	base := startServer(t)
	code, body, err := get(base, "/b.cgi", nil)
	if err != nil || code != 500 || strings.Contains(body, "not-executable") || strings.Contains(body, "exec") {
		t.Fatalf("code=%d body=%q err=%v; expected 500 without details", code, body, err)
	}
}

// #48: the body sent to a CGI is limited to MBB, and the CGI doesn't get Turbo's environment (TURBO_PASSWORD).
func TestW_CGIBodyAndEnv(t *testing.T) {
	t.Setenv("TURBO_PASSWORD", "test-secret")
	cgiSite(t)
	base := startServer(t)
	body := bytes.Repeat([]byte("a"), 3*1024*1024)
	req, _ := http.NewRequest("POST", base+"/x.cgi?a=1", bytes.NewReader(body))
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 413 || strings.Contains(string(b), "BODY_BYTES=3145728") {
		t.Fatalf("POST of %d bytes with MBB=%d: code=%d; expected 413 without passing the body to the CGI\n%s", len(body), maxBodySize.Load(), res.StatusCode, b)
	}
	// The CGI gets the variables of the CGI specification and of the temporary folder, never Turbo's own environment
	code, output, err := get(base, "/x.cgi?a=1", nil)
	if err != nil || code != 200 {
		t.Fatalf("GET /x.cgi: %d %v", code, err)
	}
	if names := cgiEnv(output)["ENV_NAMES"]; strings.Contains(","+names+",", ",TURBO_PASSWORD,") {
		t.Errorf("TURBO_PASSWORD reaches the CGI: %s", names)
	}
}

// #32: QUERY_STRING without a stray "&" when the rewrite adds no query.
func TestW_CGIQueryString(t *testing.T) {
	cgiSite(t)
	base := startServer(t)
	code, body, err := get(base, "/x.cgi?a=1", nil)
	if err != nil || code != 200 || !strings.Contains(body, "QUERY_STRING=a=1\n") {
		t.Fatalf("code=%d err=%v; expected QUERY_STRING=a=1\n%s", code, err, body)
	}
}

// #27: a CGI that takes longer than the timeout (WT) is cut off and doesn't keep running.
func TestW_CGITimeout(t *testing.T) {
	dir := cgiSite(t)
	if ok, msg := defaultSettingValidators["."]["WT"]("500ms", "Admin"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	mark := dir + "finished"
	start := time.Now()
	code, _, err := get(base, "/x.cgi?sleep=2500&mark="+mark, nil)
	elapsed := time.Since(start)
	t.Logf("code=%d err=%v in %v", code, err, elapsed)
	if code != 504 {
		t.Errorf("code=%d; expected 504", code)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("the request took %v; expected the cut-off near 500ms", elapsed)
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(mark); err == nil {
		t.Error("the CGI kept running after the timeout")
	}
}

// #47: with several indexes, the one served is always the same (the first one added).
func TestW_IndexPriority(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/index.cgi", []byte("x"), 0644)
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", ""); !ok {
		t.Fatalf("adding the preprocessor: %q", msg)
	}
	if ok, msg := subdomainContentCheckers["-"](true, map[string]interface{}{"index.cgi": false}, false, "localhost", ""); !ok {
		t.Fatalf("adding the index: %q", msg)
	}
	base := startServer(t)
	html, cgi := 0, 0
	for i := 0; i < 30; i++ {
		_, body, err := rawGet(base, "localhost", "/")
		if err != nil {
			continue
		}
		if strings.Contains(body, "QUERY_STRING") {
			cgi++
		} else if strings.Contains(body, "hello") {
			html++
		}
		time.Sleep(40 * time.Millisecond)
	}
	if html != 30 {
		t.Fatalf("30 requests to / -> index.html=%d, index.cgi=%d; expected 30 from index.html", html, cgi)
	}
}

// #41: a wildcard subdomain is served over HTTP only once, without a redirect
// or "superfluous WriteHeader".
func TestW_Placeholders(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"example.com/@", 0755)
	os.MkdirAll(dir+"example.com/#/@", 0755)
	os.WriteFile(dir+"example.com/#/@/e.cgi", []byte("x"), 0644)
	updateSettings(false)
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "example.com", "*"); !ok {
		t.Fatalf("adding the preprocessor: %q", msg)
	}
	target := "/e.cgi?WS={WILDCARD_SITE}&WD={WILDCARD_DOMAIN}&WSUB={WILDCARD_SUBDOMAIN}&D={DOMAIN}&S={SUBDOMAIN}&SITE={SITE}&FD={FIRST_DOMAIN}&FS={FIRST_SUBDOMAIN}&FSITE={FIRST_SITE}&FR={FIRST_REQUEST}&FQ={FIRST_QUERY}&DIR={DIR}&FILE={FILE}&EXT={EXT}&RW={REWRITE}&RWC={REWRITE_COMPLEMENT}"
	if ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/p/": target}, false, "example.com", "*"); !ok {
		t.Fatalf("adding the rewrite: %q", msg)
	}
	if ok, msg := subdomainContentCheckers["&"](true, map[string]interface{}{"alias.test": false}, false, "example.com", "*"); !ok {
		t.Fatalf("adding the alias: %q", msg)
	}
	base, errLog := startServerLog(t)
	for _, h := range []string{"foo.example.com", "bar.foo.example.com", "alias.test"} {
		res, body, err := rawGet(base, h, "/p/dir/file.txt?q=1&r=2")
		if err != nil {
			t.Errorf("host=%s err=%v", h, err)
			continue
		}
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "QUERY_STRING=") {
				t.Logf("host=%s code=%d\n    %s", h, res.StatusCode, strings.ReplaceAll(l, "&", "\n    "))
			}
		}
		if res.StatusCode != 200 || res.Header.Get("Location") != "" {
			t.Errorf("host=%s -> %d Location=%q; expected 200 without a redirect", h, res.StatusCode, res.Header.Get("Location"))
		}
		if n := strings.Count(body, "QUERY_STRING="); n != 1 {
			t.Errorf("host=%s: CGI run %d times", h, n)
		}
	}
	if l := errLog.String(); strings.Contains(l, "superfluous") {
		t.Errorf("server errors:\n%s", l)
	}
}

// #46: rewrite redirects (DP8): the exact target if it has a path or a query;
// if it is just a domain, the original URI is appended.
func TestW_RewriteRedirect(t *testing.T) {
	initForTest(t)
	for k, v := range map[string]string{"/go/": "https://dest.example", "/gp/": "https://dest.example/target", "/gq/": "https://dest.example/target?x=1"} {
		if ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{k: v}, false, "localhost", ""); !ok {
			t.Fatalf("adding the rewrite %s -> %s: %q", k, v, msg)
		}
	}
	base := startServer(t)
	for p, want := range map[string]string{
		"/go/abc?q=2": "https://dest.example/go/abc?q=2",
		"/gp/abc?q=2": "https://dest.example/target",
		"/gq/abc?q=2": "https://dest.example/target?x=1",
	} {
		res, _, err := rawGet(base, "localhost", p)
		if err != nil {
			t.Errorf("%s -> err %v", p, err)
			continue
		}
		if res.StatusCode != 302 || res.Header.Get("Location") != want {
			t.Errorf("%s -> %d Location=%q; expected 302 %q", p, res.StatusCode, res.Header.Get("Location"), want)
		}
	}
}

// #41: an unconfigured subdomain of an existing site is not redirected to
// HTTPS: it answers 404. "/" is requested because "/index.html" always
// redirects to "./" (stdlib behavior, #39).
func TestW_UnknownSubdomain(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	for h, want := range map[string]int{"zzz.localhost": 404, "www.localhost": 404, "localhost": 200} {
		res, body, err := rawGet(base, h, "/")
		if err != nil {
			t.Errorf("%s err=%v", h, err)
			continue
		}
		if res.StatusCode != want || res.Header.Get("Location") != "" {
			t.Errorf("%s -> %d Location=%q body=%q; expected %d without a redirect", h, res.StatusCode, res.Header.Get("Location"), body, want)
		}
	}
}

// Character replacements apply to the values sent to the panel, not to the
// URIs received (the documentation says the opposite).
func TestW_CharReplaceIncoming(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/a;b.txt", []byte("file-with-semicolon"), 0644)
	os.WriteFile(dir+"localhost/@/a-.-b.txt", []byte("file-with-token"), 0644)
	base := startServer(t)
	for p, want := range map[string]string{"/a;b.txt": "file-with-semicolon", "/a-.-b.txt": "file-with-token"} {
		res, body, err := rawGet(base, "localhost", p)
		if err != nil || res.StatusCode != 200 || body != want {
			t.Errorf("%s -> %v %q %v; expected 200 %q", p, res, body, err, want)
		}
	}
}

// #51: error responses carry nosniff.
func TestW_ErrorHeaders(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	res, body, _ := rawGet(base, "localhost", "/nope")
	t.Logf("default 404: CT=%q body=%q", res.Header.Get("Content-Type"), body)
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("default 404 without nosniff")
	}
	adminAddHandlers["#"]("404", "<h1>Error {TURBO_RESPONSE_CODE}</h1>")
	res, body, _ = rawGet(base, "localhost", "/nope")
	t.Logf("404 HTML: CT=%q body=%q", res.Header.Get("Content-Type"), body)
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("404 HTML without nosniff")
	}
}

// #12: the dx> prefix is not implemented and is rejected when a preprocessor
// is added.
func TestP12_PreprocessorDxRejected(t *testing.T) {
	initForTest(t)
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"php": "dx>" + toolPath("cgiecho")}, false, "localhost", "")
	if ok {
		t.Fatalf("dx> accepted: %q", msg)
	}
	ok, msg = subdomainContentCheckers["?"](true, map[string]interface{}{"php": "cgi>" + toolPath("cgiecho")}, false, "localhost", "")
	if !ok {
		t.Fatalf("cgi> rejected: %q", msg)
	}
}

// #69: on a new installation, a site found in the directory has index.html
// as its index, and "/" answers 200.
func TestW_NewInstallIndex(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir()) + "/"
	resetTestState(dir)
	t.Cleanup(func() {
		serverSetLogState(visitsLogName, nil)
		serverSetLogState(denialsLogName, nil)
	})
	os.MkdirAll(dir+"localhost/@", 0755)
	os.WriteFile(dir+"localhost/@/index.html", []byte("hello"), 0644)
	updateSettings(false)
	base := startServer(t)
	if code, body, err := get(base, "/", nil); err != nil || code != 200 || body != "hello" {
		t.Fatalf("GET / -> %d %q %v; expected 200 hello", code, body, err)
	}
}

// #15: a rewrite whose placeholders produce ".." doesn't leave the content
// directory: {FILE} of "/r/.." is "..", and "/{FILE}/{FILE}/x.cgi" pointed
// to a CGI two folders above @.
func TestW_PlaceholderTraversal(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"x.cgi", []byte("x"), 0644) // Outside @
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", ""); !ok {
		t.Fatalf("adding the preprocessor: %q", msg)
	}
	if ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/r/": "/{FILE}/{FILE}/x.cgi"}, false, "localhost", ""); !ok {
		t.Fatalf("adding the rewrite: %q", msg)
	}
	base := startServer(t)
	res, body, err := rawGet(base, "localhost", "/r/..")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("/r/.. -> %d", res.StatusCode)
	if strings.Contains(body, "SCRIPT_FILENAME") {
		t.Fatalf("a CGI outside @ was run:\n%s", body)
	}
}

// §5.2 (DP10): the indexes of a turbo.config in schema 1 take the order of the
// file; they are saved with their position, and a reload keeps the order.
func TestC_IndexOrderMigration(t *testing.T) {
	dir := initForTest(t)
	names := []string{"z.html", "a.html", "m.html", "b.html", "y.html"}
	cfg := `{"localhost":{"":{"-":{"z.html":"","a.html":"","m.html":"","b.html":"","y.html":""}}}}`
	resetSettings() // As at startup: the site doesn't exist yet when turbo.config is read
	loadConfig(t, dir, cfg)
	check := func(when string) {
		t.Helper()
		globalMutex.RLock()
		got := orderedIndexes("localhost")
		globalMutex.RUnlock()
		if strings.Join(got, ",") != strings.Join(names, ",") {
			t.Fatalf("%s: order %v; expected %v", when, got, names)
		}
	}
	check("after migrating")
	saveDefaultConfig() // It takes the locks itself (T20)
	raw := savedConfig(t, dir)
	indexes := raw["localhost"][""].(map[string]interface{})["-"].(map[string]interface{})
	for i, n := range names {
		if indexes[n] != strconv.Itoa(i+1) {
			t.Errorf("saved position of %s: %v; expected %d", n, indexes[n], i+1)
		}
	}
	b, _ := os.ReadFile(dir + "turbo.config")
	loadConfig(t, dir, string(b))
	check("after reloading")
}

// #12: read from turbo.config, a preprocessor without an executable or with dx>
// doesn't let the source code be served, doesn't keep the others from loading
// and isn't lost when saving.
func TestP12_PreprocessorFailClosedFromConfig(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/a.php", []byte("<?php $secret = 'key'; ?>"), 0644)
	os.WriteFile(dir+"localhost/@/b.dx", []byte("secret dx"), 0644)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	cfg := `{"localhost":{"":{"?":{"php":"cgi>` + dir + `missing.exe","dx":"dx>` + dir + `something","cgi":"` + toolPath("cgiecho") + `"}}}}`
	resetSettings()
	loadConfig(t, dir, cfg)
	base := startServer(t)
	for _, p := range []string{"/a.php", "/b.dx"} {
		if code, body, err := get(base, p, nil); err != nil || code != 500 || strings.Contains(body, "secret") {
			t.Errorf("GET %s -> %d %q %v; expected 500 without the content", p, code, body, err)
		}
	}
	if code, body, _ := get(base, "/x.cgi", nil); code != 200 || !strings.Contains(body, "QUERY_STRING") {
		t.Errorf("the valid preprocessor was not loaded: %d %q", code, body)
	}
	saveDefaultConfig() // It takes the locks itself (T20)
	pre := savedConfig(t, dir)["localhost"][""].(map[string]interface{})["?"].(map[string]interface{})
	if pre["php"] == nil || pre["dx"] == nil {
		t.Errorf("saved preprocessors: %v; expected php and dx", pre)
	}
}

// T1.3 review: the site's headers go on the files served, not on the 404s
// (a long Cache-Control would make a cache keep the 404).
func TestW_SiteHeadersNotOn404(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["."](true, map[string]interface{}{"Cache-Control": "max-age=31536000"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("addHeader: %q", msg)
	}
	base := startServer(t)
	res, _, err := rawGet(base, "localhost", "/missing")
	if err != nil || res.StatusCode != 404 || res.Header.Get("Cache-Control") != "" {
		t.Errorf("404 -> %v Cache-Control=%q; expected without the site's header", err, res.Header.Get("Cache-Control"))
	}
	res, _, err = rawGet(base, "localhost", "/")
	if err != nil || res.StatusCode != 200 || res.Header.Get("Cache-Control") != "max-age=31536000" {
		t.Errorf("200 -> %v Cache-Control=%q; expected the site's header", err, res.Header.Get("Cache-Control"))
	}
}
