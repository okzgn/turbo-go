package server

// The expressions of the headers of a site: a value written with "=" before it is computed for each request, from
// what the request names and what it sends, within the rules of the package expr.

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"turbo/internal/expr"
)

// addSiteHeaders adds the headers of the site localhost as addHeader does, and fails the test if one is refused.
func addSiteHeaders(t *testing.T, headers map[string]string) {
	t.Helper()
	globalMutex.Lock()
	defer globalMutex.Unlock()
	for name, value := range headers {
		if ok, message := subdomainContentCheckers["."](true, map[string]interface{}{name: value}, false, "localhost", ""); !ok {
			t.Fatalf("addHeader %s: %q", name, message)
		}
	}
}

// requestWithHeaders makes a request to the server at base, for host, with the headers given.
func requestWithHeaders(t *testing.T, method string, base string, host string, path string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	request, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response, string(body)
}

// A header computed by extension: the files that change with each version are kept by the browsers for a year, the
// pages aren't. EXT is the extension of the file served: "/" serves index.html, whose extension is html.
func TestHeaderExpressionByExtension(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/app.js", []byte("js"), 0644)
	os.WriteFile(dir+"localhost/@/page.html", []byte("html"), 0644)
	addSiteHeaders(t, map[string]string{"Cache-Control": "=EXT in ['js', 'css'] ? 'public, max-age=31536000' : 'no-cache'"})
	base := startServer(t)
	for path, want := range map[string]string{"/app.js": "public, max-age=31536000", "/page.html": "no-cache", "/": "no-cache"} {
		response, _ := requestWithHeaders(t, "GET", base, "localhost", path, nil)
		if response.StatusCode != 200 || response.Header.Get("Cache-Control") != want {
			t.Errorf("%s: %d Cache-Control %q; expected %q", path, response.StatusCode, response.Header.Get("Cache-Control"), want)
		}
	}
	// HEAD and a range carry it too
	if response, _ := requestWithHeaders(t, "HEAD", base, "localhost", "/app.js", nil); response.Header.Get("Cache-Control") != "public, max-age=31536000" {
		t.Errorf("HEAD: Cache-Control %q", response.Header.Get("Cache-Control"))
	}
	if response, body := requestWithHeaders(t, "GET", base, "localhost", "/app.js", map[string]string{"Range": "bytes=0-0"}); response.StatusCode != 206 || body != "j" || response.Header.Get("Cache-Control") != "public, max-age=31536000" {
		t.Errorf("a range: %d %q Cache-Control %q", response.StatusCode, body, response.Header.Get("Cache-Control"))
	}
}

// An origin allowed only if it is one of the list: oneOf gives the element of the list, never what the client sent,
// and the response says that it depends on Origin, so that a cache doesn't give one origin's answer to another.
func TestHeaderExpressionOriginFromAList(t *testing.T) {
	initForTest(t)
	addSiteHeaders(t, map[string]string{"Access-Control-Allow-Origin": "=oneOf(HEADER('Origin'), ['https://app.example', 'https://admin.example'])"})
	base := startServer(t)
	for origin, want := range map[string]string{"https://app.example": "https://app.example", "https://evil.example": "", "": ""} {
		headers := map[string]string{}
		if origin != "" {
			headers["Origin"] = origin
		}
		response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", headers)
		got, sent := response.Header["Access-Control-Allow-Origin"]
		if response.StatusCode != 200 || want == "" && sent || want != "" && (len(got) != 1 || got[0] != want) {
			t.Errorf("Origin %q: %d Access-Control-Allow-Origin %q; expected %q", origin, response.StatusCode, got, want)
		}
		if !headerListHas(response.Header.Values("Vary"), "Origin") {
			t.Errorf("Origin %q: Vary %q; expected Origin in it", origin, response.Header.Values("Vary"))
		}
	}
}

// A file name of the request goes into a header only through quoted, between quotes and with its quotes escaped.
func TestHeaderExpressionQuotedFileName(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/d", 0755)
	os.WriteFile(dir+"localhost/@/d/report 1.pdf", []byte("pdf"), 0644)
	os.WriteFile(dir+"localhost/@/other.pdf", []byte("pdf"), 0644)
	addSiteHeaders(t, map[string]string{"Content-Disposition": "=DIR == '/d' ? 'attachment; filename=' + quoted(FILE) : ''"})
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/d/report%201.pdf", nil); response.Header.Get("Content-Disposition") != `attachment; filename="report 1.pdf"` {
		t.Errorf("in /d: %d %q", response.StatusCode, response.Header.Get("Content-Disposition"))
	}
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/other.pdf", nil); response.Header.Values("Content-Disposition") != nil {
		t.Errorf("outside /d: %q; expected none", response.Header.Values("Content-Disposition"))
	}
}

// What the request sends as it wants can't reach a header: the expression is refused when it is added, with why.
func TestHeaderExpressionRefusesTheRequestAsItCame(t *testing.T) {
	initForTest(t)
	for _, value := range []string{"=HEADER('Origin')", "='x' + QUERY('a')", "=FILE", "=lower(COOKIE('lang'))", "=HEADER('Cookie') != '' ? 'a' : 'b'", "=COOKIE('turbo_session') != '' ? 'a' : 'b'", "=", "=foo("} {
		globalMutex.Lock()
		ok, message := subdomainContentCheckers["."](true, map[string]interface{}{"X-Test": value}, false, "localhost", "")
		globalMutex.Unlock()
		if ok || !strings.HasPrefix(message, "Expression: ") {
			t.Errorf("%q: %v %q; expected an error of the expression", value, ok, message)
		}
	}
	globalMutex.Lock()
	_, kept := customHeaders["localhost"]["X-Test"]
	globalMutex.Unlock()
	if kept {
		t.Error("a refused expression was kept")
	}
}

// An expression that gives nothing sends no header, and the CGI's header of that name goes out. The headers the
// expressions read are added to the CGI's own Vary.
func TestHeaderExpressionWithACGI(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	addSiteHeaders(t, map[string]string{
		"X-Mode":           "=HTTPS ? 'site' : ''",
		"Content-Language": "=HEADER('Accept-Language').startsWith('es') ? 'es' : 'en'",
	})
	base := startServer(t)
	query := url.Values{"header": {"X-Mode: cgi", "Vary: Origin"}}.Encode()
	response, _ := requestWithHeaders(t, "GET", base, "localhost", "/x.cgi?"+query, map[string]string{"Accept-Language": "es-ES"})
	if response.StatusCode != 200 || response.Header.Get("X-Mode") != "cgi" {
		t.Errorf("%d X-Mode %q; expected the CGI's, as the expression gave nothing", response.StatusCode, response.Header.Get("X-Mode"))
	}
	if response.Header.Get("Content-Language") != "es" {
		t.Errorf("Content-Language %q; expected es", response.Header.Get("Content-Language"))
	}
	if vary := response.Header.Values("Vary"); !headerListHas(vary, "Origin") || !headerListHas(vary, "Accept-Language") {
		t.Errorf("Vary %q; expected the CGI's Origin and the expression's Accept-Language", vary)
	}
}

// An expression that fails answers 500, before the CGI runs: the page never goes out without its header.
func TestHeaderExpressionFailureAnswers500(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	addSiteHeaders(t, map[string]string{"Content-Security-Policy": "=HTTPS ? 'default-src https:' : '" + strings.Repeat("a", expr.MaxHeaderValue+1) + "'"})
	base := startServer(t)
	mark := dir + "ran"
	response, body := requestWithHeaders(t, "GET", base, "localhost", "/x.cgi?sleep=1&mark="+url.QueryEscape(mark), nil)
	if response.StatusCode != 500 || strings.Contains(body, "aaaa") {
		t.Errorf("%d %q; expected 500 without the value", response.StatusCode, body)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(mark); err == nil {
		t.Error("the CGI ran")
	}
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil); response.StatusCode != 500 {
		t.Errorf("a file: %d; expected 500", response.StatusCode)
	}
}

// An expression of turbo.config that doesn't compile (edited by hand) is kept, saved as it was, and the site answers
// 500 until it is fixed; the file of an ACME challenge is still served, so the certificate doesn't stop.
func TestHeaderExpressionBrokenInTurboConfig(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/.well-known/acme-challenge", 0755)
	os.WriteFile(dir+"localhost/@/.well-known/acme-challenge/tok_en-1", []byte("challenge-content"), 0644)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{".":{"X-Broken":"=foo(","X-Fixed":"kept"},"-":{"index.html":"1"}}}}`)
	globalMutex.RLock()
	saved := createSubdomainData("localhost", "")
	globalMutex.RUnlock()
	if !strings.Contains(saved, `"X-Broken":"=foo("`) || !strings.Contains(saved, `"X-Fixed":"kept"`) {
		t.Errorf("what would be saved: %s", saved)
	}
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil); response.StatusCode != 500 {
		t.Errorf("the site: %d; expected 500", response.StatusCode)
	}
	if response, body := requestWithHeaders(t, "GET", base, "localhost", "/.well-known/acme-challenge/tok_en-1", nil); response.StatusCode != 200 || body != "challenge-content" {
		t.Errorf("the ACME challenge: %d %q", response.StatusCode, body)
	}
}

// A precompressed file says it depends on Accept-Encoding, and on what the expressions read: one Vary adds to the
// other.
func TestHeaderExpressionVaryWithPrecompressedFiles(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/app.js", []byte("plain"), 0644)
	os.WriteFile(dir+"localhost/@/app.js.gz", []byte("gzipped"), 0644)
	if applied, answer := lockedCheck(func() (bool, string) { return siteSSLSettingCheckers["Z"](false, "1", "localhost", "") }); !applied {
		t.Fatalf("Z: %q", answer)
	}
	addSiteHeaders(t, map[string]string{"X-Origin-Seen": "=HEADER('Origin') != '' ? 'yes' : 'no'"})
	base := startServer(t)
	response, body := requestWithHeaders(t, "GET", base, "localhost", "/app.js", map[string]string{"Accept-Encoding": "gzip", "Origin": "https://a.example"})
	if body != "gzipped" || response.Header.Get("X-Origin-Seen") != "yes" {
		t.Errorf("%q X-Origin-Seen %q", body, response.Header.Get("X-Origin-Seen"))
	}
	if vary := response.Header.Values("Vary"); !headerListHas(vary, "Accept-Encoding") || !headerListHas(vary, "Origin") {
		t.Errorf("Vary %q; expected Accept-Encoding and Origin", vary)
	}
}

// The same expression added again is "Header unchanged", as a value written as it is.
func TestHeaderExpressionUnchanged(t *testing.T) {
	initForTest(t)
	value := "=HTTPS ? 'max-age=63072000' : ''"
	addSiteHeaders(t, map[string]string{"Strict-Transport-Security": value})
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["."](true, map[string]interface{}{"Strict-Transport-Security": value}, false, "localhost", "")
	globalMutex.Unlock()
	if ok || message != "Header unchanged" {
		t.Errorf("%v %q; expected Header unchanged", ok, message)
	}
}

// Every variable of the expressions has its value: those of the placeholders of the rewrites, and IP, PATH and
// METHOD.
func TestExpressionRequestHasEveryVariable(t *testing.T) {
	for v := expr.Variable(1); v.Name() != ""; v++ {
		if _, placeholder := shortcutWordReplacers[v.Name()]; !placeholder && v != expr.IP && v != expr.Path && v != expr.Method {
			t.Errorf("%s has no value", v.Name())
		}
	}
}

// Requests while the panel changes an expression get the old value or the new one, never another (with -race, no
// race either).
func TestHeaderExpressionChangedWhileServed(t *testing.T) {
	initForTest(t)
	for _, step := range [][2]string{{"CIS", "6600"}, {"CII", "6600"}, {"CIS", "50000"}, {"CII", "50000"}} { // Not limited per client
		if ok, message := setting(step[0], step[1]); !ok {
			t.Fatalf("%s=%s: %s", step[0], step[1], message)
		}
	}
	addSiteHeaders(t, map[string]string{"X-Version": "=HTTPS ? 'x' : 'one'"})
	base := startServer(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil)
				if got := response.Header.Get("X-Version"); response.StatusCode != 200 || got != "one" && got != "two" {
					t.Errorf("%d X-Version %q", response.StatusCode, got)
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		value := "=HTTPS ? 'x' : 'one'"
		if i%2 == 0 {
			value = "=HTTPS ? 'x' : 'two'"
		}
		addSiteHeaders(t, map[string]string{"X-Version": value})
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

// The expressions are compiled once each, and kept a bounded number at most.
func TestCompiledExpressionsAreBounded(t *testing.T) {
	first, err := compileExpression(expr.HeaderValue, "X-Bounded", "'bounded'")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := compileExpression(expr.HeaderValue, "X-Bounded", "'bounded'"); again != first {
		t.Error("the same expression compiled twice")
	}
	for i := 0; i < maxCompiledExpressions+1; i++ {
		compileExpression(expr.HeaderValue, "X-Bounded", "'"+strings.Repeat("b", i%50)+"' + '"+strings.Repeat("c", i/50)+"'")
	}
	compiledExpressions.mutex.Lock()
	kept := len(compiledExpressions.entries)
	compiledExpressions.mutex.Unlock()
	if kept > maxCompiledExpressions {
		t.Errorf("%d expressions kept; at most %d", kept, maxCompiledExpressions)
	}
}
