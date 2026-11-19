package server

// What an independent review of the expressions found (2026-11-18), each with the test that failed before its fix.

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// rawLocation makes a request without following, or parsing, the Location of its answer.
func rawLocation(t *testing.T, base string, path string) (int, string) {
	t.Helper()
	request, _ := http.NewRequest("GET", base+path, nil)
	request.Host = "localhost"
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode, response.Header.Get("Location")
}

// "https://\/" passed for a target with a host, and a browser skips every "/" and "\" after "https:": the text that
// followed, the client's, was the host of the redirection. Refused now, in an expression and in a target with
// keywords, when added; and a redirection whose host starts with "/", "\", "?" or "#" answers 500.
func TestRedirectionHostCantStartWithASlashOrBackslash(t *testing.T) {
	initForTest(t)
	for _, target := range []string{`='https://\\/' + QUERY('u')`, `='http://\\\\/' + QUERY('u')`, `='https://' + '\\/' + QUERY('u')`, `='https://#' + QUERY('u')`, `https://\/{REWRITE_COMPLEMENT}`, `https://#{REWRITE_COMPLEMENT}`} {
		globalMutex.Lock()
		ok, message := subdomainContentCheckers["="](true, map[string]interface{}{"/go/": target}, false, "localhost", "")
		globalMutex.Unlock()
		if ok {
			t.Errorf("%s accepted: %q", target, message)
		}
	}
	// One kept before (turbo.config of an earlier version) answers 500
	globalMutex.Lock()
	sitesMap["localhost"][""]["/old/"] = `S\/{REWRITE_COMPLEMENT}`
	globalMutex.Unlock()
	base := startServer(t)
	if code, location := rawLocation(t, base, "/old/evil.example/x"); code != 500 || location != "" {
		t.Errorf("a kept target with \\ before its host: %d %q; expected 500", code, location)
	}
}

// An expression whose redirection has no host for a request answers 500, logged at most once a minute and without
// what the request sent: before, each request logged its path and query.
func TestRedirectionWithoutAHostIsLoggedOnce(t *testing.T) {
	initForTest(t)
	addSiteRewrites(t, map[string]string{"/x": "='https://' + FIRST_SITE + '/x'"})
	logs := captureLog(t)
	base := startServer(t)
	for i := 0; i < 3; i++ {
		if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/x?secret=s3cr3t", nil); response.StatusCode != 500 {
			t.Errorf("request %d: %d; expected 500", i, response.StatusCode)
		}
	}
	waitIdle()
	if strings.Contains(logs.String(), "s3cr3t") || strings.Count(logs.String(), "without a host") != 1 {
		t.Errorf("the log: %s", logs.String())
	}
}

// The answers that a rewrite expression decided, also a 404 or the redirection of a folder, say in Vary the headers
// it read: a shared cache kept them for everyone.
func TestVaryOnEveryAnswerARewriteExpressionDecided(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/v", 0755)
	os.WriteFile(dir+"localhost/@/v/a.html", []byte("a"), 0644)
	os.MkdirAll(dir+"localhost/@/docs", 0755)
	os.WriteFile(dir+"localhost/@/docs/index.html", []byte("docs"), 0644)
	os.WriteFile(dir+"localhost/@/beta.html", []byte("beta"), 0644)
	addSiteRewrites(t, map[string]string{
		"/page":  "='/v/' + (HEADER('X-Variant') == '' ? 'a' : token(HEADER('X-Variant'))) + '.html'",
		"/docs/": "=HEADER('X-Beta') == '1' ? '/beta.html' : ''",
		"/bad":   "='/v/' + urlencode(HEADER('X-Path'))",
	})
	base := startServer(t)
	for _, c := range []struct {
		path, header, value, vary string
		code                      int
	}{
		{"/page", "X-Variant", "", "X-Variant", 200},
		{"/page", "X-Variant", "zz", "X-Variant", 404},
		{"/docs", "X-Beta", "", "X-Beta", 301},
		{"/docs/", "X-Beta", "1", "X-Beta", 200},
		{"/bad", "X-Path", "..", "X-Path", 404},
	} {
		headers := map[string]string{}
		if c.value != "" {
			headers[c.header] = c.value
		}
		response, _ := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(func() *http.Request {
			request, _ := http.NewRequest("GET", base+c.path, nil)
			request.Host = "localhost"
			for name, value := range headers {
				request.Header.Set(name, value)
			}
			return request
		}())
		if response == nil {
			t.Fatalf("%s: no answer", c.path)
		}
		response.Body.Close()
		if response.StatusCode != c.code || !headerListHas(response.Header.Values("Vary"), c.vary) {
			t.Errorf("%s with %s %q: %d Vary %q; expected %d with %s", c.path, c.header, c.value, response.StatusCode, response.Header.Values("Vary"), c.code, c.vary)
		}
	}
}

// An expression of turbo.config with a control character other than a tab or a line break was dropped when read,
// and the site went out without it. Kept now, as any that doesn't compile: what it covers answers 500.
func TestExpressionWithAControlCharacterIsKept(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{".":{"Content-Security-Policy":"='default-src \u000c self'"},"=":{"/private/":"='/denied\u000c'"},"-":{"index.html":"1"}}}}`)
	globalMutex.RLock()
	saved := createSubdomainData("localhost", "")
	globalMutex.RUnlock()
	if !strings.Contains(saved, "Content-Security-Policy") || !strings.Contains(saved, "/private/") {
		t.Errorf("not kept: %s", saved)
	}
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil); response.StatusCode != 500 {
		t.Errorf("the site: %d; expected 500", response.StatusCode)
	}
}
