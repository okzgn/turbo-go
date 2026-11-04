package main

// T31 (N33, N34; D23 (a)): the keywords of a rewrite target are encoded
// according to their position (in the path, segment by segment without
// touching "/"; in the query, as a value; in the host, unable to change the
// shape of the URL), come from the decoded path, and unknown ones are
// rejected. An http(s):// target needs a host, and its scheme is not case
// sensitive.

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"turbo/customNetHttp"
)

func TestN33_RewritePlaceholderEncoding(t *testing.T) {
	for _, c := range []struct{ template, match, uri, want string }{
		// An internal target already gets the request's query (the CGI, in
		// QUERY_STRING): it isn't added again here (N64). A redirect does carry it.
		{"N/new/{REWRITE_COMPLEMENT}", "/blog/", "/blog/a/b?x=1", "N/new/a/b"},
		{"N/new/{REWRITE_COMPLEMENT}?y=2", "/blog/", "/blog/a/b?x=1", "N/new/a/b?y=2"},
		{"Sexample.test/new/{REWRITE_COMPLEMENT}", "/blog/", "/blog/a/b?x=1", "Sexample.test/new/a/b?x=1"},
		{"Sexample.test/new/{REWRITE_COMPLEMENT}?y=2", "/blog/", "/blog/a/b?x=1", "Sexample.test/new/a/b?y=2&x=1"},
		{"N/new?r={REWRITE_COMPLEMENT}", "/blog/", "/blog/a/b?x=1", "N/new?r=a%2Fb%3Fx%3D1"},
		{"N/x/{FILE}", "/d/", "/d/a%20b.txt", "N/x/a%20b.txt"},
		{"N/app.cgi?f={FILE}&d={DIR}&e={EXT}", "/d/", "/d/a%20b.txt", "N/app.cgi?f=a+b.txt&d=%2Fd&e=txt"},
		{"N/p/{FIRST_REQUEST}", "/", "/a%20b/c?q=1", "N/p//a%20b/c"},
		{"N/app.cgi?q={FIRST_QUERY}", "/", "/x?a=1&b=2", "N/app.cgi?q=a%3D1%26b%3D2"},
		{"Sexample.test/x/{FILE}?f={FILE}", "/", "/a?b.txt", "Sexample.test/x/a?f=a"},
		{"S{SITE}/{FILE}", "/", "/a%3Fb", "Sfoo.example.com/a%3Fb"},
		{"S{FILE}/x", "/", "/evil.test%40x%3Fy", "Sevil.test%40x%3Fy/x"},
	} {
		req := &customNetHttp.Request{RequestURI: c.uri, Header: customNetHttp.Header{}}
		path, _ := url.PathUnescape(cutAt(c.uri, '?'))
		got := shortcutWords(req, c.template, "example.com", "*", "example.com", "foo", "", "", c.match, path)
		if got != c.want {
			t.Errorf("%s with %s → %q; expected %q", c.template, c.uri, got, c.want)
		}
	}
}

// Validation: unknown keywords, targets without a host and the scheme in
// upper case.
func TestN33_RewriteTargetValidation(t *testing.T) {
	initForTest(t)
	add := func(target string) (bool, string) {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		return subdomainContentCheckers["="](true, map[string]interface{}{"/r/": target}, false, "localhost", "")
	}
	for _, bad := range []string{"https://", "http://", "https:///x", "/a/{X}", "/a?b={UNKNOWN}"} {
		if ok, msg := add(bad); ok {
			t.Errorf("%q accepted: %s", bad, msg)
		}
	}
	for target, stored := range map[string]string{"HTTPS://x.test/y": "Sx.test/y", "Http://x.test": "Hx.test", "https://{FIRST_SITE}/a": "S{FIRST_SITE}/a", "/a/{FILE}{": "N/a/{FILE}{"} {
		if ok, msg := add(target); !ok {
			t.Errorf("%q rejected: %s", target, msg)
			continue
		}
		globalMutex.RLock()
		got := sitesMap["localhost"][""]["/r/"]
		globalMutex.RUnlock()
		if got != stored {
			t.Errorf("%q saved as %q; expected %q", target, got, stored)
		}
	}
	logs := captureLog(t)
	globalMutex.Lock()
	subdomainContentCheckers["="](false, map[string]interface{}{"/f/": "/a/{X}"}, true, "localhost", "")
	_, kept := sitesMap["localhost"][""]["/f/"]
	globalMutex.Unlock()
	if kept || !strings.Contains(logs.String(), "{X}") {
		t.Errorf("from the file, an unknown keyword: saved=%v, no warning:\n%s", kept, logs.String())
	}
}

// N34: a target whose host comes out empty when responding gives 500, never https:///.
func TestN34_RewriteEmptyHostAt500(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	subdomainContentCheckers["="](true, map[string]interface{}{"/r/": "https://{FIRST_SITE}"}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	res, _, err := rawGet(base, "localhost", "/r/x")
	if err != nil {
		t.Fatal(err)
	}
	if loc := res.Header.Get("Location"); res.StatusCode != 500 || strings.HasPrefix(loc, "https:///") {
		t.Errorf("target without a host: %d Location=%q; expected 500", res.StatusCode, loc)
	}
}

// N77: the query a redirect copies from the request has its control
// characters encoded, like the rest of the target.
func TestN77_RedirectQueryControlChars(t *testing.T) {
	for _, template := range []string{"S/{REWRITE_COMPLEMENT}", "Hexample.org/b/{REWRITE_COMPLEMENT}"} {
		req := &customNetHttp.Request{RequestURI: "/a?x=1\r\ny\x7f\t", Header: customNetHttp.Header{}}
		got := shortcutWords(req, template, "example.com", "*", "example.com", "foo", "", "", "/", "/a")
		if strings.ContainsAny(got, "\r\n\x7f\t") || !strings.HasSuffix(got, "?x=1%0D%0Ay%7F%09") {
			t.Errorf("%s: %q; expected the query x=1%%0D%%0Ay%%7F%%09", template, got)
		}
	}
}

// FuzzRewriteTarget: with any target and request, the internal path doesn't
// leave @ nor carry CR/LF, and a redirect never goes to https:///.
func FuzzRewriteTarget(f *testing.F) {
	for _, seed := range [][2]string{{"N/new/{REWRITE_COMPLEMENT}", "/blog/a/b?x=1"}, {"S{FILE}", "/%2F%2Fevil"}, {"N/{DIR}/../{FILE}", "/a/b"}, {"H{FIRST_REQUEST}", "/x\r\n"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, template, uri string) {
		if len(uri) == 0 || uri[0] != '/' || len(template) == 0 || strings.ContainsAny(template, "\r\n") {
			return
		}
		path, ok := cleanRequestPath(cutAt(uri, '?'))
		if !ok {
			return
		}
		req := &customNetHttp.Request{RequestURI: uri, Header: customNetHttp.Header{}}
		got := shortcutWords(req, template, "example.com", "*", "example.com", "foo", "", "", "/", path)
		if strings.ContainsAny(got, "\r\n") && !strings.ContainsAny(template, "\r\n") {
			t.Fatalf("CR/LF in %q (template %q, request %q)", got, template, uri)
		}
		targetPath := cutAt(got, '?')
		switch template[0] {
		case 'N':
			if clean, ok := cleanRequestPath(targetPath[1:]); ok && (!strings.HasPrefix(clean, "/") || strings.Contains(clean+"/", "/../")) {
				t.Fatalf("internal path %q outside @", clean)
			}
		case 'H', 'S':
			recorder := &responseRecorder{}
			rewriteRedirect(template[0] == 'S', targetPath[1:], strings.TrimPrefix(got[len(targetPath):], "?"), recorder, req)
			if loc := recorder.Header().Get("Location"); strings.HasPrefix(loc, "https:///") || strings.HasPrefix(loc, "http:///") {
				t.Fatalf("redirect to %q", loc)
			}
		}
	})
}

// N64: {REWRITE_COMPLEMENT} in the path of an internal rewrite to a CGI: the
// client's query reaches QUERY_STRING only once.
func TestN64_ComplementQueryOnceForCGI(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/new", 0755)
	os.WriteFile(dir+"localhost/@/new/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	subdomainContentCheckers["="](true, map[string]interface{}{"/blog/": "/new/{REWRITE_COMPLEMENT}"}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	code, body, err := get(base, "/blog/x.cgi?a[]=1", nil)
	if err != nil || code != 200 {
		t.Fatalf("GET: %d %v %s", code, err, body)
	}
	if q := cgiEnv(body)["QUERY_STRING"]; q != "a[]=1" {
		t.Errorf("QUERY_STRING=%q; expected the client's query once", q)
	}
	// With a query in the target, both, each one once
	globalMutex.Lock()
	subdomainContentCheckers["="](true, map[string]interface{}{"/other/": "/new/{REWRITE_COMPLEMENT}?y=2"}, false, "localhost", "")
	globalMutex.Unlock()
	if _, body, _ = get(base, "/other/x.cgi?a=1", nil); cgiEnv(body)["QUERY_STRING"] != "a=1&y=2" {
		t.Errorf("QUERY_STRING=%q; expected \"a=1&y=2\"", cgiEnv(body)["QUERY_STRING"])
	}
}
