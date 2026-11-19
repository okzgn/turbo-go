package server

// The expressions of the rewrites: a target written with "=" before it is computed for each request. Its parts are
// placed as those of a target with placeholders, by the same code (targetWriter): the texts of the expression as they
// are, the rest encoded for where it goes.

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"turbo/customNetHttp"
	"turbo/internal/expr"
)

// addSiteRewrites adds rewrites of the site localhost as addRewrite does, and fails the test if one is refused.
func addSiteRewrites(t *testing.T, rewrites map[string]string) {
	t.Helper()
	globalMutex.Lock()
	defer globalMutex.Unlock()
	for source, target := range rewrites {
		if ok, message := subdomainContentCheckers["="](true, map[string]interface{}{source: target}, false, "localhost", ""); !ok {
			t.Fatalf("addRewrite %s: %q", source, message)
		}
	}
}

// A page in the language of the visitor: the target depends on Accept-Language, and the response says so.
func TestRewriteExpressionByLanguage(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/es", 0755)
	os.WriteFile(dir+"localhost/@/page.html", []byte("english"), 0644)
	os.WriteFile(dir+"localhost/@/es/page.html", []byte("español"), 0644)
	addSiteRewrites(t, map[string]string{"/page.html": "=HEADER('Accept-Language').startsWith('es') ? '/es' + FIRST_REQUEST : ''"})
	base := startServer(t)
	for language, want := range map[string]string{"es-ES,es;q=0.9": "español", "en-US": "english", "": "english"} {
		headers := map[string]string{}
		if language != "" {
			headers["Accept-Language"] = language
		}
		response, body := requestWithHeaders(t, "GET", base, "localhost", "/page.html", headers)
		if response.StatusCode != 200 || body != want {
			t.Errorf("Accept-Language %q: %d %q; expected %q", language, response.StatusCode, body, want)
		}
		if !headerListHas(response.Header.Values("Vary"), "Accept-Language") {
			t.Errorf("Accept-Language %q: Vary %q", language, response.Header.Values("Vary"))
		}
	}
}

// A redirection whose host is chosen from a list: what the client asks for is only a choice among the hosts written.
func TestRewriteExpressionRedirectionToAListedHost(t *testing.T) {
	initForTest(t)
	addSiteRewrites(t, map[string]string{"/go": "='https://' + oneOf(QUERY('to'), ['a.example', 'b.example']) + '/landing'"})
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/go?to=b.example", nil); response.StatusCode != 302 || response.Header.Get("Location") != "https://b.example/landing" {
		t.Errorf("a listed host: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	for _, to := range []string{"evil.example", "b.example@evil.example", "b.example%2F%2Fevil", ""} {
		if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/go?to="+to, nil); response.StatusCode != 500 || response.Header.Get("Location") != "" {
			t.Errorf("to=%q: %d %q; expected 500 without a host", to, response.StatusCode, response.Header.Get("Location"))
		}
	}
}

// The host of a redirection, and the start of a target, can only be written in the expression: what could put the
// request there is refused when it is added.
func TestRewriteExpressionRefusesTheClientInTheHost(t *testing.T) {
	initForTest(t)
	for _, target := range []string{
		"='https://' + QUERY('h')", "='https://' + token(HEADER('X-Host')) + '/'", "='http://' + IP", "=QUERY('p')",
		"=FIRST_REQUEST", "=HEADER('Referer')", "='//evil.example'", "='/a/../b'", "=", "=HEADER('Cookie') == '' ? '/a' : '/b'",
		"=PATH",
	} {
		globalMutex.Lock()
		ok, message := subdomainContentCheckers["="](true, map[string]interface{}{"/x": target}, false, "localhost", "")
		globalMutex.Unlock()
		if ok || !strings.HasPrefix(message, "Expression: ") {
			t.Errorf("%q: %v %q; expected an error of the expression", target, ok, message)
		}
	}
}

// What the request sends goes into the path or the query encoded: it can't add a segment, leave the site or end the
// query. A CGI gets it as one value.
func TestRewriteExpressionEncodesTheRequest(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	os.MkdirAll(dir+"localhost/@/x", 0755)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	addSiteRewrites(t, map[string]string{
		"/q": "='/x.cgi?v=' + HEADER('X-Value')",
		"/p": "='/x/' + QUERY('p')",
	})
	base := startServer(t)
	response, body := requestWithHeaders(t, "GET", base, "localhost", "/q", map[string]string{"X-Value": "a&b=c;d #e"})
	if response.StatusCode != 200 || !strings.Contains(body, "QUERY_STRING=v=a%26b%3Dc%3Bd+%23e") {
		t.Errorf("into the query: %d %q", response.StatusCode, body)
	}
	for _, p := range []string{"..%2F..%2Fturbo.config", "a%2F..%2F..%2Fb", "%0D%0ASet-Cookie:%20x=1", "..", "a\\b"} {
		if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/p?p="+p, nil); response.StatusCode != 404 || response.Header.Get("Set-Cookie") != "" {
			t.Errorf("p=%q: %d %q; expected 404", p, response.StatusCode, response.Header.Get("Set-Cookie"))
		}
	}
}

// A target longer than 2048 bytes once placed answers 500.
func TestRewriteExpressionTooLong(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/a", []byte("a"), 0644)
	addSiteRewrites(t, map[string]string{"/long": "='/a?v=' + HEADER('X-Long')"})
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/long", map[string]string{"X-Long": strings.Repeat("a&b&", 200)}); response.StatusCode != 200 {
		t.Errorf("800 bytes, 1600 once encoded: %d", response.StatusCode)
	}
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/long", map[string]string{"X-Long": strings.Repeat("a&b&", 300)}); response.StatusCode != 500 {
		t.Errorf("1200 bytes, 2400 once encoded: %d; expected 500", response.StatusCode)
	}
}

// REWRITE_COMPLEMENT keeps its rule: in the path, the rest of the path, and in a redirection the request's query at
// the end, as in a target with placeholders.
func TestRewriteExpressionComplement(t *testing.T) {
	initForTest(t)
	addSiteRewrites(t, map[string]string{"/blog/": "='https://example.com/new/' + REWRITE_COMPLEMENT"})
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/blog/a/b?x=1", nil); response.StatusCode != 302 || response.Header.Get("Location") != "https://example.com/new/a/b?x=1" {
		t.Errorf("%d %q", response.StatusCode, response.Header.Get("Location"))
	}
}

// A rewrite to an expression needs the current password, whatever its target: it may send the visitors away for some
// requests.
func TestRewriteExpressionNeedsThePassword(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	token := login(t, base)
	target := url.QueryEscape("='/y'")
	if code, body, _ := post(base, "/admin:inside:addRewrite?s=localhost&d=&a=/x&b="+target, token); code != 400 || !strings.Contains(body, "the current password") {
		t.Errorf("without the password: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:addRewrite?s=localhost&d=&a=/x&b="+target+"&c=Admin", token); code != 200 || body != "Rewrite created" {
		t.Errorf("with the password: %d %q", code, body)
	}
	globalMutex.RLock()
	stored, saved := sitesMap["localhost"][""]["/x"], createSubdomainData("localhost", "")
	globalMutex.RUnlock()
	if stored != "X'/y'" || !strings.Contains(saved, `"/x":"='/y'"`) {
		t.Errorf("kept %q, saved %s", stored, saved)
	}
}

// An expression of turbo.config that doesn't compile is kept and saved as it was; the paths it takes answer 500, the
// others are served.
func TestRewriteExpressionBrokenInTurboConfig(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"=":{"/broken":"=foo(","/fine":"/index.html"},"-":{"index.html":"1"}}}}`)
	globalMutex.RLock()
	saved := createSubdomainData("localhost", "")
	globalMutex.RUnlock()
	if !strings.Contains(saved, `"/broken":"=foo("`) {
		t.Errorf("what would be saved: %s", saved)
	}
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/broken", nil); response.StatusCode != 500 {
		t.Errorf("/broken: %d; expected 500", response.StatusCode)
	}
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/fine", nil); response.StatusCode != 200 {
		t.Errorf("/fine: %d", response.StatusCode)
	}
}

// templateExpression is the expression that writes what a target with placeholders writes, as it is kept ("N/…",
// "H…" or "S…"): its texts as texts, its placeholders as variables. false for what an expression can't say.
func templateExpression(template string) (string, bool) {
	if template == "" {
		return "", false
	}
	text := map[byte]string{'N': "", 'H': "http://", 'S': "https://"}
	scheme, known := text[template[0]]
	if !known {
		return "", false
	}
	quote := func(s string) string {
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}
	var parts []string
	pending := scheme
	remaining := template[1:]
	for { // As shortcutWords reads it
		open := strings.IndexByte(remaining, '{')
		if open == -1 {
			break
		}
		closing := strings.IndexByte(remaining[open:], '}')
		if closing == -1 {
			break
		}
		closing += open
		pending += remaining[:open]
		name := remaining[open+1 : closing]
		remaining = remaining[closing+1:]
		if _, known := shortcutWordReplacers[name]; !known {
			// Dropped, but the texts on each side are written apart, each one read as UTF-8 on its own: one text
			// of the expression would join the halves of a character that the target splits ("\xc3{}\xb1").
			if pending != "" {
				parts = append(parts, quote(pending))
				pending = ""
			}
			continue
		}
		if pending != "" {
			parts = append(parts, quote(pending))
			pending = ""
		}
		parts = append(parts, name)
	}
	if pending += remaining; pending != "" {
		parts = append(parts, quote(pending))
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, " + "), true
}

// targetWriterSeeds are targets with every placeholder in every place, for the requests of targetWriterRequests.
var targetWriterSeeds = []string{
	"N/new/{REWRITE_COMPLEMENT}", "H{DOMAIN}/{REWRITE_COMPLEMENT}", "S{FIRST_SITE}/x?a={FILE}&b={REWRITE_COMPLEMENT}",
	"N/{DIR}/{FILE}.{EXT}?q={FIRST_QUERY}", "Sexample.com", "H{FIRST_REQUEST}", "N/a}b/{REWRITE}", "N/{X}{", "S{SUBDOMAIN}.{WILDCARD_DOMAIN}?{WILDCARD_SITE}",
	"N/ñ/{FILE}", "Sa.example/{REWRITE_COMPLEMENT}?x", "N/{TURBO_CURRENT_DIR}", "",
}

var targetWriterRequests = []string{"/blog/a/b?x=1&y=%0D", "/a b/c%3Fd", "/", "/blog/?", "/x?\x7f"}

// FuzzRewriteExpressionMatchesTemplate: a target with placeholders, and the expression that says the same, give the
// same target for any request, whenever the expression compiles (it can't put what the client sends in the host of
// a redirection, which a target with placeholders encodes there).
func FuzzRewriteExpressionMatchesTemplate(f *testing.F) {
	for _, seed := range targetWriterSeeds {
		f.Add(seed, targetWriterRequests[0], "/blog/")
	}
	f.Add("Sexample.com/new/{REWRITE_COMPLEMENT}", "/blog/a b/c?x=1&y", "/blog/")
	f.Add("N/es{FIRST_REQUEST}", "/page.html?q=%0D", "/")
	f.Fuzz(func(t *testing.T, template string, uri string, match string) {
		if uri == "" || uri[0] != '/' {
			return
		}
		source, ok := templateExpression(template)
		if !ok {
			return
		}
		if _, err := compileExpression(expr.RewriteTarget, "", source); err != nil {
			return
		}
		request := &customNetHttp.Request{RequestURI: uri, Method: "GET", RemoteAddr: "203.0.113.9:40000", Header: customNetHttp.Header{}}
		site := siteMatch{siteDomain: "example.com", siteSubdomain: "*", domain: "foo.example.com", subdomain: "foo"}
		path := cutAt(uri, '?')
		want := shortcutWords(request, template, site, match, path)
		got, _, answered := expressionTarget(&responseRecorder{}, &expressionRequest{request: request, site: site, rewriteMatch: match, requestPath: path}, source)
		if answered {
			if len(want) > maxExpressionTarget { // The expressions have a limit that the templates don't
				return
			}
			// A redirection without a host answers 500 either way: the template's in rewriteRedirect
			if (want[0] == 'H' || want[0] == 'S') && (len(want) == 1 || strings.IndexByte(redirectHostStarters, want[1]) != -1) {
				return
			}
			t.Fatalf("%q (%s) with %q answered; the template gives %q", template, source, uri, want)
		}
		if got != want { // Never "": the expression starts with a text, as the template does
			t.Fatalf("%q (%s) with %q: %q; the template gives %q", template, source, uri, got, want)
		}
	})
}
