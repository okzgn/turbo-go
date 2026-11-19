package server

// The tests of the findings about the expressions, the headers and the targets of the rewrites of the review of
// v2.5.1: each failed before its fix. The two fuzz targets check the rule of the host of a redirection, which no change
// of these may break: they passed before and after each.

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"turbo/customNetHttp"
	"turbo/internal/expr"
)

// clientLabelsAreTheHost reports whether host, the host of a redirection as a browser takes it from what Turbo placed
// (up to "/", "\", "?" or "#", after a userinfo, without its port nor a final dot), is the labels that the client
// chose ("zz.evil") alone, or ends with them.
func clientLabelsAreTheHost(placed string) (string, bool) {
	host := placed
	if i := strings.IndexAny(host, `/\?#`); i != -1 {
		host = host[:i]
	}
	if i := strings.LastIndexByte(host, '@'); i != -1 {
		host = host[i+1:]
	}
	if i := strings.LastIndexByte(host, ':'); i != -1 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	return host, host == "zz.evil" || strings.HasSuffix(host, ".zz.evil")
}

// describeResponse is a response's status and Location, or the error of the request, for the messages of a test.
func describeResponse(response *http.Response, err error) string {
	if err != nil {
		return err.Error()
	}
	return response.Status + ", Location " + strconv.Quote(response.Header.Get("Location"))
}

// clientLabelSites are a wildcard subdomain whose client chose the labels "zz.evil", without an alias and through one.
var clientLabelSites = []siteMatch{
	{siteDomain: "example.com", siteSubdomain: "*", domain: "example.com", subdomain: "zz.evil"},
	{siteDomain: "example.com", siteSubdomain: "*", domain: "example.com", subdomain: "zz.evil", firstDomain: "alias.test", firstSubdomain: "zz.evil"},
}

// V2.5.1 review (EX-5 and XP-1 in the CI): the host that expressionTarget leaves for a redirection is never the labels
// that the client chose alone, whatever the expression that compiles.
func FuzzExpressionTargetHost(f *testing.F) {
	for _, seed := range []string{
		`'https://' + SUBDOMAIN + '.example.org'`, `'https://' + SUBDOMAIN + '.' + FIRST_DOMAIN + '/home'`,
		`'https://' + (HTTPS ? SUBDOMAIN + '.' : '') + DOMAIN`, `'https://' + SUBDOMAIN + '.' + oneOf(QUERY('d'), ['a.example']) + '/x'`,
		`'https://' + SUBDOMAIN + FIRST_SUBDOMAIN + '.x.example'`, `'http://' + lower(SUBDOMAIN) + '.a' + (HTTPS ? '' : '.b')`,
		`'https://' + SUBDOMAIN + '.' + WILDCARD_SUBDOMAIN + '.x'`, `'https://' + oneOf(QUERY('a'), ['x', '']) + SUBDOMAIN + '.y'`,
		`'https://' + SUBDOMAIN + '.com\\.example.com/'`, `'https://' + DOMAIN + REWRITE`, `'https://a.example/' + urlencode(SUBDOMAIN)`,
	} {
		f.Add(seed, true)
	}
	request := &customNetHttp.Request{RequestURI: "/a?d=zz", Header: customNetHttp.Header{}}
	f.Fuzz(func(t *testing.T, source string, https bool) {
		program, err := compileExpression(expr.RewriteTarget, "", source)
		if err != nil || program == nil {
			return
		}
		for _, site := range clientLabelSites {
			read := &expressionRequest{request: request, site: site, rewriteMatch: "/a", requestPath: "/a", overTLS: https}
			var target string
			var answered bool
			withReadLock(func() { target, _, answered = expressionTarget(&responseRecorder{}, read, source) })
			if answered || target == "" || target[0] != 'H' && target[0] != 'S' {
				continue
			}
			if host, theirs := clientLabelsAreTheHost(target[1:]); theirs {
				t.Fatalf("%q gave the host %q (target %q)", source, host, target)
			}
		}
	})
}

// V2.5.1 review (EX-1 in the CI): the same for the targets written as a text, as they are kept ("S" and the host).
func FuzzTextTargetHost(f *testing.F) {
	for _, seed := range []string{"{SUBDOMAIN}.{FIRST_DOMAIN}/home", "{SUBDOMAIN}.{FIRST_SITE}", "{SUBDOMAIN}.example.org", "{SUBDOMAIN}{FIRST_SUBDOMAIN}.x", "{SUBDOMAIN}.{FIRST_SUBDOMAIN}.{FIRST_DOMAIN}:1/", `{SUBDOMAIN}.com\.example.com/`, "a.example{REWRITE}"} {
		f.Add(seed)
	}
	request := &customNetHttp.Request{RequestURI: "/a?d=zz", Header: customNetHttp.Header{}}
	f.Fuzz(func(t *testing.T, written string) {
		target := "S" + written
		if written == "" || strings.IndexByte(redirectHostStarters, written[0]) != -1 || textTargetProblem(target) != "" || unknownPlaceholder(written) != "" || strings.Contains(written, "//") || strings.Contains(written, "..") {
			return // Refused when added and read
		}
		for _, site := range clientLabelSites {
			placed, kept := shortcutWordsChecked(request, target, site, "/a", "/a")
			if !kept {
				continue // 500
			}
			if host, theirs := clientLabelsAreTheHost(placed[1:]); theirs {
				t.Fatalf("%q gave the host %q (%q)", written, host, placed)
			}
		}
	})
}

// V2.5.1 review XP-1: Refresh, Location and Content-Location, whose value a browser follows, can't carry SUBDOMAIN nor
// FIRST_SUBDOMAIN, which a wildcard subdomain lets the client choose: through what changes a text (token, urlencode,
// quoted, lower, upper) and either branch of ? : as well. "'0; url=https://' + SUBDOMAIN + '.' + FIRST_DOMAIN" sent the
// visitors of a request without an alias to the host that the client chose. oneOf, a condition, and another header
// still take them.
func TestR251_XP1_NavigationHeadersDontTakeTheClientsLabels(t *testing.T) {
	const refused = "SUBDOMAIN and FIRST_SUBDOMAIN can't be used in this header"
	for _, header := range []string{"Refresh", "refresh", "LOCATION", "Location", "content-location", "Content-Location"} {
		for _, source := range []string{
			`'0; url=https://' + SUBDOMAIN + '.' + FIRST_DOMAIN`, `token(SUBDOMAIN)`, `urlencode(FIRST_SUBDOMAIN)`, `lower(SUBDOMAIN)`,
			`upper(token(FIRST_SUBDOMAIN))`, `HTTPS ? 'https://a.example/' : 'https://' + SUBDOMAIN + '.example.com/'`,
			`HTTPS ? 'https://' + FIRST_SUBDOMAIN + '.example.com/' : 'https://a.example/'`,
		} {
			if _, err := expr.Compile(source, expressionOptions(expr.HeaderValue, header)); err == nil || !strings.Contains(err.Error(), refused) {
				t.Errorf("%s: %s: %v; expected it refused", header, source, err)
			}
		}
		for _, source := range []string{`oneOf(SUBDOMAIN, ['a', 'b'])`, `SUBDOMAIN == 'www' ? 'https://example.com/' : 'https://www.example.com/'`, `'https://' + DOMAIN + '/'`, `token(QUERY('x'))`} {
			if _, err := expr.Compile(source, expressionOptions(expr.HeaderValue, header)); err != nil {
				t.Errorf("%s: %s: %v; expected it to compile", header, source, err)
			}
		}
	}
	if _, err := expr.Compile(`quoted(SUBDOMAIN)`, expressionOptions(expr.HeaderValue, "Location")); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("Location: quoted(SUBDOMAIN): %v; expected it refused", err)
	}
	for _, source := range []string{`SUBDOMAIN`, `token(SUBDOMAIN)`, `'https://' + SUBDOMAIN + '.example.com/'`} {
		if _, err := expr.Compile(source, expressionOptions(expr.HeaderValue, "X-Tenant")); err != nil {
			t.Errorf("X-Tenant: %s: %v; expected it to compile", source, err)
		}
	}
	// Compiled once for each: the same expression, taken for another header first, isn't taken for these
	if _, err := compileExpression(expr.HeaderValue, "X-Tenant", "token(SUBDOMAIN) + 'x'"); err != nil {
		t.Fatal(err)
	}
	if _, err := compileExpression(expr.HeaderValue, "Refresh", "token(SUBDOMAIN) + 'x'"); err == nil {
		t.Error("compiled for X-Tenant first, the expression was taken for Refresh")
	}

	// From turbo.config: kept as it is, and what the site serves answers 500 until it is changed
	dir := initForTest(t)
	logs := captureLog(t)
	for _, folder := range []string{"example.com/@", "example.com/#/@"} {
		os.MkdirAll(dir+folder, 0755)
	}
	os.WriteFile(dir+"example.com/#/@/index.html", []byte("hi"), 0644)
	loadConfig(t, dir, `{"^":{"v":"2"},"example.com":{"":{},"*":{"-":{"index.html":"1"},".":{`+
		`"Refresh":"='0; url=https://' + SUBDOMAIN + '.' + FIRST_DOMAIN + '/home'"}}}}`)
	withReadLock(func() {
		if _, kept := customHeaders["*.example.com"]["Refresh"]; !kept {
			t.Errorf("the header of turbo.config wasn't kept: %v", customHeaders)
		}
	})
	if !strings.Contains(logs.String(), "turbo.config header whose expression doesn't compile") || !strings.Contains(logs.String(), refused) {
		t.Errorf("the log doesn't say why the header doesn't compile:\n%s", logs.String())
	}
	base := startServer(t)
	for _, host := range []string{"evil.test.example.com", "evil.example.com"} {
		response, _, err := rawGet(base, host, "/")
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 500 || response.Header.Get("Refresh") != "" {
			t.Errorf("Host %s: %d, Refresh %q; expected 500 without it", host, response.StatusCode, response.Header.Get("Refresh"))
		}
	}
}

// V2.5.1 review XP-2: what urlencode gives is placed in the path and the query of a target as it is: it has only the
// characters that need no encoding and %XX. It was encoded again ("a%20b" as "a%2520b"). In the path, a "/" that it
// encodes leaves the target where it was without it: a %2F of a path isn't served.
func TestR251_XP2_URLEncodeIsPlacedAsItIs(t *testing.T) {
	request := &customNetHttp.Request{RequestURI: "/s?q=a%20b%2Fc", Header: customNetHttp.Header{}}
	site := siteMatch{siteDomain: "localhost", domain: "localhost"}
	for source, expected := range map[string]string{
		`'/find?q=' + urlencode(QUERY('q'))`:                    "N/find?q=a%20b%2Fc",
		`'/find/' + urlencode(QUERY('q'))`:                      "N/find/a%20b%2Fc",
		`'https://example.com/find?q=' + urlencode(QUERY('q'))`: "Sexample.com/find?q=a%20b%2Fc",
		`'/find?q=' + lower(urlencode(QUERY('q')))`:             "N/find?q=a%20b%2fc",
		`'/find?q=' + QUERY('q')`:                               "N/find?q=a+b%2Fc", // Without it, encoded for where it goes
		`'https://' + urlencode(QUERY('q')) + '.example.com/'`:  "",                 // Not in the host: refused
	} {
		var target string
		var answered bool
		withReadLock(func() {
			target, _, answered = expressionTarget(&responseRecorder{}, &expressionRequest{request: request, site: site, rewriteMatch: "/s", requestPath: "/s"}, source)
		})
		if target != expected || answered != (expected == "") {
			t.Errorf("%s: %q, answered %v; expected %q", source, target, answered, expected)
		}
	}

	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/files", 0755)
	os.WriteFile(dir+"localhost/@/files/x", []byte("file x"), 0644)
	os.WriteFile(dir+"localhost/@/files/a b", []byte("file a b"), 0644)
	os.WriteFile(dir+"localhost/@/x", []byte("x of the root"), 0644)
	os.WriteFile(dir+"localhost/secret.txt", []byte("secret"), 0644)
	addSiteRewrites(t, map[string]string{
		"/encoded/": "='/files/' + urlencode(QUERY('f'))", "/plain/": "='/files/' + QUERY('f')",
		"/go": "='https://example.com/find?q=' + urlencode(QUERY('q'))",
	})
	base := startServer(t)
	for _, f := range []string{"x", "a%20b", "..%2Fx", "../x", "..%2F..%2Fsecret.txt", "a%2Fb"} {
		encoded, encodedBody, err := rawGet(base, "localhost", "/encoded/?f="+f)
		if err != nil {
			t.Fatal(err)
		}
		plain, plainBody, err := rawGet(base, "localhost", "/plain/?f="+f)
		if err != nil {
			t.Fatal(err)
		}
		if encoded.StatusCode != plain.StatusCode || encodedBody != plainBody || strings.Contains(encodedBody, "secret") || strings.Contains(encodedBody, "of the root") {
			t.Errorf("f=%s: with urlencode %d %q, without it %d %q; expected the same, inside /files/", f, encoded.StatusCode, encodedBody, plain.StatusCode, plainBody)
		}
	}
	if response, _, err := rawGet(base, "localhost", "/go?q=a%20b%2Fc"); err != nil || response.StatusCode != 302 || response.Header.Get("Location") != "https://example.com/find?q=a%20b%2Fc" {
		t.Errorf("a redirection with urlencode: %v; expected 302 to https://example.com/find?q=a%%20b%%2Fc", describeResponse(response, err))
	}
}

// V2.5.1 review XP-3: {REWRITE} and REWRITE, which always start with "/", are refused in the host of a redirection:
// "https://new.example.com{REWRITE}" encoded it there, and the Location was no URL. From turbo.config, the text is
// discarded with its warning, and the expression kept, whose requests answer 500. An IPv6 address, the {DOMAIN} of the
// site * served by one, goes in the host between brackets.
func TestR251_XP3_TheRewriteKeyIsNoHost(t *testing.T) {
	const refused = `starts with "/": it can't be in the host of a redirection`
	if problem := textTargetProblem("Snew.example.com{REWRITE}"); !strings.Contains(problem, "{REWRITE} "+refused) {
		t.Errorf("text target with {REWRITE} in the host: %q", problem)
	}
	for _, source := range []string{`'https://new.example.com' + REWRITE`, `'https://' + lower(REWRITE)`, `'http://a' + (HTTPS ? '.example' : REWRITE)`} {
		if _, err := expr.Compile(source, expressionOptions(expr.RewriteTarget, "")); err == nil || !strings.Contains(err.Error(), "REWRITE "+refused) {
			t.Errorf("%s: %v; expected it refused", source, err)
		}
	}
	for _, target := range []string{"Snew.example.com/{REWRITE}x", "N/new{REWRITE}"} {
		if problem := textTargetProblem(target); problem != "" {
			t.Errorf("%s, {REWRITE} in the path: %q", target, problem)
		}
	}
	if _, err := expr.Compile(`'https://new.example.com/x' + REWRITE`, expressionOptions(expr.RewriteTarget, "")); err != nil {
		t.Errorf("REWRITE in the path: %v", err)
	}

	dir := initForTest(t)
	logs := captureLog(t)
	os.MkdirAll(dir+"#/@", 0755) // The site *, which serves the IP addresses
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"=":{"/blog/":"https://new.example.com{REWRITE}","/e/":"='https://new.example.com' + REWRITE"}}},`+
		`"*":{"":{"=":{"/x":"https://{DOMAIN}/x","/y":"='https://' + DOMAIN + '/y'"}}}}`)
	withReadLock(func() {
		if _, kept := sitesMap["localhost"][""]["/blog/"]; kept {
			t.Error("the text target with {REWRITE} in the host was kept")
		}
		if _, kept := sitesMap["localhost"][""]["/e/"]; !kept {
			t.Error("the expression with REWRITE in the host wasn't kept")
		}
	})
	if !strings.Contains(logs.String(), "Rewrite discarded: {REWRITE} starts with") { // The log escapes the quotes
		t.Errorf("the log doesn't say why the text target is discarded:\n%s", logs.String())
	}
	base := startServer(t)
	if response, _, err := rawGet(base, "localhost", "/e/a"); err != nil || response.StatusCode != 500 {
		t.Errorf("the expression with REWRITE in the host, kept: %v; expected 500", describeResponse(response, err))
	}
	addr := strings.TrimPrefix(base, "http://")
	for path, expected := range map[string]string{"/x": "https://[::1]/x", "/y": "https://[::1]/y"} {
		response, body := sendRaw(t, addr, "GET "+path+" HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n")
		if response.StatusCode != 302 || response.Header.Get("Location") != expected {
			t.Errorf("%s by [::1]: %d %q, Location %q; expected 302 to %s", path, response.StatusCode, body, response.Header.Get("Location"), expected)
		}
	}
}

// V2.5.1 review XP-4: a "\" in the host of a redirection is refused, in a text and in an expression (also in a list of
// oneOf): a browser ends the host there, and "https://{SUBDOMAIN}.com\.example.com/" went to the domain of the
// client's labels and ".com", with no warning.
func TestR251_XP4_ABackslashInTheHostIsRefused(t *testing.T) {
	initForTest(t)
	const refused = `the host of a redirection can't have a \`
	withGlobalLock(func() {
		for _, target := range []string{`https://{SUBDOMAIN}.com\.example.com/`, `https://a\b.example/x`, `http://example.com\`} {
			if ok, message := subdomainContentCheckers["="](true, map[string]interface{}{"/r": target}, false, "localhost", ""); ok || !strings.EqualFold(message, refused) {
				t.Errorf("addRewrite %s: %v %q; expected it refused", target, ok, message)
			}
		}
		if ok, message := subdomainContentCheckers["="](true, map[string]interface{}{"/r": `https://example.com/a\b`}, false, "localhost", ""); !ok {
			t.Errorf(`a "\" in the path of a redirection: %q`, message)
		}
	})
	for _, source := range []string{
		`'https://' + SUBDOMAIN + '.com\\.example.com/'`, `'https://a\\b.example/'`,
		`'https://' + oneOf(QUERY('h'), ['a.example', 'b\\c.example']) + '/'`, `'https://' + DOMAIN + lower('\\x')`,
	} {
		if _, err := expr.Compile(source, expressionOptions(expr.RewriteTarget, "")); err == nil || !strings.Contains(err.Error(), refused) {
			t.Errorf("%s: %v; expected it refused", source, err)
		}
	}
	if _, err := expr.Compile(`'https://example.com/a\\b'`, expressionOptions(expr.RewriteTarget, "")); err != nil {
		t.Errorf(`a "\" in the path: %v`, err)
	}
}

// V2.5.1 review XP-5: the warnings of a rewrite's host are the same for a text and an expression: the one of the
// labels and one label also with a final dot or a port after it, and the one of the labels before FIRST_DOMAIN or
// FIRST_SITE (EX-1) for an expression too. Neither is written again for a rewrite sent again unchanged.
func TestR251_XP5_TheWarningsOfTheHostAgree(t *testing.T) {
	for _, host := range []string{".com/", ".com./", ".com:8443/", ".com.:8443/", ".example.com/", ".com.example./"} {
		program, err := expr.Compile(`'https://' + SUBDOMAIN + '`+host+`'`, expressionOptions(expr.RewriteTarget, ""))
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if text := labelsBeforeOneLabel("S{SUBDOMAIN}" + host); program.LabelsBeforeOneLabel() != text {
			t.Errorf("SUBDOMAIN and %q: the expression warns %v, the text %v", host, program.LabelsBeforeOneLabel(), text)
		}
	}
	for source, warns := range map[string]bool{
		`'https://' + SUBDOMAIN + '.' + FIRST_DOMAIN + '/home'`: true, `'https://' + FIRST_SUBDOMAIN + '.' + lower(FIRST_SITE)`: true,
		`'https://' + SUBDOMAIN + '.' + DOMAIN`: false, `'https://' + SUBDOMAIN + '.example.org/' + FIRST_DOMAIN`: false,
	} {
		program, err := expr.Compile(source, expressionOptions(expr.RewriteTarget, ""))
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if program.LabelsBeforeAnAliasName() != warns {
			t.Errorf("%s: LabelsBeforeAnAliasName %v; expected %v", source, program.LabelsBeforeAnAliasName(), warns)
		}
	}

	initForTest(t)
	logs := captureLog(t)
	for _, target := range []string{"https://{SUBDOMAIN}.com/", "https://{SUBDOMAIN}.{FIRST_DOMAIN}/", "='https://' + SUBDOMAIN + '.com/'", "='https://' + SUBDOMAIN + '.' + FIRST_DOMAIN + '/'"} {
		for _, expected := range []string{"Rewrite created", "Rewrite unchanged"} {
			before := strings.Count(logs.String(), "level=WARN")
			withGlobalLock(func() {
				if _, message := subdomainContentCheckers["="](true, map[string]interface{}{"/r": target}, false, "localhost", ""); message != expected {
					t.Errorf("%s: %q; expected %q", target, message, expected)
				}
			})
			warnings := strings.Count(logs.String(), "level=WARN") - before
			if expected == "Rewrite created" && warnings != 1 || expected == "Rewrite unchanged" && warnings != 0 {
				t.Errorf("%s, %s: %d warnings; expected %v", target, expected, warnings, map[bool]int{true: 1, false: 0}[expected == "Rewrite created"])
			}
		}
		withGlobalLock(func() { delete(sitesMap["localhost"][""], "/r") })
	}
	if !strings.Contains(logs.String(), "Rewrite whose host is SUBDOMAIN and FIRST_DOMAIN or FIRST_SITE") {
		t.Errorf("no warning of the labels before FIRST_DOMAIN in an expression:\n%s", logs.String())
	}
}
