package server

// The tests of the findings about the expressions and the targets of the rewrites of the external review of v2.5.2
// (GGCH): each failed before its fix.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"turbo/customNetHttp"
	"turbo/internal/expr"
)

// queryAsTheScriptsReadIt are queries, a name, and the value that a preprocessor reads for it: dx-core's parse_query
// (REQUEST.params of dx-lua) and PHP's $_GET (the same separator and decoding). The same cases are in the tests of
// dx-core (util.rs, query_as_the_expressions_read_it): the two sides read a query alike.
var queryAsTheScriptsReadIt = []struct{ query, name, want string }{
	{"id=123;x=1", "id", "123;x=1"}, // ";" separates nothing
	{"a=1;rol=admin", "rol", ""},
	{"q=%zz<s>", "q", "%zz<s>"}, // A "%" without two hexadecimal digits stays as it is
	{"q=%4", "q", "%4"},
	{"q=50%", "q", "50%"},
	{"q=a+b%20c", "q", "a b c"},
	{"q=%41%e2%82%ac", "q", "A€"},
	{"a=1&a=1", "a", "1"}, // A repeated name with one value
	{"%71=x", "q", "x"},   // The name decoded too
	{"q%zz=1&q=2", "q", "2"},
	{"q+r=1", "q r", "1"},
	{"&&q=1", "q", "1"},
	{"q", "q", ""},
	{"q=1=2", "q", "1=2"},
	{"", "q", ""},
}

// GGCH H-01: QUERY() reads the query as the preprocessors do. A guard in an expression saw "123" in "id=123;x=1", where
// the script got "123;x=1", and "" for a value with a "%" that can't be decoded, which the script got as it was.
func TestGGCH_H01_QueryReadsAsTheScripts(t *testing.T) {
	for _, c := range queryAsTheScriptsReadIt {
		uri := "/x"
		if c.query != "" {
			uri += "?" + c.query
		}
		read := &expressionRequest{request: &customNetHttp.Request{RequestURI: uri, Header: customNetHttp.Header{}}}
		if got := read.Query(c.name); got != c.want {
			t.Errorf("QUERY(%q) of %q: %q; expected %q", c.name, c.query, got, c.want)
		}
	}
	// As many parameters as a preprocessor reads (dx-core's MAX_PAIRS, PHP's max_input_vars): one after them isn't
	// there for it, nor for the expression.
	many := strings.Repeat("a=1&", 999)
	for _, c := range []struct{ query, want string }{{many + "q=1", "1"}, {many + "b=2&q=1", ""}, {many + "&&&q=1", "1"}} {
		read := &expressionRequest{request: &customNetHttp.Request{RequestURI: "/x?" + c.query, Header: customNetHttp.Header{}}}
		if got := read.Query("q"); got != c.want {
			t.Errorf("QUERY('q') after %d parameters: %q; expected %q", strings.Count(c.query, "=")-1, got, c.want)
		}
	}
}

// Review of v2.5.3 (M-2): where the preprocessors could read different values of a name, QUERY() is "". With the
// first value of a repeated name, a guard checked "1" in "id=1&id=x", and PHP's $_GET (the last) got "x"; PHP takes
// "id.x", "id x" and "id_x" as one variable, "id[]" as an array of "id", and a name up to a NUL byte.
func TestGGCH_H01_QueryWhereTheScriptsDisagree(t *testing.T) {
	for _, c := range []struct{ query, name, want string }{
		{"id=1&id=x", "id", ""}, // dx-lua reads "1", PHP "x"
		{"id=x&id=1", "id", ""},
		{"id=1&id=1&z=2", "id", "1"},
		{"id=1&id=1&id=2", "id", ""},
		{"id=1&id[]=1", "id", ""}, // An array for PHP
		{"id[x]=1&id=1", "id", ""},
		{"id[=1", "id", ""}, // PHP: "id_"
		{"id[=1", "id_", ""},
		{"id[=1&id_=1", "id_", "1"},
		{"id_x=1&id.x=2", "id_x", ""},
		{"id.x=1&id_x=2", "id.x", ""},
		{"id+x=1&id_x=1", "id_x", "1"},
		{"id.x=1", "id_x", ""}, // Only another spelling: dx-lua reads nothing, PHP "1"
		{"%20id=x&id=1", "id", ""},
		{"id%00x=x&id=1", "id", ""},
		{"id%00x=1&id=1", "id", "1"},
		{"id[]=1", "id[]", "1"},
		{"id[]=1&id[]=2", "id[]", ""},
		{"id[]=1&id[0]=1", "id[]", ""},
		{"[x]=1&%20=2&id=1", "id", "1"}, // Names that PHP ignores
		{"a.b=1&a_b=1&c=2", "c", "2"},
	} {
		read := &expressionRequest{request: &customNetHttp.Request{RequestURI: "/x?" + c.query, Header: customNetHttp.Header{}}}
		if got := read.Query(c.name); got != c.want {
			t.Errorf("QUERY(%q) of %q: %q; expected %q", c.name, c.query, got, c.want)
		}
	}
	for name, want := range map[string]struct {
		variable string
		array    bool
	}{
		"a.b": {"a_b", false}, " a b": {"a_b", false}, "a[": {"a_", false}, "a[.]": {"a", true}, "a[x": {"a_x", false},
		"a[ ]": {"a", true}, "a\x00[]": {"a", false}, "[x]": {"", true}, "a.[b": {"a__b", false}, "a]": {"a]", false},
	} {
		if variable, array := phpParameterName(name); variable != want.variable || array != want.array {
			t.Errorf("phpParameterName(%q): %q %v; expected %q %v", name, variable, array, want.variable, want.array)
		}
	}
}

// GGCH H-01, through a request: the guard of an expression decides with what the script would get.
func TestGGCH_H01_QueryGuardThroughARequest(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/ok.html", []byte("ok"), 0644)
	os.WriteFile(dir+"localhost/@/no.html", []byte("no"), 0644)
	addSiteRewrites(t, map[string]string{"/r": "=QUERY('id').matches('^[0-9]+$') ? '/ok.html' : '/no.html'"})
	base := startServer(t)
	for query, want := range map[string]string{"id=123": "ok", "id=123;x=1": "no", "x=1;id=123": "no", "id=%zz": "no", "id=1%32": "ok"} {
		if response, body := requestWithHeaders(t, "GET", base, "localhost", "/r?"+query, nil); response.StatusCode != 200 || body != want {
			t.Errorf("/r?%s: %d %q; expected %q", query, response.StatusCode, body, want)
		}
	}
}

// GGCH H-01: the parameters of the client that a rewrite's query sets are dropped by the name a script reads.
func TestGGCH_H01_DroppedByTheNameTheScriptReads(t *testing.T) {
	for _, c := range []struct{ query, other, want string }{
		{"role=admin&z=1", "role=user", "z=1"},
		{"r%6fle=admin&z=1", "role=user", "z=1"},
		{"a=1;role=admin", "role=user", "a=1"}, // ";" still separates here: a library that takes it gets no role of the client's
		{"role%zz=1&z=1", "role%zz=2", "z=1"},
		{"role+x=1&z=1", "role x=2", "z=1"},
	} {
		if got := withoutParametersOf(c.query, c.other); got != c.want {
			t.Errorf("withoutParametersOf(%q, %q) = %q; expected %q", c.query, c.other, got, c.want)
		}
	}
}

// notThere is, in cookieAsTheScriptsReadIt, a cookie that a preprocessor doesn't read by that name, and phpArray one
// that PHP reads as an array: a header Cookie can't have a NUL byte.
const (
	notThere = "\x00"
	phpArray = "\x00array"
)

// cookieAsTheScriptsReadIt are headers Cookie (as a script receives them), a name, and what each preprocessor reads
// for it: dx-lua's REQUEST.cookies (dx-core's parse_cookies, the first of a name) and PHP's $_COOKIE (as php-cgi 8.5
// read each one), and what COOKIE() gives: the value where both read the same, or "". The column of dx-lua is in the
// tests of dx-core too (util.rs, cookies_as_the_expressions_read_them).
var cookieAsTheScriptsReadIt = []struct{ header, name, dxLua, php, want string }{
	{"a=1; b=2", "a", "1", "1", "1"},
	{"a=1;b=2", "b", "2", "2", "2"},
	{"   a=1", "a", "1", "1", "1"},
	{"\ta=1", "a", "1", "1", "1"},
	{"a = 1", "a", "1", notThere, ""}, // PHP: "a_" is " 1"
	{"a\t=1", "a", "1", notThere, ""},
	{"a= 1", "a", "1", " 1", ""},
	{"a=1 ; b=2", "a", "1", "1 ", ""},
	{"a=1\t", "a", "1", "1\t", ""},
	{`a="x"`, "a", "x", `"x"`, ""},
	{`a=""`, "a", "", `""`, ""},
	{`a="`, "a", `"`, `"`, `"`},
	{`a=x"y`, "a", `x"y`, `x"y`, `x"y`},
	{`a=x\y; a=1`, "a", `x\y`, `x\y`, `x\y`}, // Go's reader (RFC 6265) skipped the first one, and gave "1"
	{"a=é", "a", "é", "é", "é"},
	{"a=%61dmin", "a", "%61dmin", "admin", ""},
	{"a=x+y", "a", "x+y", "x+y", "x+y"},
	{"a=%zz", "a", "%zz", "%zz", "%zz"},
	{"a=%2", "a", "%2", "%2", "%2"},
	{"%61=1", "a", notThere, notThere, ""}, // A name isn't decoded
	{"%61=1", "%61", "1", "1", "1"},
	{"a=1; a=2", "a", "1", "1", "1"}, // The first of a name
	{"a=1=2", "a", "1=2", "1=2", "1=2"},
	{"a=1,b=2", "a", "1,b=2", "1,b=2", "1,b=2"},
	{"a=", "a", "", "", ""},
	{";;a=1;;", "a", "1", "1", "1"},
	{"=1; a=2", "a", "2", "2", "2"},
	{" =1; a=2", "a", "2", "2", "2"},
	{"a; a=2", "a", "2", "", ""}, // PHP: "a" without "=" is ""
	{"a.b=1; a_b=2", "a.b", "1", "1", "1"},
	{"a.b=1; a_b=2", "a_b", "2", "1", ""}, // "a.b" is "a_b" for PHP
	{"a_b=2; a.b=1", "a.b", "1", "2", ""},
	{"a b=1", "a_b", notThere, "1", ""},
	{"a.=1", "a_", notThere, "1", ""},
	{"a[=1", "a_", notThere, "1", ""},
	{"a[x]=1; a=2", "a", "2", phpArray, ""},
	{"a=2; a[x]=1", "a", "2", phpArray, ""},
	{"[x]=1; a=2", "a", "2", "2", "2"},
	{"", "a", notThere, notThere, ""},
	// The panel's session never reaches a script (withoutPanelCredentials): PHP reads "turbo.session" as
	// $_COOKIE['turbo_session'], whose first cookie is that one
	{"turbo_session=s; turbo.session=1", "turbo.session", "1", "1", "1"},
}

// GGCH H-01 (COOKIE(), review of v2.5.3): COOKIE() reads the cookies as the preprocessors do, and gives "" where they
// read different values, as QUERY(). Go's reader (RFC 6265) skipped a cookie with a byte that RFC 6265 doesn't take,
// and a guard saw "1" in "a=x\; a=1", where the scripts got "x\"; it took the double quotes away, which PHP keeps, and
// decoded nothing, where PHP decodes "%XX" ("role=%61dmin" is "admin" for PHP).
func TestGGCH_H01_CookieReadsAsTheScripts(t *testing.T) {
	check := func(lines []string, name, dxLua, php, want string) {
		t.Helper()
		header := strings.Join(lines, "; ")
		shown := header
		if len(shown) > 80 {
			shown = "…" + shown[len(shown)-24:]
		}
		readDX, found := dxLuaCookie(header, name)
		if !found {
			readDX = notThere
		}
		readPHP, phpFound, array := phpCookie(header, name)
		if array {
			readPHP = phpArray
		} else if !phpFound {
			readPHP = notThere
		}
		if readDX != dxLua || readPHP != php {
			t.Errorf("%q, %q: dx-lua %q, PHP %q; expected %q, %q", shown, name, readDX, readPHP, dxLua, php)
		}
		read := &expressionRequest{request: &customNetHttp.Request{Header: customNetHttp.Header{"Cookie": lines}}}
		if got := read.Cookie(name); got != want {
			t.Errorf("COOKIE(%q) of %q: %q; expected %q", name, shown, got, want)
		}
	}
	for _, c := range cookieAsTheScriptsReadIt {
		check([]string{c.header}, c.name, c.dxLua, c.php, c.want)
	}
	check(nil, "a", notThere, notThere, "")
	check([]string{"a=1", "b=2; a=3"}, "b", "2", "2", "2") // Lines joined with "; ", as a CGI and a worker get them
	// As many cookies as a preprocessor reads (dx-core's MAX_PAIRS, PHP's max_input_vars), which they count apart: PHP
	// counts a cookie without "=" and one whose name it drops, and dx-lua doesn't count the first
	var many strings.Builder
	for i := 1; i < 1000; i++ {
		many.WriteString("x" + strconv.Itoa(i) + "=1;")
	}
	for _, c := range []struct{ last, dxLua, php, want string }{
		{"a=1", "1", "1", "1"},
		{"y;a=1", "1", notThere, ""},
		{"=v;a=1", "1", "1", "1"},
		{" ;a=1", "1", "1", "1"},
		{"[z]=1;a=1", notThere, notThere, ""},
	} {
		check([]string{many.String() + c.last}, "a", c.dxLua, c.php, c.want)
	}
}

// GGCH H-01 (COOKIE()), through a request: the guard of an expression decides with what the script would get.
func TestGGCH_H01_CookieGuardThroughARequest(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/ok.html", []byte("ok"), 0644)
	os.WriteFile(dir+"localhost/@/no.html", []byte("no"), 0644)
	addSiteRewrites(t, map[string]string{"/r": "=COOKIE('id').matches('^[0-9]+$') ? '/ok.html' : '/no.html'"})
	base := startServer(t)
	for cookie, want := range map[string]string{"id=123": "ok", `id=x\; id=123`: "no", `id="123"`: "no", "id=%31": "no", "a=1; id=1": "ok"} {
		if response, body := requestWithHeaders(t, "GET", base, "localhost", "/r", map[string]string{"Cookie": cookie}); response.StatusCode != 200 || body != want {
			t.Errorf("/r with %q: %d %q; expected %q", cookie, response.StatusCode, body, want)
		}
	}
}

// GGCH H-15.e: with TURBO_DIR, only the "M" that is {TURBO_CURRENT_DIR} (what a save wrote when Turbo was started from
// that folder) means that folder; one with a folder after it ("{TURBO_CURRENT_DIR}/sub") was taken for it too, and the
// sites directory stayed where nothing named it. It is followed, as without TURBO_DIR.
func TestGGCH_H15e_ACurrentDirWithAFolderAfterItIsFollowed(t *testing.T) {
	dirA := initForTest(t)
	cwd := filepath.ToSlash(t.TempDir()) + "/" // The working directory of the service
	os.MkdirAll(cwd+"sub/example.com/@", 0755)
	os.WriteFile(dirA+"turbo.config", []byte(`{"^":{"v":"2"},"example.com":{"":{"-":{"index.html":"1"}}},".":{"M":"{TURBO_CURRENT_DIR}/sub","CII":"40"},"_":{}}`), 0600)
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	resetTestState(dirA) // As TURBO_DIR sets it
	sitesDirFromEnv = true
	t.Cleanup(func() { sitesDirFromEnv = false })
	logs := captureLog(t)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if !sameDir(sitesDir.Get(), cwd+"sub/") {
		t.Errorf("the sites directory is %q; expected %q", sitesDir.Get(), cwd+"sub/")
	}
	if strings.Contains(logs.String(), "which with TURBO_DIR is another directory") {
		t.Errorf("warned as the M of a save: %s", logs.String())
	}
}

// GGCH H-06: a value before a "." that gives nothing for a request (SUBDOMAIN in the site's root) left the host of a
// redirection starting with "." or with "..": "https://.example.com/" went out as a Location. It answers 500, for a
// target written as a text and for an expression, and the log warns of the rewrite when it is added.
func TestGGCH_H06_ARedirectionHostLeftWithADotAnswers500(t *testing.T) {
	initForTest(t)
	logs := captureLog(t)
	addSiteRewrites(t, map[string]string{
		"/a": "='https://' + SUBDOMAIN + '.example.com/'",
		"/b": "https://{SUBDOMAIN}.example.com/",
		"/c": "='https://app.' + SUBDOMAIN + '.example.com/x'",
		"/d": "https://app.{SUBDOMAIN}.example.com/x",
		"/e": "='https://' + FIRST_DOMAIN + ':8443/'",
	})
	if !strings.Contains(logs.String(), "only values that may give nothing for a request") {
		t.Errorf("no warning of the texts that meet: %s", logs.String())
	}
	base := startServer(t)
	for _, path := range []string{"/a", "/b", "/c", "/d", "/e"} {
		if response, _ := requestWithHeaders(t, "GET", base, "localhost", path, nil); response.StatusCode != 500 || response.Header.Get("Location") != "" {
			t.Errorf("%s: %d %q; expected 500 without a Location", path, response.StatusCode, response.Header.Get("Location"))
		}
	}
	for target, malformed := range map[string]bool{
		".example.com/": true, "app..example.com/x": true, "": true, ":8443/": true, "user@.example.com/": true, ".": true,
		"example.com./": false, "example.com": false, "[::1]:8443/": false, "a.example.com:8443/x?y#z": false, "example.com/..x": false,
	} {
		if redirectHostMalformed(target) != malformed {
			t.Errorf("redirectHostMalformed(%q): %v; expected %v", target, !malformed, malformed)
		}
	}
}

// GGCH H-06: in the path, the texts that meet where a value gives nothing stay as they are in a redirection (a value
// of the request may put "//" there too: "{DIR}" is "/a"), and a path of the site is cleaned as a request's.
func TestGGCH_H06_ThePathKeepsWhatTheValuesLeave(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/file", []byte("file"), 0644)
	addSiteRewrites(t, map[string]string{
		"/r":  "='https://example.com/' + EXT + '/r'",
		"/n/": "='/' + EXT + '/file'",
	})
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/r", nil); response.StatusCode != 302 || response.Header.Get("Location") != "https://example.com//r" {
		t.Errorf("a redirection: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	if response, body := requestWithHeaders(t, "GET", base, "localhost", "/n/", nil); response.StatusCode != 200 || body != "file" {
		t.Errorf("a path of the site: %d %q", response.StatusCode, body)
	}
	for target, joins := range map[string]bool{
		"N/{EXT}/x": true, "Sexample.com/{DIR}{FILE}/x": true, "Sexample.com{DIR}/{FILE}": false, "Sapp.{SUBDOMAIN}.example.com/": true, "N/a/{FILE}/": true,
		"N/{DOMAIN}/x": false, "N/a.{EXT}.b": true, "S{SUBDOMAIN}.example.com/": false, "N/{EXT}{DOMAIN}/x": false,
		"N/{EXT}{FILE}/x": true, "N/x/{EXT}": false,
	} {
		if textTargetValueJoins(target) != joins {
			t.Errorf("textTargetValueJoins(%q): %v; expected %v", target, !joins, joins)
		}
	}
	for source, joins := range map[string]bool{
		`'/' + EXT + '/x'`: true, `'/' + DOMAIN + '/x'`: false, `'/a/' + FILE + FIRST_QUERY + '/b'`: true, `'/a.' + EXT + '.b'`: true,
		`'https://app.' + SUBDOMAIN + '.example.com/'`: true, `'https://' + SUBDOMAIN + '.example.com/'`: false,
		`'/a/' + (HTTPS ? EXT : 'x') + '/b'`: true, `'/a/' + EXT + 'x/b'`: false,
	} {
		program, err := expr.Compile(source, expressionOptions(expr.RewriteTarget, ""))
		if err != nil {
			t.Errorf("%s: %v", source, err)
			continue
		}
		if program.ValueMayJoinTexts() != joins {
			t.Errorf("%s: ValueMayJoinTexts %v; expected %v", source, program.ValueMayJoinTexts(), joins)
		}
	}
}

// GGCH H-07: the warning of a host made of the client's labels and one label follows the host to its end, however its
// texts are written: the "." apart, or the label chosen with ? :, warned of nothing, and a label followed by DOMAIN
// warned of one. (With oneOf after the ".", the expression doesn't compile: oneOf may give nothing, and the host
// would end with the labels and the ".".)
func TestGGCH_H07_OneLabelIsFollowedToTheEndOfTheHost(t *testing.T) {
	for source, want := range map[string]bool{
		`'https://' + SUBDOMAIN + '.' + 'com/'`:                                 true,
		`'https://' + SUBDOMAIN + '.' + (HTTPS ? 'com' : 'org') + '/'`:          true,
		`'https://' + SUBDOMAIN + '.' + 'co' + 'm/x'`:                           true,
		`'https://' + SUBDOMAIN + '.com' + '.'`:                                 true,
		`'https://' + SUBDOMAIN + '.com.' + ':8443/'`:                           true,
		`'https://' + SUBDOMAIN + '.com' + (HTTPS ? '/a' : '/b')`:               true,
		`'https://' + SUBDOMAIN + '.interno.' + FIRST_DOMAIN + '/'`:             true, // FIRST_DOMAIN may give nothing
		`'https://' + SUBDOMAIN + '.interno.' + DOMAIN + '/'`:                   false,
		`'https://' + SUBDOMAIN + '.app.' + 'example.com/'`:                     false,
		`'https://' + SUBDOMAIN + '.com.' + 'example/'`:                         false,
		`'https://' + SUBDOMAIN + '.' + (HTTPS ? 'a.com' : 'b.org') + '/'`:      false,
		`'https://' + SUBDOMAIN + '.example.org'`:                               false,
		`'https://' + SUBDOMAIN + '.com'`:                                       true,
		`'https://' + SUBDOMAIN + '.' + (HTTPS ? 'com' : 'a.example') + '#x.y'`: true,
	} {
		program, err := expr.Compile(source, expressionOptions(expr.RewriteTarget, ""))
		if err != nil {
			t.Errorf("%s: %v", source, err)
			continue
		}
		if program.LabelsBeforeOneLabel() != want {
			t.Errorf("%s: LabelsBeforeOneLabel %v; expected %v", source, program.LabelsBeforeOneLabel(), want)
		}
	}
	if labelsBeforeOneLabel("S{SUBDOMAIN}.interno.{DOMAIN}/") || !labelsBeforeOneLabel("S{SUBDOMAIN}.com#x.y") {
		t.Error("the text targets: a label before {DOMAIN} warns, or one before a fragment doesn't")
	}
}

// GGCH H-08: a "#" starts the fragment of a target, where nothing else starts: a redirection with one isn't "only a
// domain", the request's query goes before it, and a "?" in it is no query. A path of the site is served without it.
func TestGGCH_H08_TheFragmentOfATarget(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/index.html", []byte("index"), 0644)
	addSiteRewrites(t, map[string]string{
		"/a":     "https://example.com#top",
		"/blog/": "https://example.com/{REWRITE_COMPLEMENT}#top",
		"/tab":   "https://example.com/x#tab?y=1",
		"/c/":    "='https://example.com/' + REWRITE_COMPLEMENT + '#tab?y=1'",
		"/i":     "/index.html#section",
		"/f":     "https://example.com/p#{FILE}",
		"/q":     "='https://example.com/p#' + QUERY('s')",
		// Review of v2.5.3 (M-1): a value in the fragment goes as in the path, and REWRITE_COMPLEMENT with the
		// request's query after its path, as in v2.5.2 (the route of a page's router: "#a/b?x=1"); written as one
		// value, it was "#a%2Fb%3Fx=1"
		"/legacy/": "https://example.com/#{REWRITE_COMPLEMENT}",
		"/e/":      "='https://example.com/#' + REWRITE_COMPLEMENT",
		"/m/":      "https://example.com/#{REWRITE_COMPLEMENT}/more",
		"/t/":      "https://example.com/#/r?tab=1/{REWRITE_COMPLEMENT}",
	})
	base := startServer(t)
	for path, want := range map[string]string{
		"/a":                "https://example.com#top",
		"/blog/a/b?x=1":     "https://example.com/a/b?x=1#top",
		"/tab?z=2":          "https://example.com/x#tab?y=1",
		"/c/a?x=1":          "https://example.com/a?x=1#tab?y=1",
		"/f":                "https://example.com/p#f",
		"/q?s=a%20b%23c":    "https://example.com/p#a%20b%23c",
		"/q?s=%2Fa%2Fb%3Fx": "https://example.com/p#/a/b%3Fx",
		"/legacy/a/b?x=1":   "https://example.com/#a/b?x=1",
		"/legacy/a/b":       "https://example.com/#a/b",
		"/e/a/b?x=1&y=%2F":  "https://example.com/#a/b?x=1&y=%2F",
		"/m/a/b?x=1":        "https://example.com/#a/b/more?x=1", // At the end of the fragment, as in v2.5.2
		"/t/a?x=1":          "https://example.com/#/r?tab=1/a&x=1",
	} {
		if response, _ := requestWithHeaders(t, "GET", base, "localhost", path, nil); response.StatusCode != 302 || response.Header.Get("Location") != want {
			t.Errorf("%s: %d %q; expected %q", path, response.StatusCode, response.Header.Get("Location"), want)
		}
	}
	if response, body := requestWithHeaders(t, "GET", base, "localhost", "/i", nil); response.StatusCode != 200 || body != "index" {
		t.Errorf("a path of the site with a fragment: %d %q", response.StatusCode, body)
	}
	if labelsBeforeAnAliasKeyword("S{SUBDOMAIN}.example.com#{SUBDOMAIN}.{FIRST_DOMAIN}") {
		t.Error("a fragment taken for the host")
	}
}
