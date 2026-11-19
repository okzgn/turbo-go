package expr

import (
	"errors"
	goparser "go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeRequest answers what an expression reads from maps, and counts what it is asked.
type fakeRequest struct {
	vars    map[Variable]string
	headers map[string]string // By the name in lower case
	query   map[string]string
	cookies map[string]string
	https   bool
	panics  bool
	asked   []string
}

func (f *fakeRequest) Variable(v Variable) string {
	if f.panics {
		panic("broken request")
	}
	f.asked = append(f.asked, v.Name())
	return f.vars[v]
}

func (f *fakeRequest) Header(name string) string {
	f.asked = append(f.asked, "HEADER:"+name)
	return f.headers[strings.ToLower(name)]
}

func (f *fakeRequest) Query(name string) string {
	f.asked = append(f.asked, "QUERY:"+name)
	return f.query[name]
}

func (f *fakeRequest) Cookie(name string) string {
	f.asked = append(f.asked, "COOKIE:"+name)
	return f.cookies[name]
}

func (f *fakeRequest) HTTPS() bool { return f.https }

// The options Turbo compiles with: the credentials of the client and of its panel can't be read.
var (
	headerOptions  = Options{Target: HeaderValue, UnreadableHeaders: []string{"Cookie", "Authorization", "Proxy-Authorization", "ok"}, UnreadableCookies: []string{"turbo_session", "__Host-turbo_session"}}
	rewriteOptions = Options{Target: RewriteTarget, UnreadableHeaders: headerOptions.UnreadableHeaders, UnreadableCookies: headerOptions.UnreadableCookies}
)

func optionsFor(target Target) Options {
	if target == RewriteTarget {
		return rewriteOptions
	}
	return headerOptions
}

func TestCompileErrors(t *testing.T) {
	const H, R = HeaderValue, RewriteTarget
	cases := []struct {
		target   Target
		source   string
		message  string
		position int
	}{
		{H, "", "expected a text, a name, a list or (, not the end", 1},
		{H, "   \n\t", "expected a text, a name, a list or (, not the end", 6},
		{H, "'a", "a text without its closing quote", 1},
		{H, `'a\x'`, `the only escapes in a text are \\, \" and \'`, 3},
		{H, "'a\nb'", "a text can't have control characters", 3},
		{H, "'a\tb'", "a text can't have control characters", 3},
		{H, "'a\x7f'", "a text can't have control characters", 3},
		{H, "'a' \r", "the only control characters allowed are spaces", 5},
		{H, "'a' = 'b'", "unexpected character '=' (== compares)", 5},
		{H, "'a' | 'b'", "unexpected character '|' (|| and && join conditions)", 5},
		{H, "'a' 'b'", "expected the end, not a text", 5},
		{H, "'a' +", "expected a text, a name, a list or (, not the end", 6},
		{H, "('a'", "expected ), not the end", 5},
		{H, "foo", "unknown name foo", 1},
		{H, "foo('a')", "unknown function foo", 1},
		{H, "token", "token is a function: token(…)", 1},
		{H, "in", "unknown name in", 1},
		{H, "'a'.bar('b')", "unknown method bar", 5},
		{H, "'a'.", "expected the name of a method, not the end", 5},
		{H, "HTTPS", "the expression must give a text, not a condition", 1},
		{H, "['a']", "the expression must give a text, not a list", 1},
		{H, "'a' + HTTPS", "+ needs a text, not a condition", 7},
		{H, "'a' + ['b']", "a list can only follow in, or be the second argument of oneOf", 7},
		{H, "HTTPS ? 'a' : HTTPS", "The other branch of ? : needs a text, not a condition", 15},
		{H, "'a' ? 'a' : 'b'", "The condition of ? : needs a condition, not a text", 1},
		{H, "'a' == HTTPS ? 'a' : 'b'", "== and != compare two texts or two conditions", 5},
		{H, "'a' in 'b' ? 'a' : 'b'", "in needs a list written in the expression", 8},
		{H, "!'a' ? 'a' : 'b'", "! needs a condition, not a text", 2},
		{H, "HTTPS && 'a' ? 'a' : 'b'", "&& needs a condition, not a text", 10},
		{H, "oneOf('a')", "oneOf takes a text and a list", 1},
		{H, "oneOf('a', 'b')", "the second argument of oneOf is a list", 12},
		{H, "token('a', 'b')", "token takes one text", 1},
		{H, "'a'.startsWith()", "startsWith takes one text", 5},
		{H, "HEADER(DOMAIN)", "HEADER takes a name written between quotes", 1},
		{H, "HEADER('Cookie')", "the header Cookie can't be read: it carries credentials", 8},
		{H, "HEADER('cOOKIE')", "the header cOOKIE can't be read", 8},
		{H, "HEADER('Authorization')", "can't be read", 8},
		{H, "HEADER('proxy-authorization')", "can't be read", 8},
		{H, "HEADER('OK')", "can't be read", 8},
		{H, "COOKIE('TURBO_SESSION')", "the cookie TURBO_SESSION can't be read", 8},
		{H, "COOKIE('__host-turbo_session')", "can't be read", 8},
		{H, "HEADER('a b')", "invalid header name", 8},
		{H, "COOKIE('a=b')", "invalid cookie name", 8},
		{H, "QUERY('')", "a name of 1 to 128 bytes", 7},
		{H, "QUERY('" + strings.Repeat("q", 129) + "')", "a name of 1 to 128 bytes", 7},
		{H, "'a'.matches('(') ? 'a' : 'b'", "invalid pattern", 13},
		{H, "'a'.matches(DOMAIN) ? 'a' : 'b'", "the pattern of matches is a text written in the expression", 13},
		{H, "FILE", "a header can't carry FILE, which the request sends as it wants", 1},
		{H, "'x' + QUERY('a')", "a header can't carry QUERY('a')", 7},
		{H, "lower(HEADER('Origin'))", "a header can't carry HEADER('Origin')", 7},
		{H, "HTTPS ? 'a' : METHOD", "a header can't carry METHOD", 15},
		{H, "'a' + COOKIE('lang')", "a header can't carry COOKIE('lang')", 7},
		{H, "REWRITE_COMPLEMENT", "a header can't carry REWRITE_COMPLEMENT", 1},
		{R, "PATH", "PATH is only for headers", 1},
		{R, "'a'", "a target starts with /, http:// or https://", 1},
		{R, "DOMAIN + '/x'", "a target starts with a text written in the expression (/, http:// or https://), and DOMAIN may come first", 1},
		{R, "'' + FILE", "FILE may come first", 6},
		{R, "HTTPS ? '/a' : FILE", "FILE may come first", 16},
		{R, "lower(QUERY('x')) + '/a'", "QUERY('x') may come first", 7},
		{R, "'https://' + token(QUERY('h'))", "the host of a redirection can only be written in the expression, chosen with oneOf, or one that Turbo serves; token(…) may fall in it", 14},
		{R, "'https://' + HEADER('Host')", "HEADER('Host') may fall in it", 14},
		{R, "'https://' + IP", "IP may fall in it", 14},
		{R, "'https://a' + (HTTPS ? '' : '/') + FILE", "FILE may fall in it", 36},
		{R, "'https://' + DOMAIN + DIR", "DIR may fall in it", 23},
		{H, "['a', 'b'] == ['a'] ? 'a' : 'b'", "== and != compare two texts or two conditions", 12},
		{H, "'a' + 't\\tb'", `the only escapes in a text are \\, \" and \'`, 9},
		{R, "'https:///x'", "the target needs a host", 1},
		{R, "'http://?x'", "the target needs a host", 1},
		{R, "'/a/../b'", "a target can't have '..' or '//'", 1},
		{R, "'https://a.com//x'", "a target can't have '..' or '//'", 1},
		{R, "'/x?v=1..2'", "a target can't have '..' or '//'", 1},
		{R, "'//evil.example'", "a target can't have '..' or '//'", 1},
		{R, `'https://\\/' + QUERY('u')`, "the target needs a host", 1},
		{R, `'http://\\\\/' + QUERY('u')`, "the target needs a host", 1},
		{R, `'https://' + '\\/' + QUERY('u')`, "the target needs a host", 14},
		{R, `'https://' + oneOf(QUERY('h'), ['a.example', '/x'])`, "the target needs a host", 32},
		{R, `'https://#' + QUERY('u')`, "the target needs a host", 1},
		{R, `'https://' + (HTTPS ? '' : '?') + DOMAIN`, "the target needs a host", 28},
		{R, "HTTPS ? '//a' : '/b'", "a target can't have '..' or '//'", 9},
		{R, "oneOf(QUERY('x'), ['/a', 'b'])", "a target starts with /, http:// or https://", 19},
		{R, "'/a' + oneOf(QUERY('x'), ['..'])", "a target can't have '..' or '//'", 26},
		{H, strings.Repeat("a", MaxSource+1), "longer than 2048 bytes", 0},
		{H, "'\xff'", "invalid UTF-8", 0},
		{H, "'ñ' + foo", "unknown name foo", 7},
	}
	for _, c := range cases {
		_, err := Compile(c.source, optionsFor(c.target))
		var compileErr *Error
		if !errors.As(err, &compileErr) {
			t.Errorf("%q: %v; expected an *Error with %q", c.source, err, c.message)
			continue
		}
		if !strings.Contains(compileErr.Message, c.message) || compileErr.Position != c.position {
			t.Errorf("%q: %q at %d; expected %q at %d", c.source, compileErr.Message, compileErr.Position, c.message, c.position)
		}
		if want := "Expression: " + compileErr.Message; !strings.HasPrefix(compileErr.Error(), want) {
			t.Errorf("%q: Error() = %q", c.source, compileErr.Error())
		}
	}
}

func TestCompileAccepts(t *testing.T) {
	header := []string{
		`'no-cache'`,
		`EXT in ['js', 'css', 'woff2'] ? 'public, max-age=31536000' : 'no-cache'`,
		`oneOf(HEADER('Origin'), ['https://app.example.com', 'https://admin.example.com'])`,
		`DIR == '/descargas' ? 'attachment; filename=' + quoted(FILE) : ''`,
		`token(QUERY('v'))`,
		`urlencode(FIRST_REQUEST)`,
		`DOMAIN + ':' + IP + SITE + WILDCARD_SITE + REWRITE`,
		"HTTPS\n\t? 'max-age=63072000'\n\t: ''",
		`"double" + 'single' + "it's" + 'say \'hi\'' + "\\"`,
		`HEADER('accept-language').startsWith('es') ? 'es' : 'en'`,
		`METHOD.matches('^(GET|HEAD)$') ? 'cacheable' : 'no-store'`,
		`!(HTTPS) ? 'a' : 'b'`,
		`HTTPS == !HTTPS ? 'a' : 'b'`,
		`lower(SITE) + upper(oneOf(COOKIE('lang'), ['es', 'en']))`,
		`PATH.endsWith('.html') && !HTTPS || EXT != 'css' ? 'a' : 'b'`,
		`(HTTPS ? HTTPS : !HTTPS) ? 'a' : 'b'`,
		`EXT in ['a', 'b',] ? 'a' : 'b'`,
		`EXT in [] ? 'a' : 'b'`,
	}
	rewrite := []string{
		`'/es' + FIRST_REQUEST`,
		`HEADER('Accept-Language').startsWith('es') ? '/es' + FIRST_REQUEST : ''`,
		`'https://' + oneOf(QUERY('to'), ['a.example', 'b.example']) + '/x'`,
		`'https://' + DOMAIN + '/' + FILE`,
		`'https://example.com/' + QUERY('q')`,
		`'/x?ref=' + HEADER('Referer')`,
		`oneOf(COOKIE('lang'), ['/es', '/en'])`,
		`'HTTPS://Example.com'`,
		`''`,
		`'/new/' + REWRITE_COMPLEMENT + '?a=' + DIR`,
		`'http://' + WILDCARD_DOMAIN + '/x'`,
		`'https://a.example' + (HTTPS ? '/' : '?') + token(FILE)`,
	}
	for _, source := range header {
		if _, err := Compile(source, headerOptions); err != nil {
			t.Errorf("header %q: %v", source, err)
		}
	}
	for _, source := range rewrite {
		if _, err := Compile(source, rewriteOptions); err != nil {
			t.Errorf("rewrite %q: %v", source, err)
		}
	}
}

func mustCompile(t testing.TB, source string, options Options) *Program {
	t.Helper()
	program, err := Compile(source, options)
	if err != nil {
		t.Fatalf("%q: %v", source, err)
	}
	return program
}

func TestHeaderEvaluation(t *testing.T) {
	request := func() *fakeRequest {
		return &fakeRequest{
			vars:    map[Variable]string{Ext: "js", Dir: "/descargas", File: `in"for\me.pdf`, Domain: "example.com", IP: "203.0.113.9", Method: "GET", Path: "/a/index.html"},
			headers: map[string]string{"origin": "https://app.example.com", "accept-language": "es-ES,es;q=0.9"},
			query:   map[string]string{"v": "1.2_3", "bad": "a b"},
			cookies: map[string]string{"lang": "en"},
			https:   true,
		}
	}
	cases := []struct{ source, want string }{
		{`'no-cache'`, "no-cache"},
		{`EXT in ['js', 'css'] ? 'public, max-age=31536000' : 'no-cache'`, "public, max-age=31536000"},
		{`EXT in ['css'] ? 'public' : 'no-cache'`, "no-cache"},
		{`oneOf(HEADER('Origin'), ['https://app.example.com'])`, "https://app.example.com"},
		{`oneOf(HEADER('origin'), ['https://evil.example'])`, ""},
		{`DIR == '/descargas' ? 'attachment; filename=' + quoted(FILE) : ''`, `attachment; filename="in\"for\\me.pdf"`},
		{`token(QUERY('v'))`, "1.2_3"},
		{`token(QUERY('bad'))`, ""},
		{`token(QUERY('missing'))`, ""},
		{`urlencode(QUERY('bad')) + '|' + urlencode(FILE)`, `a%20b|in%22for%5Cme.pdf`},
		{`'  padded' + '  '`, "padded"},
		{`'   '`, ""},
		{`HEADER('Accept-Language').startsWith('es') ? 'es' : 'en'`, "es"},
		{`HEADER('Accept-Language').contains('q=0.9') && HEADER('x').endsWith('') ? 'yes' : 'no'`, "yes"},
		{`METHOD.matches('^(GET|HEAD)$') ? 'cacheable' : 'no-store'`, "cacheable"},
		{`HTTPS ? 'max-age=63072000' : ''`, "max-age=63072000"},
		{`!HTTPS ? 'a' : 'b'`, "b"},
		{`HTTPS == HTTPS ? 'a' : 'b'`, "a"},
		{`HTTPS != HTTPS ? 'a' : 'b'`, "b"},
		{`DOMAIN != 'example.com' ? 'a' : 'b'`, "b"},
		{`upper(DOMAIN) + '/' + lower('MiXeD')`, "EXAMPLE.COM/mixed"},
		{`oneOf(COOKIE('lang'), ['es', 'en'])`, "en"},
		{`PATH.endsWith('.html') ? 'text' : 'other'`, "text"},
		{`IP`, "203.0.113.9"},
		{`quoted('')`, `""`},
		{`HEADER('missing') == '' ? 'none' : 'some'`, "none"},
	}
	for _, c := range cases {
		got, err := mustCompile(t, c.source, headerOptions).Header(request())
		if err != nil || got != c.want {
			t.Errorf("%s → %q, %v; expected %q", c.source, got, err, c.want)
		}
	}
}

func TestRewriteParts(t *testing.T) {
	request := &fakeRequest{
		vars:    map[Variable]string{FirstRequest: "/blog/a", RewriteComplement: "a?x=1", Domain: "example.com", Dir: "/blog"},
		headers: map[string]string{"accept-language": "es"},
		query:   map[string]string{"to": "b.example"},
	}
	cases := []struct {
		source string
		want   []Part
	}{
		{`'/es' + FIRST_REQUEST`, []Part{{"/es", Const, "", false}, {"/blog/a", Raw, "FIRST_REQUEST", false}}},
		{`HEADER('Accept-Language') == 'en' ? '/en' + FIRST_REQUEST : ''`, nil},
		{`'https://' + oneOf(QUERY('to'), ['a.example', 'b.example']) + '/x'`, []Part{{"https://", Const, "", false}, {"b.example", Const, "", false}, {"/x", Const, "", false}}},
		{`'/new/' + REWRITE_COMPLEMENT`, []Part{{"/new/", Const, "", false}, {"a?x=1", Raw, "REWRITE_COMPLEMENT", false}}},
		// With its name: the rewrite places it as REWRITE_COMPLEMENT, the query apart (in other capitals, it was placed in
		// the path, and the query with it)
		{`'/new/' + lower(REWRITE_COMPLEMENT)`, []Part{{"/new/", Const, "", false}, {"a?x=1", Raw, "REWRITE_COMPLEMENT", false}}},
		{`'https://' + DOMAIN + '/' + DIR`, []Part{{"https://", Const, "", false}, {"example.com", Host, "DOMAIN", false}, {"/", Const, "", false}, {"/blog", Raw, "DIR", false}}},
		{`'/a' + '' + FILE`, []Part{{"/a", Const, "", false}}},
		// What urlencode gives is marked: a rewrite places it as it is in a path or a query, also once lower changed it
		{`'/find?q=' + urlencode(QUERY('to'))`, []Part{{"/find?q=", Const, "", false}, {"b.example", Clean, "", true}}},
		{`'/find?q=' + lower(urlencode(HEADER('Accept-Language') + ' X'))`, []Part{{"/find?q=", Const, "", false}, {"es%20x", Clean, "", true}}},
		{`'/find?q=' + token(QUERY('to'))`, []Part{{"/find?q=", Const, "", false}, {"b.example", Clean, "", false}}},
	}
	for _, c := range cases {
		got, err := mustCompile(t, c.source, rewriteOptions).Rewrite(request)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s → %+v, %v; expected %+v", c.source, got, err, c.want)
		}
	}
}

func TestFunctions(t *testing.T) {
	for _, c := range []struct {
		value string
		token bool
	}{{"a", true}, {"A-z.0_9~", true}, {strings.Repeat("t", 128), true}, {strings.Repeat("t", 129), false}, {"", false}, {"a b", false}, {"a/b", false}, {"é", false}, {"a\x00", false}} {
		if isToken(c.value) != c.token {
			t.Errorf("isToken(%q) = %v", c.value, !c.token)
		}
	}
	if got, ok := quote("a\"b\\c"); !ok || got != `"a\"b\\c"` {
		t.Errorf("quote: %q, %v", got, ok)
	}
	for _, value := range []string{"a\nb", "a\rb", "\x00", "a\tb", "\x7f"} {
		if _, ok := quote(value); ok {
			t.Errorf("quote(%q) accepted a control character", value)
		}
	}
	if got := urlEncode("a b/é?&%~._-Z9"); got != "a%20b%2F%C3%A9%3F%26%25~._-Z9" {
		t.Errorf("urlEncode: %q", got)
	}
	if got := asciiLower("ÀBC\xffdÉ"); got != "Àbc\xffdÉ" {
		t.Errorf("asciiLower changed other bytes: %q", got)
	}
	if got := asciiUpper("àbc\xffDé"); got != "àBC\xffDé" {
		t.Errorf("asciiUpper changed other bytes: %q", got)
	}
}

func TestLimits(t *testing.T) {
	nested := func(levels int) string { return strings.Repeat("(", levels) + "'a'" + strings.Repeat(")", levels) }
	concat := func(texts int) string { return strings.TrimSuffix(strings.Repeat("'a'+", texts), "+") }
	list := func(items int, size int) string {
		elements := make([]string, items)
		for i := range elements {
			elements[i] = "'" + strings.Repeat("l", size) + "'"
		}
		return "oneOf('l', [" + strings.Join(elements, ",") + "])"
	}
	pattern := func(size int) string { return "'a'.matches('" + strings.Repeat("a", size) + "') ? 'a' : 'b'" }
	for _, c := range []struct {
		name     string
		accepted string
		refused  string
		message  string
	}{
		{"source", "'" + strings.Repeat("s", MaxSource-2) + "'", "'" + strings.Repeat("s", MaxSource-1) + "'", "longer than 2048 bytes"},
		{"nesting", nested(maxDepth - 1), nested(maxDepth), "more than 32 levels of nesting"},
		{"negations", strings.Repeat("!", maxDepth-1) + "HTTPS ? 'a' : 'b'", strings.Repeat("!", maxDepth) + "HTTPS ? 'a' : 'b'", "more than 32 levels of nesting"},
		{"elements", concat((maxNodes + 1) / 2), concat((maxNodes+1)/2 + 1), "more than 512 elements"},
		{"list", list(maxListItems, 1), list(maxListItems+1, 1), "more than 64 texts in a list"},
		{"list item", list(1, maxListItem), list(1, maxListItem+1), "a text of a list longer than 512 bytes"},
		{"pattern", pattern(maxPattern), pattern(maxPattern + 1), "a pattern longer than 256 bytes"},
		{"cost of the patterns", "'a'.matches('a{400}') && 'a'.matches('a{400}') ? 'a' : 'b'", "'a'.matches('a{400}') && 'a'.matches('a{400}') && 'a'.matches('a{400}') ? 'a' : 'b'", "patterns too costly"},
	} {
		if _, err := Compile(c.accepted, headerOptions); err != nil {
			t.Errorf("%s at the limit refused: %v", c.name, err)
		}
		if _, err := Compile(c.refused, headerOptions); err == nil || !strings.Contains(err.Error(), c.message) {
			t.Errorf("%s over the limit: %v; expected %q", c.name, err, c.message)
		}
	}

	read := func(value string) (string, error) {
		return mustCompile(t, `oneOf(HEADER('X'), ['a']) + token(HEADER('X'))`, headerOptions).Header(&fakeRequest{headers: map[string]string{"x": value}})
	}
	if _, err := read(strings.Repeat("x", MaxText)); err != nil {
		t.Errorf("a header of 8 KiB: %v", err)
	}
	if _, err := read(strings.Repeat("x", MaxText+1)); !errors.Is(err, ErrTooLong) {
		t.Errorf("a header over 8 KiB: %v; expected ErrTooLong", err)
	}
	half := &fakeRequest{vars: map[Variable]string{Domain: strings.Repeat("d", MaxText/2), Site: strings.Repeat("s", MaxText/2)}}
	if _, err := mustCompile(t, `'/' + DOMAIN + SITE`, rewriteOptions).Rewrite(half); !errors.Is(err, ErrTooLong) {
		t.Errorf("texts joined over 8 KiB: %v; expected ErrTooLong", err)
	}
	if _, err := mustCompile(t, `urlencode(DOMAIN)`, headerOptions).Header(&fakeRequest{vars: map[Variable]string{Domain: strings.Repeat(" ", MaxText/3+1)}}); !errors.Is(err, ErrTooLong) {
		t.Errorf("urlencode over 8 KiB: %v; expected ErrTooLong", err)
	}

	value := func(text string) (string, error) {
		return mustCompile(t, `WILDCARD_DOMAIN`, headerOptions).Header(&fakeRequest{vars: map[Variable]string{WildcardDomain: text}})
	}
	if got, err := value(strings.Repeat("v", MaxHeaderValue)); err != nil || len(got) != MaxHeaderValue {
		t.Errorf("a value of 512 bytes: %d, %v", len(got), err)
	}
	if _, err := value(strings.Repeat("v", MaxHeaderValue+1)); !errors.Is(err, ErrHeaderValue) {
		t.Errorf("a value of 513 bytes: %v; expected ErrHeaderValue", err)
	}
	if got, err := value("  " + strings.Repeat("v", MaxHeaderValue) + "\t "); err != nil || len(got) != MaxHeaderValue {
		t.Errorf("512 bytes between spaces: %d, %v", len(got), err)
	}
	for _, bad := range []string{"a\r\nInjected: 1", "a\nb", "a\x00", "a\x7f"} {
		if _, err := value(bad); !errors.Is(err, ErrHeaderValue) {
			t.Errorf("%q: %v; expected ErrHeaderValue", bad, err)
		}
	}
	if got, err := value("a\tb"); err != nil || got != "a\tb" {
		t.Errorf("a tab inside: %q, %v", got, err)
	}
}

// The patterns of an expression can't cost more than maxPatternCost in all: one with 53 patterns \pL{1000} took 6.8 s
// on a header of 8 KiB. The costliest one allowed (\pL{990}) takes some 60 ms on such a header, and patterns as
// people write them, like these, much less: matching costs what the documentation says, the size of the patterns.
func TestPatternsCostIsBounded(t *testing.T) {
	one := `HEADER('X').matches('\\pL{1000}0') || `
	if _, err := Compile(strings.Repeat(one, (MaxSource-20)/len(one))+`HTTPS ? 'a' : 'b'`, headerOptions); err == nil || !strings.Contains(err.Error(), "patterns too costly") {
		t.Errorf("53 patterns \\pL{1000}: %v", err)
	}
	program := mustCompile(t, `HEADER('X').matches('\\pL{30}0') || HEADER('X').matches('(a|b|c)*d{20}') ? 'a' : 'b'`, headerOptions)
	start := time.Now()
	for i := 0; i < 10; i++ {
		if _, err := program.Header(&fakeRequest{headers: map[string]string{"x": strings.Repeat("a", MaxText)}}); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start) / 10; elapsed > 200*time.Millisecond {
		t.Errorf("one evaluation took %v", elapsed)
	}
}

// || and && evaluate their right side only when it decides, and ? : only the branch it takes.
func TestShortCircuit(t *testing.T) {
	for _, c := range []struct {
		source string
		https  bool
		asked  []string
	}{
		{`HTTPS || HEADER('A') == 'x' ? 'a' : 'b'`, true, nil},
		{`HTTPS || HEADER('A') == 'x' ? 'a' : 'b'`, false, []string{"HEADER:A"}},
		{`HTTPS && HEADER('A') == 'x' ? 'a' : 'b'`, false, nil},
		{`HTTPS ? DOMAIN : SITE`, true, []string{"DOMAIN"}},
		{`HTTPS ? DOMAIN : SITE`, false, []string{"SITE"}},
	} {
		request := &fakeRequest{https: c.https}
		if _, err := mustCompile(t, c.source, headerOptions).Header(request); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(request.asked, c.asked) {
			t.Errorf("%s (HTTPS %v) asked %v; expected %v", c.source, c.https, request.asked, c.asked)
		}
	}
}

func TestPanicIsAnError(t *testing.T) {
	if _, err := mustCompile(t, `DOMAIN`, headerOptions).Header(&fakeRequest{panics: true}); !errors.Is(err, ErrFailed) {
		t.Errorf("a request that panics: %v; expected ErrFailed", err)
	}
	if _, err := mustCompile(t, `'/' + DOMAIN`, rewriteOptions).Rewrite(&fakeRequest{panics: true}); !errors.Is(err, ErrFailed) {
		t.Errorf("a request that panics: %v; expected ErrFailed", err)
	}
	broken := mustCompile(t, `DOMAIN`, headerOptions)
	broken.root = &node{op: opNot} // No operand: what no compilation makes
	if _, err := broken.Header(&fakeRequest{}); !errors.Is(err, ErrFailed) {
		t.Errorf("a program made by hand: %v; expected ErrFailed", err)
	}
}

func TestTargetMismatch(t *testing.T) {
	if _, err := mustCompile(t, `'/a'`, rewriteOptions).Header(&fakeRequest{}); !errors.Is(err, ErrTarget) {
		t.Errorf("Header of a rewrite: %v", err)
	}
	if _, err := mustCompile(t, `'a'`, headerOptions).Rewrite(&fakeRequest{}); !errors.Is(err, ErrTarget) {
		t.Errorf("Rewrite of a header: %v", err)
	}
	if _, err := Compile(`'a'`, Options{}); !errors.Is(err, ErrTarget) {
		t.Errorf("Compile without a target: %v", err)
	}
}

func TestReads(t *testing.T) {
	program := mustCompile(t, `HEADER('Accept') == HEADER('accept') && HEADER('Origin') != '' ? 'a' : token(COOKIE('lang'))`, headerOptions)
	if got := program.ReadsHeaders(); !reflect.DeepEqual(got, []string{"Accept", "Origin"}) {
		t.Errorf("ReadsHeaders = %v", got)
	}
	if !program.ReadsCookies() {
		t.Error("ReadsCookies = false")
	}
	plain := mustCompile(t, `token(QUERY('v'))`, headerOptions)
	if plain.ReadsHeaders() != nil || plain.ReadsCookies() {
		t.Errorf("an expression that reads only the query: %v, %v", plain.ReadsHeaders(), plain.ReadsCookies())
	}
	if program.Source() != `HEADER('Accept') == HEADER('accept') && HEADER('Origin') != '' ? 'a' : token(COOKIE('lang'))` || program.Target() != HeaderValue {
		t.Error("Source or Target changed")
	}
}

// Two compilations of the same expression are equal (Turbo compares the views of the sites with reflect.DeepEqual).
func TestCompileIsDeterministic(t *testing.T) {
	source := `METHOD.matches('^G') && EXT in ['js'] ? oneOf(HEADER('Origin'), ['https://a']) + quoted(FILE) : ''`
	if !reflect.DeepEqual(mustCompile(t, source, headerOptions), mustCompile(t, source, headerOptions)) {
		t.Error("two compilations differ")
	}
}

// The package reads nothing but what Request gives: it imports no package of the system, the network, the clock or
// Turbo.
func TestImports(t *testing.T) {
	allowed := map[string]bool{"errors": true, "regexp": true, "regexp/syntax": true, "strconv": true, "strings": true, "unicode/utf8": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := goparser.ParseFile(gotoken.NewFileSet(), file, source, goparser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if !allowed[path] {
				t.Errorf("%s imports %s", file, path)
			}
		}
		checked++
	}
	if checked < 4 {
		t.Errorf("only %d files checked", checked)
	}
}
