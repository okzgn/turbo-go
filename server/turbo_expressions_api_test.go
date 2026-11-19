package server

// The expressions through the panel's API and turbo.config: they may span lines (the panel sends them from a text
// area), they go through the character replacements as any value, and they are saved and read back as they are.

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// An expression may have tabs and line breaks ("\r\n" kept as "\n"); a value that isn't one, and the parameters of the
// other actions, may not. A lone "\r" is refused by the expression.
func TestExpressionsSpanLinesThroughTheAPI(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	token := login(t, base)
	add := func(action string, values url.Values) (int, string) {
		values.Set("s", "localhost")
		values.Set("d", "")
		code, body, err := post(base, "/admin:inside:"+action+"?"+values.Encode(), token)
		if err != nil {
			t.Fatal(err)
		}
		return code, body
	}
	if code, body := add("addHeader", url.Values{"a": {"X-Lines"}, "b": {"=HTTPS\r\n\t? 'secure'\r\n\t: 'plain'"}, "c": {"Admin"}}); code != 200 || body != "Header created" {
		t.Errorf("a header over lines: %d %q", code, body)
	}
	if code, body := add("addRewrite", url.Values{"a": {"/lines"}, "b": {"=HTTPS\n? '/a'\n: '/b'"}, "c": {"Admin"}}); code != 200 || body != "Rewrite created" {
		t.Errorf("a rewrite over lines: %d %q", code, body)
	}
	globalMutex.RLock()
	header, rewrite := customHeaders["localhost"]["X-Lines"], sitesMap["localhost"][""]["/lines"]
	globalMutex.RUnlock()
	if header != "=HTTPS\n\t? 'secure'\n\t: 'plain'" || rewrite != "XHTTPS\n? '/a'\n: '/b'" {
		t.Errorf("kept %q and %q", header, rewrite)
	}
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil); response.Header.Get("X-Lines") != "plain" {
		t.Errorf("X-Lines %q", response.Header.Get("X-Lines"))
	}
	for _, c := range []struct {
		action string
		values url.Values
		answer string
	}{
		{"addHeader", url.Values{"a": {"X-Text"}, "b": {"two\nlines"}, "c": {"Admin"}}, "Control characters not allowed"},
		{"addRewrite", url.Values{"a": {"/text"}, "b": {"/a\n"}}, "Control characters not allowed"},
		{"addMIME", url.Values{"a": {"xyz"}, "b": {"=text/plain\n"}, "c": {"Admin"}}, "Control characters not allowed"},
		{"addHeader", url.Values{"a": {"X-Lone"}, "b": {"=HTTPS\r? 'a' : 'b'"}, "c": {"Admin"}}, "Expression: the only control characters allowed are spaces"},
		{"addHeader", url.Values{"a": {"X-Name\n"}, "b": {"='a'"}, "c": {"Admin"}}, "Control characters not allowed"},
	} {
		if code, body := add(c.action, c.values); code != 400 || !strings.HasPrefix(body, c.answer) {
			t.Errorf("%s %v: %d %q; expected 400 %q", c.action, c.values, code, body, c.answer)
		}
	}
}

// An expression goes through the character replacements as any value: the panel replaces ";", "#", "&" (and those
// added), and the server undoes them before it reads the expression. A replacement may stand for the mark itself.
func TestExpressionsThroughTheCharacterReplacements(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	token := login(t, base)
	sent := "=HTTPS -_--_- HTTPS ? 'a-.-b-,-c' : 'd-.-e'" // =HTTPS && HTTPS ? 'a;b#c' : 'd;e'
	if code, body, _ := post(base, "/admin:inside:addHeader?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-Replaced"}, "b": {sent}, "c": {"Admin"}}.Encode(), token); code != 200 {
		t.Fatalf("addHeader: %d %q", code, body)
	}
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil); response.Header.Get("X-Replaced") != "d;e" {
		t.Errorf("X-Replaced %q; expected d;e", response.Header.Get("X-Replaced"))
	}
	if applied, answer := lockedCheck(func() (bool, string) { return adminAddHandlers["_"]("=", "~e~") }); !applied {
		t.Fatalf("a replacement for =: %q", answer)
	}
	if code, body, _ := post(base, "/admin:inside:addHeader?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-Mark"}, "b": {"~e~HTTPS\n? 'a' : 'b'"}, "c": {"Admin"}}.Encode(), token); code != 200 {
		t.Fatalf("an expression whose mark is replaced, over lines: %d %q", code, body)
	}
	globalMutex.RLock()
	kept := customHeaders["localhost"]["X-Mark"]
	globalMutex.RUnlock()
	if kept != "=HTTPS\n? 'a' : 'b'" {
		t.Errorf("kept %q", kept)
	}
}

// The expressions of a header and of a rewrite, saved to turbo.config and read back, are the same, whatever
// character their texts have.
func TestExpressionsSavedAndReadBack(t *testing.T) {
	dir := initForTest(t)
	values := []string{"é", "😀", `quote " and \ backslash`, "it's", "<b>&amp;</b>", "{DOMAIN}", "a;b#c&d"}
	for c := 0x20; c < 0x7f; c++ {
		values = append(values, "a"+string(rune(c))+"b")
	}
	for kind := range configValueKinds {
		if !strings.HasSuffix(configValueKinds[kind].name, "expression") {
			continue
		}
		accepted := 0
		for _, v := range values {
			ok, before, after := storeAndReload(t, dir, kind, v)
			if ok && before != after {
				t.Errorf("%s %q: stored %q, read %q", configValueKinds[kind].name, v, before, after)
			}
			if ok {
				accepted++
			}
		}
		if accepted < len(values)/2 {
			t.Errorf("%s: only %d of %d values accepted", configValueKinds[kind].name, accepted, len(values))
		}
	}
}

// Read from turbo.config, an expression of a header or a rewrite may span lines; a value that isn't one, and the
// values of the other lists, may not (they are dropped, with a warning).
func TestExpressionsSpanLinesInTurboConfig(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{".":{"X-Expr":"=HTTPS\n\t? 'a'\n\t: 'b'","X-Text":"a\nb"},"=":{"/e":"=HTTPS\n? '/a'\n: '/b'","/t":"/a\nb"},"$":{"xyz":"=text/plain\n"},"-":{"index.html":"1"}}}}`)
	globalMutex.RLock()
	_, expressionHeader := customHeaders["localhost"]["X-Expr"]
	_, textHeader := customHeaders["localhost"]["X-Text"]
	_, expressionRewrite := sitesMap["localhost"][""]["/e"]
	_, textRewrite := sitesMap["localhost"][""]["/t"]
	_, mime := mimeTypes["localhost"]["xyz"]
	globalMutex.RUnlock()
	if !expressionHeader || !expressionRewrite || textHeader || textRewrite || mime {
		t.Errorf("kept: header expression %v, rewrite expression %v; header text %v, rewrite text %v, MIME %v (expected the expressions only)", expressionHeader, expressionRewrite, textHeader, textRewrite, mime)
	}
}

// A site kept without its folder keeps its expressions, and has them again when the folder comes back.
func TestExpressionsOfASiteKeptWithoutItsFolder(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	if err := os.MkdirAll(dir+"localhost/www/@", 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"localhost/www/@/index.html", []byte("www"), 0644)
	updateSettings(true)
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["."](true, map[string]interface{}{"X-Kept": "=HTTPS ? 'a' : 'kept'"}, false, "localhost", "www")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(message)
	}
	if err := os.Rename(dir+"localhost/www/@", dir+"localhost/www/@.away"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	globalMutex.RLock()
	kept := dormantSites["localhost"]["www"]
	globalMutex.RUnlock()
	if !strings.Contains(kept, `"X-Kept":"=HTTPS ? 'a' : 'kept'"`) {
		t.Fatalf("kept without its folder: %s", kept)
	}
	if err := os.Rename(dir+"localhost/www/@.away", dir+"localhost/www/@"); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	if response, body := requestWithHeaders(t, "GET", base, "www.localhost", "/", nil); response.StatusCode != 200 || body != "www" || response.Header.Get("X-Kept") != "kept" {
		t.Errorf("back: %d %q X-Kept %q", response.StatusCode, body, response.Header.Get("X-Kept"))
	}
}

// The example turbo.config has a header computed by the extension of the file served, which compiles and works.
func TestExampleConfigHasAHeaderExpression(t *testing.T) {
	dir := initForTest(t)
	example, err := os.ReadFile("testdata/config/v2-example.json")
	if err != nil {
		t.Fatal(err)
	}
	loadConfig(t, dir, strings.Replace(string(example), `"M":"{TURBO_CURRENT_DIR}",`, "", 1))
	globalMutex.RLock()
	value := customHeaders["localhost"]["Cache-Control"]
	globalMutex.RUnlock()
	if !strings.HasPrefix(value, "=") {
		t.Fatalf("Cache-Control of the example: %q", value)
	}
	os.WriteFile(dir+"localhost/@/app.js", []byte("js"), 0644)
	base := startServer(t)
	for path, want := range map[string]string{"/": "no-cache", "/app.js": "public, max-age=31536000"} {
		if response, _ := requestWithHeaders(t, "GET", base, "localhost", path, nil); response.StatusCode != 200 || response.Header.Get("Cache-Control") != want {
			t.Errorf("%s: %d %q; expected %q", path, response.StatusCode, response.Header.Get("Cache-Control"), want)
		}
	}
}

// Upgrading: a header of turbo.config written as it is that starts with "=" is an expression now. Kept, it answers
// 500 if it doesn't compile, and the log says how to write it as a text.
func TestUpgradeHeaderThatStartsWithTheMark(t *testing.T) {
	dir := initForTest(t)
	log := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{".":{"X-Equal":"=abc"},"-":{"index.html":"1"}}}}`)
	if !strings.Contains(log.String(), "a text that starts with it is written as one, between quotes") {
		t.Errorf("the log: %s", log.String())
	}
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil); response.StatusCode != 500 {
		t.Errorf("%d; expected 500", response.StatusCode)
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{".":{"X-Equal":"='=abc'"},"-":{"index.html":"1"}}}}`)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/", nil); response.StatusCode != 200 || response.Header.Get("X-Equal") != "=abc" {
		t.Errorf("written as an expression: %d %q", response.StatusCode, response.Header.Get("X-Equal"))
	}
}
