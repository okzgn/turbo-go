package main

// T11 (N8, DOC11): character replacements are not applied to the
// credentials, their tokens don't overlap or change the fixed ones, they are
// undone deterministically, and what is read from turbo.config is not decoded
// again.

import (
	"net/url"
	"strings"
	"testing"
)

// N8: a password with a replacement token is saved as it is.
func TestN08_PasswordWithToken(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.80"
	token := newSession(t, ip)
	if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setP?"+url.Values{"a": {"ab-.-cd"}, "b": {"Admin"}}.Encode()); rec.code != 200 {
		t.Fatalf("setP: %d %q", rec.code, rec.body.String())
	}
	if rec := loginFrom(serverHandlerFn(""), ip, "Turbo", "ab-.-cd"); rec.code != 200 {
		t.Errorf("login with the new password: %d", rec.code)
	}
	if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setU?"+url.Values{"a": {"us-_-er"}, "b": {"ab-.-cd"}}.Encode()); rec.code != 200 {
		t.Fatalf("setU with a b that has a token: %d %q", rec.code, rec.body.String())
	}
	if panelUser.Get() != "us-_-er" {
		t.Errorf("saved user: %q", panelUser.Get())
	}
}

// N8: with TURBO_PASSWORD=my-_-password, the set* actions accept
// b=my-_-password.
func TestN08_EnvPasswordWithToken(t *testing.T) {
	initForTest(t)
	setPanelPassword("my-_-password")
	const ip = "198.51.100.81"
	rec := loginFrom(serverHandlerFn(""), ip, "Turbo", "my-_-password")
	token := strings.TrimPrefix(rec.body.String(), "ok")
	if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setMUB?"+url.Values{"a": {"2000"}, "b": {"my-_-password"}}.Encode()); rec.code != 200 {
		t.Errorf("setMUB with b=my-_-password: %d %q", rec.code, rec.body.String())
	}
}

// N8: the fixed ones are not changed, and the tokens don't overlap or
// contain a replaced character.
func TestN08_TokenRules(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.82"
	token := newSession(t, ip)
	add := func(char, replacement string) int {
		return apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:addCharsReplace?"+url.Values{"s": {char}, "d": {replacement}}.Encode()).code
	}
	for _, c := range [][2]string{
		{";", "zz"},   // Fixed
		{"+", "p"},    // One character
		{"+", "-.-x"}, // Contains a fixed token
		{"+", "x;y"},  // Contains a replaced character
		{"+", "a+b"},  // Contains its own character
		{"+", "-"},    // Inside the fixed tokens
	} {
		if code := add(c[0], c[1]); code != 400 {
			t.Errorf("addCharsReplace %q -> %q: %d; expected 400", c[0], c[1], code)
		}
	}
	if code := add("+", "plus"); code != 200 {
		t.Errorf("addCharsReplace + -> plus: %d", code)
	}
	if code := add("?", "pl"); code != 400 {
		t.Errorf("addCharsReplace ? -> pl (inside plus): %d; expected 400", code)
	}
}

// N8: what is read from turbo.config is not decoded: a rewrite /plusone with
// the replacement + -> plus is still /plusone after reloading.
func TestN08_FileValuesLiteral(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"_":{"+":"plus","!":"x","?":"-.-y"},"localhost":{"":{"=":{"/plusone":"/index.html"},".":{"X-Plus":"plusone"}}}}`)
	globalMutex.RLock()
	_, rewrite := sitesMap["localhost"][""]["/plusone"]
	header := customHeaders["localhost"]["X-Plus"]
	_, short := charReplacements["!"]
	_, overlapping := charReplacements["?"]
	globalMutex.RUnlock()
	if !rewrite || header != "plusone" {
		t.Errorf("turbo.config values decoded: rewrite /plusone=%v, header %q", rewrite, header)
	}
	if short || overlapping {
		t.Errorf("invalid tokens loaded: ! -> x %v, ? -> -.-y %v", short, overlapping)
	}
	if !strings.Contains(logs.String(), "-.-y") {
		t.Errorf("no warning about the discarded token:\n%s", logs.String())
	}
}

// FuzzCharReplacements: undoing the replacements is deterministic, and
// encoding a text without tokens and undoing it gives back the original or,
// if the text is ambiguous (N78: "-,#" and "#,-" are encoded the same),
// another one that is encoded the same. The GUI doesn't send ambiguous texts.
func FuzzCharReplacements(f *testing.F) {
	for _, s := range []string{"a;b#c&d", "-.-", "plus+one", "", "x-_-y", ";;;"} {
		f.Add(s)
	}
	initFuzz(f)
	withGlobalLock(func() { adminAddHandlers["_"]("+", "plus") })
	f.Fuzz(func(t *testing.T, text string) {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		first := replaceURIChars(text)
		for i := 0; i < 3; i++ {
			if again := replaceURIChars(text); again != first {
				t.Fatalf("%q: %q and then %q", text, first, again)
			}
		}
		for _, token := range charReplacements {
			if strings.Contains(text, token) {
				return
			}
		}
		encoded := text
		for char, token := range charReplacements {
			encoded = strings.ReplaceAll(encoded, char, token)
		}
		if decoded := replaceURIChars(encoded); decoded != text {
			again := decoded
			for char, token := range charReplacements {
				again = strings.ReplaceAll(again, char, token)
			}
			if again != encoded {
				t.Fatalf("%q -> %q -> %q, which is encoded as %q", text, encoded, decoded, again)
			}
		}
	})
}

// N78: with the fixed tokens, "-,#" and "#,-" are encoded the same ("-,-,-")
// and the server reads "#,-". It is a limit of the scheme (API §2.1): the GUI
// doesn't send such a text.
func TestN78_AmbiguousCharReplacement(t *testing.T) {
	initForTest(t)
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	for _, c := range []struct{ sent, want string }{{"-,-,-", "#,-"}, {"a-.-.-b", "a;.-b"}, {"-_-_-", "&_-"}} {
		if got := replaceURIChars(c.sent); got != c.want {
			t.Errorf("%q is read as %q; expected %q", c.sent, got, c.want)
		}
	}
}
