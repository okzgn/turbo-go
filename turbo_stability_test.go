package main

// Crashes and hangs: panics with the global mutex held and validations that
// dereference a nil FileInfo (#1, #2, #35, #62).

import (
	"os"
	"testing"
)

// #1, #2: extChars(".") must not panic and must reject the extension.
func TestP01_ExtCharsDot(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in extChars(\".\"): %v", r)
		}
	}()
	if extChars(".") {
		t.Fatal(`extChars(".") accepted`)
	}
}

// #1: a panic in addMIME must not leave the global mutex locked.
func TestP01_AddMIMEDotHangs(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:addMIME?s=localhost&d=&a=.&b=image/png", tok)
	t.Logf("addMIME a='.': code=%d body=%q err=%v", code, body, err)
	if err != nil {
		t.Fatalf("addMIME without a response: %v", err)
	}
	code, body, err = get(base, "/index.html", nil)
	if err != nil || code != 200 || body != "hello" {
		t.Fatalf("later request: code=%d body=%q err=%v; expected 200", code, body, err)
	}
}

// #2: a turbo.config with the extension "." must not crash the loading.
func TestP02_ConfigDotPanics(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{"$":{".":"image/png"}}}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileModTime = 0
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in updateSettings: %v", r)
		}
	}()
	updateSettings(false)
}

// #62: a preprocessor path that the system rejects must not leave the
// global mutex locked.
func TestS_PreprocessorBadPathHangs(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, `/admin:inside:addPreprocessor?s=localhost&d=&a=php&b=%22x`, tok)
	t.Logf("addPreprocessor b='\"x': %d %q %v", code, body, err)
	code, _, err = get(base, "/index.html", nil)
	if err != nil || code != 200 {
		t.Fatalf("later request: code=%d err=%v; expected 200", code, err)
	}
}

// #62: the same with the sites directory.
func TestS_SetMBadPathHangs(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, `/admin:inside:setM?a=%22x`, tok)
	t.Logf("setM a='\"x': %d %q %v", code, body, err)
	code, _, err = get(base, "/index.html", nil)
	if err != nil || code != 200 {
		t.Fatalf("later request: code=%d err=%v; expected 200", code, err)
	}
}

// #62: fileExists with a path that the system rejects (an invalid character
// on Windows) or that goes through a file (Linux).
func TestS_FileExistsBadPath(t *testing.T) {
	file := t.TempDir() + "/file"
	os.WriteFile(file, []byte("x"), 0644)
	for _, p := range []string{`"x`, file + "/x"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic in fileExists(%q): %v", p, r)
				}
			}()
			if fileExists(p) {
				t.Errorf("fileExists(%q) = true", p)
			}
		}()
	}
}

// #35: a rewrite whose target is left empty after the placeholders must not
// panic: it is rejected when it is added, or it answers 404.
func TestP35_EmptyRewrite(t *testing.T) {
	initForTest(t)
	ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/x": "{EXT}"}, false, "localhost", "")
	t.Logf("adding the rewrite: %v %q stored=%q", ok, msg, sitesMap["localhost"][""]["/x"])
	base, errLog := startServerLog(t)
	code, body, err := get(base, "/x", nil)
	if err != nil || code != 404 {
		t.Fatalf("GET /x -> code=%d body=%q err=%v; expected 404", code, body, err)
	}
	// A rewrite like this, saved before this fix (an old turbo.config), is
	// served as "/".
	globalMutex.Lock()
	sitesMap["localhost"][""]["/y"] = "N{EXT}"
	globalMutex.Unlock()
	code, body, err = get(base, "/y", nil)
	if err != nil || code != 200 || body != "hello" {
		t.Fatalf("GET /y -> code=%d body=%q err=%v; expected 200 with the index", code, body, err)
	}
	if l := errLog.String(); l != "" {
		t.Fatalf("server errors:\n%s", l)
	}
}

// #1, #2, #62 (T0.1): a panic in a panel validator answers 500 and does not
// leave the global mutex locked. It is injected, because T0.2 already
// prevents the known panics.
func TestP01_PanicInValidatorUnlocks(t *testing.T) {
	initForTest(t)
	original := defaultSettingValidators["."]["CII"]
	defaultSettingValidators["."]["CII"] = func(args ...string) (bool, string) { panic("broken validator") }
	t.Cleanup(func() { defaultSettingValidators["."]["CII"] = original })
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:setCII?a=1&b=Admin", tok)
	if err != nil || code != 500 {
		t.Fatalf("setCII with a panic -> code=%d body=%q err=%v; expected 500", code, body, err)
	}
	code, _, err = get(base, "/index.html", nil)
	if err != nil || code != 200 {
		t.Fatalf("later request: code=%d err=%v; expected 200", code, err)
	}
	if !globalMutex.TryLock() {
		t.Fatal("the global mutex is still held after the panic")
	}
	globalMutex.Unlock()
}

// T0.1: a periodic task of main() that panics does not end the process or
// leave the global mutex held.
func TestP01_PeriodicTaskPanic(t *testing.T) {
	runRecovering("test", func() { withGlobalLock(func() { panic("broken task") }) })
	if !globalMutex.TryLock() {
		t.Fatal("the global mutex is still held after the panic")
	}
	globalMutex.Unlock()
}

// #11: the SSL validators (E, A, C, S, R, W) reject a number of arguments
// outside 3-5 instead of indexing out of range.
func TestP11_SSLValidatorArgCount(t *testing.T) {
	initForTest(t)
	for key, check := range siteSSLSettingCheckers {
		for _, args := range [][]string{nil, {"1"}, {"1", "localhost"}, {"1", "localhost", "", "", "", "x"}} {
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s with %d arguments: panic %v", key, len(args), p)
					}
				}()
				globalMutex.Lock()
				defer globalMutex.Unlock()
				if ok, msg := check(false, args...); ok {
					t.Errorf("%s with %d arguments accepted: %q", key, len(args), msg)
				}
			}()
		}
	}
}

// #17: a preprocessor extension that is too long, read from turbo.config
// (without showing errors), never runs the preprocessor. Since T04 (N7) the
// entry is kept, so that its extension answers 500.
func TestP17_PreprocessorLongExtension(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	subdomainContentCheckers["?"](false, map[string]interface{}{"toolongextension": toolPath("cgiecho")}, true, "localhost", "")
	value, added := preprocessors["localhost"]["toolongextension"]
	globalMutex.Unlock()
	if _, problem := preprocessorCommand(value); added && problem == "" {
		t.Fatal("a preprocessor with an extension of more than 12 characters can run")
	}
}
