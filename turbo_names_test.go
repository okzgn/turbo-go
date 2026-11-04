package main

// T47 (I4, I5) and T24 (N21): the full list of Windows reserved names, and the
// index names with the same rules as the paths.

import (
	"net/url"
	"runtime"
	"strings"
	"testing"
)

func TestI04_WindowsReservedNames(t *testing.T) {
	reserved := []string{"CON", "con", "PRN", "AUX", "NUL", "nul.txt", "COM0", "COM1", "com9.log", "LPT0", "LPT9",
		"COM¹", "COM²", "LPT³.x", "CONIN$", "conout$", "CONOUT$.txt", "CON .txt", "NUL.tar.gz"}
	for _, name := range reserved {
		if !windowsReservedName(name) {
			t.Errorf("%q isn't recognized as reserved", name)
		}
		if pathSegmentAllowed(name, true) {
			t.Errorf("%q is allowed as a segment with the Windows rules", name)
		}
		if _, ok := uploadedFilePath("site/" + name); ok {
			t.Errorf("the upload allows %q", name)
		}
	}
	for _, name := range []string{"CONSOLE", "COM10", "COM", "LPT", "COMA", "CONIN", "conin$x", "AUXILIARY.txt", "NULL", "COM⁴"} {
		if windowsReservedName(name) {
			t.Errorf("%q is taken for reserved", name)
		}
	}
}

// I4: on Windows, a request for a reserved name gets 404.
func TestI04_ReservedNamesAnswer404(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	for _, name := range []string{"COM0", "LPT0.txt", "CONIN$", "CONOUT$", "COM%C2%B9"} {
		if code, _, _ := get(base, "/"+name, nil); code != 404 && runtime.GOOS == "windows" {
			t.Errorf("GET /%s: %d; expected 404", name, code)
		}
	}
}

func TestN21_IndexNames(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, name := range []string{"index.php.", "index.php ", "INDEX~1.PHT", "a::$DATA", "index.php:x", "NUL.html", "CONIN$"} {
		code, body, _ := post(base, "/admin:inside:addIndex?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {name}}.Encode(), tok)
		if code != 400 {
			t.Errorf("addIndex %q: %d %q; expected 400", name, code, body)
		}
	}
	if code, body, _ := post(base, "/admin:inside:addIndex?s=localhost&d=&a=start.html", tok); code != 200 {
		t.Errorf("addIndex start.html: %d %q", code, body)
	}

	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1","index.php.":"2","INDEX~1.PHT":"3"}}}}`)
	globalMutex.RLock()
	indexes := orderedIndexes("localhost")
	globalMutex.RUnlock()
	for _, name := range indexes {
		if name == "index.php." || name == "INDEX~1.PHT" {
			t.Errorf("invalid index loaded from turbo.config: %q", name)
		}
	}
	if !strings.Contains(logs.String(), "INDEX~1.PHT") {
		t.Errorf("no warning about the discarded index:\n%s", logs.String())
	}
}

// N80: an index follows the rules of file upload, also for the characters Windows doesn't allow in a name.
func TestN80_IndexNamesWindowsRefuses(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, name := range []string{"a<b.html", "a>b.html", `a"b.html`, "a|b.html", "a?b.html", "a*b.html"} {
		if code, body, _ := post(base, "/admin:inside:addIndex?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {name}}.Encode(), tok); code != 400 {
			t.Errorf("addIndex %q: %d %q; expected 400", name, code, body)
		}
	}
}
