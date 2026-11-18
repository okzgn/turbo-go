package server

// T04 (N7): a turbo.config preprocessor that can't be used never disappears
// silently: its extension answers 500 (never the source code), the log gives
// the site, the extension and the reason, and saving keeps it. The limit of
// 128 characters is measured on the path as written, without the protocol
// prefix, and the path is saved with {TURBO_CURRENT_DIR} (D13).

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// N7: a path with {TURBO_CURRENT_DIR} that goes past 128 characters once
// expanded is run, also after saving and loading again.
func TestN07_PreprocessorPathMeasuredAsWritten(t *testing.T) {
	dir := initForTest(t)
	work := t.TempDir()
	t.Chdir(work)
	sub := strings.Repeat("p", 70) + "/" + strings.Repeat("q", 20) + "/"
	exe := "cgiecho"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	os.MkdirAll(filepath.Join(work, sub), 0755)
	data, err := os.ReadFile(toolPath("cgiecho"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(work, sub, exe), data, 0755)
	written := "{TURBO_CURRENT_DIR}" + sub + exe
	if len(written) > 128 || len(filepath.ToSlash(work)+"/"+sub+exe) <= 128 {
		t.Fatalf("the test needs a written path of 128 or less (%d) that goes past 128 when expanded", len(written))
	}
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("cgi-source"), 0644)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"?":{"cgi":"`+written+`"}}}}`)
	base := startServer(t)
	check := func(when string) {
		code, body, _ := get(base, "/x.cgi", nil)
		if strings.Contains(body, "cgi-source") || code != 200 && code != 500 {
			t.Errorf("%s: GET /x.cgi -> %d %q; expected the CGI run (or 500), never the source", when, code, body)
		}
	}
	check("on load")
	if !saveDefaultConfig() { // It takes the locks itself (T20)
		t.Fatal("couldn't save")
	}
	raw := savedConfig(t, dir)
	site, _ := raw["localhost"][""].(map[string]interface{})
	if got := site["?"].(map[string]interface{})["cgi"]; got != written {
		t.Errorf("saved preprocessor = %q; expected it as written, %q", got, written)
	}
	resetSettings()
	configFileStamp = configStamp{}
	updateSettings(false)
	check("after saving and loading again")
}

// N7: a value that isn't a string, an empty path, an unknown protocol or an
// extension of 13 characters: the extension answers 500, the log says so, and
// saving doesn't lose the entry.
func TestN07_InvalidPreprocessorAnswers500(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	cases := map[string]string{"num": `5`, "empty": `""`, "dx": `"dx>/bin/x"`, "abcdefghijklm": `"` + filepath.ToSlash(toolPath("cgiecho")) + `"`, "long": `"` + strings.Repeat("r", 129) + `"`}
	var entries []string
	for ext, value := range cases {
		os.WriteFile(dir+"localhost/@/x."+ext, []byte("source-"+ext), 0644)
		entries = append(entries, `"`+ext+`":`+value)
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"?":{`+strings.Join(entries, ",")+`}}}}`)
	base := startServer(t)
	for ext := range cases {
		code, body, _ := get(base, "/x."+ext, nil)
		if code != 500 || strings.Contains(body, "source-") {
			t.Errorf(".%s: %d %q; expected 500 without the source", ext, code, body)
		}
		if !strings.Contains(logs.String(), "extension="+ext) {
			t.Errorf(".%s: no warning in the log", ext)
		}
	}
	saveDefaultConfig()
	raw := savedConfig(t, dir)
	site, _ := raw["localhost"][""].(map[string]interface{})
	saved, _ := site["?"].(map[string]interface{})
	for ext := range cases {
		if _, kept := saved[ext]; !kept {
			t.Errorf(".%s: the entry was lost when saving: %v", ext, saved)
		}
	}
	resetSettings()
	configFileStamp = configStamp{}
	updateSettings(false)
	for ext := range cases {
		if code, body, _ := get(base, "/x."+ext, nil); code != 500 || strings.Contains(body, "source-") {
			t.Errorf(".%s after saving and loading again: %d %q; expected 500", ext, code, body)
		}
	}
}

// The limit of 128 doesn't count the protocol prefix.
func TestN07_PreprocessorLimitWithoutProtocol(t *testing.T) {
	initForTest(t)
	path := "/" + strings.Repeat("s", 127)
	withGlobalLock(func() {
		if _, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": "cgi>" + path}, false, "localhost", ""); strings.Contains(msg, "too long") {
			t.Errorf("cgi> plus 128 characters: %q; the prefix must not count", msg)
		}
	})
}

// R6 V-10: an extension with a dot inside matches no file, as the extension of a name is what follows its last dot:
// it is refused, instead of answered as added while the files it was meant for were served as text.
func TestR6_V10_ExtensionWithADotInside(t *testing.T) {
	for extension, valid := range map[string]bool{"php": true, ".php": true, "php5": true, "x-y": true, "blade.php": false, ".tar.gz": false, "a.b.c": false, "php.": false, ".": false} {
		if extChars(extension) != valid {
			t.Errorf("extChars(%q) = %v; expected %v", extension, !valid, valid)
		}
	}
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/view.blade.php", []byte("SOURCE"), 0644)
	base := startServer(t)
	tok := login(t, base)
	code, body, _ := post(base, "/admin:inside:addPreprocessor?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"blade.php"}, "b": {toolPath("cgiecho")}, "c": {"Admin"}}.Encode(), tok)
	if code != 400 || !strings.Contains(body, "Invalid extension") {
		t.Errorf("addPreprocessor blade.php: %d %q; expected 400 \"Invalid extension…\"", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:addMIME?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"tar.gz"}, "b": {"application/gzip"}, "c": {"Admin"}}.Encode(), tok); code != 400 {
		t.Errorf("addMIME tar.gz: %d %q; expected 400", code, body)
	}
	// From turbo.config it is kept, with a warning that says what it does: nothing
	logs := captureLog(t)
	loadConfig(t, dir, `{"localhost":{"":{"-":{"index.html":"1"},"?":{"blade.php":"`+toolPath("cgiecho")+`"}}}}`)
	if !strings.Contains(logs.String(), "has a dot inside") {
		t.Errorf("no warning for the extension of turbo.config:\n%s", logs.String())
	}
	if !strings.Contains(createDefaultConfig(true, false, true), "blade.php") {
		t.Error("saving loses the entry of turbo.config")
	}
}
