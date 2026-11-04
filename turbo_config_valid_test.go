package main

// A3 (H4, H5): turbo.config is always valid JSON, values with control
// characters are rejected, and an unreadable file is not replaced with the
// default values (D11).

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// configValueKinds are the kinds of text value saved in turbo.config, with
// how they are stored, how they are read from memory and whether they accept
// line breaks and tabs (only the response templates).
var configValueKinds = []struct {
	name       string
	whitespace bool
	store      func(value string) (bool, string)
	stored     func() (string, bool)
}{
	{"header", false,
		func(v string) (bool, string) {
			return subdomainContentCheckers["."](true, map[string]interface{}{"X-Test": v}, false, "localhost", "")
		},
		func() (string, bool) { v, ok := customHeaders["localhost"]["X-Test"]; return v, ok }},
	{"rewrite", false,
		func(v string) (bool, string) {
			return subdomainContentCheckers["="](true, map[string]interface{}{"/source": "/" + v}, false, "localhost", "")
		},
		func() (string, bool) {
			v, ok := sitesMap["localhost"][""]["/source"]
			if !ok {
				return "", false
			}
			return v[2:], true // "N/<target>"
		}},
	{"template", true,
		func(v string) (bool, string) { return adminAddHandlers["#"]("404", v) },
		func() (string, bool) { v, ok := (*httpResponses.Load())[404]; return v, ok }},
	{"user", false,
		func(v string) (bool, string) { return defaultSettingValidators["."]["U"](v, internalAuth) },
		func() (string, bool) { return panelUser.Get(), panelUser.Get() != "Turbo" }},
	{"mime", false,
		func(v string) (bool, string) {
			return subdomainContentCheckers["$"](true, map[string]interface{}{"xyz": "text/" + v}, false, "localhost", "")
		},
		func() (string, bool) {
			v, ok := mimeTypes["localhost"]["xyz"]
			return strings.TrimPrefix(v, "text/"), ok
		}},
	{"index", false,
		func(v string) (bool, string) {
			return subdomainContentCheckers["-"](true, map[string]interface{}{"i" + v: false}, false, "localhost", "")
		},
		func() (string, bool) {
			for _, name := range orderedIndexes("localhost") {
				if name != "index.html" {
					return name[1:], true
				}
			}
			return "", false
		}},
	{"replacement", false,
		func(v string) (bool, string) { return adminAddHandlers["_"]("~", "r"+v) },
		func() (string, bool) { v, ok := charReplacements["~"]; return strings.TrimPrefix(v, "r"), ok }},
}

// storeAndReload stores value as a value of configValueKinds[kind] the way
// the panel would (the API's character check and the validator), saves
// turbo.config, reads it again into an empty state and returns the value in
// memory before and after. accepted is false if the panel rejects it.
func storeAndReload(t testing.TB, dir string, kind int, value string) (accepted bool, before, after string) {
	t.Helper()
	k := configValueKinds[kind]
	if !textAllowed(value, k.whitespace) {
		return false, "", ""
	}
	// The replacement of "~" would turn its text into "~" in the values of the next calls.
	defer withGlobalLock(func() { delete(charReplacements, "~") })
	globalMutex.Lock()
	ok, _ := k.store(value)
	if ok {
		before, _ = k.stored()
	}
	globalMutex.Unlock()
	if !ok {
		return false, "", ""
	}
	if !saveDefaultConfig() { // Takes the locks itself (T20)
		t.Fatalf("%s %q: could not save", k.name, value)
	}
	data, err := os.ReadFile(dir + "turbo.config")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("%s %q: saved turbo.config is not valid JSON:\n%s", k.name, value, data)
	}
	lightReset(dir)
	if err := updateSettings(false); err != nil {
		t.Fatalf("%s %q: reload: %v", k.name, value, err)
	}
	globalMutex.RLock()
	after, found := k.stored()
	globalMutex.RUnlock()
	if !found {
		t.Fatalf("%s %q: the stored value (%q) is missing after reloading; turbo.config:\n%s", k.name, value, before, data)
	}
	return true, before, after
}

// lightReset empties the configuration in memory without waiting for
// Certbot, to read turbo.config again many times in a test.
func lightReset(dir string) {
	resetSettings()
	globalMutex.Lock()
	httpResponses.Store(&map[int]string{0: serverName + `\n{TURBO_RESPONSE_CODE}`})
	for k := range charReplacements {
		delete(charReplacements, k)
	}
	charReplacements[";"] = "-.-"
	charReplacements["#"] = "-,-"
	charReplacements["&"] = "-_-"
	panelUser.Set("Turbo")
	sitesDir.Set(dir)
	configFileModTime = 0
	globalMutex.Unlock()
}

// H4: each character from 0x00 to 0x7f and some non-ASCII ones, in each kind
// of value, is rejected when stored or comes back the same after saving and
// reading turbo.config, which is always valid JSON.
func TestA3_ConfigRoundTripEveryChar(t *testing.T) {
	dir := initForTest(t)
	values := []string{"é", "€", "😀", "a b", "<b>&amp;</b>"}
	for c := 0; c <= 0x7f; c++ {
		values = append(values, "a"+string(rune(c))+"b")
	}
	for kind := range configValueKinds {
		for _, v := range values {
			accepted, before, after := storeAndReload(t, dir, kind, v)
			if accepted && before != after {
				t.Errorf("%s %q: stored %q, read %q", configValueKinds[kind].name, v, before, after)
			}
			if c := v[1]; !accepted && len(v) == 3 && c >= 0x20 && c != 0x7f && configValueKinds[kind].name == "header" {
				t.Errorf("header %q rejected", v)
			}
		}
	}
}

func FuzzConfigRoundTrip(f *testing.F) {
	f.Add(uint8(0), "value\x01broken")
	f.Add(uint8(2), "<h1>{TURBO_RESPONSE_CODE}</h1>\n")
	f.Add(uint8(3), "us\"e\\r")
	f.Add(uint8(6), "\xff")
	dir := filepath.ToSlash(f.TempDir()) + "/"
	resetTestState(dir)
	os.MkdirAll(dir+"localhost/@", 0755)
	updateSettings(false)
	f.Fuzz(func(t *testing.T, kind uint8, value string) {
		k := int(kind) % len(configValueKinds)
		if accepted, before, after := storeAndReload(t, dir, k, value); accepted && before != after {
			t.Fatalf("%s %q: stored %q, read %q", configValueKinds[k].name, value, before, after)
		}
	})
}

// H4: from the panel, a value with control characters is rejected; saving
// and reloading keep the password, PA and the sites.
func TestA3_PanelRejectsControlChars(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:setPA?"+url.Values{"a": {"127.0.0.0/8,::1/128"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("setPA: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:setP?"+url.Values{"a": {"Another"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("setP: %d %q", code, body)
	}
	for _, path := range []string{
		"addHeader?" + url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-Header"}, "b": {"value\x01broken"}}.Encode(),
		"addRewrite?" + url.Values{"s": {"localhost"}, "d": {""}, "a": {"/x"}, "b": {"/y\x1b"}}.Encode(),
		"setU?" + url.Values{"a": {"us\x7fer"}, "b": {"Another"}}.Encode(),
		"addHttpCodeResponse?" + url.Values{"s": {"404"}, "d": {"no\x00"}}.Encode(),
		"addCharsReplace?" + url.Values{"s": {"\x02"}, "d": {"x"}}.Encode(),
	} {
		code, body, _ := post(base, "/admin:inside:"+path, tok)
		if code != 400 || body != "Control characters not allowed" {
			t.Errorf("%s: %d %q; expected 400 \"Control characters not allowed\"", path, code, body)
		}
	}
	// A template may span lines.
	if code, body, _ := post(base, "/admin:inside:addHttpCodeResponse?"+url.Values{"s": {"404"}, "d": {"<p>\r\n\tNot here</p>"}}.Encode(), tok); code != 200 {
		t.Errorf("template with line breaks: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:setC?a=&b=Another", tok); code != 200 {
		t.Fatalf("setC: %d %q", code, body)
	}
	if data, _ := os.ReadFile(dir + "turbo.config"); !json.Valid(data) {
		t.Fatalf("turbo.config is not valid JSON:\n%s", data)
	}
	lightReset(dir)
	setPanelPassword("Admin")
	panelAccess.Store(&panelAccessList{})
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if passwordMatches("Admin") || !passwordMatches("Another") {
		t.Error("after reloading, the password is not the saved one")
	}
	if panelAccess.Load().setting != "127.0.0.0/8,::1/128" {
		t.Errorf("PA after reloading: %q", panelAccess.Load().setting)
	}
	if (*httpResponses.Load())[404] != "<p>\r\n\tNot here</p>" {
		t.Errorf("template after reloading: %q", (*httpResponses.Load())[404])
	}
}

// H4: a turbo.config with an escaped control character (valid JSON) loads
// the rest and discards that value with a warning. A user with a control
// character makes the file invalid (D17): see TestN05_InvalidPanelSettingStopsStart.
func TestA3_ControlCharsFromFileDiscarded(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{".":{"X-Bad":"a\u0001b","X-Good":"ok"}}},"#":{"404":"x\u0000"}}`
	loadConfig(t, dir, cfg)
	if _, bad := customHeaders["localhost"]["X-Bad"]; bad {
		t.Error("header with a control character loaded")
	}
	if customHeaders["localhost"]["X-Good"] != "ok" {
		t.Error("the valid header was not loaded")
	}
	if _, bad := (*httpResponses.Load())[404]; bad {
		t.Error("template with NUL loaded")
	}
}

// D11: describeConfigError places the error (line, column, fragment with the
// marker), with the control characters escaped and the long lines cut, and
// lists the .bak copies.
func TestA3_DescribeConfigError(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir()) + "/"
	path := dir + "turbo.config"
	os.WriteFile(dir+"turbo.config.v1.bak", []byte("{}"), 0600)
	old := time.Now().Add(-time.Hour)
	os.WriteFile(dir+"turbo.config.invalid.20261029-101010.bak", []byte("x"), 0600)
	os.Chtimes(dir+"turbo.config.invalid.20261029-101010.bak", old, old)

	parse := func(data string) error {
		var raw map[string]map[string]interface{}
		return json.Unmarshal([]byte(data), &raw)
	}
	cases := []struct {
		name, data, line, fragment, marker string
	}{
		{"at the start", "x{}", "Line 1, column 1", "    x{}", "    ^"},
		{"control character", "{\n \"a\": {\n  \"X-Header\": \"value\x01broken\"}}", "Line 3, column 21", `    "X-Header": "value\x01broken"}}`, "                        ^"},
		{"at the end", "{\"a\":{}", "Line 1, column 7", "    {\"a\":{}", "          ^"},
		{"type", "{\"a\":\"b\"}", "Line 1, column 8", "    {\"a\":\"b\"}", "           ^"},
	}
	for _, c := range cases {
		msg := describeConfigError(path, []byte(c.data), parse(c.data))
		for _, want := range []string{"File: " + path, c.line, c.fragment + "\n", c.marker + "\n"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: %q missing in:\n%s", c.name, want, msg)
			}
		}
		newest := strings.Index(msg, "turbo.config.v1.bak")
		oldest := strings.Index(msg, "turbo.config.invalid.20261029-101010.bak")
		if newest < 0 || oldest < 0 || newest > oldest {
			t.Errorf("%s: .bak copies missing or out of order:\n%s", c.name, msg)
		}
	}

	long := "{\"a\":\"" + strings.Repeat("x", 300) + "\x01" + strings.Repeat("y", 300) + "\"}"
	msg := describeConfigError(path, []byte(long), parse(long))
	if !strings.Contains(msg, "Line 1, column 307") {
		t.Errorf("long line: wrong position:\n%s", msg)
	}
	lines := strings.Split(msg, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "    ") && strings.Contains(l, `\x01`) { // The fragment, not the cause
			if n := len([]rune(strings.TrimSpace(l))); n > 130 {
				t.Errorf("fragment of %d characters; expected about 120", n)
			}
			if i+1 >= len(lines) || strings.Index(lines[i+1], "^") != strings.Index(l, `\x01`) {
				t.Errorf("the marker is not under the character:\n%s\n%s", l, lines[i+1])
			}
		}
	}
}

// D11, H4: with an invalid turbo.config, Turbo does not start: it exits with
// code 1 without opening the ports or touching the file, and explains where
// the error is.
func TestA3_StartWithInvalidConfig(t *testing.T) {
	bin := turboBinary(t)
	dir := filepath.ToSlash(t.TempDir()) + "/"
	cfg := "{\n  \"localhost\": {\"\": {\".\": {\n    \"X-Header\": \"value\x01broken\"}}},\n  \".\": {\"PH\": \"x\"}\n}\n"
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	os.WriteFile(dir+"turbo.config.v1.bak", []byte("{}"), 0600)
	port := freePort(t)
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_DIR="+dir, "TURBO_HTTP_ADDR=127.0.0.1:"+port, "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t))
	done := make(chan error, 1)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		exitErr, isExit := err.(*exec.ExitError)
		if !isExit || exitErr.ExitCode() != 1 {
			t.Fatalf("Turbo exited with %v; expected code 1\n%s", err, out.String())
		}
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatalf("Turbo started with an invalid turbo.config\n%s", out.String())
	}
	msg := out.String()
	for _, want := range []string{"Turbo does not start", "File: " + dir + "turbo.config", "Line 3, column 23", `"X-Header": "value\x01broken"}}},`, "^", dir + "turbo.config.v1.bak"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q missing in the message:\n%s", want, msg)
		}
	}
	if data, _ := os.ReadFile(dir + "turbo.config"); string(data) != cfg {
		t.Error("turbo.config modified")
	}
}

// freePort returns a free TCP port of 127.0.0.1.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := strings.Cut(l.Addr().String(), ":")
	return port
}

// D11: if turbo.config breaks while the server is running, the reload keeps
// the configuration in use (the Admin password does not come back) and does
// not retry it until the date of the file changes.
func TestA3_ReloadKeepsConfigInUse(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	globalMutex.Lock()
	subdomainContentCheckers["."](true, map[string]interface{}{"X-Site": "1"}, false, "localhost", "")
	setPanelPassword("Another")
	defaultSettingValidators["."]["PA"]("localhost", internalAuth)
	globalMutex.Unlock()
	saveDefaultConfig() // Takes the locks itself (T20)
	updateSettings(true)

	broken := []byte(`{"localhost":{"":{}},".":{"U":"x"`)
	os.WriteFile(dir+"turbo.config", broken, 0600)
	future := time.Now().Add(2 * time.Second)
	os.Chtimes(dir+"turbo.config", future, future)
	if err := updateSettings(true); err == nil {
		t.Error("the reload of an invalid file returned no error")
	}
	if passwordMatches("Admin") || !passwordMatches("Another") {
		t.Error("the reload changed the password")
	}
	if customHeaders["localhost"]["X-Site"] != "1" {
		t.Error("the reload lost the site's header")
	}
	if panelAccess.Load().setting != "localhost" {
		t.Errorf("the reload changed PA: %q", panelAccess.Load().setting)
	}
	if code, body, err := get(base, "/", nil); err != nil || code != 200 || body != "hello" {
		t.Errorf("GET / after the reload: %d %q %v", code, body, err)
	}
	if err := updateSettings(true); err != nil {
		t.Errorf("with the file unchanged, the reload was retried: %v", err)
	}
}

// H5: saving with an invalid turbo.config on disk first copies it to
// turbo.config.invalid.<date>.bak; the write is atomic: if it fails, the
// previous file is left intact.
func TestA3_SaveBackupAndAtomic(t *testing.T) {
	dir := initForTest(t)
	broken := []byte("{broken")
	os.WriteFile(dir+"turbo.config", broken, 0600)
	ok := saveDefaultConfig() // Takes the locks itself (T20)
	if !ok {
		t.Fatal("could not save")
	}
	backups, _ := filepath.Glob(dir + "turbo.config.invalid.*.bak")
	if len(backups) != 1 {
		t.Fatalf("copies of the invalid file: %v", backups)
	}
	if data, _ := os.ReadFile(backups[0]); string(data) != string(broken) {
		t.Errorf("the copy is not the invalid file: %q", data)
	}
	saved, _ := os.ReadFile(dir + "turbo.config")
	if !json.Valid(saved) {
		t.Fatal("saved turbo.config is not valid JSON")
	}

	// The temporary file can't be created: the save fails and the file is left as it was. (The temporary file
	// has a name of its own now, so a folder in the way no longer makes it fail.)
	createTempFile = func(string, string) (*os.File, error) { return nil, os.ErrPermission }
	t.Cleanup(func() { createTempFile = os.CreateTemp })
	globalMutex.Lock()
	subdomainContentCheckers["."](true, map[string]interface{}{"X-New": "1"}, false, "localhost", "")
	globalMutex.Unlock()
	ok = saveDefaultConfig() // Takes the locks itself (T20)
	if ok {
		t.Error("the save did not fail")
	}
	if data, _ := os.ReadFile(dir + "turbo.config"); string(data) != string(saved) {
		t.Error("turbo.config changed after a failed save")
	}
}

// H62: if turbo.config is a symbolic link, it is written to its target and
// the link is kept, instead of being replaced with a regular file.
func TestH62_AtomicWriteKeepsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.config")
	link := filepath.Join(dir, "turbo.config")
	os.WriteFile(target, []byte("{}"), 0600)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symbolic links on this system: %v", err)
	}
	if err := writeFileAtomic(link, []byte(`{"a":"1"}`)); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("turbo.config is no longer a symbolic link: %v %v", info, err)
	}
	if data, _ := os.ReadFile(target); string(data) != `{"a":"1"}` {
		t.Errorf("target of the link: %q; expected the new content", data)
	}
}

// D11: the panel does not switch to a sites directory with an invalid
// turbo.config (reading it would lose the configuration in use).
func TestA3_SetMInvalidConfig(t *testing.T) {
	dir := initForTest(t)
	other := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(other+"turbo.config", []byte("{broken"), 0600)
	base := startServer(t)
	tok := login(t, base)
	code, body, _ := post(base, "/admin:inside:setM?"+url.Values{"a": {other}, "b": {"Admin"}}.Encode(), tok)
	if code != 400 || !strings.Contains(body, "is not valid JSON") || !strings.Contains(body, "Line 1, column 2") {
		t.Errorf("setM to a directory with an invalid turbo.config: %d %q", code, body)
	}
	if sitesDir.Get() != dir {
		t.Errorf("sites directory changed to %q", sitesDir.Get())
	}
}

// N67: the message of a malformed turbo.config shows nothing of P or PH, even
// if the value has escaped quotes.
func TestN67_HideSecretsEscapedQuote(t *testing.T) {
	data := []byte("{\"x\":{\"P\":\"ab\\\"SECRETPASS\" !}}")
	msg := describeConfigError("/tmp/turbo.config", data, func() error {
		var raw map[string]map[string]interface{}
		return parseConfig(data, &raw)
	}())
	t.Log(msg)
	if strings.Contains(msg, "SECRETPASS") {
		t.Errorf("part of P in the error message")
	}
}

// N66: the headline of the error says what is wrong: a valid JSON with a PA
// that can't be used is not "not valid JSON".
func TestN66_HeadlineOfSettingError(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"PA":"*,x"}}`), 0600)
	_, err := parseSiteConfig(dir + "turbo.config")
	msg := configErrorMessage(err, true)
	t.Log(msg)
	if strings.HasPrefix(msg, "turbo.config is not valid JSON") {
		t.Errorf("the headline says not valid JSON for a valid JSON with an unusable PA")
	}
}

// N86: a turbo.config that only points to another sites directory (M), whose target doesn't exist, has no
// turbo.config or points back, is invalid: Turbo doesn't start with it (before, the pointer alone was applied:
// the default credentials and the panel open to every host). A whole turbo.config whose M names a folder without
// turbo.config keeps its settings there, as setM does.
func TestN86_PointerWithoutTarget(t *testing.T) {
	hash, err := hashPassword("Another")
	if err != nil {
		t.Fatal(err)
	}
	whole := `{"^":{"v":"2"},".":{"U":"admin2","PH":"` + hash + `","PA":"127.0.0.0/8"}}`
	for _, scenario := range []string{"no turbo.config", "no directory", "loop"} {
		dirA := initForTest(t)
		dirB := filepath.ToSlash(t.TempDir()) + "/"
		switch scenario {
		case "no turbo.config":
		case "no directory":
			os.RemoveAll(dirB)
		case "loop":
			os.WriteFile(dirB+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirA+`"}}`), 0600)
		}
		os.WriteFile(dirA+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirB+`"}}`), 0600)
		resetTestState(dirA)
		if err := updateSettings(false); err == nil {
			t.Errorf("%s: a pointer that can't be followed was applied (user %q, PA %q); expected Turbo not to start", scenario, panelUser.Get(), panelAccess.Load().setting)
		} else if !strings.Contains(configErrorMessage(err, true), "does not start") {
			t.Errorf("%s: message %q", scenario, configErrorMessage(err, true))
		}
	}

	dirA := initForTest(t)
	dirC := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(dirA+"turbo.config", []byte(strings.Replace(whole, `".":{`, `".":{"M":"`+dirC+`",`, 1)), 0600)
	resetTestState(dirA)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if user, access := panelUser.Get(), panelAccess.Load().setting; user != "admin2" || access != "127.0.0.0/8" || !sameDir(sitesDir.Get(), dirC) {
		t.Errorf("whole turbo.config with M to a folder without turbo.config: user %q, PA %q, sites %q; expected admin2, 127.0.0.0/8 and %s", user, access, sitesDir.Get(), dirC)
	}

	// In a running Turbo, a turbo.config replaced by a pointer that can't be followed is an invalid file: the
	// reload keeps what is in use, also when the pointers loop, which applying them would have found out too late.
	for _, scenario := range []string{"no turbo.config", "loop"} {
		dirA := initForTest(t)
		dirB := filepath.ToSlash(t.TempDir()) + "/"
		os.WriteFile(dirA+"turbo.config", []byte(whole), 0600)
		resetTestState(dirA)
		if err := updateSettings(false); err != nil {
			t.Fatal(err)
		}
		if scenario == "loop" {
			os.WriteFile(dirB+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirA+`"}}`), 0600)
		}
		os.WriteFile(dirA+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dirB+`"}}`), 0600)
		withGlobalLock(func() { configFileModTime = 3 }) // Changed since it was read
		if err := updateSettings(false); err == nil {
			t.Errorf("reload %s: the pointer was applied without an error", scenario)
		}
		if user, access := panelUser.Get(), panelAccess.Load().setting; user != "admin2" || access != "127.0.0.0/8" || !sameDir(sitesDir.Get(), dirA) {
			t.Errorf("reload %s: user %q, PA %q, sites %q; expected admin2, 127.0.0.0/8 and %s to stay", scenario, user, access, sitesDir.Get(), dirA)
		}
	}
}

// N115: a turbo.config without "M" and with nothing else ({}, only "^", or an empty ".") points nowhere: it is an
// empty configuration, valid for parseSiteConfig, and has to load as one, at start and in a reload. The check of
// N86 took it for a pointer whose target doesn't exist. Found by FuzzConfigReload.
func TestN115_EmptyConfigIsNotAPointer(t *testing.T) {
	for _, content := range []string{`{}`, `{"^":{"v":"2"}}`, `{"^":{"v":"2"},".":{}}`} {
		dir := initForTest(t)
		os.WriteFile(dir+"turbo.config", []byte(content), 0600)
		resetTestState(dir)
		if err := updateSettings(false); err != nil {
			t.Errorf("startup with turbo.config %s: %v", content, err)
		}
		os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"U":"other"}}`), 0600)
		withGlobalLock(func() { configFileModTime = 0 })
		if err := updateSettings(false); err != nil || panelUser.Get() != "other" {
			t.Fatalf("turbo.config with U: %v, user %q", err, panelUser.Get())
		}
		os.WriteFile(dir+"turbo.config", []byte(content), 0600)
		withGlobalLock(func() { configFileModTime = 0 })
		if err := updateSettings(false); err != nil {
			t.Errorf("reload with turbo.config %s: %v", content, err)
		}
		if _, err := parseSiteConfig(dir + "turbo.config"); err != nil {
			t.Errorf("parseSiteConfig of %s: %v", content, err)
		}
		if !sameDir(sitesDir.Get(), dir) {
			t.Errorf("turbo.config %s: sites directory %q; expected %s", content, sitesDir.Get(), dir)
		}
	}
}

// N88: a turbo.config with a control character escaped in PA or PH (\t, \n, \r) has to be invalid. They passed the
// panel checks, which trim the blanks, and were then dropped with the rest of the control characters: the panel
// opened to any host, or the password went back to the default.
func TestN88_ControlCharsInPanelSettings(t *testing.T) {
	hash, err := hashPassword("Another")
	if err != nil {
		t.Fatal(err)
	}
	for name, setting := range map[string]string{
		"PA with a line feed":             `"PA":"127.0.0.0/8\n"`,
		"PA with a tab":                   `"PA":"\t127.0.0.0/8"`,
		"PA with a carriage return":       `"PA":"127.0.0.1,\r127.0.0.2"`,
		"PH with a line feed":             `"PH":"` + hash + `\n"`,
		"PH with a carriage return":       `"PH":"` + hash + `\r"`,
		"PA and PH with a line feed":      `"PA":"127.0.0.0/8\n","PH":"` + hash + `\n"`,
		"P (without PH) with a line feed": `"P":"Another\n"`,
	} {
		dir := initForTest(t)
		os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"U":"admin2",`+setting+`}}`), 0600)
		resetTestState(dir)
		if err := updateSettings(false); err == nil {
			t.Errorf("%s: applied (user %q, PA %q); expected an invalid turbo.config", name, panelUser.Get(), panelAccess.Load().setting)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}
