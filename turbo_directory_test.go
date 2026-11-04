package main

// T01 (N1, duplicate of N17): the sites directory is always resolved the same
// way (TURBO_DIR, "M" and setM), it is compared as a folder and not as a
// string, and saving never leaves in the start directory a turbo.config that
// only points to itself. With D13 (a), "M" is saved as it was written.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	turboBinaryOnce sync.Once
	turboBinaryPath string
	turboBinaryErr  error
)

// turboBinary builds Turbo once for all the tests of this file.
func turboBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	turboBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "turbo-bin")
		if err != nil {
			turboBinaryErr = err
			return
		}
		turboBinaryPath = filepath.Join(dir, "turbo")
		if runtime.GOOS == "windows" {
			turboBinaryPath += ".exe"
		}
		build := exec.Command("go", "build", "-o", turboBinaryPath, ".")
		build.Env = append(os.Environ(), "CGO_ENABLED=0") // As the published binaries
		if out, err := build.CombinedOutput(); err != nil {
			turboBinaryErr = &buildError{err, string(out)}
		}
	})
	if turboBinaryErr != nil {
		t.Fatalf("go build: %v", turboBinaryErr)
	}
	return turboBinaryPath
}

type buildError struct {
	err error
	out string
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

// turboProcess is Turbo running as a separate process.
type turboProcess struct {
	cmd  *exec.Cmd
	base string
	out  *syncBuffer
	done chan error
}

// startTurbo starts Turbo in workDir (without TURBO_DIR, unless env gives it)
// and waits for it to answer; if it ends before, it returns the ended process.
func startTurbo(t *testing.T, workDir string, env ...string) *turboProcess {
	t.Helper()
	addr := "127.0.0.1:" + freePort(t)
	p := &turboProcess{cmd: exec.Command(turboBinary(t)), base: "http://" + addr, out: &syncBuffer{}, done: make(chan error, 1)}
	p.cmd.Dir = workDir
	p.cmd.Env = append(append(os.Environ(), "TURBO_HTTP_ADDR="+addr, "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t)), env...)
	p.cmd.Stdout, p.cmd.Stderr = p.out, p.out
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(p.stop)
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		select {
		case err := <-p.done:
			p.done <- err
			return p
		default:
		}
		if res, err := http.Get(p.base + "/"); err == nil {
			res.Body.Close()
			return p
		}
	}
	t.Fatalf("Turbo doesn't answer\n%s", p.out.String())
	return nil
}

// exited returns the error the process ended with, or nil and false if it is
// still running.
func (p *turboProcess) exited() (error, bool) {
	select {
	case err := <-p.done:
		p.done <- err
		return err, true
	default:
		return nil, false
	}
}

func (p *turboProcess) stop() {
	if _, ended := p.exited(); !ended {
		p.cmd.Process.Kill()
		<-p.done
		p.done <- nil
	}
}

// panelPost runs a panel action with the token of a login in p.
func panelPost(t *testing.T, p *turboProcess, token, action string, form url.Values) (int, string) {
	t.Helper()
	code, body, err := post(p.base, "/admin:inside:"+action+"?"+form.Encode(), token)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return code, body
}

// writeTree creates in dir the site localhost and a turbo.config with "M" = m.
func writeTree(t *testing.T, dir, m string) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, "localhost", "@"), 0755)
	os.WriteFile(filepath.Join(dir, "localhost", "@", "index.html"), []byte("hello"), 0644)
	mJSON, _ := json.Marshal(m)
	cfg := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},".":{"X-Test":"yes"}}},".":{"M":` + string(mJSON) + `,"CII":"90"}}`
	if err := os.WriteFile(filepath.Join(dir, "turbo.config"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
}

// N1: with "M" = {TURBO_CURRENT_DIR} (and its variants), signing in, changing
// PA and saving leaves the whole file; after a restart, the configuration is
// the same.
func TestN01_SaveKeepsConfigWithCurrentDirMarker(t *testing.T) {
	variants := map[string]string{
		"marker":       "{TURBO_CURRENT_DIR}",
		"marker-slash": "{TURBO_CURRENT_DIR}/",
		"dot":          ".",
		"dot-segment":  "{TURBO_CURRENT_DIR}/./",
		"double-slash": "{TURBO_CURRENT_DIR}//",
	}
	if runtime.GOOS == "windows" {
		variants["backslash"] = "{TURBO_CURRENT_DIR}\\"
	}
	for name, m := range variants {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, m)
			p := startTurbo(t, dir)
			token := login(t, p.base)
			if code, body := panelPost(t, p, token, "setPA", url.Values{"a": {"127.0.0.0/8"}, "b": {"Admin"}}); code != 200 {
				t.Fatalf("setPA: %d %s", code, body)
			}
			if code, body := panelPost(t, p, token, "setC", url.Values{"a": {""}, "b": {"Admin"}}); code != 200 {
				t.Fatalf("setC: %d %s", code, body)
			}
			raw := savedConfig(t, dir)
			if _, ok := raw["localhost"]; !ok {
				t.Fatalf("turbo.config without the site after saving: %v", raw)
			}
			for _, key := range []string{"U", "PH", "PA", "CII"} {
				if _, ok := raw["."][key]; !ok {
					t.Errorf("turbo.config without %s after saving: %v", key, raw["."])
				}
			}
			if got := raw["."]["M"]; got != m {
				t.Errorf("saved M = %q; expected it as written, %q", got, m)
			}
			p.stop()
			p = startTurbo(t, dir)
			if err, ended := p.exited(); ended {
				t.Fatalf("Turbo doesn't start after saving: %v\n%s", err, p.out.String())
			}
			res, _, err := rawGet(p.base, "localhost", "/")
			if err != nil || res.StatusCode != 200 || res.Header.Get("X-Test") != "yes" {
				t.Errorf("after restarting: %v %v; expected the site with its header", res, err)
			}
			if code, _, _ := get(p.base, "/admin:", nil); code != 200 {
				t.Errorf("panel on 127.0.0.1 after restarting: %d", code)
			}
		})
	}
}

// N1 through a symbolic link (on Windows they can't be created without
// privileges).
func TestN01_SaveThroughSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0755)
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	writeTree(t, real, link)
	p := startTurbo(t, real)
	token := login(t, p.base)
	if code, body := panelPost(t, p, token, "setC", url.Values{"a": {""}, "b": {"Admin"}}); code != 200 {
		t.Fatalf("setC: %d %s", code, body)
	}
	if raw := savedConfig(t, real); raw["localhost"] == nil || raw["."]["U"] == nil {
		t.Errorf("turbo.config reduced to a pointer: %v", raw)
	}
}

// resolveSitesDir is idempotent, ends in a single "/" and replaces the marker.
func TestN01_ResolveSitesDir(t *testing.T) {
	wd, _ := os.Getwd()
	cwd := filepath.ToSlash(wd) + "/"
	for _, value := range []string{"{TURBO_CURRENT_DIR}", "{TURBO_CURRENT_DIR}/", "{TURBO_CURRENT_DIR}//", ".", "./", "{TURBO_CURRENT_DIR}/./", cwd, cwd + "/"} {
		got, err := resolveSitesDir(value)
		if err != nil || got != cwd {
			t.Errorf("resolveSitesDir(%q) = %q, %v; expected %q", value, got, err, cwd)
		}
	}
	for _, value := range []string{"sub", "{TURBO_CURRENT_DIR}sub", "{TURBO_CURRENT_DIR}/sub/", "./sub//"} {
		if got, _ := resolveSitesDir(value); got != cwd+"sub/" {
			t.Errorf("resolveSitesDir(%q) = %q; expected %q", value, got, cwd+"sub/")
		}
	}
	if _, err := resolveSitesDir(""); err == nil {
		t.Error("an empty directory gives no error")
	}
}

// sameDir compares folders, not strings.
func TestN01_SameDir(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir())
	os.Mkdir(dir+"/a", 0755)
	os.Mkdir(dir+"/b", 0755)
	same := [][2]string{{dir + "/a", dir + "/a/"}, {dir + "/a", dir + "//a"}, {dir + "/a", dir + "/./a/"}, {dir + "/b/../a", dir + "/a"}, {dir + "/no", dir + "/no/"}}
	if runtime.GOOS == "windows" {
		same = append(same, [2]string{dir + "/a", filepath.FromSlash(dir + "/a")}, [2]string{dir + "/A", dir + "/a"}, [2]string{dir + "/NO", dir + "/no"})
	}
	for _, pair := range same {
		if !sameDir(pair[0], pair[1]) {
			t.Errorf("sameDir(%q, %q) = false", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{dir + "/a", dir + "/b"}, {dir + "/a", dir + "/no"}} {
		if sameDir(pair[0], pair[1]) {
			t.Errorf("sameDir(%q, %q) = true", pair[0], pair[1])
		}
	}
}

// FuzzSitesDir: resolveSitesDir is idempotent and never panics.
func FuzzSitesDir(f *testing.F) {
	for _, seed := range []string{"{TURBO_CURRENT_DIR}", ".", "a//b/./c/..", "{TURBO_CURRENT_DIR}{TURBO_CURRENT_DIR}", "C:\\x\\", "/", "\\\\srv\\share"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		once, err := resolveSitesDir(value)
		if err != nil {
			return
		}
		twice, err := resolveSitesDir(once)
		if err != nil || twice != once {
			t.Fatalf("resolveSitesDir(%q) = %q; again = %q, %v", value, once, twice, err)
		}
		if !strings.HasSuffix(once, "/") || strings.HasSuffix(once, "//") && once != "//" {
			t.Fatalf("resolveSitesDir(%q) = %q: it must end in a single /", value, once)
		}
	})
}

// Starting in A with a whole file, setM to B and saving: A's file is copied to
// turbo.config.<date>.bak before the pointer is left.
func TestN01_PointerBacksUpStartConfig(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"CII":"77"}}`)
	original, _ := os.ReadFile(dir + "turbo.config")
	other := filepath.ToSlash(t.TempDir()) + "/"
	if ok, msg := defaultSettingValidators["."]["M"](other, "Admin"); !ok {
		t.Fatalf("M: %s", msg)
	}
	if !saveDefaultConfig() { // It takes the locks itself (T20)
		t.Fatal("saveDefaultConfig failed")
	}
	if raw := savedConfig(t, dir); !isSitesDirPointerMap(raw) {
		t.Fatalf("no pointer left in the start directory: %v", raw)
	}
	backups, _ := filepath.Glob(dir + "turbo.config.*.bak")
	found := false
	for _, backup := range backups {
		if data, _ := os.ReadFile(backup); string(data) == string(original) {
			found = true
		}
	}
	if !found {
		t.Errorf("no backup of the start turbo.config; backups: %v", backups)
	}
}

// A turbo.config that only has "M" and points to its own directory: at
// startup, Turbo doesn't start; on a reload, the configuration is kept.
func TestN01_SelfPointer(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(dir+"localhost/@", 0755)
	os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"{TURBO_CURRENT_DIR}"}}`), 0600)
	os.WriteFile(dir+"turbo.config.20261031-120000.bak", []byte(`{}`), 0600)
	p := startTurbo(t, dir)
	err, ended := p.exited()
	if !ended {
		t.Fatalf("Turbo started with a turbo.config that points to itself\n%s", p.out.String())
	}
	if exitErr, isExit := err.(*exec.ExitError); !isExit || exitErr.ExitCode() != 1 {
		t.Errorf("it ended with %v; expected code 1", err)
	}
	for _, want := range []string{"Turbo does not start", "its own directory", "turbo.config.20261031-120000.bak"} {
		if !strings.Contains(p.out.String(), want) {
			t.Errorf("%q missing from the message:\n%s", want, p.out.String())
		}
	}

	dir = initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"PA":"127.0.0.0/8","CII":"55"}}`)
	os.WriteFile(dir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"M":"`+dir+`"}}`), 0600)
	configFileStamp = configStamp{}
	if err := updateSettings(false); err == nil {
		t.Error("the reload doesn't report the pointer to itself")
	}
	if panelAccess.Load().setting != "127.0.0.0/8" || serverRequestLimits.CII.Load() != 55 {
		t.Errorf("the reload didn't keep the configuration: PA=%q CII=%d", panelAccess.Load().setting, serverRequestLimits.CII.Load())
	}
}

// Production review, M-07: when the turbo.config of the start directory is the very file of the directory that "M"
// names (a symbolic link), saving doesn't write the pointer over the whole configuration it has just saved there.
// Before, the file was left pointing to its own directory, and Turbo didn't start again.
func TestRP_M07_SameFileNotReducedToPointer(t *testing.T) {
	dirA := initForTest(t)
	dirC := filepath.ToSlash(t.TempDir()) + "/"
	if err := os.MkdirAll(dirC+"example.test/@", 0755); err != nil {
		t.Fatal(err)
	}
	whole := `{"^":{"v":"2"},".":{"M":"` + dirC + `","U":"admin2"},"example.test":{"":{".":{"X-Kept":"1"}}}}`
	if err := os.WriteFile(dirC+"turbo.config", []byte(whole), 0600); err != nil {
		t.Fatal(err)
	}
	os.Remove(dirA + "turbo.config")
	if err := os.Symlink(dirC+"turbo.config", dirA+"turbo.config"); err != nil {
		t.Skip("no symbolic links here: " + err.Error())
	}
	resetTestState(dirA)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	if raw := savedConfig(t, dirC); isSitesDirPointerMap(raw) || raw["example.test"] == nil {
		t.Errorf("turbo.config of %s after saving: %v; expected the whole configuration", dirC, raw)
	}
	resetTestState(dirA) // A start after saving
	if err := updateSettings(false); err != nil {
		t.Fatalf("Turbo doesn't start after saving: %v", err)
	}
	globalMutex.RLock()
	header := customHeaders["example.test"]["X-Kept"]
	globalMutex.RUnlock()
	if panelUser.Get() != "admin2" || header != "1" {
		t.Errorf("after a start: user %q, header of example.test %q; expected admin2 and 1", panelUser.Get(), header)
	}
}
