package main

// Operation: startup without a port, closing the logs and configurable listen
// addresses (#31, #53, #19).

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// #53: if it can't open port 80, Turbo exits with a nonzero code instead of
// staying alive without serving.
func TestW_ExitWithoutPort80(t *testing.T) {
	bin := turboBinary(t)
	// Takes the port if it can; if not (no privileges, or another process has
	// it), Turbo can't open it either.
	if l, err := net.Listen("tcp", ":80"); err == nil {
		defer l.Close()
	}
	dir := t.TempDir()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Turbo exited with code 0; expected an error")
		}
		t.Logf("Turbo exited: %v", err)
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("Turbo is still running without port 80")
	}
}

// #31: resetSettings closes the open logs; it doesn't just forget their pointers.
func TestW_ResetSettingsClosesLogs(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	updateSettings(false) // the periodic reload opens the logs
	visits, denials := serverGetLogState(visitsLogName), serverGetLogState(denialsLogName)
	if visits == nil || denials == nil {
		t.Fatal("the logs weren't opened")
	}
	resetSettings()
	for name, f := range map[string]*os.File{"turbo.visits": visits, "turbo.denials": denials} {
		if _, err := f.WriteString("x"); err == nil {
			t.Errorf("%s still open after resetSettings", name)
		}
	}
}

// T2.5 (#19): TURBO_HTTP_ADDR and TURBO_HTTPS_ADDR change where Turbo listens.
func TestT25_ListenAddress(t *testing.T) {
	cases := []struct{ value, want string }{
		{"", ":80"},
		{"8080", ":8080"},
		{":8080", ":8080"},
		{"127.0.0.1:8080", "127.0.0.1:8080"},
		{"[::1]:8443", "[::1]:8443"},
		{"localhost:0", ""},
		{"port", ""},
		{"1.2.3.4:70000", ""},
	}
	for _, c := range cases {
		t.Setenv("TURBO_TEST_ADDR", c.value)
		got, err := listenAddress("TURBO_TEST_ADDR", ":80")
		if c.want == "" {
			if err == nil {
				t.Errorf("%q: %q without error; expected an error", c.value, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: %q, %v; expected %q", c.value, got, err, c.want)
		}
	}
}

func TestT25_ServeOnConfiguredAddress(t *testing.T) {
	bin := turboBinary(t)
	addr := "127.0.0.1:" + freePort(t)
	dir := t.TempDir()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_DIR="+dir, "TURBO_HTTP_ADDR="+addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		res, err := http.Get("http://" + addr + "/")
		if err != nil {
			continue
		}
		res.Body.Close()
		if res.Header.Get("Server") != serverName {
			t.Fatalf("it answers without Turbo's Server header: %v", res.Header)
		}
		return
	}
	t.Fatalf("Turbo doesn't answer on %s", addr)
}

// R6: Turbo says at startup which version it is, from which commit and with which Go, so that an administrator
// can tell whether an advisory applies. release.sh sets the version with -X; built from the source, it is
// "development".
func TestR6_VersionAtStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "turbo")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	for _, c := range []struct{ ldflags, version string }{{"-X main.turboVersion=v9.8.7", "v9.8.7"}, {"", "development"}} {
		if out, err := exec.Command("go", "build", "-ldflags", c.ldflags, "-o", bin, ".").CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", c.ldflags, err, out)
		}
		dir := t.TempDir()
		cmd := exec.Command(bin)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TURBO_DIR="+dir+"/", "TURBO_HTTP_ADDR=127.0.0.1:"+freePort(t), "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t))
		var out syncBuffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var line string
		for start := time.Now(); line == "" && time.Since(start) < 10*time.Second; time.Sleep(50 * time.Millisecond) {
			for _, l := range strings.Split(out.String(), "\n") {
				if strings.Contains(l, "msg=Starting") {
					line = l
				}
			}
		}
		cmd.Process.Kill()
		cmd.Wait()
		if !strings.Contains(line, "version="+c.version+" ") || !strings.Contains(line, " commit=") || !strings.Contains(line, " go="+runtime.Version()) {
			t.Errorf("built with %q, the startup line is %q; expected version=%s, the commit and go=%s", c.ldflags, line, c.version, runtime.Version())
		}
	}
}
