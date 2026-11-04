//go:build linux

package main

// T19 (N14): with AmbientCapabilities=CAP_NET_BIND_SERVICE in the systemd
// unit, the CGIs don't inherit that capability: Turbo clears its ambient
// capabilities at startup. It needs root to give them to Turbo with setpriv;
// it runs in WSL with wsl -u root.

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestN14_CGIWithoutAmbientCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give Turbo ambient capabilities (wsl -u root)")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("no setpriv")
	}
	bin := turboBinary(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "localhost", "@"), 0755)
	os.WriteFile(filepath.Join(dir, "localhost", "@", "x.cgi"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(dir, "turbo.config"), []byte(`{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"`+toolPath("cgiecho")+`"}}}}`), 0600)
	addr := "127.0.0.1:" + freePort(t)
	cmd := exec.Command(setpriv, "--inh-caps=+net_bind_service", "--ambient-caps=+net_bind_service", bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_HTTP_ADDR="+addr, "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t))
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	var body string
	for start := time.Now(); time.Since(start) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/x.cgi?procstatus=1", nil)
		req.Host = "localhost"
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		body = string(b)
		break
	}
	if !strings.Contains(body, "CapAmb:") {
		t.Fatalf("the CGI did not return its capabilities: %q\n%s", body, out.String())
	}
	if !strings.Contains(body, "CapAmb:\t0000000000000000") {
		t.Errorf("the CGI inherited ambient capabilities:\n%s", body)
	}
}

// N84: nor do they keep it in their inheritable set (with it, a program a CGI runs whose file marks the
// capability as inheritable would get it back): Turbo empties its inheritable capabilities too.
func TestN84_CGIWithoutInheritableCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give Turbo inheritable capabilities (wsl -u root)")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Skip("no setpriv")
	}
	bin := turboBinary(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "localhost", "@"), 0755)
	os.WriteFile(filepath.Join(dir, "localhost", "@", "x.cgi"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(dir, "turbo.config"), []byte(`{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"`+toolPath("cgiecho")+`"}}}}`), 0600)
	addr := "127.0.0.1:" + freePort(t)
	cmd := exec.Command(setpriv, "--inh-caps=+net_bind_service", "--ambient-caps=+net_bind_service", bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_HTTP_ADDR="+addr, "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t))
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	var body string
	for start := time.Now(); time.Since(start) < 15*time.Second && body == ""; time.Sleep(100 * time.Millisecond) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/x.cgi?procstatus=1", nil)
		req.Host = "localhost"
		if res, err := http.DefaultClient.Do(req); err == nil {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			body = string(b)
		}
	}
	if !strings.Contains(body, "CapInh:") {
		t.Fatalf("the CGI did not return its capabilities: %q\n%s", body, out.String())
	}
	if !strings.Contains(body, "CapInh:\t0000000000000000") {
		t.Errorf("the CGI keeps inheritable capabilities:\n%s", body)
	}
}
