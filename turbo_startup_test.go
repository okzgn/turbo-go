package main

// T33 (N40, I2, I3): without the HTTPS address open, nothing is redirected to
// HTTPS and opening it is retried; SIGTERM shuts Turbo down gracefully.

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestN40_HTTPSRetried(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	previousAddr, previousDelay := httpsAddr, httpsRetryDelay
	httpsAddr, httpsRetryDelay = busy.Addr().String(), 100*time.Millisecond
	server := newHTTPSServer(tlsConfig)
	t.Cleanup(func() {
		httpsAddr, httpsRetryDelay = previousAddr, previousDelay
		server.Close()
		httpsListening.Store(false)
	})
	withGlobalLock(func() {
		if ok, msg := siteSSLSettingCheckers["S"](false, "1", "localhost", ""); !ok {
			t.Fatalf("cfgS: %s", msg)
		}
	})
	safeServerStart(server, tlsConfig)
	base := startServer(t)
	if res, _, err := rawGet(base, "localhost", "/"); err != nil || res.StatusCode != 200 {
		t.Errorf("with the HTTPS address busy: %v %v; expected serving over HTTP without a redirect", res, err)
	}
	busy.Close()
	deadline := time.Now().Add(5 * time.Second)
	for !httpsListening.Load() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !httpsListening.Load() {
		t.Fatal("HTTPS didn't open when the address became free")
	}
	if res, _, err := rawGet(base, "localhost", "/"); err != nil || res.StatusCode != 301 {
		t.Errorf("with HTTPS open: %v %v; expected the redirect", res, err)
	}
}

// I3: with SIGTERM, Turbo exits with code 0 in less than 10 s, and the request
// in progress finishes.
func TestI03_GracefulShutdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows doesn't send SIGTERM to another process: it is checked in WSL")
	}
	bin := turboBinary(t)
	dir := t.TempDir()
	os.MkdirAll(dir+"/localhost/@", 0755)
	os.WriteFile(dir+"/localhost/@/x.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"/turbo.config", []byte(`{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"`+toolPath("cgiecho")+`"}}}}`), 0600)
	addr := "127.0.0.1:" + freePort(t)
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_DIR="+dir+"/", "TURBO_HTTP_ADDR="+addr, "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t))
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(100 * time.Millisecond) {
		if conn, err := net.Dial("tcp", addr); err == nil {
			conn.Close()
			break
		}
	}
	answered := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("GET", "http://"+addr+"/x.cgi?sleep=1500", nil)
		req.Host = "localhost"
		res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			answered <- 0
			return
		}
		res.Body.Close()
		answered <- res.StatusCode
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Turbo exited with %v; expected code 0\n%s", err, out.String())
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("it took %v to exit", elapsed)
		}
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("Turbo didn't exit with SIGTERM\n%s", out.String())
	}
	if code := <-answered; code != 200 {
		t.Errorf("the request in progress ended with %d; expected 200", code)
	}
}

// Review of 57cbb3c, F6: a TURBO_USER that can't be "U" (more than 24 characters) stops Turbo from starting: it is
// saved as "U", and the turbo.config would be refused once the variable is unset.
func TestRL_F6_InvalidTurboUser(t *testing.T) {
	p := startTurbo(t, t.TempDir(), "TURBO_USER="+strings.Repeat("u", 25), "TURBO_PASSWORD=Another-1")
	select {
	case err := <-p.done:
		p.done <- err
		if err == nil || !strings.Contains(p.out.String(), "TURBO_USER must have 1 to 24 characters") {
			t.Errorf("exit %v with:\n%s", err, p.out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("Turbo started with a TURBO_USER of 25 characters\n%s", p.out.String())
	}
}
