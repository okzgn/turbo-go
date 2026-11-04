package main

// T29 (N28, N29): PA rejects entries that never match and a value that would
// leave out the request itself, accepts a literal IPv6, and Turbo doesn't start
// with an empty TURBO_USER or TURBO_PASSWORD.

import (
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

func TestN28_PanelAccessRules(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.90"
	token := newSession(t, ip)
	setPA := func(value string) *responseRecorder { // From panel.test, a host that serves no site
		req := newPanelRequest("/admin:inside:setPA?"+url.Values{"a": {value}, "b": {"Admin"}}.Encode(), ip+":40000")
		req.Host = "panel.test"
		req.Header.Set(sessionHeaderName, token)
		rec := &responseRecorder{}
		serverHandlerFn("")(rec, req)
		return rec
	}
	for _, value := range []string{"a.test,*", "*.example.com", "panel.test,10.0.0.0/8", "other.test", "panel.test,10.0.0.0/8,192.0.2.0/24"} {
		if rec := setPA(value); rec.code != 400 {
			t.Errorf("setPA %q: %d %q; expected 400", value, rec.code, rec.body.String())
		}
	}
	if panelAccess.Load().setting != "" {
		t.Fatalf("PA changed: %q", panelAccess.Load().setting)
	}
	rec := setPA("panel.test,198.51.100.90")
	if rec.code != 200 || !strings.Contains(rec.body.String(), "/32") {
		t.Errorf("setPA with an IP without a mask: %d %q; expected 200 and the note about /32", rec.code, rec.body.String())
	}
	if rec := setPA("panel.test,198.51.100.0/24"); rec.code != 200 {
		t.Errorf("setPA with the request's network: %d %q", rec.code, rec.body.String())
	}
}

// N28: an IPv6 literal in PA matches Host: [::1].
func TestN28_PanelAccessIPv6Literal(t *testing.T) {
	initForTest(t)
	for _, value := range []string{"[::1]", "::1"} {
		list, problem := parsePanelAccess(value)
		if list == nil {
			t.Fatalf("PA %q: %s", value, problem)
		}
		panelAccess.Store(list)
		for _, hostHeader := range []string{"[::1]", "[::1]:8080"} {
			req, _ := customNetHttp.NewRequest("GET", "http://localhost/admin:", nil)
			req.Host = hostHeader
			req.RemoteAddr = "[::1]:40000"
			if !panelAllowed(req) {
				t.Errorf("PA %q doesn't match Host: %s", value, hostHeader)
			}
		}
	}
	panelAccess.Store(&panelAccessList{})
}

// N29: TURBO_PASSWORD or TURBO_USER set but empty keep Turbo from starting.
func TestN29_EmptyEnvCredentials(t *testing.T) {
	bin := turboBinary(t)
	for _, variable := range []string{"TURBO_PASSWORD=", "TURBO_USER="} {
		dir := t.TempDir()
		cmd := exec.Command(bin)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "TURBO_DIR="+dir, "TURBO_HTTP_ADDR=127.0.0.1:"+freePort(t), "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t), variable)
		var out syncBuffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(out.String(), strings.TrimSuffix(variable, "=")) {
				t.Errorf("%s: it exited (%v) without explaining the empty variable:\n%s", variable, err, out.String())
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Errorf("%s: Turbo started with the empty variable", variable)
		}
	}
}
