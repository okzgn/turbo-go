package main

// A7 (H8, D3): the panel is kept apart from the sites with a dedicated host in
// PA. PA's hosts and networks combine with AND; PA doesn't accept a host that
// serves a site, and a new site, subdomain or alias can't serve PA's host.

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// postHost sends a POST to the panel with the given Host and session.
func postHost(t *testing.T, base, hostName, path, token string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", base+path, nil)
	req.Host = hostName
	req.Header.Set("ok", token)
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// panelAnswers reports whether /admin: serves the panel (the login page) on that host.
func panelAnswers(t *testing.T, base, hostName string) bool {
	t.Helper()
	res, body, err := rawGet(base, hostName, "/admin:")
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode == 200 && strings.Contains(body, `name="u"`)
}

// captureLog returns what is written with slog until the end of the test.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	logBuffer := &syncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logBuffer
}

// H8: with hosts and networks in PA, both are required: from an allowed
// network, the panel doesn't answer on a site's host.
func TestA7_HostsAndNetworksBothRequired(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	globalMutex.Lock()
	ok, msg := defaultSettingValidators["."]["PA"]("panel.test,127.0.0.0/8", internalAuth)
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("PA: %q", msg)
	}
	if panelAnswers(t, base, "localhost") {
		t.Error("PA=panel.test,127.0.0.0/8: the panel answers from 127.0.0.1 on the host of the site localhost")
	}
	if !panelAnswers(t, base, "panel.test") {
		t.Error("PA=panel.test,127.0.0.0/8: the panel doesn't answer on panel.test from 127.0.0.1")
	}
	globalMutex.Lock()
	defaultSettingValidators["."]["PA"]("panel.test,10.0.0.0/8", internalAuth)
	globalMutex.Unlock()
	if panelAnswers(t, base, "panel.test") {
		t.Error("PA=panel.test,10.0.0.0/8: the panel answers from 127.0.0.1, outside the network")
	}
}

// H8, D3: setPA rejects a host that serves a site; with a dedicated host, the
// panel stops answering on the sites' hosts.
func TestA7_SetPARejectsSiteHost(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, value := range []string{"localhost", "panel.test,LOCALHOST", "localhost,127.0.0.0/8"} {
		code, body := postHost(t, base, "localhost", "/admin:inside:setPA?"+url.Values{"a": {value}, "b": {"Admin"}}.Encode(), tok)
		if code != 400 || !strings.Contains(body, "serves the site localhost") {
			t.Errorf("setPA %q with the site localhost: %d %q; expected 400 with the reason", value, code, body)
		}
	}
	// From panel.test: setPA refuses a value that would leave out the request that sets it.
	if code, body := postHost(t, base, "panel.test", "/admin:inside:setPA?a=panel.test&b=Admin", tok); code != 200 {
		t.Fatalf("setPA panel.test: %d %q", code, body)
	}
	if panelAnswers(t, base, "localhost") {
		t.Error("with PA=panel.test, the panel answers on localhost")
	}
	if !panelAnswers(t, base, "panel.test") {
		t.Error("with PA=panel.test, the panel doesn't answer on panel.test")
	}
}

// D3: with PA=panel.test,www.localhost, no new site, wildcard, subdomain or
// alias can serve those hosts; what is rejected leaves no folders.
func TestA7_SitesCannotServePanelHost(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	globalMutex.Lock()
	ok, msg := defaultSettingValidators["."]["PA"]("panel.test,www.localhost", internalAuth)
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("PA: %q", msg)
	}
	tok := panelToken(t, base, "panel.test") // login() uses Host localhost, where PA no longer lets the panel answer
	req := func(path string) (int, string) { return postHost(t, base, "panel.test", path, tok) }
	for _, c := range []struct{ path, folder string }{
		{"/admin:inside:addSite?s=panel.test", "panel.test"},
		{"/admin:inside:addSite?s=*.test", "#.test"},
		{"/admin:inside:addSubdomain?s=localhost&d=www", "localhost/www"},
		{"/admin:inside:addAlias?s=localhost&d=&a=panel.test", ""},
	} {
		code, body := req(c.path)
		if code != 400 || !strings.Contains(body, "panel") {
			t.Errorf("%s: %d %q; expected 400 because of the panel host", c.path, code, body)
		}
		if c.folder != "" {
			if _, err := os.Stat(dir + c.folder); err == nil {
				t.Errorf("%s: the folder %s was created", c.path, c.folder)
			}
		}
	}
	if code, body := req("/admin:inside:addSite?s=other.test"); code != 200 {
		t.Errorf("addSite other.test: %d %q", code, body)
	}
}

// panelToken signs in to the panel with the given Host.
func panelToken(t *testing.T, base, hostName string) string {
	t.Helper()
	buf, contentType := multipartCredentials("Turbo", "Admin")
	req, _ := http.NewRequest("POST", base+"/admin:", buf)
	req.Host = hostName
	req.Header.Set("Content-Type", contentType)
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if !bytes.HasPrefix(b, []byte("ok")) {
		t.Fatalf("login on %s: %d %q", hostName, res.StatusCode, b)
	}
	return string(b[2:])
}

// D3: a turbo.config with a PA that clashes with a site loads all the same
// (the configuration isn't broken), with a warning; and with an empty PA there
// is a warning that the panel shares its origin with the sites.
func TestA7_ConfigWarnings(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"localhost":{"":{}},".":{"PA":"localhost"}}`)
	if panelAccess.Load().setting != "localhost" {
		t.Errorf("PA loaded: %q; expected localhost", panelAccess.Load().setting)
	}
	if !strings.Contains(logs.String(), "serves the site localhost") {
		t.Errorf("no warning for the PA that serves a site:\n%s", logs.String())
	}
	loadConfig(t, dir, `{"localhost":{"":{}},".":{"PA":""}}`)
	if !strings.Contains(logs.String(), "The panel answers on the same hosts as the sites") {
		t.Errorf("no warning with an empty PA:\n%s", logs.String())
	}
}

// H61: a site that appears on disk and serves the panel host is activated, as
// from turbo.config, but with the warning that it shares the origin.
func TestH61_DiskSiteServingPanelHostWarns(t *testing.T) {
	dir := initForTest(t)
	globalMutex.Lock()
	ok, msg := defaultSettingValidators["."]["PA"]("panel.test", internalAuth)
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("PA: %q", msg)
	}
	updateSettings(true)
	logs := captureLog(t)
	os.MkdirAll(dir+"panel.test/@", 0755)
	updateSettings(true)
	if !strings.Contains(logs.String(), "serves the site panel.test") {
		t.Errorf("site panel.test created on disk with PA=panel.test: no warning: %s", logs.String())
	}
}

// N89: an error template is HTML that the panel's session can set without the password. On the panel's origin
// (its paths, and every path of its own host) it must not run scripts: there, everything but the panel's own
// pages carries a Content-Security-Policy without scripts. The panel's pages keep theirs.
func TestN89_ErrorTemplateWithoutScriptsOnPanelOrigin(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	globalMutex.Lock()
	ok, msg := defaultSettingValidators["."]["PA"]("panel.test", internalAuth)
	setHTTPResponses(func(responses map[int]string) { responses[404] = "<p>404</p><script>alert(1)</script>" })
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	scriptsAllowed := func(policy string) bool {
		for _, directive := range strings.Split(policy, ";") {
			if fields := strings.Fields(directive); len(fields) > 1 && (fields[0] == "script-src" || fields[0] == "default-src") {
				return fields[1] != "'none'"
			}
		}
		return true
	}
	for _, path := range []string{"/admin:missing.html", "/admin:inside:missing", "/something-else", "/.well-known/acme-challenge/x"} {
		res, body, err := rawGet(base, "panel.test", path)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode == 404 && strings.Contains(body, "<script>") && scriptsAllowed(res.Header.Get("Content-Security-Policy")) {
			t.Errorf("%s on the panel host: the template with a script goes out with Content-Security-Policy %q", path, res.Header.Get("Content-Security-Policy"))
		}
	}
	res, body, err := rawGet(base, "panel.test", "/admin:")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !strings.Contains(body, `name="u"`) || !scriptsAllowed(res.Header.Get("Content-Security-Policy")) {
		t.Errorf("the panel's page: %d, Content-Security-Policy %q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
}
