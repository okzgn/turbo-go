package main

// A7 (H8, D3): el panel se separa de los sitios con un host dedicado en PA.
// Hosts y redes de PA se combinan con AND; PA no admite un host que sirva un
// sitio y un sitio, subdominio o alias nuevo no puede servir el host de PA.

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

// postHost envía un POST al panel con el Host y la sesión dados.
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

// panelAnswers dice si /admin: sirve el panel (la página de login) en ese host.
func panelAnswers(t *testing.T, base, hostName string) bool {
	t.Helper()
	res, body, err := rawGet(base, hostName, "/admin:")
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode == 200 && strings.Contains(body, `name="u"`)
}

// captureLog devuelve lo que se escriba con slog hasta el final de la prueba.
func captureLog(t *testing.T) *syncBuffer {
	logBuffer := &syncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logBuffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logBuffer
}

// H8: con hosts y redes en PA, se exigen las dos cosas: desde una red
// permitida, el panel no responde en el host de un sitio.
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
		t.Error("PA=panel.test,127.0.0.0/8: el panel responde desde 127.0.0.1 en el host del sitio localhost")
	}
	if !panelAnswers(t, base, "panel.test") {
		t.Error("PA=panel.test,127.0.0.0/8: el panel no responde en panel.test desde 127.0.0.1")
	}
	globalMutex.Lock()
	defaultSettingValidators["."]["PA"]("panel.test,10.0.0.0/8", internalAuth)
	globalMutex.Unlock()
	if panelAnswers(t, base, "panel.test") {
		t.Error("PA=panel.test,10.0.0.0/8: el panel responde desde 127.0.0.1, fuera de la red")
	}
}

// H8, D3: setPA rechaza un host que sirve un sitio; con un host dedicado, el
// panel deja de responder en los hosts de los sitios.
func TestA7_SetPARejectsSiteHost(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, value := range []string{"localhost", "panel.test,LOCALHOST", "localhost,127.0.0.0/8"} {
		code, body := postHost(t, base, "localhost", "/admin:inside:setPA?"+url.Values{"a": {value}, "b": {"Admin"}}.Encode(), tok)
		if code != 400 || !strings.Contains(body, "sirve el sitio localhost") {
			t.Errorf("setPA %q con el sitio localhost: %d %q; se esperaba 400 con el motivo", value, code, body)
		}
	}
	if code, body := postHost(t, base, "localhost", "/admin:inside:setPA?a=panel.test&b=Admin", tok); code != 200 {
		t.Fatalf("setPA panel.test: %d %q", code, body)
	}
	if panelAnswers(t, base, "localhost") {
		t.Error("con PA=panel.test, el panel responde en localhost")
	}
	if !panelAnswers(t, base, "panel.test") {
		t.Error("con PA=panel.test, el panel no responde en panel.test")
	}
}

// D3: con PA=panel.test,www.localhost, ningún sitio, wildcard, subdominio ni
// alias nuevo puede servir esos hosts; lo rechazado no deja carpetas.
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
			t.Errorf("%s: %d %q; se esperaba 400 por el host del panel", c.path, code, body)
		}
		if c.folder != "" {
			if _, err := os.Stat(dir + c.folder); err == nil {
				t.Errorf("%s: la carpeta %s quedó creada", c.path, c.folder)
			}
		}
	}
	if code, body := req("/admin:inside:addSite?s=otro.test"); code != 200 {
		t.Errorf("addSite otro.test: %d %q", code, body)
	}
}

// panelToken inicia sesión en el panel con el Host dado.
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
		t.Fatalf("login en %s: %d %q", hostName, res.StatusCode, b)
	}
	return string(b[2:])
}

// D3: un turbo.config con un PA que choca con un sitio se carga igual (no se
// rompe la configuración), con un aviso; y con PA vacío se avisa de que el
// panel comparte origen con los sitios.
func TestA7_ConfigWarnings(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"localhost":{"":{}},".":{"PA":"localhost"}}`)
	if panelAccess.Load().setting != "localhost" {
		t.Errorf("PA cargado: %q; se esperaba localhost", panelAccess.Load().setting)
	}
	if !strings.Contains(logs.String(), "sirve el sitio localhost") {
		t.Errorf("sin aviso por el PA que sirve un sitio:\n%s", logs.String())
	}
	loadConfig(t, dir, `{"localhost":{"":{}},".":{"PA":""}}`)
	if !strings.Contains(logs.String(), "El panel responde en los mismos hosts que los sitios") {
		t.Errorf("sin aviso con PA vacío:\n%s", logs.String())
	}
}

// H61: un sitio que aparece en disco y sirve el host del panel se activa,
// como desde turbo.config, pero con el aviso de que comparte origen.
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
	if !strings.Contains(logs.String(), "sirve el sitio panel.test") {
		t.Errorf("sitio panel.test creado en disco con PA=panel.test: sin aviso: %s", logs.String())
	}
}
