package main

// Servido de archivos, reescrituras, CGI y redirecciones (#12, #27, #32, #41,
// #46, #47, #48, #51).

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// #12: un preprocesador sin ejecutable no debe servir el código fuente.
func TestP12_PreprocessorFailOpen(t *testing.T) {
	dir := initForTest(t)
	exe := dir + "fake-cgi.exe"
	os.WriteFile(exe, []byte("x"), 0755)
	os.WriteFile(dir+"localhost/@/a.php", []byte("<?php $secreto = 'clave'; ?>"), 0644)
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"php": exe}, false, "localhost", "")
	t.Logf("alta preprocesador: %v %q", ok, msg)
	os.Remove(exe)
	base := startServer(t)
	code, body, err := get(base, "/a.php", nil)
	if err != nil || code != 500 || strings.Contains(body, "secreto") {
		t.Fatalf("GET /a.php sin ejecutable -> code=%d body=%q err=%v; se esperaba 500 sin el contenido", code, body, err)
	}
}

// #27: un fallo al lanzar el CGI responde 500 sin el error del sistema.
func TestP27_CGIErrorDisclosure(t *testing.T) {
	dir := initForTest(t)
	exe := dir + "no-ejecutable.txt" // existe pero no es ejecutable
	os.WriteFile(exe, []byte("texto"), 0644)
	os.WriteFile(dir+"localhost/@/b.cgi", []byte("x"), 0644)
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": exe}, false, "localhost", "")
	t.Logf("alta preprocesador: %v %q", ok, msg)
	base := startServer(t)
	code, body, err := get(base, "/b.cgi", nil)
	if err != nil || code != 500 || strings.Contains(body, "no-ejecutable") || strings.Contains(body, "exec") {
		t.Fatalf("code=%d body=%q err=%v; se esperaba 500 sin detalles", code, body, err)
	}
}

// #48: el cuerpo enviado a un CGI se limita a MBB.
func TestW_CGIBodyAndEnv(t *testing.T) {
	t.Setenv("TURBO_PASSWORD", "secreto-de-prueba")
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	base := startServer(t)
	body := bytes.Repeat([]byte("a"), 3*1024*1024)
	req, _ := http.NewRequest("POST", base+"/x.cgi?a=1", bytes.NewReader(body))
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	t.Logf("MBB=%d, POST de %d bytes al CGI -> code=%d\n%s", maxBodySize.Load(), len(body), res.StatusCode, b)
	t.Logf("TURBO_PASSWORD visible para el CGI = %v", strings.Contains(string(b), "TURBO_PASSWORD"))
	if res.StatusCode != 413 || strings.Contains(string(b), "BODY_BYTES=3145728") {
		t.Fatalf("code=%d; se esperaba 413 sin pasar el cuerpo al CGI", res.StatusCode)
	}
}

// #32: QUERY_STRING sin "&" sobrante cuando la reescritura no aporta consulta.
func TestW_CGIQueryString(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	base := startServer(t)
	code, body, err := get(base, "/x.cgi?a=1", nil)
	if err != nil || code != 200 || !strings.Contains(body, "QUERY_STRING=a=1\n") {
		t.Fatalf("code=%d err=%v; se esperaba QUERY_STRING=a=1\n%s", code, err, body)
	}
}

// #27: un CGI que tarda más que el timeout (WT) se corta y no sigue en ejecución.
func TestW_CGITimeout(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	if ok, msg := defaultSettingValidators["."]["WT"]("500ms", "Admin"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	mark := dir + "terminado"
	start := time.Now()
	code, _, err := get(base, "/x.cgi?sleep=2500&mark="+mark, nil)
	elapsed := time.Since(start)
	t.Logf("code=%d err=%v en %v", code, err, elapsed)
	if elapsed > 1500*time.Millisecond {
		t.Errorf("la petición tardó %v; se esperaba el corte cerca de 500ms", elapsed)
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(mark); err == nil {
		t.Error("el CGI siguió en ejecución tras el timeout")
	}
}

// #47: con varios índices, el servido es siempre el mismo (el primero añadido).
func TestW_IndexPriority(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/index.cgi", []byte("x"), 0644)
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	t.Logf("preprocesador: %v %q", ok, msg)
	subdomainContentCheckers["-"](true, map[string]interface{}{"index.cgi": false}, false, "localhost", "")
	base := startServer(t)
	html, cgi := 0, 0
	for i := 0; i < 30; i++ {
		_, body, err := rawGet(base, "localhost", "/")
		if err != nil {
			continue
		}
		if strings.Contains(body, "QUERY_STRING") {
			cgi++
		} else if strings.Contains(body, "hola") {
			html++
		}
		time.Sleep(40 * time.Millisecond)
	}
	if html != 30 {
		t.Fatalf("30 peticiones a / -> index.html=%d, index.cgi=%d; se esperaban 30 de index.html", html, cgi)
	}
}

// #41: un subdominio wildcard se sirve por HTTP una sola vez, sin redirección
// ni "superfluous WriteHeader".
func TestW_Placeholders(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"example.com/@", 0755)
	os.MkdirAll(dir+"example.com/#/@", 0755)
	os.WriteFile(dir+"example.com/#/@/e.cgi", []byte("x"), 0644)
	updateSettings(false)
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "example.com", "*")
	t.Logf("preprocesador: %v %q", ok, msg)
	target := "/e.cgi?WS={WILDCARD_SITE}&WD={WILDCARD_DOMAIN}&WSUB={WILDCARD_SUBDOMAIN}&D={DOMAIN}&S={SUBDOMAIN}&SITE={SITE}&FD={FIRST_DOMAIN}&FS={FIRST_SUBDOMAIN}&FSITE={FIRST_SITE}&FR={FIRST_REQUEST}&FQ={FIRST_QUERY}&DIR={DIR}&FILE={FILE}&EXT={EXT}&RW={REWRITE}&RWC={REWRITE_COMPLEMENT}"
	ok, msg = subdomainContentCheckers["="](true, map[string]interface{}{"/p/": target}, false, "example.com", "*")
	t.Logf("reescritura: %v %q", ok, msg)
	ok, msg = subdomainContentCheckers["&"](true, map[string]interface{}{"alias.test": false}, false, "example.com", "*")
	t.Logf("alias: %v %q", ok, msg)
	base, errLog := startServerLog(t)
	for _, h := range []string{"foo.example.com", "bar.foo.example.com", "alias.test"} {
		res, body, err := rawGet(base, h, "/p/dir/file.txt?q=1&r=2")
		if err != nil {
			t.Errorf("host=%s err=%v", h, err)
			continue
		}
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "QUERY_STRING=") {
				t.Logf("host=%s code=%d\n    %s", h, res.StatusCode, strings.ReplaceAll(l, "&", "\n    "))
			}
		}
		if res.StatusCode != 200 || res.Header.Get("Location") != "" {
			t.Errorf("host=%s -> %d Location=%q; se esperaba 200 sin redirección", h, res.StatusCode, res.Header.Get("Location"))
		}
		if n := strings.Count(body, "QUERY_STRING="); n != 1 {
			t.Errorf("host=%s: CGI ejecutado %d veces", h, n)
		}
	}
	if l := errLog.String(); strings.Contains(l, "superfluous") {
		t.Errorf("errores del servidor:\n%s", l)
	}
}

// #46: redirecciones de reescritura (DP8): destino exacto si tiene ruta o
// consulta; si es solo un dominio, se añade el URI original.
func TestW_RewriteRedirect(t *testing.T) {
	initForTest(t)
	for k, v := range map[string]string{"/go/": "https://dest.example", "/gp/": "https://dest.example/destino", "/gq/": "https://dest.example/destino?x=1"} {
		ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{k: v}, false, "localhost", "")
		t.Logf("alta %s -> %s: %v %q stored=%q", k, v, ok, msg, sitesMap["localhost"][""][k])
	}
	base := startServer(t)
	for p, want := range map[string]string{
		"/go/abc?q=2": "https://dest.example/go/abc?q=2",
		"/gp/abc?q=2": "https://dest.example/destino",
		"/gq/abc?q=2": "https://dest.example/destino?x=1",
	} {
		res, _, err := rawGet(base, "localhost", p)
		if err != nil {
			t.Errorf("%s -> err %v", p, err)
			continue
		}
		if res.StatusCode != 302 || res.Header.Get("Location") != want {
			t.Errorf("%s -> %d Location=%q; se esperaba 302 %q", p, res.StatusCode, res.Header.Get("Location"), want)
		}
	}
}

// #41: un subdominio no configurado de un sitio existente no se redirige a
// HTTPS: responde 404. Se pide "/" porque "/index.html" siempre redirige a
// "./" (comportamiento de la stdlib, #39).
func TestW_UnknownSubdomain(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	for h, want := range map[string]int{"zzz.localhost": 404, "www.localhost": 404, "localhost": 200} {
		res, body, err := rawGet(base, h, "/")
		if err != nil {
			t.Errorf("%s err=%v", h, err)
			continue
		}
		if res.StatusCode != want || res.Header.Get("Location") != "" {
			t.Errorf("%s -> %d Location=%q body=%q; se esperaba %d sin redirección", h, res.StatusCode, res.Header.Get("Location"), body, want)
		}
	}
}

// Los reemplazos de caracteres se aplican a los valores enviados al panel, no
// a las URI recibidas (la documentación dice lo contrario).
func TestW_CharReplaceIncoming(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/a;b.txt", []byte("archivo-con-punto-y-coma"), 0644)
	os.WriteFile(dir+"localhost/@/a-.-b.txt", []byte("archivo-con-token"), 0644)
	base := startServer(t)
	for p, want := range map[string]string{"/a;b.txt": "archivo-con-punto-y-coma", "/a-.-b.txt": "archivo-con-token"} {
		res, body, err := rawGet(base, "localhost", p)
		if err != nil || res.StatusCode != 200 || body != want {
			t.Errorf("%s -> %v %q %v; se esperaba 200 %q", p, res, body, err, want)
		}
	}
}

// #51: las respuestas de error llevan nosniff.
func TestW_ErrorHeaders(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	res, body, _ := rawGet(base, "localhost", "/nope")
	t.Logf("404 por defecto: CT=%q body=%q", res.Header.Get("Content-Type"), body)
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("404 por defecto sin nosniff")
	}
	adminAddHandlers["#"]("404", "<h1>Error {TURBO_RESPONSE_CODE}</h1>")
	res, body, _ = rawGet(base, "localhost", "/nope")
	t.Logf("404 HTML: CT=%q body=%q", res.Header.Get("Content-Type"), body)
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("404 HTML sin nosniff")
	}
}

// #12: el prefijo dx> no está implementado y se rechaza al añadir un
// preprocesador.
func TestP12_PreprocessorDxRejected(t *testing.T) {
	initForTest(t)
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"php": "dx>" + toolPath("cgiecho")}, false, "localhost", "")
	if ok {
		t.Fatalf("dx> aceptado: %q", msg)
	}
	ok, msg = subdomainContentCheckers["?"](true, map[string]interface{}{"php": "cgi>" + toolPath("cgiecho")}, false, "localhost", "")
	if !ok {
		t.Fatalf("cgi> rechazado: %q", msg)
	}
}

// #69: en una instalación nueva, un sitio encontrado en el directorio tiene
// index.html como índice y "/" responde 200.
func TestW_NewInstallIndex(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir()) + "/"
	resetTestState(dir)
	t.Cleanup(func() {
		serverSetLogState(visitsLogName, nil)
		serverSetLogState(denialsLogName, nil)
	})
	os.MkdirAll(dir+"localhost/@", 0755)
	os.WriteFile(dir+"localhost/@/index.html", []byte("hola"), 0644)
	updateSettings(false)
	base := startServer(t)
	if code, body, err := get(base, "/", nil); err != nil || code != 200 || body != "hola" {
		t.Fatalf("GET / -> %d %q %v; se esperaba 200 hola", code, body, err)
	}
}

// #15: una reescritura cuyos placeholders producen ".." no sale del directorio
// de contenido: {FILE} de "/r/.." es "..", y "/{FILE}/{FILE}/x.cgi" apuntaba
// a un CGI dos carpetas por encima de @.
func TestW_PlaceholderTraversal(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"x.cgi", []byte("x"), 0644) // fuera de @
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/r/": "/{FILE}/{FILE}/x.cgi"}, false, "localhost", "")
	t.Logf("reescritura: %v %q", ok, msg)
	base := startServer(t)
	res, body, err := rawGet(base, "localhost", "/r/..")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("/r/.. -> %d", res.StatusCode)
	if strings.Contains(body, "SCRIPT_FILENAME") {
		t.Fatalf("se ejecutó un CGI fuera de @:\n%s", body)
	}
}

// §5.2 (DP10): los índices de un turbo.config de esquema 1 toman el orden del
// archivo; se guardan con su posición y la recarga conserva el orden.
func TestC_IndexOrderMigration(t *testing.T) {
	dir := initForTest(t)
	names := []string{"z.html", "a.html", "m.html", "b.html", "y.html"}
	cfg := `{"localhost":{"":{"-":{"z.html":"","a.html":"","m.html":"","b.html":"","y.html":""}}}}`
	resetSettings() // como al arrancar: el sitio aún no existe al leer turbo.config
	loadConfig(t, dir, cfg)
	check := func(when string) {
		t.Helper()
		globalMutex.RLock()
		got := orderedIndexes("localhost")
		globalMutex.RUnlock()
		if strings.Join(got, ",") != strings.Join(names, ",") {
			t.Fatalf("%s: orden %v; se esperaba %v", when, got, names)
		}
	}
	check("tras migrar")
	globalMutex.Lock()
	saveDefaultConfig()
	globalMutex.Unlock()
	raw := savedConfig(t, dir)
	indexes := raw["localhost"][""].(map[string]interface{})["-"].(map[string]interface{})
	for i, n := range names {
		if indexes[n] != strconv.Itoa(i+1) {
			t.Errorf("posición guardada de %s: %v; se esperaba %d", n, indexes[n], i+1)
		}
	}
	b, _ := os.ReadFile(dir + "turbo.config")
	loadConfig(t, dir, string(b))
	check("tras recargar")
}

// #12: leído de turbo.config, un preprocesador sin ejecutable o con dx> no
// deja servir el código fuente, no impide cargar los demás y no se pierde al
// guardar.
func TestP12_PreprocessorFailClosedFromConfig(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/a.php", []byte("<?php $secreto = 'clave'; ?>"), 0644)
	os.WriteFile(dir+"localhost/@/b.dx", []byte("secreto dx"), 0644)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	cfg := `{"localhost":{"":{"?":{"php":"cgi>` + dir + `no-existe.exe","dx":"dx>` + dir + `algo","cgi":"` + toolPath("cgiecho") + `"}}}}`
	resetSettings()
	loadConfig(t, dir, cfg)
	base := startServer(t)
	for _, p := range []string{"/a.php", "/b.dx"} {
		if code, body, err := get(base, p, nil); err != nil || code != 500 || strings.Contains(body, "secreto") {
			t.Errorf("GET %s -> %d %q %v; se esperaba 500 sin el contenido", p, code, body, err)
		}
	}
	if code, body, _ := get(base, "/x.cgi", nil); code != 200 || !strings.Contains(body, "QUERY_STRING") {
		t.Errorf("el preprocesador válido no se cargó: %d %q", code, body)
	}
	globalMutex.Lock()
	saveDefaultConfig()
	globalMutex.Unlock()
	pre := savedConfig(t, dir)["localhost"][""].(map[string]interface{})["?"].(map[string]interface{})
	if pre["php"] == nil || pre["dx"] == nil {
		t.Errorf("preprocesadores guardados: %v; se esperaban php y dx", pre)
	}
}

// Revisión de T1.3: las cabeceras del sitio van en los archivos servidos, no
// en los 404 (un Cache-Control largo haría que una caché guardase el 404).
func TestW_SiteHeadersNotOn404(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["."](true, map[string]interface{}{"Cache-Control": "max-age=31536000"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("addHeader: %q", msg)
	}
	base := startServer(t)
	res, _, err := rawGet(base, "localhost", "/no-existe")
	if err != nil || res.StatusCode != 404 || res.Header.Get("Cache-Control") != "" {
		t.Errorf("404 -> %v Cache-Control=%q; se esperaba sin la cabecera del sitio", err, res.Header.Get("Cache-Control"))
	}
	res, _, err = rawGet(base, "localhost", "/")
	if err != nil || res.StatusCode != 200 || res.Header.Get("Cache-Control") != "max-age=31536000" {
		t.Errorf("200 -> %v Cache-Control=%q; se esperaba la cabecera del sitio", err, res.Header.Get("Cache-Control"))
	}
}
