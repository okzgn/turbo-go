package main

// A3 (H4, H5): turbo.config es siempre JSON válido, los valores con caracteres
// de control se rechazan y un archivo ilegible no se sustituye por los valores
// por defecto (D11).

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// configValueKinds son los tipos de valor de texto que se guardan en
// turbo.config, con cómo se guardan, cómo se leen de memoria y si admiten
// saltos de línea y tabuladores (solo las plantillas de respuesta).
var configValueKinds = []struct {
	name       string
	whitespace bool
	store      func(value string) (bool, string)
	stored     func() (string, bool)
}{
	{"cabecera", false,
		func(v string) (bool, string) {
			return subdomainContentCheckers["."](true, map[string]interface{}{"X-Prueba": v}, false, "localhost", "")
		},
		func() (string, bool) { v, ok := customHeaders["localhost"]["X-Prueba"]; return v, ok }},
	{"reescritura", false,
		func(v string) (bool, string) {
			return subdomainContentCheckers["="](true, map[string]interface{}{"/origen": "/" + v}, false, "localhost", "")
		},
		func() (string, bool) {
			v, ok := sitesMap["localhost"][""]["/origen"]
			if !ok {
				return "", false
			}
			return v[2:], true // "N/<destino>"
		}},
	{"plantilla", true,
		func(v string) (bool, string) { return adminAddHandlers["#"]("404", v) },
		func() (string, bool) { v, ok := (*httpResponses.Load())[404]; return v, ok }},
	{"usuario", false,
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
	{"índice", false,
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
	{"reemplazo", false,
		func(v string) (bool, string) { return adminAddHandlers["_"]("~", "r"+v) },
		func() (string, bool) { v, ok := charReplacements["~"]; return strings.TrimPrefix(v, "r"), ok }},
}

// storeAndReload guarda value con el tipo kind como lo haría el panel (la
// comprobación de caracteres de la API y el validador), guarda turbo.config,
// lo vuelve a leer en un estado vacío y devuelve el valor en memoria antes y
// después. accepted es false si el panel lo rechaza.
func storeAndReload(t testing.TB, dir string, kind int, value string) (accepted bool, before, after string) {
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
		ok = saveDefaultConfig()
		if !ok {
			globalMutex.Unlock()
			t.Fatalf("%s %q: no se pudo guardar", k.name, value)
		}
	}
	globalMutex.Unlock()
	if !ok {
		return false, "", ""
	}
	data, err := os.ReadFile(dir + "turbo.config")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("%s %q: turbo.config guardado no es JSON válido:\n%s", k.name, value, data)
	}
	lightReset(dir)
	if err := updateSettings(false); err != nil {
		t.Fatalf("%s %q: recarga: %v", k.name, value, err)
	}
	globalMutex.RLock()
	after, found := k.stored()
	globalMutex.RUnlock()
	if !found {
		t.Fatalf("%s %q: el valor guardado (%q) no está tras recargar; turbo.config:\n%s", k.name, value, before, data)
	}
	return true, before, after
}

// lightReset vacía la configuración en memoria sin esperar a Certbot, para
// volver a leer turbo.config muchas veces en una prueba.
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

// H4: cada carácter de 0x00 a 0x7f y algunos no ASCII, en cada tipo de valor,
// se rechaza al guardarlo o vuelve igual tras guardar y leer turbo.config, que
// siempre es JSON válido.
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
				t.Errorf("%s %q: guardado %q, leído %q", configValueKinds[kind].name, v, before, after)
			}
			if c := v[1]; !accepted && len(v) == 3 && c >= 0x20 && c != 0x7f && configValueKinds[kind].name == "cabecera" {
				t.Errorf("cabecera %q rechazada", v)
			}
		}
	}
}

func FuzzConfigRoundTrip(f *testing.F) {
	f.Add(uint8(0), "valor\x01roto")
	f.Add(uint8(2), "<h1>{TURBO_RESPONSE_CODE}</h1>\n")
	f.Add(uint8(3), "us\"u\\ario")
	f.Add(uint8(6), "\xff")
	dir := filepath.ToSlash(f.TempDir()) + "/"
	resetTestState(dir)
	os.MkdirAll(dir+"localhost/@", 0755)
	updateSettings(false)
	f.Fuzz(func(t *testing.T, kind uint8, value string) {
		k := int(kind) % len(configValueKinds)
		if accepted, before, after := storeAndReload(t, dir, k, value); accepted && before != after {
			t.Fatalf("%s %q: guardado %q, leído %q", configValueKinds[k].name, value, before, after)
		}
	})
}

// H4: desde el panel, un valor con caracteres de control se rechaza; el
// guardado y la recarga mantienen la contraseña, PA y los sitios.
func TestA3_PanelRejectsControlChars(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:setPA?"+url.Values{"a": {"127.0.0.0/8,::1/128"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("setPA: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:setP?"+url.Values{"a": {"Otra"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("setP: %d %q", code, body)
	}
	for _, path := range []string{
		"addHeader?" + url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-Cabecera"}, "b": {"valor\x01roto"}}.Encode(),
		"addRewrite?" + url.Values{"s": {"localhost"}, "d": {""}, "a": {"/x"}, "b": {"/y\x1b"}}.Encode(),
		"setU?" + url.Values{"a": {"us\x7fer"}, "b": {"Otra"}}.Encode(),
		"addHttpCodeResponse?" + url.Values{"s": {"404"}, "d": {"no\x00"}}.Encode(),
		"addCharsReplace?" + url.Values{"s": {"\x02"}, "d": {"x"}}.Encode(),
	} {
		code, body, _ := post(base, "/admin:inside:"+path, tok)
		if code != 400 || body != "Caracteres de control no admitidos" {
			t.Errorf("%s: %d %q; se esperaba 400 \"Caracteres de control no admitidos\"", path, code, body)
		}
	}
	// A template may span lines.
	if code, body, _ := post(base, "/admin:inside:addHttpCodeResponse?"+url.Values{"s": {"404"}, "d": {"<p>\r\n\tNo está</p>"}}.Encode(), tok); code != 200 {
		t.Errorf("plantilla con saltos de línea: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:setC?a=&b=Otra", tok); code != 200 {
		t.Fatalf("setC: %d %q", code, body)
	}
	if data, _ := os.ReadFile(dir + "turbo.config"); !json.Valid(data) {
		t.Fatalf("turbo.config no es JSON válido:\n%s", data)
	}
	lightReset(dir)
	setPanelPassword("Admin")
	panelAccess.Store(&panelAccessList{})
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	if passwordMatches("Admin") || !passwordMatches("Otra") {
		t.Error("tras recargar, la contraseña no es la guardada")
	}
	if panelAccess.Load().setting != "127.0.0.0/8,::1/128" {
		t.Errorf("PA tras recargar: %q", panelAccess.Load().setting)
	}
	if (*httpResponses.Load())[404] != "<p>\r\n\tNo está</p>" {
		t.Errorf("plantilla tras recargar: %q", (*httpResponses.Load())[404])
	}
}

// H4: un turbo.config con un carácter de control escapado (JSON válido) carga
// el resto y descarta ese valor con un aviso.
func TestA3_ControlCharsFromFileDiscarded(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{".":{"X-Mala":"a\u0001b","X-Buena":"ok"}}},".":{"U":"Jefe\u0007"},"#":{"404":"x\u0000"}}`
	loadConfig(t, dir, cfg)
	if _, bad := customHeaders["localhost"]["X-Mala"]; bad {
		t.Error("cabecera con carácter de control cargada")
	}
	if customHeaders["localhost"]["X-Buena"] != "ok" {
		t.Error("la cabecera válida no se cargó")
	}
	if panelUser.Get() != "Turbo" {
		t.Errorf("usuario con carácter de control cargado: %q", panelUser.Get())
	}
	if _, bad := (*httpResponses.Load())[404]; bad {
		t.Error("plantilla con NUL cargada")
	}
}

// D11: describeConfigError sitúa el error (línea, columna, fragmento con la
// marca), con los caracteres de control escapados y las líneas largas
// recortadas, y lista las copias .bak.
func TestA3_DescribeConfigError(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir()) + "/"
	path := dir + "turbo.config"
	os.WriteFile(dir+"turbo.config.v1.bak", []byte("{}"), 0600)
	old := time.Now().Add(-time.Hour)
	os.WriteFile(dir+"turbo.config.invalido.20261029-101010.bak", []byte("x"), 0600)
	os.Chtimes(dir+"turbo.config.invalido.20261029-101010.bak", old, old)

	parse := func(data string) error {
		var raw map[string]map[string]interface{}
		return json.Unmarshal([]byte(data), &raw)
	}
	cases := []struct {
		name, data, line, fragment, marker string
	}{
		{"al principio", "x{}", "Línea 1, columna 1", "    x{}", "    ^"},
		{"carácter de control", "{\n \"a\": {\n  \"X-Cabecera\": \"valor\x01roto\"}}", "Línea 3, columna 23", `    "X-Cabecera": "valor\x01roto"}}`, "                          ^"},
		{"al final", "{\"a\":{}", "Línea 1, columna 7", "    {\"a\":{}", "          ^"},
		{"tipo", "{\"a\":\"b\"}", "Línea 1, columna 8", "    {\"a\":\"b\"}", "           ^"},
	}
	for _, c := range cases {
		msg := describeConfigError(path, []byte(c.data), parse(c.data))
		for _, want := range []string{"Archivo: " + path, c.line, c.fragment + "\n", c.marker + "\n"} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: falta %q en:\n%s", c.name, want, msg)
			}
		}
		newest := strings.Index(msg, "turbo.config.v1.bak")
		oldest := strings.Index(msg, "turbo.config.invalido.20261029-101010.bak")
		if newest < 0 || oldest < 0 || newest > oldest {
			t.Errorf("%s: copias .bak ausentes o desordenadas:\n%s", c.name, msg)
		}
	}

	long := "{\"a\":\"" + strings.Repeat("x", 300) + "\x01" + strings.Repeat("y", 300) + "\"}"
	msg := describeConfigError(path, []byte(long), parse(long))
	if !strings.Contains(msg, "Línea 1, columna 307") {
		t.Errorf("línea larga: posición incorrecta:\n%s", msg)
	}
	lines := strings.Split(msg, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "    ") && strings.Contains(l, `\x01`) { // The fragment, not the cause
			if n := len([]rune(strings.TrimSpace(l))); n > 130 {
				t.Errorf("fragmento de %d caracteres; se esperaban unos 120", n)
			}
			if i+1 >= len(lines) || strings.Index(lines[i+1], "^") != strings.Index(l, `\x01`) {
				t.Errorf("la marca no está bajo el carácter:\n%s\n%s", l, lines[i+1])
			}
		}
	}
}

// D11, H4: con un turbo.config inválido, Turbo no arranca: sale con código 1
// sin abrir los puertos ni tocar el archivo, y explica dónde está el error.
func TestA3_StartWithInvalidConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("compila el binario")
	}
	bin := filepath.Join(t.TempDir(), "turbo")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	dir := filepath.ToSlash(t.TempDir()) + "/"
	cfg := "{\n  \"localhost\": {\"\": {\".\": {\n    \"X-Cabecera\": \"valor\x01roto\"}}},\n  \".\": {\"PH\": \"x\"}\n}\n"
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
			t.Fatalf("Turbo terminó con %v; se esperaba el código 1\n%s", err, out.String())
		}
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatalf("Turbo arrancó con un turbo.config inválido\n%s", out.String())
	}
	msg := out.String()
	for _, want := range []string{"Turbo no arranca", "Archivo: " + dir + "turbo.config", "Línea 3, columna 25", `"X-Cabecera": "valor\x01roto"}}},`, "^", dir + "turbo.config.v1.bak"} {
		if !strings.Contains(msg, want) {
			t.Errorf("falta %q en el mensaje:\n%s", want, msg)
		}
	}
	if data, _ := os.ReadFile(dir + "turbo.config"); string(data) != cfg {
		t.Error("turbo.config modificado")
	}
}

// freePort devuelve un puerto TCP libre de 127.0.0.1.
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

// D11: si turbo.config se rompe con el servidor en marcha, la recarga mantiene
// la configuración en uso (no vuelve la contraseña Admin) y no lo reintenta
// hasta que cambie la fecha del archivo.
func TestA3_ReloadKeepsConfigInUse(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	globalMutex.Lock()
	subdomainContentCheckers["."](true, map[string]interface{}{"X-Sitio": "1"}, false, "localhost", "")
	setPanelPassword("Otra")
	defaultSettingValidators["."]["PA"]("localhost", internalAuth)
	saveDefaultConfig()
	globalMutex.Unlock()
	updateSettings(true)

	broken := []byte(`{"localhost":{"":{}},".":{"U":"x"`)
	os.WriteFile(dir+"turbo.config", broken, 0600)
	future := time.Now().Add(2 * time.Second)
	os.Chtimes(dir+"turbo.config", future, future)
	if err := updateSettings(true); err == nil {
		t.Error("la recarga de un archivo inválido no devolvió error")
	}
	if passwordMatches("Admin") || !passwordMatches("Otra") {
		t.Error("la recarga cambió la contraseña")
	}
	if customHeaders["localhost"]["X-Sitio"] != "1" {
		t.Error("la recarga perdió la cabecera del sitio")
	}
	if panelAccess.Load().setting != "localhost" {
		t.Errorf("la recarga cambió PA: %q", panelAccess.Load().setting)
	}
	if code, body, err := get(base, "/", nil); err != nil || code != 200 || body != "hola" {
		t.Errorf("GET / tras la recarga: %d %q %v", code, body, err)
	}
	if err := updateSettings(true); err != nil {
		t.Errorf("sin cambios en el archivo, la recarga se reintentó: %v", err)
	}
}

// H5: guardar con un turbo.config inválido en disco lo copia antes a
// turbo.config.invalido.<fecha>.bak; la escritura es atómica: si falla, el
// archivo anterior queda intacto.
func TestA3_SaveBackupAndAtomic(t *testing.T) {
	dir := initForTest(t)
	broken := []byte("{roto")
	os.WriteFile(dir+"turbo.config", broken, 0600)
	globalMutex.Lock()
	ok := saveDefaultConfig()
	globalMutex.Unlock()
	if !ok {
		t.Fatal("no se pudo guardar")
	}
	backups, _ := filepath.Glob(dir + "turbo.config.invalido.*.bak")
	if len(backups) != 1 {
		t.Fatalf("copias del archivo inválido: %v", backups)
	}
	if data, _ := os.ReadFile(backups[0]); string(data) != string(broken) {
		t.Errorf("la copia no es el archivo inválido: %q", data)
	}
	saved, _ := os.ReadFile(dir + "turbo.config")
	if !json.Valid(saved) {
		t.Fatal("turbo.config guardado no es JSON válido")
	}

	// The temporary file can't be created: the save fails and the file is left as it was.
	os.Mkdir(dir+"turbo.config.tmp", 0755)
	globalMutex.Lock()
	subdomainContentCheckers["."](true, map[string]interface{}{"X-Nueva": "1"}, false, "localhost", "")
	ok = saveDefaultConfig()
	globalMutex.Unlock()
	if ok {
		t.Error("el guardado no falló")
	}
	if data, _ := os.ReadFile(dir + "turbo.config"); string(data) != string(saved) {
		t.Error("turbo.config cambió tras un guardado fallido")
	}
}

// D11: el panel no cambia a un directorio de sitios con un turbo.config
// H62: si turbo.config es un enlace simbólico, se escribe en su destino y el
// enlace se mantiene, en lugar de sustituirlo por un archivo normal.
func TestH62_AtomicWriteKeepsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.config")
	link := filepath.Join(dir, "turbo.config")
	os.WriteFile(target, []byte("{}"), 0600)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("sin enlaces simbólicos en este sistema: %v", err)
	}
	if err := writeFileAtomic(link, []byte(`{"a":"1"}`)); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("turbo.config dejó de ser un enlace simbólico: %v %v", info, err)
	}
	if data, _ := os.ReadFile(target); string(data) != `{"a":"1"}` {
		t.Errorf("destino del enlace: %q; se esperaba el contenido nuevo", data)
	}
}

// inválido (al leerlo se perdería la configuración en uso).
func TestA3_SetMInvalidConfig(t *testing.T) {
	dir := initForTest(t)
	other := filepath.ToSlash(t.TempDir()) + "/"
	os.WriteFile(other+"turbo.config", []byte("{roto"), 0600)
	base := startServer(t)
	tok := login(t, base)
	code, body, _ := post(base, "/admin:inside:setM?"+url.Values{"a": {other}, "b": {"Admin"}}.Encode(), tok)
	if code != 400 || !strings.Contains(body, "no es JSON válido") || !strings.Contains(body, "Línea 1, columna 2") {
		t.Errorf("setM a un directorio con turbo.config inválido: %d %q", code, body)
	}
	if sitesDir.Get() != dir {
		t.Errorf("directorio de sitios cambiado a %q", sitesDir.Get())
	}
}
