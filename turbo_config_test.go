package main

// Compatibilidad de turbo.config entre esquemas (§5, §10).

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// loadConfig escribe turbo.config en dir y fuerza su lectura.
func loadConfig(t *testing.T, dir, cfg string) {
	t.Helper()
	if err := os.WriteFile(dir+"turbo.config", []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	configFileModTime = 0
	updateSettings(false)
}

// savedConfig devuelve el turbo.config guardado, ya interpretado.
func savedConfig(t *testing.T, dir string) map[string]map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(dir + "turbo.config")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("turbo.config guardado no es JSON válido: %v\n%s", err, b)
	}
	return raw
}

// El turbo.config del commit 4b5dc23 (esquema 1, sin "^") se carga con CIL y
// CIS migrados a milisegundos; al guardar se crea turbo.config.v1.bak con el
// original y se escribe "^"; el archivo guardado no se vuelve a migrar.
func TestC_ConfigMigrationV1(t *testing.T) {
	dir := initForTest(t)
	orig, err := os.ReadFile("testdata/config/v1-4b5dc23.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(orig), "{TURBO_CURRENT_DIR}", dir, 1)
	loadConfig(t, dir, cfg)
	if configSchemaRead != 1 {
		t.Errorf("esquema leído %d; se esperaba 1", configSchemaRead)
	}
	if sitesDir.Get() != dir {
		t.Errorf("M = %q; se esperaba %q", sitesDir.Get(), dir)
	}
	if d := time.Duration(serverRequestLimits[0]); d != 10*time.Second {
		t.Errorf("CIL = %v; se esperaba 10s (1000 unidades de 10 ms)", d)
	}
	if d := time.Duration(serverRequestLimits[1]); d != time.Second {
		t.Errorf("CIS = %v; se esperaba 1s (100 unidades de 10 ms)", d)
	}
	if serverRequestLimits[2] != 100 {
		t.Errorf("CII = %d; se esperaba 100", serverRequestLimits[2])
	}

	globalMutex.Lock()
	ok := saveDefaultConfig()
	globalMutex.Unlock()
	if !ok {
		t.Fatal("no se pudo guardar")
	}
	bak, err := os.ReadFile(dir + "turbo.config.v1.bak")
	if err != nil || string(bak) != cfg {
		t.Fatalf("copia .bak: err=%v contenido=%q", err, bak)
	}
	if fi, _ := os.Stat(dir + "turbo.config.v1.bak"); runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
		t.Errorf("permisos de la copia: %v; se esperaba 0600", fi.Mode().Perm())
	}
	raw := savedConfig(t, dir)
	if raw["^"]["v"] != "2" || raw["."]["CIL"] != "10000" || raw["."]["CIS"] != "1000" || raw["."]["CII"] != "100" {
		t.Fatalf("guardado: ^=%v .=%v", raw["^"], raw["."])
	}

	b, _ := os.ReadFile(dir + "turbo.config")
	loadConfig(t, dir, string(b))
	if configSchemaRead != configSchema {
		t.Errorf("esquema leído tras guardar: %d", configSchemaRead)
	}
	if d := time.Duration(serverRequestLimits[0]); d != 10*time.Second {
		t.Errorf("CIL tras recargar = %v; se esperaba 10s (sin migrar dos veces)", d)
	}
}

// Un turbo.config de un esquema posterior se carga sin migrar y "Guardar
// configuración" no lo sobrescribe sin confirmación explícita.
func TestC_ConfigFutureSchema(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"^":{"v":"3"},"localhost":{"":{}},".":{"CIL":"5000","NUEVO":"x"}}`
	loadConfig(t, dir, cfg)
	if d := time.Duration(serverRequestLimits[0]); d != 5*time.Second {
		t.Errorf("CIL = %v; se esperaba 5s", d)
	}
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:setC?a=&b=Admin", tok)
	if err != nil || code != 400 {
		t.Fatalf("setC sin confirmación: code=%d body=%q err=%v; se esperaba 400", code, body, err)
	}
	if b, _ := os.ReadFile(dir + "turbo.config"); string(b) != cfg {
		t.Fatalf("turbo.config sobrescrito sin confirmación: %s", b)
	}
	code, body, err = post(base, "/admin:inside:setC?a=sobrescribir&b=Admin", tok)
	if err != nil || code != 200 {
		t.Fatalf("setC con confirmación: code=%d body=%q err=%v", code, body, err)
	}
	if raw := savedConfig(t, dir); raw["^"]["v"] != "2" {
		t.Fatalf("guardado con confirmación: ^=%v", raw["^"])
	}
}

// §5.1, #58 (revisión de T1.7): al dejar en el directorio de arranque el
// turbo.config mínimo con M, el original se copia antes a
// turbo.config.v<esquema>.bak; un puntero ya escrito no se vuelve a copiar.
func TestC_SitesDirPointerBackup(t *testing.T) {
	start := initForTest(t)
	original := `{"localhost":{"":{}},".":{"CIL":"1000"}}`
	resetSettings()
	loadConfig(t, start, original)
	other := t.TempDir() + "/"
	os.MkdirAll(other+"otro.test/@", 0755)
	if ok, msg := defaultSettingValidators["."]["M"](other, "Admin"); !ok {
		t.Fatalf("setM: %q", msg)
	}
	resetSettings()
	updateSettings(true)
	for i := 0; i < 2; i++ { // el segundo guardado encuentra el puntero
		if ok, msg := defaultSettingValidators["."]["C"]("", "Admin"); !ok {
			t.Fatalf("setC: %q", msg)
		}
	}
	bak, err := os.ReadFile(start + "turbo.config.v1.bak")
	if err != nil || string(bak) != original {
		t.Fatalf("copia del directorio de arranque: err=%v contenido=%q", err, bak)
	}
	if fi, _ := os.Stat(start + "turbo.config.v1.bak"); runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
		t.Errorf("permisos de la copia: %v", fi.Mode().Perm())
	}
	if raw := savedConfig(t, start); raw["."]["M"] == nil || len(raw) != 2 {
		t.Errorf("puntero en el directorio de arranque: %v", raw)
	}
}
