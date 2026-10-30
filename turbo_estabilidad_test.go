package main

// Caídas y bloqueos: panics con el mutex global tomado y validaciones que
// desreferencian un FileInfo nulo (#1, #2, #35, #62).

import (
	"os"
	"testing"
)

// #1, #2: extChars(".") no debe entrar en panic y debe rechazar la extensión.
func TestP01_ExtCharsDot(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic en extChars(\".\"): %v", r)
		}
	}()
	if extChars(".") {
		t.Fatal(`extChars(".") aceptada`)
	}
}

// #1: un panic en addMIME no debe dejar el mutex global bloqueado.
func TestP01_AddMIMEDotHangs(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:addMIME?s=localhost&d=&a=.&b=image/png", tok)
	t.Logf("addMIME a='.': code=%d body=%q err=%v", code, body, err)
	if err != nil {
		t.Fatalf("addMIME sin respuesta: %v", err)
	}
	code, body, err = get(base, "/index.html", nil)
	if err != nil || code != 200 || body != "hola" {
		t.Fatalf("petición posterior: code=%d body=%q err=%v; se esperaba 200", code, body, err)
	}
}

// #2: un turbo.config con la extensión "." no debe tumbar la carga.
func TestP02_ConfigDotPanics(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{"$":{".":"image/png"}}}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileModTime = 0
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic en updateSettings: %v", r)
		}
	}()
	updateSettings(false)
}

// #62: una ruta de preprocesador que el sistema rechaza no debe dejar el
// mutex global bloqueado.
func TestS_PreprocessorBadPathHangs(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, `/admin:inside:addPreprocessor?s=localhost&d=&a=php&b=%22x`, tok)
	t.Logf("addPreprocessor b='\"x': %d %q %v", code, body, err)
	code, _, err = get(base, "/index.html", nil)
	if err != nil || code != 200 {
		t.Fatalf("petición posterior: code=%d err=%v; se esperaba 200", code, err)
	}
}

// #62: lo mismo con el directorio de sitios.
func TestS_SetMBadPathHangs(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, `/admin:inside:setM?a=%22x`, tok)
	t.Logf("setM a='\"x': %d %q %v", code, body, err)
	code, _, err = get(base, "/index.html", nil)
	if err != nil || code != 200 {
		t.Fatalf("petición posterior: code=%d err=%v; se esperaba 200", code, err)
	}
}

// #62: fileExists con una ruta que el sistema rechaza (carácter no válido en
// Windows) o que atraviesa un archivo (Linux).
func TestS_FileExistsBadPath(t *testing.T) {
	file := t.TempDir() + "/archivo"
	os.WriteFile(file, []byte("x"), 0644)
	for _, p := range []string{`"x`, file + "/x"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic en fileExists(%q): %v", p, r)
				}
			}()
			if fileExists(p) {
				t.Errorf("fileExists(%q) = true", p)
			}
		}()
	}
}

// #35: una reescritura cuyo destino queda vacío tras los placeholders no debe
// entrar en panic: se rechaza al darla de alta o responde 404.
func TestP35_EmptyRewrite(t *testing.T) {
	initForTest(t)
	ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/x": "{EXT}"}, false, "localhost", "")
	t.Logf("alta reescritura: %v %q stored=%q", ok, msg, sitesMap["localhost"][""]["/x"])
	base, errLog := startServerLog(t)
	code, body, err := get(base, "/x", nil)
	if err != nil || code != 404 {
		t.Fatalf("GET /x -> code=%d body=%q err=%v; se esperaba 404", code, body, err)
	}
	// Una reescritura así guardada antes de este arreglo (turbo.config antiguo)
	// se sirve como "/".
	globalMutex.Lock()
	sitesMap["localhost"][""]["/y"] = "N{EXT}"
	globalMutex.Unlock()
	code, body, err = get(base, "/y", nil)
	if err != nil || code != 200 || body != "hola" {
		t.Fatalf("GET /y -> code=%d body=%q err=%v; se esperaba 200 con el índice", code, body, err)
	}
	if l := errLog.String(); l != "" {
		t.Fatalf("errores del servidor:\n%s", l)
	}
}

// #1, #2, #62 (T0.1): un panic en un validador del panel responde 500 y no deja
// el mutex global bloqueado. Se inyecta, porque T0.2 ya evita los panics
// conocidos.
func TestP01_PanicInValidatorUnlocks(t *testing.T) {
	initForTest(t)
	original := defaultSettingValidators["."]["CII"]
	defaultSettingValidators["."]["CII"] = func(args ...string) (bool, string) { panic("validador roto") }
	t.Cleanup(func() { defaultSettingValidators["."]["CII"] = original })
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:setCII?a=1&b=Admin", tok)
	if err != nil || code != 500 {
		t.Fatalf("setCII con panic -> code=%d body=%q err=%v; se esperaba 500", code, body, err)
	}
	code, _, err = get(base, "/index.html", nil)
	if err != nil || code != 200 {
		t.Fatalf("petición posterior: code=%d err=%v; se esperaba 200", code, err)
	}
	if !globalMutex.TryLock() {
		t.Fatal("el mutex global sigue tomado tras el panic")
	}
	globalMutex.Unlock()
}

// T0.1: una tarea periódica de main() que entra en panic no termina el proceso
// ni deja el mutex global tomado.
func TestP01_PeriodicTaskPanic(t *testing.T) {
	runRecovering("prueba", func() { withGlobalLock(func() { panic("tarea rota") }) })
	if !globalMutex.TryLock() {
		t.Fatal("el mutex global sigue tomado tras el panic")
	}
	globalMutex.Unlock()
}

// #11: los validadores de SSL (E, A, C, S, R, W) rechazan un número de
// argumentos fuera de 3-5 en lugar de indexar fuera de rango.
func TestP11_SSLValidatorArgCount(t *testing.T) {
	initForTest(t)
	for key, check := range siteSSLSettingCheckers {
		for _, args := range [][]string{nil, {"1"}, {"1", "localhost"}, {"1", "localhost", "", "", "", "x"}} {
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s con %d argumentos: panic %v", key, len(args), p)
					}
				}()
				globalMutex.Lock()
				defer globalMutex.Unlock()
				if ok, msg := check(false, args...); ok {
					t.Errorf("%s con %d argumentos aceptado: %q", key, len(args), msg)
				}
			}()
		}
	}
}

// #17: una extensión de preprocesador demasiado larga leída de turbo.config
// (sin mostrar errores) se descarta.
func TestP17_PreprocessorLongExtension(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	subdomainContentCheckers["?"](false, map[string]interface{}{"extensionlarga": toolPath("cgiecho")}, true, "localhost", "")
	_, added := preprocessors["localhost"]["extensionlarga"]
	globalMutex.Unlock()
	if added {
		t.Fatal("se añadió un preprocesador con una extensión de más de 12 caracteres")
	}
}
