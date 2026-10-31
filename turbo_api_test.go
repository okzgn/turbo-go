package main

// B9 (H17-H21): la API hace lo que dice su especificación.

import (
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// H17 (D7): R (www → raíz) y W (raíz → www) se configuran en la raíz del
// sitio, que es donde se aplican; en un subdominio se rechazan.
func TestB9_RootRedirectsOnlyAtRoot(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/www/@", 0755)
	updateSettings(true)
	base := startServer(t)
	tok := login(t, base)
	for _, path := range []string{"/admin:inside:cfgR?s=localhost&d=www&a=1", "/admin:inside:cfgW?s=localhost&d=www&a=1"} {
		if code, body, _ := post(base, path, tok); code != 400 || !strings.Contains(body, "raíz del sitio") {
			t.Errorf("%s: %d %q; se esperaba 400 por no ser la raíz", path, code, body)
		}
	}
	if code, body, _ := post(base, "/admin:inside:cfgR?s=localhost&d=&a=1", tok); code != 200 {
		t.Fatalf("cfgR en la raíz: %d %q", code, body)
	}
	res, _, err := rawGet(base, "www.localhost", "/x")
	if err != nil || res.StatusCode != 301 || res.Header.Get("Location") != "http://localhost/x" {
		t.Errorf("www.localhost con R en la raíz: %v %v; se esperaba 301 a http://localhost/x", res, err)
	}
}

// H18 (D8): "Crear SSL" con la emisión en curso responde 202 con el JSON de
// espera, no 400.
func TestB9_CertificateWaitIs202(t *testing.T) {
	useFakeCertbot(t, "ok")
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	globalMutex.Lock()
	currentCertDomain = "localhost"
	globalMutex.Unlock()
	t.Cleanup(func() { withGlobalLock(func() { currentCertDomain = "" }) })
	code, body, _ := post(base, "/admin:inside:cfgC?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"1"}, "z": {"admin@localhost.test"}}.Encode(), tok)
	if code != 202 || !strings.Contains(body, `"status":"WAIT"`) {
		t.Errorf("cfgC con la emisión en curso: %d %q; se esperaba 202 con status WAIT", code, body)
	}
}

// H19: con RT = 0 (sin límite), RHT admite cualquier valor de su rango.
func TestB9_RHTWithoutRT(t *testing.T) {
	initForTest(t)
	anterior := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = anterior }) }) })
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := defaultSettingValidators["."]["RT"]("0s", internalAuth); !ok {
		t.Fatalf("RT=0: %q", msg)
	}
	if ok, msg := defaultSettingValidators["."]["RHT"]("2s", internalAuth); !ok {
		t.Errorf("RHT=2s con RT=0: %q; se esperaba aceptado", msg)
	}
}

// H20: "Borrar SSL" borra el certificado aunque tenga más de 75 días.
func TestB9_DeleteOldCertificate(t *testing.T) {
	dir := initForTest(t)
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		os.WriteFile(dir+"localhost/"+name, []byte("x"), 0600)
		old := time.Now().Add(-80 * 24 * time.Hour)
		os.Chtimes(dir+"localhost/"+name, old, old)
	}
	globalMutex.Lock()
	ok, msg := siteSSLSettingCheckers["C"](false, "0", "localhost", "")
	globalMutex.Unlock()
	if !ok || msg != "Certificado SSL borrado" || fileExists(dir+"localhost/fullchain.pem") || fileExists(dir+"localhost/privkey.pem") {
		t.Errorf("cfgC a=0 con un certificado de 80 días: %v %q; se esperaba borrado", ok, msg)
	}
}

// H21: todos los parámetros de texto pasan por el reemplazo de caracteres
// (§2.1), también la plantilla de respuesta y el nombre de una cabecera.
func TestB9_AllTextParametersReplaced(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addCharsReplace?"+url.Values{"s": {"Q"}, "d": {"zz"}}.Encode(), tok); code != 200 {
		t.Fatalf("addCharsReplace: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:addHttpCodeResponse?"+url.Values{"s": {"404"}, "d": {"No -,- existe"}}.Encode(), tok); code != 200 {
		t.Fatalf("addHttpCodeResponse: %d %q", code, body)
	}
	if got := (*httpResponses.Load())[404]; got != "No # existe" {
		t.Errorf("plantilla guardada %q; se esperaba \"No # existe\"", got)
	}
	if code, body, _ := post(base, "/admin:inside:addHeader?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-zz"}, "b": {"1"}}.Encode(), tok); code != 200 {
		t.Fatalf("addHeader: %d %q", code, body)
	}
	globalMutex.RLock()
	_, replaced := customHeaders["localhost"]["X-Q"]
	globalMutex.RUnlock()
	if !replaced {
		t.Error("el nombre de la cabecera X-zz no se guardó como X-Q")
	}
	if code, body, _ := post(base, "/admin:inside:delHeader?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"X-zz"}}.Encode(), tok); code != 200 {
		t.Errorf("delHeader X-zz: %d %q", code, body)
	}
}
