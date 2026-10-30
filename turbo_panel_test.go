package main

// Panel y API (#28, #29, #38, #49, #50, #52).

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// La documentación dice "/admin"; el panel responde en "/admin:".
func TestW_AdminURL(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	res, body, err := rawGet(base, "localhost", "/admin:")
	if err != nil || res.StatusCode != 200 || !strings.Contains(body, "data-signin") {
		t.Fatalf("/admin: no sirve el login: %v %v", res, err)
	}
	for _, p := range []string{"/admin", "/admin/"} {
		res, body, err := rawGet(base, "localhost", p)
		if err != nil {
			t.Fatalf("%s -> %v", p, err)
		}
		if strings.Contains(body, "data-signin") {
			t.Errorf("%s sirve el login", p)
		}
		t.Logf("%s -> %d", p, res.StatusCode)
	}
}

// #50: con turbo.dev parcial, lo que falta se sirve desde la copia embebida.
func TestW_TurboDevPartial(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"turbo.dev/admin", 0755)
	os.WriteFile(dir+"turbo.dev/admin/#.html", []byte("<html>dev</html>"), 0644)
	base := startServer(t)
	for _, p := range []string{"/admin:", "/admin:m.css", "/admin:i.png"} {
		res, body, err := rawGet(base, "localhost", p)
		if err != nil || res.StatusCode != 200 {
			t.Errorf("%s -> %v %v; se esperaba 200", p, res, err)
			continue
		}
		if strings.Contains(body, dir) || strings.Contains(body, strings.ReplaceAll(dir, "/", `\`)) {
			t.Errorf("%s revela la ruta del servidor", p)
		}
	}
}

// #52: dos logins dan tokens distintos; la sesión dura 600 s de inactividad.
func TestW_SessionLifetime(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	globalMutex.RLock()
	exp := signedInTokens["127.0.0.1"+tok]
	globalMutex.RUnlock()
	if d := exp - time.Now().Unix(); d < 595 || d > 600 {
		t.Errorf("expiración = ahora + %d s; se esperaban 600", d)
	}
	if tok2 := login(t, base); tok2 == tok {
		t.Error("dos logins desde la misma IP comparten token")
	}
}

// #49: los ajustes generales exigen la contraseña actual (b).
func TestW_SettingsWithoutPassword(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, p := range []string{"/admin:inside:setRT?a=7s", "/admin:inside:setRT?a=8s&b=incorrecta", "/admin:inside:setC?a=x"} {
		code, body, err := post(base, p, tok)
		if err != nil || code != 400 {
			t.Errorf("%s -> %d %q %v; se esperaba 400", p, code, body, err)
		}
	}
}

// #28, #72: el panel funciona con la cookie de sesión (HttpOnly, SameSite=Strict)
// sin token en la URL; sin cookie se ve el login; salir la borra; un CGI del
// mismo host no la recibe.
func TestW_SessionCookie(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	base := startServer(t)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("u", "Turbo")
	w.WriteField("p", "Admin")
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	setCookie := res.Header.Get("Set-Cookie")
	t.Logf("Set-Cookie: %s", setCookie)
	for _, attr := range []string{"turbo_session=", "Path=/", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(setCookie, attr) {
			t.Fatalf("falta %q en Set-Cookie", attr)
		}
	}
	cookie := strings.SplitN(setCookie, ";", 2)[0]

	panel := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Host = "localhost"
		if cookie != "" {
			req.Header.Set("Cookie", cookie+"; otra=1")
		}
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := panel("/admin:inside:"); code != 200 || strings.Contains(body, "<meta http-equiv") {
		t.Fatalf("panel con cookie: %d %.80q", code, body)
	}
	if code, body := panel("/admin:inside:"); code != 200 || strings.Contains(body, "<meta http-equiv") {
		t.Fatalf("recarga del panel con cookie: %d %.80q", code, body)
	}
	if _, body := panel("/x.cgi"); strings.Contains(body, "turbo_session") || !strings.Contains(body, "HTTP_COOKIE=otra=1\n") {
		t.Fatalf("el CGI debe recibir solo las demás cookies:\n%s", body)
	}
	saved := cookie
	cookie = ""
	if _, body := panel("/admin:inside:"); !strings.Contains(body, "<meta http-equiv") {
		t.Fatalf("panel sin cookie: se esperaba la redirección al login, %.80q", body)
	}
	cookie = saved
	req, _ = http.NewRequest("POST", base+"/admin:signout:", nil)
	req.Host = "localhost"
	req.Header.Set("Cookie", cookie)
	res, err = (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if sc := res.Header.Get("Set-Cookie"); !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("salir no borra la cookie: %q", sc)
	}
	if _, body := panel("/admin:inside:"); !strings.Contains(body, "<meta http-equiv") {
		t.Fatal("la sesión sigue válida tras salir")
	}
}

// #28: el token de sesión no debe aparecer en turbo.visits.
func TestP28_TokenInVisitsLog(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false) // la recarga periódica abre el log
	base := startServer(t)
	tok := login(t, base)
	get(base, "/admin:inside:", map[string]string{"Cookie": "turbo_session=" + tok}) // como el panel tras T1.6
	get(base, "/index.html", nil)
	serverSetLogState(visitsLogName, nil)
	b, _ := os.ReadFile(dir + "turbo.visits")
	if strings.Contains(string(b), tok) {
		t.Fatalf("el token aparece en turbo.visits:\n%s", b)
	}
}

// #29: "Guardar configuración" guarda el usuario y el hash de la contraseña,
// nunca la contraseña en texto plano.
func TestP29_CredentialsNotPersisted(t *testing.T) {
	dir := initForTest(t)
	defaultSettingValidators["."]["P"]("NuevaClave", "Admin")
	if ok, msg := defaultSettingValidators["."]["C"]("", "NuevaClave"); !ok {
		t.Fatalf("setC: %q", msg)
	}
	b, _ := os.ReadFile(dir + "turbo.config")
	s := string(b)
	if strings.Contains(s, "NuevaClave") {
		t.Error("contraseña en texto plano en turbo.config")
	}
	if !strings.Contains(s, `"PH"`) || !strings.Contains(s, `"U"`) {
		t.Errorf("faltan U o PH en turbo.config: %s", s)
	}
	// Reinicio: el estado vuelve a Turbo/Admin y se lee turbo.config.
	resetTestState(dir)
	updateSettings(false)
	if !passwordMatches("NuevaClave") || passwordMatches("Admin") {
		t.Errorf("tras reiniciar: NuevaClave=%v Admin=%v; se esperaba solo NuevaClave", passwordMatches("NuevaClave"), passwordMatches("Admin"))
	}
}

// TURBO_USER y TURBO_PASSWORD tienen prioridad sobre U y PH de turbo.config.
func TestC_CredentialsEnvPriority(t *testing.T) {
	dir := initForTest(t)
	defaultSettingValidators["."]["U"]("Otro", "Admin")
	defaultSettingValidators["."]["P"]("DelArchivo", "Admin")
	globalMutex.Lock()
	saveDefaultConfig()
	globalMutex.Unlock()
	resetTestState(dir)
	setPanelPassword("DelEntorno")
	userFromEnv, passwordFromEnv = true, true
	updateSettings(false)
	if panelUser.Get() != "Turbo" || !passwordMatches("DelEntorno") || passwordMatches("DelArchivo") {
		t.Errorf("U=%q DelEntorno=%v DelArchivo=%v; se esperaban las credenciales del entorno", panelUser.Get(), passwordMatches("DelEntorno"), passwordMatches("DelArchivo"))
	}
}

// #58: tras cambiar el directorio de sitios (M) y guardar, al reiniciar se
// sirve el nuevo directorio con su configuración.
func TestC_SitesDirPersisted(t *testing.T) {
	start := initForTest(t)
	other := filepath.ToSlash(t.TempDir()) + "/"
	os.MkdirAll(other+"otro.test/@", 0755)
	if ok, msg := defaultSettingValidators["."]["M"](other, "Admin"); !ok {
		t.Fatalf("setM: %q", msg)
	}
	resetSettings()
	updateSettings(true)
	if ok, msg := defaultSettingValidators["."]["C"]("", "Admin"); !ok {
		t.Fatalf("setC: %q", msg)
	}
	resetTestState(start) // reinicio en el directorio de trabajo
	updateSettings(false)
	if sitesDir.Get() != other {
		t.Fatalf("directorio tras reiniciar: %q; se esperaba %q", sitesDir.Get(), other)
	}
	if _, ok := sitesMap["otro.test"]; !ok {
		t.Error("el sitio del nuevo directorio no se cargó")
	}
}

// Una clave raíz que no es un nombre de host ("^", la de la versión de
// esquema de §5.1) no se confunde con un sitio.
func TestC_UnknownRootKey(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"^":{"v":"2"},"version":"x","localhost":{"":{"-":{"index.html":""}}}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileModTime = 0
	updateSettings(false)
	if _, ok := sitesMap["^"]; ok {
		t.Fatal("la clave '^' se trata como un sitio")
	}
	if _, ok := sitesMap["localhost"]; !ok {
		t.Fatal("localhost no se cargó")
	}
}

// #29: U y P en texto plano en turbo.config se migran a U y PH al guardar.
func TestC_CredentialsFromConfig(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{"-":{"index.html":""}}},".":{"U":"Operador","P":"Secreta1","CIL":"1000"}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileModTime = 0
	updateSettings(false)
	if panelUser.Get() != "Operador" {
		t.Errorf("U=%q", panelUser.Get())
	}
	saveDefaultConfig()
	b, _ := os.ReadFile(dir + "turbo.config")
	s := string(b)
	if strings.Contains(s, "Secreta1") || !strings.Contains(s, `"PH"`) || !strings.Contains(s, `"^"`) {
		t.Errorf("turbo.config tras guardar: %s", s)
	}
	if !passwordMatches("Secreta1") || passwordMatches("Admin") {
		t.Error("la contraseña de P no se aplica")
	}
}

// #30, #38: hardUpload vacía todo @, incluidas las subcarpetas, y lista los
// nombres descartados.
func TestP_HardUpload(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/old", 0755)
	os.WriteFile(dir+"localhost/@/old/keep.txt", []byte("x"), 0644)
	base := startServer(t)
	tok := login(t, base)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("s", "localhost")
	w.WriteField("d", "")
	names := []string{"assets/img/logo.png", "../../evil1.txt", "a/../../evil2.txt", `..\..\evil3.txt`, "/abs/evil4.txt", "x/y/../z.txt"}
	for _, n := range names {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f"; filename="%s"`, n))
		p, _ := w.CreatePart(h)
		p.Write([]byte("contenido " + n))
	}
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload?s=localhost&d=", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	t.Logf("respuesta: %d %q", res.StatusCode, b)
	if fileExists(dir + "localhost/@/old/keep.txt") {
		t.Error("queda old/keep.txt")
	}
	if !strings.Contains(string(b), "evil1.txt") {
		t.Error("la respuesta no lista los archivos descartados")
	}
	for _, f := range []string{"evil1.txt", "evil2.txt", "evil3.txt"} {
		if fileExists(dir+f) || fileExists(dir+"localhost/"+f) {
			t.Errorf("%s escrito fuera de @", f)
		}
	}
}

// DP13: si no se puede vaciar @, hardUpload no escribe nada y lo dice, en vez
// de mezclar archivos nuevos con los que no se pudieron borrar.
func TestP_HardUploadUndeletable(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("root puede borrar en una carpeta sin permiso de escritura")
	}
	dir := initForTest(t)
	locked := dir + "localhost/@/bloqueado"
	os.MkdirAll(locked, 0755)
	os.WriteFile(locked+"/viejo.txt", []byte("x"), 0644)
	if runtime.GOOS == "windows" {
		f, err := os.Open(locked + "/viejo.txt") // Windows no borra un archivo abierto
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
	} else {
		os.Chmod(locked, 0500) // sin escritura: no se pueden borrar sus entradas
		defer os.Chmod(locked, 0755)
	}
	base := startServer(t)
	tok := login(t, base)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	p, _ := w.CreateFormFile("f", "carpeta/nuevo.txt")
	p.Write([]byte("nuevo"))
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload?s=localhost&d=", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 || !strings.Contains(string(b), "bloqueado") || fileExists(dir+"localhost/@/nuevo.txt") {
		t.Fatalf("respuesta %d %q, nuevo.txt escrito=%v; se esperaba 400 que nombre bloqueado y nada escrito",
			res.StatusCode, b, fileExists(dir+"localhost/@/nuevo.txt"))
	}
}

// #70: un valor con "+" codificado llega intacto (el panel ya no convierte "+"
// en espacio).
func TestW_AddMIMEPlus(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	code, body, err := post(base, "/admin:inside:addMIME?s=localhost&d=&a=svg&b=image%2Fsvg%2Bxml", tok)
	if err != nil || code != 200 {
		t.Fatalf("addMIME: %d %q %v", code, body, err)
	}
	globalMutex.RLock()
	got := mimeTypes["localhost"]["svg"]
	globalMutex.RUnlock()
	if got != "image/svg+xml" {
		t.Fatalf("MIME guardado %q; se esperaba image/svg+xml", got)
	}
}

// #38: s y d se aceptan también en el cuerpo multipart, sin la URL.
func TestP_HardUploadBodyParams(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("s", "localhost")
	w.WriteField("d", "")
	p, _ := w.CreateFormFile("f", "carpeta/nuevo.txt")
	p.Write([]byte("nuevo"))
	w.Close()
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload", &buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !fileExists(dir+"localhost/@/nuevo.txt") || fileExists(dir+"localhost/@/index.html") {
		t.Fatalf("respuesta %d %q; se esperaba @ con solo nuevo.txt", res.StatusCode, b)
	}
}

// #68: el panel no se puede incrustar en un iframe ni se guarda en caché, en
// el login, en el panel y en las respuestas de la API.
func TestW_PanelHeaders(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	check := func(name string, h http.Header) {
		t.Helper()
		if h.Get("X-Frame-Options") != "DENY" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: X-Frame-Options=%q CSP=%q Cache-Control=%q", name, h.Get("X-Frame-Options"), h.Get("Content-Security-Policy"), h.Get("Cache-Control"))
		}
	}
	res, _, err := rawGet(base, "localhost", "/admin:")
	if err != nil {
		t.Fatal(err)
	}
	check("login", res.Header)
	for _, p := range []string{"/admin:inside:", "/admin:inside:sites"} {
		req, _ := http.NewRequest("POST", base+p, nil)
		req.Host = "localhost"
		req.Header.Set("ok", tok)
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		check(p, res.Header)
	}
}

// DP7: con PA, /admin: responde solo en los hosts o redes de la lista (404
// fuera); vacío o "*" no restringe; PA se valida y se guarda.
func TestW_PanelAccessHosts(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	adminCode := func(host string) int {
		res, _, err := rawGet(base, host, "/admin:")
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	if c := adminCode("otro.test"); c != 200 {
		t.Fatalf("sin PA, /admin: en otro.test -> %d; se esperaba 200", c)
	}
	for _, bad := range []string{"10.0.0.0/33", "no válido", "a..b"} {
		if ok, _ := defaultSettingValidators["."]["PA"](bad, "Admin"); ok {
			t.Errorf("PA %q aceptado", bad)
		}
	}
	if ok, msg := defaultSettingValidators["."]["PA"]("admin.test, 192.0.2.0/24", "Admin"); !ok {
		t.Fatalf("PA: %q", msg)
	}
	if c := adminCode("admin.test"); c != 200 {
		t.Errorf("/admin: en admin.test -> %d; se esperaba 200", c)
	}
	if c := adminCode("otro.test"); c != 404 {
		t.Errorf("/admin: en otro.test -> %d; se esperaba 404", c)
	}
	if code, _, _ := get(base, "/", nil); code != 200 {
		t.Errorf("el sitio dejó de responder: %d", code)
	}
	if ok, msg := defaultSettingValidators["."]["PA"]("127.0.0.0/8", "Admin"); !ok { // por la IP del cliente
		t.Fatalf("PA: %q", msg)
	}
	if c := adminCode("otro.test"); c != 200 {
		t.Errorf("/admin: desde 127.0.0.1 con PA=127.0.0.0/8 -> %d; se esperaba 200", c)
	}
	globalMutex.Lock()
	saveDefaultConfig()
	globalMutex.Unlock()
	if raw := savedConfig(t, dir); raw["."]["PA"] != "127.0.0.0/8" {
		t.Errorf("PA guardado = %v", raw["."]["PA"])
	}
	resetTestState(dir) // reinicio: PA se lee de turbo.config
	updateSettings(false)
	if s := panelAccess.Load().setting; s != "127.0.0.0/8" {
		t.Errorf("PA tras reiniciar = %q", s)
	}
	if ok, msg := defaultSettingValidators["."]["PA"]("*", "Admin"); !ok {
		t.Fatalf("PA *: %q", msg)
	}
	if c := adminCode("otro.test"); c != 200 {
		t.Errorf("con PA=* -> %d; se esperaba 200", c)
	}
}

// #72 (revisión de T1.6): al quitar turbo_session, el resto de la cabecera
// Cookie llega al CGI sin cambios (comillas, espacios, comas, no ASCII, sin
// valor).
func TestW_CGICookiesUnchanged(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	base := startServer(t)
	for header, want := range map[string]string{
		`a=b c; turbo_session=secreto; x="y"; d=1,2; nombre=café; sinvalor`: `a=b c; x="y"; d=1,2; nombre=café; sinvalor`,
		`turbo_session=secreto; a=1`:                                        `a=1`,
		`a=b c; x="y"`:                                                      `a=b c; x="y"`,
	} {
		_, body, err := get(base, "/x.cgi", map[string]string{"Cookie": header})
		if err != nil || !strings.Contains(body, "HTTP_COOKIE="+want+"\n") {
			t.Errorf("Cookie %q -> err=%v; se esperaba HTTP_COOKIE=%s\n%s", header, err, want, body)
		}
	}
}

// #72 (revisión de T1.6): una acción del panel autenticada con la cookie solo
// se acepta desde el mismo origen (CSRF desde otro subdominio del mismo
// sitio); con la cabecera ok no hace falta.
func TestW_PanelCSRF(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	n := 0
	action := func(hdr map[string]string) int {
		n++ // una cabecera distinta en cada petición
		req, _ := http.NewRequest("POST", base+"/admin:inside:addHeader?s=localhost&d=&a=X-Csrf-"+strconv.Itoa(n)+"&b=1", nil)
		req.Host = "localhost"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	cookie := "turbo_session=" + tok
	for name, hdr := range map[string]map[string]string{
		"Origin de otro subdominio": {"Cookie": cookie, "Origin": "http://evil.localhost"},
		"Sec-Fetch-Site same-site":  {"Cookie": cookie, "Sec-Fetch-Site": "same-site", "Origin": "http://localhost"},
		"sin Origin":                {"Cookie": cookie},
	} {
		if code := action(hdr); code != 403 {
			t.Errorf("%s -> %d; se esperaba 403", name, code)
		}
	}
	for name, hdr := range map[string]map[string]string{
		"Origin propio":              {"Cookie": cookie, "Origin": "http://localhost"},
		"Sec-Fetch-Site same-origin": {"Cookie": cookie, "Sec-Fetch-Site": "same-origin"},
		"cabecera ok":                {"ok": tok},
	} {
		if code := action(hdr); code != 200 {
			t.Errorf("%s -> %d; se esperaba 200", name, code)
		}
	}
}

// Revisión de T1.7: los PBKDF2 de contraseñas incorrectas no ocupan más que
// los huecos de passwordHashSlots; con todos ocupados, la comprobación espera.
func TestW_PasswordHashSlots(t *testing.T) {
	initForTest(t)
	for i := 0; i < cap(passwordHashSlots); i++ {
		passwordHashSlots <- struct{}{}
	}
	done := make(chan bool)
	go func() { done <- passwordMatches("incorrecta") }()
	select {
	case <-done:
		t.Fatal("se calculó un PBKDF2 con todos los huecos ocupados")
	case <-time.After(300 * time.Millisecond):
	}
	for i := 0; i < cap(passwordHashSlots); i++ {
		<-passwordHashSlots
	}
	if <-done {
		t.Fatal("contraseña incorrecta aceptada")
	}
	if !passwordMatches("Admin") {
		t.Fatal("la contraseña correcta no se acepta")
	}
}

// T2.6 (#21): la GUI embebida es la de turbo.dev/ (una sola copia), se sirve
// archivo por archivo y no se sale de la carpeta de cada panel.
func TestT26_EmbeddedGUI(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	for _, c := range []struct{ path, archivo, tipo string }{
		{"/admin:", "turbo.dev/admin/#.html", "text/html"},
		{"/admin:m.css", "turbo.dev/admin/m.css", "text/css"},
		{"/admin:i.png", "turbo.dev/admin/i.png", "image/png"},
		{"/admin:r.ttf", "turbo.dev/admin/r.ttf", "font/ttf"},
		{"/admin:b.ttf", "turbo.dev/admin/b.ttf", "font/ttf"},
	} {
		res, body, err := rawGet(base, "localhost", c.path)
		if err != nil || res.StatusCode != 200 {
			t.Errorf("%s -> %v %v; se esperaba 200", c.path, res, err)
			continue
		}
		disco, err := os.ReadFile(c.archivo)
		if err != nil {
			t.Fatal(err)
		}
		if body != string(disco) {
			t.Errorf("%s no es %s", c.path, c.archivo)
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, c.tipo) {
			t.Errorf("%s: Content-Type %q; se esperaba %s", c.path, ct, c.tipo)
		}
	}
	for _, p := range []string{"/admin:../inside/%23.html", "/admin:inside/%23.html", "/admin:nada.css"} {
		if res, _, err := rawGet(base, "localhost", p); err != nil || res.StatusCode != 404 {
			t.Errorf("%s -> %v %v; se esperaba 404", p, res, err)
		}
	}
}

// La GUI envía los parámetros de la API en el cuerpo de la POST, así que la
// contraseña actual (b) de los set* no llega a turbo.visits; el servidor los
// acepta en el cuerpo igual que en la URL.
func TestW_SettingsInBodyNotLogged(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false)
	anterior := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = anterior }) }) })
	base := startServer(t)
	tok := login(t, base)
	req, _ := http.NewRequest("POST", base+"/admin:inside:setRT", strings.NewReader("a=7s&b=Admin"))
	req.Host = "localhost"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cuerpo, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || serverTimeLimits.Load().RT != 7*time.Second {
		t.Fatalf("setRT en el cuerpo: %d %q, RT = %v", res.StatusCode, cuerpo, serverTimeLimits.Load().RT)
	}
	serverSetLogState(visitsLogName, nil)
	b, _ := os.ReadFile(dir + "turbo.visits")
	if !strings.Contains(string(b), "setRT") || strings.Contains(string(b), "Admin") {
		t.Fatalf("turbo.visits:\n%s", b)
	}
}

// addDenied rechaza la IP desde la que se usa el panel: el administrador se
// dejaría fuera a sí mismo.
func TestW_DenyCurrentIP(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	futuro := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	code, body, err := post(base, "/admin:inside:addDenied?s=127.0.0.1&d="+futuro, tok)
	if err != nil || code != 400 || body != "IP actual" {
		t.Fatalf("addDenied de la propia IP: %d %q %v; se esperaba 400 \"IP actual\"", code, body, err)
	}
	if code, body, _ := post(base, "/admin:inside:addDenied?s=203.0.113.5&d="+futuro, tok); code != 200 {
		t.Fatalf("addDenied de otra IP: %d %q", code, body)
	}
	for _, c := range []struct {
		ip, remote string
		es         bool
	}{
		{"203.0.113.5", "203.0.113.5:4000", true},
		{" 203.0.113.5 ", "203.0.113.5:4000", true},
		{"203.0.113.6", "203.0.113.5:4000", false},
		{"2001:db8:0::1", "[2001:db8::1]:443", true},
		{"no-ip", "203.0.113.5:4000", false},
	} {
		if got := isClientIP(c.ip, &customNetHttp.Request{RemoteAddr: c.remote}); got != c.es {
			t.Errorf("isClientIP(%q, %q) = %v", c.ip, c.remote, got)
		}
	}
}

// Los del* de contenido de un subdominio sin todos sus parámetros responden 400,
// como el resto de la API, en lugar de 200 vacío.
func TestW_DeleteWithoutParams(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, accion := range []string{"Index", "Alias", "Preprocessor", "Header", "MIME", "Rewrite"} {
		for _, consulta := range []string{"", "?s=localhost&d=", "?s=localhost&a=x", "?d=&a=x"} {
			code, body, err := post(base, "/admin:inside:del"+accion+consulta, tok)
			if err != nil || code != 400 || body != msgMissingData {
				t.Errorf("del%s%s: %d %q %v; se esperaba 400 %q", accion, consulta, code, body, err, msgMissingData)
			}
		}
	}
}

// setU y setP rechazan un valor igual al actual, como el resto de los ajustes.
func TestW_CredentialsUnchanged(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, c := range []struct{ ruta, esperado string }{
		{"/admin:inside:setU?a=Turbo&b=Admin", "Usuario sin cambios"},
		{"/admin:inside:setP?a=Admin&b=Admin", "Contraseña sin cambios"},
	} {
		if code, body, err := post(base, c.ruta, tok); err != nil || code != 400 || body != c.esperado {
			t.Errorf("%s: %d %q %v; se esperaba 400 %q", c.ruta, code, body, err, c.esperado)
		}
	}
	if code, body, _ := post(base, "/admin:inside:setU?a=Turbo2&b=Admin", tok); code != 200 {
		t.Errorf("setU con otro usuario: %d %q", code, body)
	}
}

// El 404 de /admin: fuera de PA lleva las mismas cabeceras de seguridad que el
// resto de las respuestas del panel.
func TestW_PanelAccessDeniedHeaders(t *testing.T) {
	initForTest(t)
	if ok, msg := defaultSettingValidators["."]["PA"]("admin.test", "Admin"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	res, _, err := rawGet(base, "localhost", "/admin:")
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("/admin: fuera de PA -> %v %v; se esperaba 404", res, err)
	}
	for k, v := range map[string]string{"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'", "Cache-Control": "no-store"} {
		if got := res.Header.Get(k); got != v {
			t.Errorf("%s = %q; se esperaba %q", k, got, v)
		}
	}
}
