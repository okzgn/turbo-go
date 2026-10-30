package main

// Arnés de pruebas: reproduce la inicialización de main() en un directorio
// temporal y arranca servidores en 127.0.0.1:0. Las pruebas que dependen de un
// arreglo pendiente empiezan con t.Skip("pendiente de T…").

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// TestMain compila las herramientas auxiliares (CGI de eco y Certbot simulado)
// en TOOLS_BIN, o en una carpeta temporal si no está definida. En Windows debe
// ser una ruta corta: Turbo rechaza rutas de preprocesador de más de 128
// caracteres.
func TestMain(m *testing.M) {
	toolsDir := os.Getenv("TOOLS_BIN")
	cleanup := false
	if toolsDir == "" {
		d, err := os.MkdirTemp("", "tt")
		if err != nil {
			fmt.Fprintln(os.Stderr, "TOOLS_BIN:", err)
			os.Exit(1)
		}
		toolsDir = d
		cleanup = true
	}
	toolsDir, _ = filepath.Abs(toolsDir)
	os.Setenv("TOOLS_BIN", toolsDir)
	for _, tool := range []string{"cgiecho", "certbot"} {
		out := filepath.Join(toolsDir, tool)
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, "./internal/testtools/"+map[string]string{"cgiecho": "cgiecho", "certbot": "fakecertbot"}[tool])
		if b, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "no se pudo compilar %s: %v\n%s", tool, err, b)
			os.Exit(1)
		}
	}
	code := m.Run()
	if cleanup {
		os.RemoveAll(toolsDir)
	}
	os.Exit(code)
}

// resetTestState deja el estado global como lo deja main() antes de leer la
// configuración, con el directorio de sitios en dir.
func resetTestState(dir string) {
	// Una emisión de certificado de la prueba anterior escribiría en los mapas
	// recién creados.
	waitIdle()

	serverSetLogState(visitsLogName, nil)
	serverSetLogState(denialsLogName, nil)

	panelUser.Set("Turbo")
	setPanelPassword("Admin")
	userFromEnv, passwordFromEnv = false, false
	sitesDir.Set(dir)
	startDir = dir

	resetSettings()

	globalMutex.Lock()
	httpResponses.Store(&map[int]string{0: serverName + `\n{TURBO_RESPONSE_CODE}`})
	fixedHTTPResponses = map[int]bool{0: true}
	for k := range charReplacements {
		delete(charReplacements, k)
	}
	charReplacements[";"] = "-.-"
	charReplacements["#"] = "-,-"
	charReplacements["&"] = "-_-"
	fixedCharReplacements = map[string]bool{";": true, "#": true, "&": true}
	charEscapeLists['J'] = []string{
		"\\", "\"", "\t", "\r", "\n", "\f", "\b",
		`\\`, `\\"`, `\\t`, `\\r`, `\\n`, `\\f`, `\\b`,
	}
	for k := range signedInTokens {
		delete(signedInTokens, k)
	}
	for k := range persistentIPs {
		delete(persistentIPs, k)
	}
	deniedIPs.Store(&map[string]int64{})
	configFileModTime = 0
	globalMutex.Unlock()

	ipReferences.Clear()
	lastRequestTimeNano = time.Now().UnixNano()
	requestCountInWindow = 0
}

// initForTest crea un directorio de sitios temporal con el sitio localhost
// (index.html = "hola") y carga la configuración por defecto.
func initForTest(t testing.TB) string {
	dir := filepath.ToSlash(t.TempDir()) + "/"
	resetTestState(dir)
	// Se registra después de TempDir, así que se ejecuta antes de borrarlo:
	// Windows no deja borrar un log abierto.
	t.Cleanup(func() {
		serverSetLogState(visitsLogName, nil)
		serverSetLogState(denialsLogName, nil)
	})
	os.MkdirAll(dir+"localhost/@", 0755)
	os.WriteFile(dir+"localhost/@/index.html", []byte("hola"), 0644)
	updateSettings(false)
	globalMutex.Lock()
	addIndex("localhost", "index.html") // ya lo añade constructSite; se deja explícito
	globalMutex.Unlock()
	return dir
}

// syncBuffer recoge el ErrorLog del servidor (avisos como "superfluous
// response.WriteHeader").
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startServer(t testing.TB) string {
	base, _ := startServerLog(t)
	return base
}

// startServerLog arranca un servidor HTTP como el de main() y devuelve su URL
// base y el ErrorLog del servidor.
func startServerLog(t testing.TB) (string, *syncBuffer) {
	errLog := &syncBuffer{}
	srv := &customNetHttp.Server{
		ReadHeaderTimeout: serverTimeLimits.Load().RHT,
		ReadTimeout:       serverTimeLimits.Load().RT,
		WriteTimeout:      serverTimeLimits.Load().WT,
		IdleTimeout:       serverTimeLimits.Load().IT,
		ConnState:         connHandler,
		Handler:           customNetHttp.HandlerFunc(serverHandlerFn("")),
		ErrorLog:          log.New(errLog, "", 0),
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return "http://" + l.Addr().String(), errLog
}

// clientTimeout is how long a test request waits for its response. With the race
// detector, password checks (PBKDF2, 600 000 iterations) are about ten times
// slower, so a loaded machine needs more margin.
func clientTimeout() time.Duration {
	if raceEnabled {
		return 15 * time.Second
	}
	return 3 * time.Second
}

func get(base, path string, hdr map[string]string) (int, string, error) {
	req, _ := http.NewRequest("GET", base+path, nil)
	req.Host = "localhost"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c := &http.Client{Timeout: clientTimeout()}
	res, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), nil
}

func post(base, path, token string) (int, string, error) {
	req, _ := http.NewRequest("POST", base+path, nil)
	req.Host = "localhost"
	if token != "" {
		req.Header.Set("ok", token)
	}
	c := &http.Client{Timeout: clientTimeout()}
	res, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), nil
}

func login(t testing.TB, base string) string {
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
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	s := string(b)
	if !strings.HasPrefix(s, "ok") {
		t.Fatalf("login falló: %d %q", res.StatusCode, s)
	}
	return strings.TrimPrefix(s, "ok")
}

// toolPath devuelve la ruta de una herramienta compilada por TestMain.
func toolPath(name string) string {
	p := filepath.Join(os.Getenv("TOOLS_BIN"), name)
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	return filepath.ToSlash(p)
}

func rawGet(base, host, path string) (*http.Response, string, error) {
	req, _ := http.NewRequest("GET", base+path, nil)
	req.Host = host
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b), nil
}

// useFakeCertbot pone el Certbot simulado en el PATH y devuelve el archivo
// donde registra cada invocación. mode "ok" emite un certificado autofirmado.
func useFakeCertbot(t *testing.T, mode string) string {
	logf := filepath.ToSlash(filepath.Join(t.TempDir(), "certbot.log"))
	t.Setenv("PATH", os.Getenv("TOOLS_BIN")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_CERTBOT_LOG", logf)
	t.Setenv("FAKE_CERTBOT_MODE", mode)
	certRetryDelay = 100 * time.Millisecond
	return logf
}

// waitIdle espera a que no haya ninguna emisión de certificado en curso.
func waitIdle() {
	busy := func() bool {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		return currentCertDomain != ""
	}
	for i := 0; i < 100 && busy(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
}
