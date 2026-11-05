package main

// Test harness: reproduces the initialization of main() in a temporary
// directory and starts servers on 127.0.0.1:0.

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

// TestMain builds the helper tools (the echo CGI and the fake Certbot) in
// TOOLS_BIN, or in a temporary folder if it isn't set. On Windows it must be
// a short path: Turbo rejects preprocessor paths longer than 128 characters.
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
			fmt.Fprintf(os.Stderr, "could not build %s: %v\n%s", tool, err, b)
			os.Exit(1)
		}
	}
	code := m.Run()
	if cleanup {
		os.RemoveAll(toolsDir)
	}
	os.Exit(code)
}

// resetTestState leaves the global state as main() leaves it before reading
// the configuration, with the sites directory in dir.
func resetTestState(dir string) {
	// A certificate issuance from the previous test would write into the maps
	// just created.
	waitIdle()

	serverSetLogState(visitsLogName, nil)
	serverSetLogState(denialsLogName, nil)
	errorLines.reopen() // Grouped again, as at the start, also after a test that ran the shutdown

	panelUser.Set("Turbo")
	setPanelPassword("Admin")
	userFromEnv, passwordFromEnv = false, false
	sitesDir.Set(dir)
	sitesDirValue.Set(dir)
	startDir = dir
	settingsUpdateMutex.Lock()
	sitesDirHops = 0 // The start directory, as at the start
	settingsUpdateMutex.Unlock()

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
	for k := range signedInTokens {
		delete(signedInTokens, k)
	}
	clear(sessionDeadlines)
	publishDeniedIPs(map[string]int64{}) // With its /64s, which a test's denial of an IPv6 would leave behind
	configFileStamp = configStamp{}
	globalMutex.Unlock()

	ipReferences.Clear()
	for level := range ipReferenceCounts {
		ipReferenceCounts[level].Store(0)
	}
	// One test's failed logins, trusted clients (V15) and wrong current passwords of a session (V14) must not
	// carry over to the next one.
	loginFailuresMutex.Lock()
	clear(loginFailuresByIP)
	clear(loginTrusted)
	clear(sessionPasswordChecks)
	loginFailuresMutex.Unlock()
	globalRequestLimit.Store(0)
	globalRequestWindow.Store(0)
}

// initForTest creates a temporary sites directory with the site localhost
// (index.html = "hello") and loads the default configuration.
func initForTest(t testing.TB) string {
	t.Helper()
	dir := filepath.ToSlash(t.TempDir()) + "/"
	resetTestState(dir)
	// Registered after TempDir, so it runs before the directory is deleted:
	// Windows doesn't let an open log be deleted.
	t.Cleanup(func() {
		serverSetLogState(visitsLogName, nil)
		serverSetLogState(denialsLogName, nil)
	})
	os.MkdirAll(dir+"localhost/@", 0755)
	os.WriteFile(dir+"localhost/@/index.html", []byte("hello"), 0644)
	updateSettings(false)
	globalMutex.Lock()
	addIndex("localhost", "index.html") // Activating the site found on disk already adds it; it is kept explicit
	globalMutex.Unlock()
	return dir
}

// syncBuffer collects the server's ErrorLog (warnings such as "superfluous
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

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func startServer(t testing.TB) string {
	t.Helper()
	base, _ := startServerLog(t)
	return base
}

// startServerLog starts an HTTP server like the one of main() and returns its
// base URL and the server's ErrorLog.
func startServerLog(t testing.TB) (string, *syncBuffer) {
	t.Helper()
	return startServerAs(t, nil)
}

// startServerAs is startServerLog for a server that sees each connection as
// coming from the address that remote gives it (with the connection's own
// port), or from where it comes if remote is nil. It shares everything else
// with the other servers of the test: the CGI slots, the limits per client…
func startServerAs(t testing.TB, remote func() net.IP) (string, *syncBuffer) {
	t.Helper()
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
	address := l.Addr().String()
	if remote != nil {
		l = remoteAsListener{l, remote}
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return "http://" + address, errLog
}

// remoteAsListener presents each connection it accepts as coming from the
// address that remote gives. The server takes a client's address from its
// connection, before reading anything (the RemoteAddr of the request, and
// connHandler), so a test can be another client, or many, without the
// loopback addresses of the system: macOS has only 127.0.0.1.
type remoteAsListener struct {
	net.Listener
	remote func() net.IP
}

func (l remoteAsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	port := 0
	if address, isTCP := conn.RemoteAddr().(*net.TCPAddr); isTCP {
		port = address.Port
	}
	return remoteAsConn{conn, &net.TCPAddr{IP: l.remote(), Port: port}}, nil
}

// remoteAsConn is a connection seen as coming from remote.
type remoteAsConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAsConn) RemoteAddr() net.Addr { return c.remote }

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

// postSession is post for the actions that renew the session (setU, setP, and setM with other credentials): it
// returns the token to go on with, the new one if the answer carries it in the "ok" header. A request whose session
// has ended gets 401 instead of the 200 of the login page.
func postSession(base, path, token string) (int, string, string, error) {
	req, _ := http.NewRequest("POST", base+path, nil)
	req.Host = "localhost"
	if token != "" {
		req.Header.Set("ok", token)
	}
	c := &http.Client{Timeout: clientTimeout()}
	res, err := c.Do(req)
	if err != nil {
		return 0, "", token, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.Header.Get("X-Turbo-Login") == "required" {
		return 401, string(b), token, nil
	}
	if renewed := res.Header.Get(sessionHeaderName); renewed != "" {
		token = renewed
	}
	return res.StatusCode, string(b), token, nil
}

func login(t testing.TB, base string) string {
	t.Helper()
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
		t.Fatalf("login failed: %d %q", res.StatusCode, s)
	}
	return strings.TrimPrefix(s, "ok")
}

// toolPath returns the path of a tool built by TestMain.
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

// useFakeCertbot puts the fake Certbot in the PATH and returns the file where
// it logs each invocation. Mode "ok" issues a self-signed certificate.
func useFakeCertbot(t *testing.T, mode string) string {
	t.Helper()
	logf := filepath.ToSlash(filepath.Join(t.TempDir(), "certbot.log"))
	t.Setenv("PATH", os.Getenv("TOOLS_BIN")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_CERTBOT_LOG", logf)
	t.Setenv("FAKE_CERTBOT_MODE", mode)
	certRetryDelay = 100 * time.Millisecond
	return logf
}

// waitIdle waits until no certificate issuance is in progress and no retry is
// pending, and gives whatever that issuance left running 300 ms more; with
// nothing in progress, the usual case, it doesn't wait.
func waitIdle() {
	busy := func() bool {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		return currentCertDomain != "" || len(certPending) > 0
	}
	waited := false
	for i := 0; i < 100 && busy(); i++ {
		waited = true
		time.Sleep(100 * time.Millisecond)
	}
	if waited {
		time.Sleep(300 * time.Millisecond)
	}
}

// fileExists says whether path exists and is a file (not a folder).
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
