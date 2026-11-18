package server

// Review of 6046dbe (R6): a client that leaves a CGI, the code of a URI that is too long, the request bodies kept in
// temporary files, the kinds of the error lines, and a second signal while stopping.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// R6 N-04 (P14): a client that goes away before its CGI answers is no error of the CGI. It was written a 500 that
// no one read, and a line of the CGIs' errors ("no headers", or "context canceled" when it left before the CGI
// started) that blamed the script. A client that only closes its side of the connection after its request (some
// monitoring probes) is taken, as Go's server takes it, for one that left.
func TestR6_N04_ClientGoneBeforeTheCGIAnswers(t *testing.T) {
	cgiSite(t)
	base := startServer(t)
	logs := &syncBuffer{}
	previous := cgiErrorLog.Writer()
	cgiErrorLog.SetOutput(logs)
	t.Cleanup(func() { cgiErrorLog.SetOutput(previous) })
	address := strings.TrimPrefix(base, "http://")
	request := "GET /x.cgi?sleep=600 HTTP/1.1\r\nHost: localhost\r\n\r\n"

	gone, err := net.Dial("tcp", address) // Leaves while the CGI runs
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(gone, request)
	time.Sleep(200 * time.Millisecond)
	gone.Close()

	half, err := net.Dial("tcp", address) // Closes its side at once, and waits for the answer
	if err != nil {
		t.Fatal(err)
	}
	defer half.Close()
	io.WriteString(half, request)
	half.(*net.TCPConn).CloseWrite()
	half.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer, _ := io.ReadAll(half)
	if strings.Contains(string(answer), " 500 ") {
		t.Errorf("the client that closed its side got a 500: %q", answer)
	}
	if !eventually(3*time.Second, func() bool { return cgiSlotsRunning() == 0 }) {
		t.Error("the CGIs of the clients that left are still running")
	}
	time.Sleep(200 * time.Millisecond)
	if text := logs.String(); strings.Contains(text, "CGI error") || strings.Contains(text, "no headers") {
		t.Errorf("a client that left was logged as an error of the CGI:\n%s", text)
	}
	// A client that stays gets its answer, and a CGI that answers nothing is still an error
	if code, body, err := get(base, "/x.cgi?sleep=100", nil); err != nil || code != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
		t.Errorf("a client that stays: %d %v", code, err)
	}
	if code, _, _ := get(base, "/x.cgi?raw=1", nil); code != 500 || !strings.Contains(logs.String(), "CGI error") {
		t.Errorf("a CGI without headers: %d, log %q; expected 500 and its line", code, logs.String())
	}
}

// R6 N-09 (P14): a URI over MUB is answered 414 whatever the rest of the request takes. When the whole request also
// went over MHB, the answer was 431.
func TestR6_N09_URITooLongIs414(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	uri := "/" + strings.Repeat("a", 4500) // MUB = 1000, MHB = 5000
	for name, request := range map[string]string{
		"a request under MHB": "GET " + uri + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
		"a request over MHB":  "GET " + uri + " HTTP/1.1\r\nHost: localhost\r\nX-Pad: " + strings.Repeat("b", 1000) + "\r\nConnection: close\r\n\r\n",
	} {
		if res, _ := rawFullRequest(t, base, request); res.StatusCode != 414 {
			t.Errorf("a URI of 4500 bytes in %s: %d; expected 414", name, res.StatusCode)
		}
	}
	// Headers over MHB, with a URI that fits, are still 431
	if res, _ := rawFullRequest(t, base, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Pad: "+strings.Repeat("b", 6000)+"\r\nConnection: close\r\n\r\n"); res.StatusCode != 431 {
		t.Errorf("headers of 6000 bytes: %d; expected 431", res.StatusCode)
	}
}

// R6 N-09 (P4): a header block whose lines end in LF and whose blank line ends in CRLF is one that ends, also when
// more than MHB is waiting behind it. It was answered 431.
func TestR6_N09_HeaderBlockWithMixedLineEndings(t *testing.T) {
	initForTest(t)
	if ok, msg := setting("MHB", "600"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// The first request, and behind it, in the same write, another one that is longer than MHB
	io.WriteString(conn, "GET / HTTP/1.1\nHost: localhost\n\r\n"+"GET /second HTTP/1.1\r\nHost: localhost\r\nX-Pad: "+strings.Repeat("b", 900)+"\r\n\r\n")
	data, _ := io.ReadAll(conn)
	if text := string(data); !strings.HasPrefix(text, "HTTP/1.1 200 ") || !strings.Contains(text, "hello") {
		t.Errorf("the first request, with LF lines and a CRLF blank line: %.80q; expected 200", text)
	}
}

// R6 M-04: the request bodies of the CGIs kept in temporary files have a budget, all of them: beyond it a request
// gets 503, as without a free slot, and what a body took comes back when its file is closed.
func TestR6_M04_BodyFilesBudget(t *testing.T) {
	cgiSite(t)
	withBodyBudget(t, 0) // Every body goes to a file
	previousMin, previousMBB := cgiBodyFileBudgetMin, maxBodySize.Load()
	t.Cleanup(func() { cgiBodyFileBudgetMin = previousMin; maxBodySize.Store(previousMBB) })
	cgiBodyFileBudgetMin = 0
	maxBodySize.Store(64 << 10) // 16 bodies of MBB: a budget of 1 MiB
	if cgiBodyFileBudget() != 1<<20 {
		t.Fatalf("budget: %d; expected 1 MiB", cgiBodyFileBudget())
	}
	body := bytes.Repeat([]byte("b"), 300<<10)
	var cleanups []func()
	for i := 0; i < 3; i++ {
		reader, size, cleanup, err := bufferedRequestBody(bytes.NewReader(body), int64(len(body)))
		if err != nil || size != int64(len(body)) {
			t.Fatalf("body %d: %v, %d bytes", i, err, size)
		}
		if got, _ := io.ReadAll(reader); !bytes.Equal(got, body) {
			t.Errorf("body %d isn't what was sent", i)
		}
		cleanups = append(cleanups, cleanup)
	}
	if used := cgiBodyFilesInUse.Load(); used != 3*int64(len(body)) {
		t.Errorf("three bodies in files take %d bytes of the budget; expected %d", used, 3*len(body))
	}
	if _, _, _, err := bufferedRequestBody(bytes.NewReader(body), int64(len(body))); !errors.Is(err, errCGIBodyFilesFull) {
		t.Errorf("a fourth body, over the budget: %v; expected errCGIBodyFilesFull", err)
	}
	if used := cgiBodyFilesInUse.Load(); used != 3*int64(len(body)) {
		t.Errorf("the body that didn't fit left %d bytes taken; expected %d", used, 3*len(body))
	}
	// Over HTTP: 503 with Retry-After while the budget is full, and served once a body's file is closed
	maxBodySize.Store(512 << 10)
	cgiBodyFileBudgetMin = 3*int64(len(body)) + 64<<10
	if cgiBodyFileBudget() < cgiBodyFileBudgetMin {
		t.Fatal("budget below its least")
	}
	cgiBodyFileBudgetMin = 16 * (512 << 10) // What 16 x MBB gives: the three bodies and the next one fit
	base := startServer(t)
	post := func() (*http.Response, string) {
		req, _ := http.NewRequest("POST", base+"/x.cgi", bytes.NewReader(body))
		req.Host = "localhost"
		res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		return res, string(data)
	}
	if res, text := post(); res.StatusCode != 200 || !strings.Contains(text, fmt.Sprintf("CONTENT_LENGTH=%d", len(body))) {
		t.Errorf("POST within the budget: %d", res.StatusCode)
	}
	cgiBodyFilesInUse.Add(cgiBodyFileBudget()) // As if other requests had filled it
	if res, _ := post(); res.StatusCode != 503 || res.Header.Get("Retry-After") == "" {
		t.Errorf("POST with the budget full: %d Retry-After=%q; expected 503 with Retry-After", res.StatusCode, res.Header.Get("Retry-After"))
	}
	cgiBodyFilesInUse.Add(-cgiBodyFileBudget())
	for _, cleanup := range cleanups {
		cleanup()
	}
	if used := cgiBodyFilesInUse.Load(); used != 0 {
		t.Errorf("with every file closed, %d bytes are still taken", used)
	}
}

// R6 M-05: the kinds of error lines that stopped coming are forgotten when their places are needed: a new kind gets
// its own, and its first line is written at once. Kept forever, the first 63 left every later kind in "(other)".
func TestR6_M05_ErrorLineKindsAreForgotten(t *testing.T) {
	logs := captureLog(t)
	errorLines.reopen()
	t.Cleanup(errorLines.reopen)
	for i := 0; i < aggregatedLogKinds-1; i++ {
		fmt.Fprintf(errorLines, "kind%c%c error happened here", 'a'+i/26, 'a'+i%26)
	}
	// While they are recent, a new kind goes with the others
	fmt.Fprint(errorLines, "another problem appears now")
	errorLines.mutex.Lock()
	_, own := errorLines.kinds["another problem appears now"]
	_, other := errorLines.kinds["(other)"]
	for _, entry := range errorLines.kinds { // As if an interval had gone by without a line of any of them
		entry.logged = time.Now().Add(-2 * aggregatedLogInterval)
	}
	errorLines.mutex.Unlock()
	if own || !other {
		t.Errorf("with every place taken by recent kinds: own entry %v, (other) %v; expected it in (other)", own, other)
	}
	logs.Reset()
	fmt.Fprint(errorLines, "brand new problem appears")
	errorLines.mutex.Lock()
	_, own = errorLines.kinds["brand new problem appears"]
	kinds := len(errorLines.kinds)
	errorLines.mutex.Unlock()
	if !own || kinds != 1 {
		t.Errorf("after an interval without lines: own entry %v, %d kinds kept; expected its own entry, alone", own, kinds)
	}
	if !strings.Contains(logs.String(), "brand new problem appears") {
		t.Errorf("the first line of the new kind wasn't written at once:\n%s", logs.String())
	}
}

// R6 M-07: a second signal while Turbo waits for the requests in progress ends that wait: their connections are
// closed, their CGIs ended, and Turbo exits as with one signal. It was ignored until the wait ended (up to 13 s).
func TestR6_M07_SecondSignalExitsAtOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows doesn't send SIGTERM to another process: it is checked in WSL")
	}
	bin := turboBinary(t)
	dir := t.TempDir()
	os.MkdirAll(dir+"/localhost/@", 0755)
	os.WriteFile(dir+"/localhost/@/x.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"/turbo.config", []byte(`{"^":{"v":"2"},"localhost":{"":{"?":{"cgi":"`+toolPath("cgiecho")+`"}}},".":{"WT":"30s"}}`), 0600)
	addr := "127.0.0.1:" + freePort(t)
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(testEnviron(), "TURBO_DIR="+dir+"/", "TURBO_HTTP_ADDR="+addr, "TURBO_HTTPS_ADDR=127.0.0.1:"+freePort(t))
	var out syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(100 * time.Millisecond) {
		if conn, err := net.Dial("tcp", addr); err == nil {
			conn.Close()
			break
		}
	}
	go func() { // A request that keeps the shutdown waiting for its whole grace
		req, _ := http.NewRequest("GET", "http://"+addr+"/x.cgi?sleep=20000", nil)
		req.Host = "localhost"
		if res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req); err == nil {
			res.Body.Close()
		}
	}()
	time.Sleep(500 * time.Millisecond)
	cmd.Process.Signal(syscall.SIGTERM)
	time.Sleep(700 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("Turbo exited with the first signal, with a request in progress: %v\n%s", err, out.String())
	default:
	}
	start := time.Now()
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("exit after the second signal: %v; expected code 0\n%s", err, out.String())
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("it took %v to exit after the second signal", elapsed)
		}
		if text := out.String(); !strings.Contains(text, "Second signal") || !strings.Contains(text, "msg=Stopped") || strings.Contains(text, "CGIs still running") {
			t.Errorf("the second signal didn't end the wait in order:\n%s", text)
		}
	case <-time.After(8 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("Turbo didn't exit with the second signal\n%s", out.String())
	}
}
