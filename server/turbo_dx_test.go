package server

// The mode dx of the preprocessors: the script of a request runs in a worker that Turbo keeps running, which gets the
// request by its input and answers by its output (the protocol DX 3). The worker of these tests is dxecho.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// setupDX makes the extension dx of localhost run with program in the mode dx, and starts a server.
func setupDX(t *testing.T, program string) (string, string) {
	t.Helper()
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.dx", []byte("the script"), 0644)
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["?"](true, map[string]interface{}{"dx": "dx>" + program}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("addPreprocessor dx: %q", message)
	}
	t.Cleanup(func() { stopPreprocessorModes(time.Second) })
	return dir, startServer(t)
}

// dxVariant is a copy of dxecho named so that it behaves as its name says (nogreet, badgreet, crash, stubborn), next to
// it: the folder of the test tools has a short path, as a preprocessor needs.
func dxVariant(t *testing.T, name string) string {
	t.Helper()
	source := toolPath("dxecho")
	target := filepath.ToSlash(filepath.Join(filepath.Dir(source), "dxecho-"+name))
	if runtime.GOOS == "windows" {
		target += ".exe"
	}
	if _, err := os.Stat(target); err != nil {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return target
}

// dxRequest makes a request to localhost and returns its status and body; status 0 if the connection was cut.
func dxRequest(t *testing.T, method string, base string, path string, body []byte, headers map[string]string) (int, string) {
	t.Helper()
	request, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
	request.Host = "localhost"
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, err.Error()
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, err.Error()
	}
	return response.StatusCode, string(data)
}

// dxLines reads the "NAME=value" lines of what dxecho or cgiecho answer.
func dxLines(body string) map[string]string {
	lines := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		if name, value, found := strings.Cut(line, "="); found {
			lines[name] = value
		}
	}
	return lines
}

// A worker gets what a CGI gets of the same request, in its pairs: the same names and values, but those of Turbo's
// own environment (which the worker has in its own) and DX_TIMEOUT_MS, which only a worker gets.
func TestDXGetsWhatACGIGets(t *testing.T) {
	dir := initForTest(t)
	t.Cleanup(func() { stopPreprocessorModes(time.Second) })
	os.WriteFile(dir+"localhost/@/x.e", []byte("the script"), 0644)
	base := startServer(t)
	names := "SERVER_SOFTWARE,SERVER_PROTOCOL,GATEWAY_INTERFACE,REQUEST_METHOD,SERVER_PORT,SERVER_NAME,REMOTE_ADDR,REMOTE_HOST,HTTP_X_TEST,HTTP_USER_AGENT,HTTP_ACCEPT_ENCODING,CONTENT_TYPE"
	path := "/x.e?a=1&b=two%20words&env=" + names
	headers := map[string]string{"X-Test": "value", "Content-Type": "text/plain", "Cookie": "a=1; turbo_session=secret; b=2", "X_Under": "dropped"}
	answer := func(program string) map[string]string {
		globalMutex.Lock()
		ok, message := subdomainContentCheckers["?"](true, map[string]interface{}{"e": program}, false, "localhost", "")
		globalMutex.Unlock()
		if !ok {
			t.Fatalf("%s: %q", program, message)
		}
		code, body := dxRequest(t, "POST", base, path, []byte("abc"), headers)
		if code != 200 {
			t.Fatalf("%s: %d %q", program, code, body)
		}
		return dxLines(body)
	}
	cgi, dx := answer(toolPath("cgiecho")), answer("dx>"+toolPath("dxecho"))
	if dx["DX_TIMEOUT_MS"] == "" || dx["DX_TIMEOUT_MS"] == "0" {
		t.Errorf("DX_TIMEOUT_MS %q; expected what is left of WT", dx["DX_TIMEOUT_MS"])
	}
	if dx["BODY_LENGTH"] != "3" || cgi["BODY_BYTES"] != "3" {
		t.Errorf("the body: dx %q, CGI %q", dx["BODY_LENGTH"], cgi["BODY_BYTES"])
	}
	process := map[string]bool{"PATH": true, "TMPDIR": true, "TEMP": true, "TMP": true, "SystemRoot": true, "COMSPEC": true, "PATHEXT": true, "WINDIR": true, "LD_LIBRARY_PATH": true, "DYLD_LIBRARY_PATH": true}
	cgiNames := map[string]bool{}
	for _, name := range strings.Split(cgi["ENV_NAMES"], ",") {
		cgiNames[name] = true
	}
	for name, value := range dx {
		switch name {
		case "DX_TIMEOUT_MS", "BODY_LENGTH", "REMOTE_PORT": // Only a worker's; the port of each connection
			continue
		}
		if process[name] {
			t.Errorf("%s reached the worker's pairs: it belongs to Turbo's environment", name)
		}
		if printed, found := cgi[name]; found && printed != value || !found && !cgiNames[name] {
			t.Errorf("%s: the worker got %q, the CGI %q (in its environment: %v)", name, value, printed, cgiNames[name])
		}
	}
	for _, name := range strings.Split(cgi["ENV_NAMES"], ",") {
		if _, got := dx[name]; !got && !process[name] && name != "" && name != "REMOTE_PORT" && name != "SYSTEMROOT" && name != "PATHEXT" {
			t.Errorf("the CGI got %s, the worker didn't", name)
		}
	}
	if strings.Contains(dx["HTTP_COOKIE"], "turbo_session") || dx["HTTP_X_UNDER"] != "" {
		t.Errorf("the panel's session cookie or a header with _ reached the worker: %q %q", dx["HTTP_COOKIE"], dx["HTTP_X_UNDER"])
	}
}

// A worker answers request after request: the same process, while its requests end well. Requests at the same time
// get workers of their own.
func TestDXWorkersAreKept(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	_, first := dxRequest(t, "GET", base, "/x.dx?pid=1", nil, nil)
	_, second := dxRequest(t, "GET", base, "/x.dx?pid=1", nil, nil)
	if dxLines(first)["PID"] == "" || dxLines(first)["PID"] != dxLines(second)["PID"] {
		t.Errorf("two requests one after the other: workers %q and %q; expected the same", dxLines(first)["PID"], dxLines(second)["PID"])
	}
	var wg sync.WaitGroup
	pids := make([]string, 4)
	for i := range pids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, body := dxRequest(t, "GET", base, "/x.dx?pid=1&sleep=400", nil, nil)
			if code != 200 {
				t.Errorf("request %d: %d %q", i, code, body)
			}
			pids[i] = dxLines(body)["PID"]
		}()
	}
	wg.Wait()
	distinct := map[string]bool{}
	for _, pid := range pids {
		distinct[pid] = true
	}
	if len(distinct) < 2 {
		t.Errorf("four requests at the same time: workers %v; expected several", pids)
	}
}

// pidAfter is the worker that answers the next request: a new one after the previous ended badly.
func pidAfter(t *testing.T, base string) string {
	t.Helper()
	code, body := dxRequest(t, "GET", base, "/x.dx?pid=1", nil, nil)
	if code != 200 {
		t.Fatalf("the next request: %d %q", code, body)
	}
	return dxLines(body)["PID"]
}

// A worker that fails answers 500 (or cuts the connection, if its answer had started), and it is not used again: the
// next request gets another worker. One that writes more than its answer isn't used again either.
func TestDXWorkerFailures(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	for _, c := range []struct {
		query string
		code  int
	}{
		{"die=before", 500},
		{"garbage=1", 500},
		{"die=after", 0},
		{"extra=1", 200},
	} {
		before := pidAfter(t, base)
		code, body := dxRequest(t, "GET", base, "/x.dx?"+c.query, nil, nil)
		if code != c.code {
			t.Errorf("%s: %d %q; expected %d", c.query, code, body, c.code)
		}
		if after := pidAfter(t, base); after == before {
			t.Errorf("%s: the same worker (%s) answered the next request", c.query, after)
		}
	}
}

// A worker out of time (WT) answers 504, and is killed; a client that goes away has its worker killed too.
func TestDXTimeAndClientGone(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	if ok, message := setting("WT", "1s"); !ok {
		t.Fatal(message)
	}
	before := pidAfter(t, base)
	start := time.Now()
	if code, _ := dxRequest(t, "GET", base, "/x.dx?sleep=5000", nil, nil); code != 504 || time.Since(start) > 4*time.Second {
		t.Errorf("a worker out of time: %d after %v; expected 504 after about 1 s", code, time.Since(start))
	}
	if after := pidAfter(t, base); after == before {
		t.Error("the worker out of time answered the next request")
	}
	before = pidAfter(t, base)
	request, _ := http.NewRequest("GET", base+"/x.dx?sleep=800", nil)
	request.Host = "localhost"
	(&http.Client{Timeout: 200 * time.Millisecond}).Do(request) // Gone before the answer
	time.Sleep(time.Second)
	if after := pidAfter(t, base); after == before {
		t.Error("the worker of a client that went away answered the next request")
	}
}

// What a worker answers goes as a CGI's would: an error status without a body gets the site's template, the site's
// headers win over the worker's, those about the connection are dropped, and a body in many chunks arrives whole.
func TestDXAnswers(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	addSiteHeaders(t, map[string]string{"X-Site": "from-site"})
	if code, body := dxRequest(t, "GET", base, "/x.dx?status=404&empty=1", nil, nil); code != 404 || !strings.Contains(body, "404") {
		t.Errorf("404 without a body: %d %q; expected the template", code, body)
	}
	request, _ := http.NewRequest("GET", base+"/x.dx?header=X-Site:%20worker&header=X-Worker:%20own&header=Connection:%20close&header=Transfer-Encoding:%20gzip", nil)
	request.Host = "localhost"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.Header.Get("X-Site") != "from-site" || response.Header.Get("X-Worker") != "own" || response.Header.Get("Transfer-Encoding") != "" || response.Close {
		t.Errorf("headers: X-Site %q, X-Worker %q, Transfer-Encoding %q, closed %v", response.Header.Get("X-Site"), response.Header.Get("X-Worker"), response.Header.Get("Transfer-Encoding"), response.Close)
	}
	if code, body := dxRequest(t, "GET", base, "/x.dx?chunks=8&size=150000", nil, nil); code != 200 || len(body) != 8*150000 {
		t.Errorf("8 chunks of 150000 bytes: %d, %d bytes", code, len(body))
	}
	if ok, message := setting("MBB", "8388608"); !ok {
		t.Fatal(message)
	}
	big := bytes.Repeat([]byte("0123456789abcdef"), 3<<16) // 3 MiB: in a temporary file, as for a CGI
	if code, body := dxRequest(t, "POST", base, "/x.dx?echo=body", big, nil); code != 200 || body != string(big) {
		t.Errorf("a body of 3 MiB: %d, %d bytes back", code, len(body))
	}
}

// A program that doesn't start as a worker (it ends, doesn't greet, or greets wrong) answers 500, and for a while no
// other is started: each request would start a process that fails again.
func TestDXWorkerThatDoesntStart(t *testing.T) {
	saved := dxGreetingWait
	dxGreetingWait = 300 * time.Millisecond
	t.Cleanup(func() { dxGreetingWait = saved })
	for _, name := range []string{"crash", "nogreet", "badgreet"} {
		t.Run(name, func(t *testing.T) {
			_, base := setupDX(t, dxVariant(t, name))
			if code, _ := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 500 {
				t.Errorf("first request: %d; expected 500", code)
			}
			start := time.Now()
			if code, _ := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 500 || time.Since(start) > 250*time.Millisecond {
				t.Errorf("right after: %d after %v; expected 500 at once, without starting another", code, time.Since(start))
			}
		})
	}
}

// The workers unused for a while, and those of a program that no preprocessor names any more, end with Turbo's
// cleaning; when Turbo stops, every worker ends, also one that doesn't end when its input closes.
func TestDXWorkersEnd(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	before := pidAfter(t, base)
	idlePreprocessorModes()
	if pidAfter(t, base) != before {
		t.Error("a worker in use ended with the cleaning")
	}
	saved := dxIdleAfter
	dxIdleAfter = 0
	idlePreprocessorModes()
	dxIdleAfter = saved
	after := pidAfter(t, base)
	if after == before {
		t.Error("an unused worker didn't end with the cleaning")
	}
	globalMutex.Lock()
	delete(preprocessors["localhost"], "dx")
	globalMutex.Unlock()
	idlePreprocessorModes()
	dxWorkers.mutex.Lock()
	kept := len(dxWorkers.pools)
	dxWorkers.mutex.Unlock()
	if kept != 0 {
		t.Errorf("%d programs kept after their preprocessor went", kept)
	}

	_, base = setupDX(t, dxVariant(t, "stubborn"))
	pidAfter(t, base)
	start := time.Now()
	stopPreprocessorModes(500 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("stopping took %v", elapsed)
	}
	dxWorkers.mutex.Lock()
	kept = len(dxWorkers.pools)
	dxWorkers.mutex.Unlock()
	if kept != 0 {
		t.Errorf("%d programs kept after stopping", kept)
	}
}

// dxAnswer is an answer of a worker in the protocol: its head, and its body in the chunks given.
func dxAnswer(status int, headers [][2]string, chunks ...string) []byte {
	u32 := func(out []byte, n int) []byte {
		return binary.LittleEndian.AppendUint32(out, uint32(n))
	}
	head := u32(nil, status)
	head = u32(head, len(headers))
	for _, pair := range headers {
		head = append(u32(head, len(pair[0])), pair[0]...)
		head = append(u32(head, len(pair[1])), pair[1]...)
	}
	out := append(u32(nil, len(head)), head...)
	for _, chunk := range chunks {
		out = append(u32(out, len(chunk)), chunk...)
	}
	return u32(out, 0)
}

// Whatever a worker writes, Turbo reads it within its limits, without a panic and without waiting for more than it
// was given; and while the answer hasn't started (an error before its head is whole, and its first chunk read),
// nothing of it reaches the client: Turbo answers 500 instead, without a header of the worker.
func FuzzDXResponse(f *testing.F) {
	const id = 0x0123456789abcdef // The id of the request of each input: the inputs start with it, or don't
	withID := func(answer []byte) []byte {
		return append(binary.LittleEndian.AppendUint64(nil, id), answer...)
	}
	f.Add(withID(dxAnswer(200, [][2]string{{"Content-Type", "text/plain"}}, "hello", " world")))
	f.Add(withID(dxAnswer(404, nil)))
	f.Add(withID(dxAnswer(302, [][2]string{{"Location", "/other"}, {"X-A", "1"}})))
	f.Add(withID(dxAnswer(99, nil, "body")))
	f.Add(withID(dxAnswer(200, [][2]string{{"Bad Name", "x"}, {"X-B", "a\r\nb"}}, "x")))
	cut := withID(dxAnswer(302, [][2]string{{"Location", "https://elsewhere.example/"}}))
	f.Add(cut[:len(cut)-4]) // A whole head, and then nothing: no chunk
	f.Add(append(binary.LittleEndian.AppendUint64(nil, id+1), dxAnswer(200, nil, "another's")...))
	f.Add(dxAnswer(200, nil, "without an id"))
	f.Add([]byte("DX3\n"))
	f.Add(withID([]byte{8, 0, 0, 0, 200, 0, 0, 0, 255, 255, 255, 255}))
	f.Add(withID(append(dxAnswer(200, nil, "a")[:16], 0, 0, 16, 0)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		request, _ := customNetHttp.NewRequest("GET", "http://localhost/x.dx?a=1", nil)
		request.RemoteAddr = "127.0.0.1:1234"
		worker := &dxWorker{reader: bufio.NewReader(bytes.NewReader(data)), writer: bufio.NewWriter(io.Discard)}
		output := &responseRecorder{}
		job := &dynamicJob{request: request, output: output, executable: "x", basePath: "/srv/", requestPath: "x.dx"}
		answered, err := worker.exchange(job, id)
		if !answered && (output.code != 0 || output.body.Len() != 0 || len(output.header) != 0) {
			t.Fatalf("not answered (%v), but the client got %d %v %q", err, output.code, output.header, output.body.String())
		}
		if answered && (output.code < 200 || output.code > 599) {
			t.Fatalf("answered with status %d", output.code)
		}
		if output.body.Len() > len(data) && output.code < 400 {
			t.Fatalf("%d bytes of body from %d bytes of the worker", output.body.Len(), len(data))
		}
		for name := range output.header {
			if !customNetHttp.ValidHeaderFieldName(name) {
				t.Fatalf("a header name that isn't one: %q", name)
			}
		}
	})
}

// A worker gets what a CGI gets of the bodies and the methods: a body without a length (chunked, or over HTTP/2) whole,
// with its CONTENT_LENGTH; one larger than MBB, 413 without reaching the worker; and HEAD, the head of the answer only.
func TestDXBodiesAndMethodsAsACGI(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	maxBodySize.Store(1 << 20)
	t.Cleanup(func() { maxBodySize.Store(1048576) })
	post := func(client *http.Client, url string, size int) (int, string) {
		request, _ := http.NewRequest("POST", url, io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("a"), size)))) // Chunked
		request.Host = "localhost"
		request.ContentLength = -1
		response, err := client.Do(request)
		if err != nil {
			return 0, err.Error()
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, response.Proto + " " + string(body)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	if code, body := post(client, base+"/x.dx?echo=body", 300<<10); code != 200 || len(body) != len("HTTP/1.1 ")+300<<10 {
		t.Errorf("a chunked body of 300 KiB: %d, %d bytes back", code, len(body))
	}
	if code, body := post(client, base+"/x.dx?env=CONTENT_LENGTH", 1000); code != 200 || !strings.Contains(body, "CONTENT_LENGTH=1000") {
		t.Errorf("CONTENT_LENGTH of a chunked body: %d %q", code, body)
	}
	if code, _ := post(client, base+"/x.dx?echo=body", 2<<20); code != 413 && code != 0 {
		t.Errorf("a body larger than MBB: %d; expected 413", code)
	}
	request, _ := http.NewRequest("HEAD", base+"/x.dx?chunks=2&size=1000", nil)
	request.Host = "localhost"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || len(body) != 0 {
		t.Errorf("HEAD: %d with %d bytes", response.StatusCode, len(body))
	}

	cfg := selfSignedTLS(t)
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(serverHandlerFn(true)), TLSConfig: cfg, ConnState: connHandler}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true} // #nosec G402 -- self-signed test certificate
	defer transport.CloseIdleConnections()
	if code, body := post(&http.Client{Transport: transport, Timeout: 15 * time.Second}, "https://"+listener.Addr().String()+"/x.dx?echo=body", 5000); code != 200 || body != "HTTP/2.0 "+strings.Repeat("a", 5000) {
		t.Errorf("HTTP/2 without a length: %d %.40q", code, body)
	}
}
