package server

// The tests of the findings about the CGIs of the review of v2.5.1: each failed before its fix.

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// goCGIProgram is a CGI written with Go's net/http/cgi, which makes the URL of its request from REQUEST_URI.
const goCGIProgram = `package main

import (
	"fmt"
	"net/http"
	"net/http/cgi"
	"os"
)

func main() {
	cgi.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "query=%s\nrole=%s\nz=%s\npath=%s\n", os.Getenv("QUERY_STRING"), r.URL.Query().Get("role"), r.URL.Query().Get("z"), r.URL.Path)
	}))
}
`

// V2.5.1 review CP-1 (decision E-2): through a rewrite whose target has a query, REQUEST_URI is what the client asked
// for, as Apache and nginx pass it, without the parameters that the rewrite's query sets; QUERY_STRING is the client's
// query without them, and the rewrite's after it. v2.5.1 put the whole QUERY_STRING in REQUEST_URI, and an
// application that compares it with its canonical URL (WordPress's redirect_canonical) redirected without end. A CGI of
// Go, which takes its URL from REQUEST_URI, never sees the client's value of a parameter that the rewrite sets, and
// sees the rewrite's in QUERY_STRING only. The same for a CGI and for the mode dx.
func TestR251_CP1_RequestURIIsWhatTheClientAskedFor(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/@/x.dxe", []byte("x"), 0644)
	globalMutex.Lock()
	for _, preprocessor := range []map[string]interface{}{{"cgi": toolPath("cgiecho")}, {"dxe": "dx>" + toolPath("dxecho")}} {
		if ok, message := subdomainContentCheckers["?"](true, preprocessor, false, "localhost", ""); !ok {
			t.Fatal(message)
		}
	}
	for source, target := range map[string]string{"/x": "/x.cgi?role=user", "/d": "/x.dxe?role=user", "/w/": "/x.cgi"} {
		if ok, message := subdomainContentCheckers["="](true, map[string]interface{}{source: target}, false, "localhost", ""); !ok {
			t.Fatal(message)
		}
	}
	globalMutex.Unlock()
	t.Cleanup(func() { stopPreprocessorModes(time.Second) })
	base := startServer(t)
	for _, prefix := range []string{"/x", "/d"} {
		for _, c := range []struct{ query, queryString, requestURI string }{
			{"", "role=user", ""},
			{"?z=1", "z=1&role=user", "?z=1"},
			{"?role=admin&z=1", "z=1&role=user", "?z=1"},
			{"?role=admin", "role=user", ""},
			{"?z=1;role=admin;a=2", "z=1;a=2&role=user", "?z=1;a=2"},
		} {
			code, body, err := get(base, prefix+c.query, nil)
			if err != nil || code != 200 {
				t.Fatalf("GET %s%s: %d %v %q", prefix, c.query, code, err, body)
			}
			env := cgiEnv(body)
			if env["QUERY_STRING"] != c.queryString || env["REQUEST_URI"] != prefix+c.requestURI {
				t.Errorf("GET %s%s: QUERY_STRING %q, REQUEST_URI %q; expected %q and %q", prefix, c.query, env["QUERY_STRING"], env["REQUEST_URI"], c.queryString, prefix+c.requestURI)
			}
		}
	}
	// Without a rewrite's query, or asked for by its name, the client's as it came
	for path, requestURI := range map[string]string{"/w/a?role=admin": "/w/a?role=admin", "/x.cgi?role=admin&z=1": "/x.cgi?role=admin&z=1"} {
		if code, body, err := get(base, path, nil); err != nil || code != 200 || cgiEnv(body)["REQUEST_URI"] != requestURI || cgiEnv(body)["QUERY_STRING"] != strings.SplitN(requestURI, "?", 2)[1] {
			t.Errorf("GET %s: %d %v, REQUEST_URI %q; expected %q", path, code, err, cgiEnv(body)["REQUEST_URI"], requestURI)
		}
	}

	if testing.Short() {
		return // What follows builds a program
	}
	build := t.TempDir()
	os.WriteFile(filepath.Join(build, "main.go"), []byte(goCGIProgram), 0644)
	os.WriteFile(filepath.Join(build, "go.mod"), []byte("module gocgi\n\ngo 1.26\n"), 0644)
	program := toolPath("r251gocgi") // Next to the test tools: a short path, as a preprocessor needs
	cmd := exec.Command("go", "build", "-o", program, ".")
	cmd.Dir = build
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Cleanup(func() { os.Remove(program) })
	os.WriteFile(dir+"localhost/@/app.gocgi", []byte("x"), 0644)
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["?"](true, map[string]interface{}{"gocgi": program}, false, "localhost", "")
	subdomainContentCheckers["="](true, map[string]interface{}{"/g": "/app.gocgi?role=user"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(message)
	}
	for path, lines := range map[string][]string{
		"/g?role=admin&z=1":         {"query=z=1&role=user", "role=", "z=1", "path=/g"},
		"/g":                        {"query=role=user", "role=", "z=", "path=/g"},
		"/app.gocgi?role=admin&z=1": {"query=role=admin&z=1", "role=admin", "z=1", "path=/app.gocgi"}, // No rewrite
	} {
		code, body, err := get(base, path, nil)
		if err != nil || code != 200 {
			t.Fatalf("GET %s, a CGI of Go: %d %v %q", path, code, err, body)
		}
		for _, line := range lines {
			if !strings.Contains("\n"+body, "\n"+line+"\n") {
				t.Errorf("GET %s, a CGI of Go: no line %q in\n%s", path, line, body)
			}
		}
	}
}

// cutBodyReader gives n bytes of "x", and then end: io.EOF for a body that ended, or what Go's body gives when the
// connection ended before the length it said (io.ErrUnexpectedEOF).
type cutBodyReader struct {
	left int
	end  error
}

func (r *cutBodyReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, r.end
	}
	n := min(len(p), r.left)
	for i := range n {
		p[i] = 'x'
	}
	r.left -= n
	return n, nil
}

// V2.5.1 review CP-3: a body cut before its end (io.ErrUnexpectedEOF of the reader) is an error, with what it took of
// the budgets given back, as on the way of the temporary file: in memory it was taken whole, with the length that
// arrived. One that ends is the body.
func TestR251_CP3_ABodyCutShortIsAnError(t *testing.T) {
	initForTest(t)
	keys := cgiSlotKeys("192.0.2.9")
	inUse := func() (int64, int64, int) {
		cgiBodyShares.mutex.Lock()
		defer cgiBodyShares.mutex.Unlock()
		return cgiBodyInUse.Load(), cgiBodyFilesInUse.Load(), len(cgiBodyShares.memory) + len(cgiBodyShares.files)
	}
	for _, expected := range []int64{100, -1, 2 << 20} {
		body, size, cleanup, err := bufferedRequestBodyOf(keys, &cutBodyReader{left: 50, end: io.ErrUnexpectedEOF}, expected)
		if err == nil {
			data, _ := io.ReadAll(body)
			cleanup()
			t.Errorf("a body of %d bytes cut at 50: taken, %d bytes (size %d); expected an error", expected, len(data), size)
		}
		if memory, files, shares := inUse(); memory != 0 || files != 0 || shares != 0 {
			t.Errorf("a body of %d bytes cut at 50: left in the budgets %d in memory, %d in files, %d shares", expected, memory, files, shares)
		}
	}
	for _, expected := range []int64{50, -1} {
		body, size, cleanup, err := bufferedRequestBodyOf(keys, &cutBodyReader{left: 50, end: io.EOF}, expected)
		if err != nil {
			t.Fatalf("a body of 50 bytes that ends, said %d: %v", expected, err)
		}
		if data, _ := io.ReadAll(body); size != 50 || string(data) != strings.Repeat("x", 50) {
			t.Errorf("a body of 50 bytes that ends, said %d: size %d, %q", expected, size, data)
		}
		cleanup()
		if memory, files, shares := inUse(); memory != 0 || files != 0 || shares != 0 {
			t.Errorf("after the body of 50 bytes, said %d: left in the budgets %d in memory, %d in files, %d shares", expected, memory, files, shares)
		}
	}
}
