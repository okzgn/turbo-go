package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// r250GoCGI is a CGI written with Go's net/http/cgi, which makes the URL of its request from REQUEST_URI.
const r250GoCGI = `package main

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

// V2.5.0 review CG-3: through a rewrite whose target has a query, REQUEST_URI carries the query of QUERY_STRING after
// the path that the client asked for. With the client's own query there, an application that reads its parameters
// from REQUEST_URI (a CGI of Go) got the client's value of a parameter that the rewrite sets: "role=admin" for a
// rewrite to "/app.cgi?role=user".
func TestR250_CG3_RequestURICarriesTheQueryOfTheRewrite(t *testing.T) {
	if testing.Short() {
		t.Skip("it builds a program")
	}
	dir := initForTest(t)
	build := t.TempDir()
	os.WriteFile(filepath.Join(build, "main.go"), []byte(r250GoCGI), 0644)
	os.WriteFile(filepath.Join(build, "go.mod"), []byte("module gocgi\n\ngo 1.26\n"), 0644)
	program := toolPath("r250gocgi") // Next to the test tools: a short path, as a preprocessor needs
	cmd := exec.Command("go", "build", "-o", program, ".")
	cmd.Dir = build
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Cleanup(func() { os.Remove(program) })
	os.WriteFile(dir+"localhost/@/app.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": program}, false, "localhost", "")
	subdomainContentCheckers["="](true, map[string]interface{}{"/x": "/app.cgi?role=user"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(message)
	}
	base := startServer(t)
	code, body, err := get(base, "/x?role=admin&z=1", nil)
	if err != nil || code != 200 {
		t.Fatalf("through the rewrite: %d %v %q", code, err, body)
	}
	for _, line := range []string{"query=z=1&role=user", "role=user", "z=1", "path=/x"} {
		if !strings.Contains("\n"+body, "\n"+line+"\n") {
			t.Errorf("through the rewrite, a CGI of Go: no line %q in\n%s", line, body)
		}
	}
	// Without a rewrite's query, REQUEST_URI is the client's, as it was
	if code, body, err = get(base, "/app.cgi?role=admin", nil); err != nil || code != 200 || !strings.Contains(body, "role=admin\n") || !strings.Contains(body, "path=/app.cgi\n") {
		t.Errorf("asked for by its name: %d %v %q", code, err, body)
	}
}
