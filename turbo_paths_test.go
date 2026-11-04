package main

// A1 (H1, H2, H48), A2 (H3, H47), B2 (H11): the requested path is decoded,
// cleaned and never leaves @; what is rejected answers 404, whether it exists
// or not; extensions ignore case.

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// rawRequest sends a request line as is (without an HTTP client normalizing
// it) with Host: localhost and returns the code and the body.
func rawRequest(t *testing.T, base, requestLine string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(clientTimeout()))
	io.WriteString(c, requestLine+"\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%q: %v", requestLine, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// servingFixture sets up localhost with a CGI (cgiecho) and files outside @:
// localhost/x.cgi, localhost/secret.txt and <dir>/outside.txt.
func servingFixture(t *testing.T) (dir, base string) {
	t.Helper()
	dir = initForTest(t)
	os.WriteFile(dir+"localhost/x.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/secret.txt", []byte("SECRET"), 0644)
	os.WriteFile(dir+"outside.txt", []byte("SECRET"), 0644)
	os.WriteFile(dir+"localhost/@/inside.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/@/note.txt", []byte("note"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	return dir, startServer(t)
}

// H1, H2: no path leaves @. What is outside is neither run nor served, and the
// response is 404 whether the file exists or not.
func TestA1_PathTraversal(t *testing.T) {
	_, base := servingFixture(t)
	for _, path := range []string{
		"/../x.cgi", "/../../x.cgi", "/a/../../x.cgi", "/%2e%2e/x.cgi", "/..%2fx.cgi", "/%2e%2e%2fx.cgi",
		"/..\\x.cgi", "/x.cgi%00.txt", "/../secret.txt", "/../../outside.txt", "/%2E%2E/secret.txt",
		"/../missing.txt", "/..%5csecreto.txt", "/note.txt%00", "/./../secret.txt",
	} {
		code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1")
		if code != 404 || strings.Contains(body, "SECRET") || strings.Contains(body, "SCRIPT_FILENAME") {
			t.Errorf("GET %s: %d %.80q; expected 404 without running or serving anything from outside @", path, code, body)
		}
	}
	// Inside @ everything keeps working.
	if code, body := rawRequest(t, base, "GET /inside.cgi HTTP/1.1"); code != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
		t.Errorf("GET /inside.cgi: %d %.80q", code, body)
	}
	if code, body := rawRequest(t, base, "GET //note.txt HTTP/1.1"); code != 200 || body != "note" {
		t.Errorf("GET //note.txt: %d %q", code, body)
	}
}

// A1: a symbolic link inside @ that points outside isn't followed.
func TestA1_SymlinkOutside(t *testing.T) {
	dir, base := servingFixture(t)
	if err := os.Symlink(dir+"outside.txt", dir+"localhost/@/link.txt"); err != nil {
		t.Skip("symbolic links can't be created:", err)
	}
	if code, body := rawRequest(t, base, "GET /link.txt HTTP/1.1"); code != 404 || strings.Contains(body, "SECRET") {
		t.Errorf("link to outside @: %d %q; expected 404", code, body)
	}
}

// H3, H47: with capitals, a dot or a space at the end, an alternate data
// stream or a Windows reserved name, a preprocessed file is run or gives 404;
// its code is never served.
func TestA2_ExtensionsAndSpecialNames(t *testing.T) {
	dir, base := servingFixture(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("SOURCE"), 0644)
	for _, path := range []string{"/x.CGI", "/x.Cgi", "/x.cgi.", "/x.cgi%20", "/x.cgi::$DATA", "/CON.cgi", "/x.cgi%2e", "/x.cgi/", "/x.cgi//", "/x.cgi%2f"} {
		code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1")
		if strings.Contains(body, "SOURCE") || (code != 404 && !strings.Contains(body, "SCRIPT_FILENAME=")) {
			t.Errorf("GET %s: %d %.80q; expected the CGI to run or 404, never the code", path, code, body)
		}
	}
	if runtime.GOOS != "windows" { // On Linux, X.CGI is another file, also run with the "cgi" preprocessor
		os.WriteFile(dir+"localhost/@/y.CGI", []byte("SOURCE"), 0644)
		if code, body := rawRequest(t, base, "GET /y.CGI HTTP/1.1"); code != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
			t.Errorf("GET /y.CGI on Linux: %d %.80q; expected it to run", code, body)
		}
	}
	// A preprocessor or MIME added with capitals is stored in lower case.
	globalMutex.Lock()
	subdomainContentCheckers["$"](true, map[string]interface{}{"TXT": "text/x-test"}, false, "localhost", "")
	_, lower := mimeTypes["localhost"]["txt"]
	globalMutex.Unlock()
	if !lower {
		t.Error("the MIME extension TXT wasn't stored as txt")
	}
}

// H55: on Windows, an 8.3 short name (INDEX~1.PHT for index.phtml) would open
// the file with another extension, without its preprocessor: those segments
// are rejected there; on other systems they are ordinary names.
func TestH55_WindowsShortNames(t *testing.T) {
	dir, base := servingFixture(t)
	os.WriteFile(dir+"localhost/@/page.cgix", []byte("SOURCE"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgix": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	for _, path := range []string{"/PAGE~1.CGI", "/page~1.cgi", "/PAGE~1"} {
		if code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1"); strings.Contains(body, "SOURCE") || (runtime.GOOS == "windows" && code != 404) {
			t.Errorf("GET %s: %d %.80q; expected 404, never the code", path, code, body)
		}
	}
	for segment, windows := range map[string]bool{"PAGE~1.CGI": false, "a~9": false, "a~b.txt": true, "~": true, "copy~.txt": true} {
		if got := pathSegmentAllowed(segment, true); got != windows {
			t.Errorf("pathSegmentAllowed(%q, windows) = %v; expected %v", segment, got, windows)
		}
		if !pathSegmentAllowed(segment, false) {
			t.Errorf("pathSegmentAllowed(%q) outside Windows = false", segment)
		}
	}
}

// H47: the file upload discards Windows reserved names, alternate data
// streams and names that end in a dot or a space.
func TestA2_UploadedNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"site/a.txt": true, "site/css/b.css": true, "site/CON": false, "site/con.txt": false, "site/x/aux.html": false,
		"site/x.php::$DATA": false, "site/x.php.": false, "site/x.php ": false, "site/COM1.log": false, "site/LPT9": false,
		"site/console.txt": true, "site/connect.txt": true,
	} {
		if _, got := uploadedFilePath(name); got != ok {
			t.Errorf("uploadedFilePath(%q) = %v; expected %v", name, got, ok)
		}
	}
}

// H11 (D5): percent-encoded paths are decoded; an encoded slash doesn't
// separate folders; rewrite keys are compared with the decoded path.
func TestB2_PercentEncodedPaths(t *testing.T) {
	dir, base := servingFixture(t)
	os.WriteFile(dir+"localhost/@/a b.txt", []byte("with space"), 0644)
	os.WriteFile(dir+"localhost/@/café.txt", []byte("with accent"), 0644)
	os.MkdirAll(dir+"localhost/@/folder", 0755)
	os.WriteFile(dir+"localhost/@/folder/x", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/@/target.txt", []byte("target"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["="](true, map[string]interface{}{"/other path": "/target.txt"}, false, "localhost", "")
	globalMutex.Unlock()
	for path, want := range map[string]string{
		"/a%20b.txt":     "with space",
		"/caf%C3%A9.txt": "with accent",
		"/other%20path":  "target",
	} {
		if code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1"); code != 200 || body != want {
			t.Errorf("GET %s: %d %q; expected 200 %q", path, code, body, want)
		}
	}
	if code, _ := rawRequest(t, base, "GET /folder%2Fx HTTP/1.1"); code != 404 {
		t.Errorf("GET /folder%%2Fx: %d; expected 404 (the encoded slash doesn't separate folders)", code)
	}
}

// H58: {REWRITE_COMPLEMENT} is what follows the key in the already decoded and
// cleaned path the key is compared with, plus the query.
func TestH58_RewriteComplementDecoded(t *testing.T) {
	_, base := servingFixture(t)
	globalMutex.Lock()
	subdomainContentCheckers["="](true, map[string]interface{}{"/old dir/": "/inside.cgi?x={REWRITE_COMPLEMENT}"}, false, "localhost", "")
	globalMutex.Unlock()
	for path, want := range map[string]string{
		"/old%20dir/a.txt":     "x=a.txt",
		"/ol%64%20dir/a.txt":   "x=a.txt",
		"//old%20dir/a.txt":    "x=a.txt",
		"/old%20dir/b%20c.txt": "x=b+c.txt",
		"/old%20dir/a.txt?q=1": "x=a.txt%3Fq%3D1",
	} {
		code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1")
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("GET %s: %d %.120q; expected the query %q", path, code, body, want)
		}
	}
}

// H48: for any input, the clean path stays inside the root or is rejected.
func FuzzServePath(f *testing.F) {
	for _, s := range []string{"/", "/a/b", "/../x", "/%2e%2e/x", "/..%2fx", "//x", "/a/./b/../c", "/x%00", "/..\\x", "/CON", "/a.", "/a ", "/a::$DATA", "/%"} {
		f.Add(s)
	}
	root := filepath.FromSlash("/srv/site/@")
	f.Fuzz(func(t *testing.T, raw string) {
		clean, ok := cleanRequestPath(raw)
		if !ok {
			return
		}
		if !strings.HasPrefix(clean, "/") || strings.ContainsAny(clean, "\\\x00") {
			t.Fatalf("cleanRequestPath(%q) = %q", raw, clean)
		}
		for _, segment := range strings.Split(clean, "/") {
			if segment == ".." || segment == "." {
				t.Fatalf("cleanRequestPath(%q) = %q, with %q", raw, clean, segment)
			}
		}
		if rel, err := filepath.Rel(root, filepath.Join(root, filepath.FromSlash(clean))); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("cleanRequestPath(%q) = %q leaves the root (%q)", raw, clean, rel)
		}
	})
}

// N97: a subdomain serves its own host only; deeper levels are served by a wildcard ("*.api", or "*"), as the
// API says. Before, "api" also served x.api.example.test, as if it were "*.api", and a site with that host was
// refused as a coincidence.
func TestN97_SubdomainServesOnlyItsHost(t *testing.T) {
	dir := initForTest(t)
	globalMutex.Lock()
	ok, msg := addSite("example.test")
	if ok {
		ok, msg = addSubdomain("example.test", "api")
	}
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	os.WriteFile(dir+"example.test/api/@/index.html", []byte("api"), 0644)
	base := startServer(t)
	status := func(host string) (int, string) {
		res, body, err := rawGet(base, host, "/")
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, body
	}
	if code, body := status("api.example.test"); code != 200 || body != "api" {
		t.Errorf("api.example.test: %d %q", code, body)
	}
	if code, body := status("x.api.example.test"); code != 404 {
		t.Errorf("x.api.example.test without a wildcard: %d %q; expected 404", code, body)
	}
	globalMutex.Lock()
	ok, msg = addSubdomain("example.test", "*.api")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	os.WriteFile(dir+"example.test/#.api/@/index.html", []byte("wildcard"), 0644)
	if code, body := status("x.api.example.test"); code != 200 || body != "wildcard" {
		t.Errorf("x.api.example.test with *.api: %d %q; expected the wildcard", code, body)
	}
	if code, body := status("api.example.test"); code != 200 || body != "api" {
		t.Errorf("api.example.test with *.api: %d %q", code, body)
	}
}

// N99: a folder's rewrite ("/private/") also takes the folder named without its final "/", which would serve its
// index, and where the file system ignores case (Windows, macOS) a path in another case, which opens the same
// files. Before, "/private" and "/PRIVATE/" got past a rewrite used to keep the folder out.
func TestN99_FolderRewriteCannotBeSidestepped(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/private", 0755)
	os.WriteFile(dir+"localhost/@/private/index.html", []byte("secret"), 0644)
	os.WriteFile(dir+"localhost/@/denied.html", []byte("denied"), 0644)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/private/": "/denied.html"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	for _, path := range []string{"/private", "/private/", "/private/index.html", "/PRIVATE/", "/Private", "/private/INDEX.HTML", "/PRIVATE/index.html"} {
		code, body, err := get(base, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if body == "secret" {
			t.Errorf("%s: %d %q; the rewrite of /private/ wasn't applied", path, code, body)
		}
	}
	if code, body, _ := get(base, "/private", nil); code != 200 || body != "denied" {
		t.Errorf("/private: %d %q; expected the rewrite", code, body)
	}
}
