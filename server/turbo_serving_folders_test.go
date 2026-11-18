package server

// Review of 6046dbe (R6): folders named without their final "/", "/index.html" where it isn't the index, and the
// names that a file system takes for another file's.

import (
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
)

// requestTo makes a request of method to host, without following redirections.
func requestTo(t *testing.T, base, method, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "localhost"
	client := &http.Client{Timeout: clientTimeout(), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	body := new(strings.Builder)
	buffer := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buffer)
		body.Write(buffer[:n])
		if err != nil {
			break
		}
	}
	return res, body.String()
}

// R6 M-02: a folder named without its final "/" is redirected to the same path with it, and the same query. It was
// answered there with its index, whose relative links then led to the folder above.
func TestR6_M02_FolderWithoutItsFinalSlash(t *testing.T) {
	dir := initForTest(t)
	for folder, index := range map[string]string{"docs": "docs", "docs/deep": "deep", "a b": "spaces", "empty": ""} {
		os.MkdirAll(dir+"localhost/@/"+folder, 0755)
		if index != "" {
			os.WriteFile(dir+"localhost/@/"+folder+"/index.html", []byte(index), 0644)
		}
	}
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/manual": "/docs"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("rewrite: %q", msg)
	}
	base := startServer(t)
	for _, c := range []struct {
		method, path string
		code         int
		location     string
	}{
		{"GET", "/docs", 301, "/docs/"},
		{"HEAD", "/docs", 301, "/docs/"},
		{"GET", "/docs?x=1&y=%20", 301, "/docs/?x=1&y=%20"},
		{"GET", "/docs/deep", 301, "/docs/deep/"},
		{"GET", "/a%20b", 301, "/a%20b/"},
		{"GET", "//docs", 301, "/docs/"}, // Never "//docs/", which a browser takes for another host
		{"POST", "/docs", 308, "/docs/"},
	} {
		res, _ := requestTo(t, base, c.method, c.path)
		if res.StatusCode != c.code || res.Header.Get("Location") != c.location {
			t.Errorf("%s %s: %d Location=%q; expected %d %q", c.method, c.path, res.StatusCode, res.Header.Get("Location"), c.code, c.location)
		}
	}
	for path, body := range map[string]string{"/docs/": "docs", "/docs/deep/": "deep", "/a%20b/": "spaces", "/": "hello", "/manual": "docs"} {
		if res, got := requestTo(t, base, "GET", path); res.StatusCode != 200 || got != body || res.Header.Get("Location") != "" {
			t.Errorf("GET %s: %d %q Location=%q; expected 200 %q", path, res.StatusCode, got, res.Header.Get("Location"), body)
		}
	}
	// A folder without an index is still 404, with or without the "/"
	for _, path := range []string{"/empty", "/empty/"} {
		if res, _ := requestTo(t, base, "GET", path); res.StatusCode != 404 {
			t.Errorf("GET %s: %d; expected 404", path, res.StatusCode)
		}
	}
}

// R6 M-03: "/index.html" is redirected to its folder only where index.html is the index that the folder serves.
// Where it isn't an index of the site, the redirection led to another file, or to 404, and index.html was never
// served; and a rewrite of a URL that ends in "/index.html" was never applied.
func TestR6_M03_IndexHTMLThatIsNotTheIndex(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/start.html", []byte("start"), 0644)
	os.WriteFile(dir+"localhost/@/note.txt", []byte("note"), 0644)
	base := startServer(t)
	// index.html is the index: as Go's file server does, and as the README says
	if res, _ := requestTo(t, base, "GET", "/index.html"); res.StatusCode != 301 || res.Header.Get("Location") != "./" {
		t.Errorf("GET /index.html, the site's index: %d %q; expected 301 to ./", res.StatusCode, res.Header.Get("Location"))
	}
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/a/index.html": "/note.txt"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("rewrite: %q", msg)
	}
	if res, body := requestTo(t, base, "GET", "/a/index.html"); res.StatusCode != 200 || body != "note" {
		t.Errorf("GET /a/index.html, rewritten to /note.txt: %d %q; expected 200 \"note\"", res.StatusCode, body)
	}
	globalMutex.Lock()
	delete(indexFiles["localhost"], "index.html")
	addIndex("localhost", "start.html")
	globalMutex.Unlock()
	res, body := requestTo(t, base, "GET", "/index.html")
	if res.StatusCode != 200 || body != "hello" || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Errorf("GET /index.html, not an index: %d %q (%s); expected the file", res.StatusCode, body, res.Header.Get("Content-Type"))
	}
	if res.Header.Get("Last-Modified") == "" || res.Header.Get("Accept-Ranges") != "bytes" {
		t.Errorf("the file isn't served as the others are: %v", res.Header)
	}
	if res, body := requestTo(t, base, "GET", "/"); res.StatusCode != 200 || body != "start" {
		t.Errorf("GET /: %d %q; expected the index start.html", res.StatusCode, body)
	}
}

// R6 V-04: with preprocessors, a name that some file system takes for another file's is never served: a short name
// ("~" and a digit), a stream (":") or an extension outside ASCII. The extension asked for chooses the preprocessor,
// and the file that opens could be a script under another name, served as text: with the Linux binary on a volume of
// Windows, "/LONGNA~1.PHT" gave the source of longname.phtml.
func TestR6_V04_NamesOfOtherFilesWithPreprocessors(t *testing.T) {
	for path, ambiguous := range map[string]bool{
		"/LONGNA~1.PHT": true, "/dir~2/x.txt": true, "/x.php:$DATA": true, "/x.jſp": true, "/x.js\u200cp": true, "/x.\uff4asp": true,
		"/x.php": false, "/a~b.txt": false, "/~user/x.txt": false, "/x~": false, "/ñ/é.txt": false, "/file.tar.gz": false,
	} {
		if ambiguousScriptName(path, ext(path)) != ambiguous {
			t.Errorf("ambiguousScriptName(%q) = %v; expected %v", path, !ambiguous, ambiguous)
		}
	}
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/script.cgi", []byte("SOURCE"), 0644)
	os.WriteFile(dir+"localhost/@/note~1.txt", []byte("note"), 0644)
	os.WriteFile(dir+"localhost/@/x.jſp", []byte("text"), 0644)
	base := startServer(t)
	if runtime.GOOS != "windows" { // Windows refuses these names for every site
		for _, path := range []string{"/note~1.txt", "/x.j%C5%BFp"} {
			if res, _ := requestTo(t, base, "GET", path); res.StatusCode != 200 {
				t.Errorf("GET %s without preprocessors: %d; expected 200", path, res.StatusCode)
			}
		}
	}
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("preprocessor: %q", msg)
	}
	for _, path := range []string{"/note~1.txt", "/x.j%C5%BFp", "/SCRIPT~1.CGI", "/script.cgi:$DATA", "/script.cg%C4%B1"} {
		if res, body := requestTo(t, base, "GET", path); res.StatusCode != 404 || strings.Contains(body, "SOURCE") {
			t.Errorf("GET %s with preprocessors: %d %q; expected 404", path, res.StatusCode, body)
		}
	}
	if res, body := requestTo(t, base, "GET", "/script.cgi"); res.StatusCode != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
		t.Errorf("GET /script.cgi: %d %q; expected the CGI's answer", res.StatusCode, body)
	}
	if res, body := requestTo(t, base, "GET", "/"); res.StatusCode != 200 || body != "hello" {
		t.Errorf("GET /: %d %q", res.StatusCode, body)
	}
}

// R6 V-04: where the sites directory takes a name in other capitals for the same file, on whatever system, the
// rewrites and the paths are treated as Windows and macOS always are. With the Linux binary on a volume of Windows,
// "/PRIVATE/x" opened the file that the rewrite of "/private/" covers.
func TestR6_V04_SitesDirectoryThatFoldsNames(t *testing.T) {
	dir := initForTest(t)
	if folds, expected := probeNameFolding(dir, []diskSite{{"localhost", ""}}), namesIgnoreCaseIn(t, dir); folds != expected {
		t.Errorf("probeNameFolding = %v in a directory where names ignore case = %v", folds, expected)
	}
	if sitesDirFolds.Load() != namesIgnoreCaseIn(t, dir) {
		t.Errorf("after loading: sitesDirFolds = %v; expected %v", sitesDirFolds.Load(), namesIgnoreCaseIn(t, dir))
	}
	if probeNameFolding(dir, nil) || probeNameFolding(dir, []diskSite{{"127.0.0.1", ""}, {"missing.test", ""}}) {
		t.Error("probeNameFolding without a site to look at reports that names fold")
	}
	os.MkdirAll(dir+"localhost/@/private", 0755)
	os.WriteFile(dir+"localhost/@/private/secret.txt", []byte("SECRET"), 0644)
	os.WriteFile(dir+"localhost/@/denied.html", []byte("denied"), 0644)
	globalMutex.Lock()
	ok, msg := subdomainContentCheckers["="](true, map[string]interface{}{"/private/": "/denied.html"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("rewrite: %q", msg)
	}
	base := startServer(t)
	previous := sitesDirFolds.Load()
	t.Cleanup(func() { sitesDirFolds.Store(previous) })
	sitesDirFolds.Store(true) // As a reload leaves it for a volume of Windows mounted on Linux
	for _, path := range []string{"/private/secret.txt", "/PRIVATE/secret.txt", "/Private/SECRET.TXT"} {
		if res, body := requestTo(t, base, "GET", path); body == "SECRET" || (res.StatusCode == 200 && body != "denied") {
			t.Errorf("GET %s where names fold: %d %q; expected the target of the rewrite of /private/", path, res.StatusCode, body)
		}
	}
	if runtime.GOOS != "darwin" {
		if _, allowed := cleanRequestPath("/PRIVAT~1/secret.txt"); allowed {
			t.Error("a short name is accepted in a path where the sites directory folds names")
		}
	}
}
