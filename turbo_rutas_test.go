package main

// A1 (H1, H2, H48), A2 (H3, H47), B2 (H11): la ruta pedida se decodifica, se
// limpia y nunca sale de @; lo que se rechaza responde 404, exista o no; las
// extensiones no distinguen mayúsculas.

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

// rawRequest envía una línea de petición tal cual (sin que un cliente HTTP la
// normalice) con Host: localhost y devuelve el código y el cuerpo.
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

// servingFixture monta localhost con un CGI (cgiecho) y archivos fuera de @:
// localhost/x.cgi, localhost/secreto.txt y <dir>/fuera.txt.
func servingFixture(t *testing.T) (dir, base string) {
	dir = initForTest(t)
	os.WriteFile(dir+"localhost/x.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/secreto.txt", []byte("SECRETO"), 0644)
	os.WriteFile(dir+"fuera.txt", []byte("SECRETO"), 0644)
	os.WriteFile(dir+"localhost/@/dentro.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/@/nota.txt", []byte("nota"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	return dir, startServer(t)
}

// H1, H2: ninguna ruta sale de @. Lo de fuera ni se ejecuta ni se sirve, y la
// respuesta es 404 tanto si el archivo existe como si no.
func TestA1_PathTraversal(t *testing.T) {
	_, base := servingFixture(t)
	for _, path := range []string{
		"/../x.cgi", "/../../x.cgi", "/a/../../x.cgi", "/%2e%2e/x.cgi", "/..%2fx.cgi", "/%2e%2e%2fx.cgi",
		"/..\\x.cgi", "/x.cgi%00.txt", "/../secreto.txt", "/../../fuera.txt", "/%2E%2E/secreto.txt",
		"/../no-existe.txt", "/..%5csecreto.txt", "/nota.txt%00", "/./../secreto.txt",
	} {
		code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1")
		if code != 404 || strings.Contains(body, "SECRETO") || strings.Contains(body, "SCRIPT_FILENAME") {
			t.Errorf("GET %s: %d %.80q; se esperaba 404 sin ejecutar ni servir nada de fuera de @", path, code, body)
		}
	}
	// Inside @ everything keeps working.
	if code, body := rawRequest(t, base, "GET /dentro.cgi HTTP/1.1"); code != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
		t.Errorf("GET /dentro.cgi: %d %.80q", code, body)
	}
	if code, body := rawRequest(t, base, "GET //nota.txt HTTP/1.1"); code != 200 || body != "nota" {
		t.Errorf("GET //nota.txt: %d %q", code, body)
	}
}

// A1: un enlace simbólico dentro de @ que apunta fuera no se sigue.
func TestA1_SymlinkOutside(t *testing.T) {
	dir, base := servingFixture(t)
	if err := os.Symlink(dir+"fuera.txt", dir+"localhost/@/enlace.txt"); err != nil {
		t.Skip("no se pueden crear enlaces simbólicos:", err)
	}
	if code, body := rawRequest(t, base, "GET /enlace.txt HTTP/1.1"); code != 404 || strings.Contains(body, "SECRETO") {
		t.Errorf("enlace a fuera de @: %d %q; se esperaba 404", code, body)
	}
}

// H3, H47: con mayúsculas, un punto o un espacio al final, un flujo
// alternativo o un nombre reservado de Windows, un archivo preprocesado se
// ejecuta o da 404, nunca se sirve su código.
func TestA2_ExtensionsAndSpecialNames(t *testing.T) {
	dir, base := servingFixture(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("FUENTE"), 0644)
	for _, path := range []string{"/x.CGI", "/x.Cgi", "/x.cgi.", "/x.cgi%20", "/x.cgi::$DATA", "/CON.cgi", "/x.cgi%2e", "/x.cgi/", "/x.cgi//", "/x.cgi%2f"} {
		code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1")
		if strings.Contains(body, "FUENTE") || (code != 404 && !strings.Contains(body, "SCRIPT_FILENAME=")) {
			t.Errorf("GET %s: %d %.80q; se esperaba la ejecución del CGI o 404, nunca el código", path, code, body)
		}
	}
	if runtime.GOOS != "windows" { // On Linux, X.CGI is another file, also run with the "cgi" preprocessor
		os.WriteFile(dir+"localhost/@/y.CGI", []byte("FUENTE"), 0644)
		if code, body := rawRequest(t, base, "GET /y.CGI HTTP/1.1"); code != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
			t.Errorf("GET /y.CGI en Linux: %d %.80q; se esperaba la ejecución", code, body)
		}
	}
	// A preprocessor or MIME added with capitals is stored in lower case.
	globalMutex.Lock()
	subdomainContentCheckers["$"](true, map[string]interface{}{"TXT": "text/x-prueba"}, false, "localhost", "")
	_, lower := mimeTypes["localhost"]["txt"]
	globalMutex.Unlock()
	if !lower {
		t.Error("la extensión MIME TXT no se guardó como txt")
	}
}

// H55: en Windows, un nombre corto 8.3 (INDEX~1.PHT por index.phtml) abriría
// el archivo con otra extensión, sin su preprocesador: esos segmentos se
// rechazan allí; en los demás sistemas son nombres corrientes.
func TestH55_WindowsShortNames(t *testing.T) {
	dir, base := servingFixture(t)
	os.WriteFile(dir+"localhost/@/pagina.cgix", []byte("FUENTE"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgix": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	for _, path := range []string{"/PAGINA~1.CGI", "/pagina~1.cgi", "/PAGINA~1"} {
		if code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1"); strings.Contains(body, "FUENTE") || (runtime.GOOS == "windows" && code != 404) {
			t.Errorf("GET %s: %d %.80q; se esperaba 404, nunca el código", path, code, body)
		}
	}
	for segment, windows := range map[string]bool{"PAGINA~1.CGI": false, "a~9": false, "a~b.txt": true, "~": true, "copia~.txt": true} {
		if got := pathSegmentAllowed(segment, true); got != windows {
			t.Errorf("pathSegmentAllowed(%q, windows) = %v; se esperaba %v", segment, got, windows)
		}
		if !pathSegmentAllowed(segment, false) {
			t.Errorf("pathSegmentAllowed(%q) fuera de Windows = false", segment)
		}
	}
}

// H47: la subida de archivos descarta los nombres reservados de Windows, los
// flujos alternativos y los que acaban en punto o espacio.
func TestA2_UploadedNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"sitio/a.txt": true, "sitio/css/b.css": true, "sitio/CON": false, "sitio/con.txt": false, "sitio/x/aux.html": false,
		"sitio/x.php::$DATA": false, "sitio/x.php.": false, "sitio/x.php ": false, "sitio/COM1.log": false, "sitio/LPT9": false,
		"sitio/console.txt": true, "sitio/connect.txt": true,
	} {
		if _, got := uploadedFilePath(name); got != ok {
			t.Errorf("uploadedFilePath(%q) = %v; se esperaba %v", name, got, ok)
		}
	}
}

// H11 (D5): las rutas con codificación porcentual se decodifican; una barra
// codificada no separa carpetas; las claves de reescritura se comparan con la
// ruta decodificada.
func TestB2_PercentEncodedPaths(t *testing.T) {
	dir, base := servingFixture(t)
	os.WriteFile(dir+"localhost/@/a b.txt", []byte("con espacio"), 0644)
	os.WriteFile(dir+"localhost/@/café.txt", []byte("con tilde"), 0644)
	os.MkdirAll(dir+"localhost/@/carpeta", 0755)
	os.WriteFile(dir+"localhost/@/carpeta/x", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/@/destino.txt", []byte("destino"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["="](true, map[string]interface{}{"/otra ruta": "/destino.txt"}, false, "localhost", "")
	globalMutex.Unlock()
	for path, want := range map[string]string{
		"/a%20b.txt":     "con espacio",
		"/caf%C3%A9.txt": "con tilde",
		"/otra%20ruta":   "destino",
	} {
		if code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1"); code != 200 || body != want {
			t.Errorf("GET %s: %d %q; se esperaba 200 %q", path, code, body, want)
		}
	}
	if code, _ := rawRequest(t, base, "GET /carpeta%2Fx HTTP/1.1"); code != 404 {
		t.Errorf("GET /carpeta%%2Fx: %d; se esperaba 404 (la barra codificada no separa carpetas)", code)
	}
}

// H58: {REWRITE_COMPLEMENT} es lo que sigue a la clave en la ruta ya
// decodificada y limpia con la que se compara la clave, más la consulta.
func TestH58_RewriteComplementDecoded(t *testing.T) {
	_, base := servingFixture(t)
	globalMutex.Lock()
	subdomainContentCheckers["="](true, map[string]interface{}{"/viejo dir/": "/dentro.cgi?x={REWRITE_COMPLEMENT}"}, false, "localhost", "")
	globalMutex.Unlock()
	for path, want := range map[string]string{
		"/viejo%20dir/a.txt":     "x=a.txt",
		"/viej%6F%20dir/a.txt":   "x=a.txt",
		"//viejo%20dir/a.txt":    "x=a.txt",
		"/viejo%20dir/b%20c.txt": "x=b+c.txt",
		"/viejo%20dir/a.txt?q=1": "x=a.txt%3Fq%3D1",
	} {
		code, body := rawRequest(t, base, "GET "+path+" HTTP/1.1")
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("GET %s: %d %.120q; se esperaba la consulta %q", path, code, body, want)
		}
	}
}

// H48: para cualquier entrada, la ruta limpia queda dentro de la raíz o se
// rechaza.
func FuzzServePath(f *testing.F) {
	for _, s := range []string{"/", "/a/b", "/../x", "/%2e%2e/x", "/..%2fx", "//x", "/a/./b/../c", "/x%00", "/..\\x", "/CON", "/a.", "/a ", "/a::$DATA", "/%"} {
		f.Add(s)
	}
	root := filepath.FromSlash("/srv/sitio/@")
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
				t.Fatalf("cleanRequestPath(%q) = %q, con %q", raw, clean, segment)
			}
		}
		if rel, err := filepath.Rel(root, filepath.Join(root, filepath.FromSlash(clean))); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("cleanRequestPath(%q) = %q sale de la raíz (%q)", raw, clean, rel)
		}
	})
}
