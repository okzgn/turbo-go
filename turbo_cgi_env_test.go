package main

// T17 (N37, I8, I10): a CGI's environment carries in SCRIPT_NAME the URL path
// of the script, not its path on disk, and the site's headers win over the
// CGI's headers with the same name.

import (
	"bytes"
	"net/url"
	"os"
	"strings"
	"testing"
)

// cgiEnv reads the NAME=value lines of cgiecho's response.
func cgiEnv(body string) map[string]string {
	env := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		if name, value, found := strings.Cut(line, "="); found {
			env[name] = value
		}
	}
	return env
}

func TestN37_CGIScriptName(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/app", 0755)
	os.WriteFile(dir+"localhost/@/app/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	subdomainContentCheckers["="](true, map[string]interface{}{"/r": "/app/x.cgi?b=2"}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	for _, c := range []struct{ path, scriptName, requestURI, query string }{
		{"/app/x.cgi?a=1", "/app/x.cgi", "/app/x.cgi?a=1", "a=1"},
		{"/r?a=1", "/app/x.cgi", "/r?a=1", "a=1&b=2"},
	} {
		code, body, err := get(base, c.path, nil)
		if err != nil || code != 200 {
			t.Fatalf("GET %s: %d %v", c.path, code, err)
		}
		env := cgiEnv(body)
		want := map[string]string{
			"SCRIPT_NAME":     c.scriptName,
			"PATH_INFO":       "",
			"REQUEST_URI":     c.requestURI,
			"QUERY_STRING":    c.query,
			"SCRIPT_FILENAME": dir + "localhost/@/app/x.cgi",
			"DOCUMENT_ROOT":   dir + "localhost/@",
		}
		for name, value := range want {
			if env[name] != value {
				t.Errorf("GET %s: %s=%q; expected %q", c.path, name, env[name], value)
			}
		}
	}
}

func TestI08_SiteHeadersWinOverCGI(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	subdomainContentCheckers["."](true, map[string]interface{}{"X-Site": "from-site"}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	query := url.Values{"header": {"X-Site: from-cgi", "X-Cgi: own"}}.Encode()
	res, _, err := rawGet(base, "localhost", "/x.cgi?"+query)
	if err != nil {
		t.Fatal(err)
	}
	if values := res.Header.Values("X-Site"); len(values) != 1 || values[0] != "from-site" {
		t.Errorf("X-Site: %q; expected only the site's", values)
	}
	if got := res.Header.Get("X-Cgi"); got != "own" {
		t.Errorf("X-Cgi: %q; expected the CGI's", got)
	}
}

// N90: an HTTP/2 request may carry a host field besides :authority, which chose the site. One that names another
// host is malformed (RFC 9113, 8.3.1) and gets 400; the same host is dropped. Before, it reached the CGI, where
// its HTTP_HOST, the last one in the environment, won over the host that chose the site.
func TestN90_HTTP2HostFieldDifferentFromAuthority(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	h := dialH2(t, forkServer(t, true, serverHandlerFn("s")))
	request := func(host string) string {
		var b bytes.Buffer
		fields := []string{":method", "GET", ":scheme", "https", ":path", "/x.cgi", ":authority", "localhost"}
		if host != "" {
			fields = append(fields, "host", host)
		}
		for i := 0; i < len(fields); i += 2 {
			hpackLiteral(&b, fields[i], fields[i+1])
		}
		id := h.id
		h.id += 2
		h.frame(1, 0x5, id, b.Bytes())
		body, _, _ := h.read(id)
		return body
	}
	if body := request("evil.test"); strings.Contains(body, "evil.test") || !strings.Contains(body, "400") {
		t.Errorf("host evil.test with :authority localhost: %q; expected 400", body)
	}
	for _, host := range []string{"", "localhost", "LocalHost"} {
		if env := cgiEnv(request(host)); env["HTTP_HOST"] != "localhost" {
			t.Errorf("host %q with :authority localhost: HTTP_HOST=%q; expected localhost", host, env["HTTP_HOST"])
		}
	}
}

// rawCGIEnv sends request as it is to the server at addr and returns the environment that cgiecho saw.
func rawCGIEnv(t *testing.T, addr string, request string) map[string]string {
	t.Helper()
	res, body := sendRaw(t, addr, request)
	if res.StatusCode != 200 {
		t.Fatalf("%q: %d %q", request, res.StatusCode, body)
	}
	return cgiEnv(body)
}

// Review of 57cbb3c, S2: a request header with "_" in its name doesn't reach the CGI, as in Apache: X_Forwarded_For
// became the same HTTP_X_FORWARDED_FOR as the X-Forwarded-For that a proxy in front sets, and the client's won
// as often as not.
func TestRL_S2_UnderscoreHeadersDontReachCGI(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	addr := strings.TrimPrefix(startServer(t), "http://")
	for i := 0; i < 20; i++ { // The order in which they were turned into variables was the map's
		env := rawCGIEnv(t, addr, "GET /x.cgi?env=HTTP_X_FORWARDED_FOR,HTTP_X_CUSTOM HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.7\r\nX_Forwarded_For: 127.0.0.1\r\nX_Custom: 1\r\nConnection: close\r\n\r\n")
		if env["HTTP_X_FORWARDED_FOR"] != "203.0.113.7" || env["HTTP_X_CUSTOM"] != "" {
			t.Fatalf("attempt %d: HTTP_X_FORWARDED_FOR=%q, HTTP_X_CUSTOM=%q; expected the proxy's and nothing", i, env["HTTP_X_FORWARDED_FOR"], env["HTTP_X_CUSTOM"])
		}
	}
}

// Review of 57cbb3c, S4: the CGI gets in HTTP_HOST and SERVER_NAME the host that chose the site, in lower case,
// without a final dot, with its port only if it is a number: before, it got whatever came around the name
// ("[localhost]x'()").
func TestRL_S4_CanonicalHostForCGI(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	addr := strings.TrimPrefix(startServer(t), "http://")
	for host, want := range map[string][2]string{
		"[localhost]x'()": {"localhost", "localhost"},
		"LocalHost.:8080": {"localhost:8080", "localhost"},
		"localhost:x":     {"localhost", "localhost"},
	} {
		env := rawCGIEnv(t, addr, "GET /x.cgi?env=SERVER_NAME HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
		if env["HTTP_HOST"] != want[0] || env["SERVER_NAME"] != want[1] {
			t.Errorf("Host %q: HTTP_HOST=%q, SERVER_NAME=%q; expected %q and %q", host, env["HTTP_HOST"], env["SERVER_NAME"], want[0], want[1])
		}
	}
}
