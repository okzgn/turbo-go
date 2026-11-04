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
