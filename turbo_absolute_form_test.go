package main

// T32 (N38): a request in absolute form (GET http://host/x HTTP/1.1) is served
// like one in origin form, and Go answers OPTIONS *.

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// rawFullRequest sends a whole HTTP/1.1 request as it is and returns the response.
func rawFullRequest(t *testing.T, base, request string) (*http.Response, string) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte(request))
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%q: %v", request, err)
	}
	defer res.Body.Close()
	var body strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return res, body.String()
}

func TestN38_AbsoluteForm(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	res, body := rawFullRequest(t, base, "GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if res.StatusCode != 200 || body != "hello" {
		t.Errorf("absolute form: %d %q; expected 200 hello", res.StatusCode, body)
	}
	// The host of the URL wins over the Host header (RFC 9112 §3.2.2).
	res, body = rawFullRequest(t, base, "GET http://localhost/ HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n")
	if res.StatusCode != 200 || body != "hello" {
		t.Errorf("absolute form with another Host: %d %q", res.StatusCode, body)
	}
	// A redirection to www keeps the path, not the absolute URI.
	withGlobalLock(func() { siteSSLConfig["localhost"]["W"] = true })
	res, _ = rawFullRequest(t, base, "GET http://localhost/a?b=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if location := res.Header.Get("Location"); res.StatusCode != 301 || location != "http://www.localhost/a?b=1" {
		t.Errorf("W redirect in absolute form: %d %q", res.StatusCode, location)
	}
}

func TestN38_OptionsAsterisk(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	res, _ := rawFullRequest(t, base, "OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if res.StatusCode != 200 {
		t.Errorf("OPTIONS *: %d; expected 200", res.StatusCode)
	}
}

// Review of 57cbb3c, S3: a target that doesn't start with "/" (an opaque one, such as x:@evil.test, or "*" outside
// OPTIONS) gets 400. Before, it was taken as the path and went after the host of a redirection: with W on,
// Location: http://www.localhost@evil.test.
func TestRL_S3_TargetWithoutSlash(t *testing.T) {
	initForTest(t)
	globalMutex.Lock()
	siteSSLConfig["localhost"]["W"] = true // localhost redirects to www.localhost
	globalMutex.Unlock()
	addr := strings.TrimPrefix(startServer(t), "http://")
	for _, target := range []string{"x:@evil.test", "*"} {
		res, _ := sendRaw(t, addr, "GET "+target+" HTTP/1.1\r\nHost: localhost\r\n\r\n")
		if res.StatusCode != 400 || res.Header.Get("Location") != "" {
			t.Errorf("GET %s: %d, Location %q; expected 400", target, res.StatusCode, res.Header.Get("Location"))
		}
	}
	res, _ := sendRaw(t, addr, "GET http://localhost/a HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if res.StatusCode != 301 || res.Header.Get("Location") != "http://www.localhost/a" {
		t.Errorf("GET in absolute form: %d, Location %q; expected 301 to http://www.localhost/a", res.StatusCode, res.Header.Get("Location"))
	}
}
