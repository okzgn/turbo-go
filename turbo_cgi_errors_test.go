package main

// T16 (N44, N47, N48, F5): the 504 of a CGI that goes past WT reaches the
// client, in HTTP/1 and in HTTP/2, and the CGI's errors (a malformed Status,
// header lines or blocks that are too long, no headers) get Turbo's
// template, never an empty 200 or a panic.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// cgiSite leaves x.cgi in localhost with cgiecho as its preprocessor.
func cgiSite(t testing.TB) string {
	t.Helper()
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	return dir
}

// isTemplate says whether body is Turbo's error template for code.
func isTemplate(body string, code string) bool {
	return strings.HasPrefix(body, serverName+"\n"+code)
}

func TestN44_CGITimeout504HTTP1(t *testing.T) {
	cgiSite(t)
	if ok, msg := setting("WT", "500ms"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	start := time.Now()
	code, body, err := get(base, "/x.cgi?sleep=3000", nil)
	if err != nil || code != 504 || !isTemplate(body, "504") {
		t.Errorf("CGI slower than WT: %d %q %v; expected 504 with the template", code, body, err)
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Errorf("the response took %v; expected little more than WT", elapsed)
	}
}

func TestN44_CGITimeout504HTTP2(t *testing.T) {
	cgiSite(t)
	if ok, msg := setting("WT", "500ms"); !ok {
		t.Fatal(msg)
	}
	cfg := selfSignedTLS(t)
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(serverHandlerFn("s")), TLSConfig: cfg, ConnState: connHandler}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "https://"+l.Addr().String()+"/x.cgi?sleep=3000", nil)
	req.Host = "localhost"
	res, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("HTTP/2: %v", err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.ProtoMajor != 2 || res.StatusCode != 504 || !isTemplate(string(b), "504") {
		t.Errorf("HTTP/2: %s %d %q; expected 504 with the template", res.Proto, res.StatusCode, b)
	}
}

func TestN48_CGIBadStatus(t *testing.T) {
	cgiSite(t)
	base, errLog := startServerLog(t)
	for _, status := range []string{"2", "abc", "099", "-10", "+50", "100", "600", "2000"} {
		query := url.Values{"header": {"Status: " + status}}.Encode()
		code, body, err := get(base, "/x.cgi?"+query, nil)
		if err != nil || code != 500 || !isTemplate(body, "500") {
			t.Errorf("Status: %s -> %d %q %v; expected 500 with the template", status, code, body, err)
		}
	}
	if strings.Contains(errLog.String(), "panic") {
		t.Errorf("panic in the server:\n%s", errLog.String())
	}
	if code, _, _ := get(base, "/x.cgi?"+url.Values{"header": {"Status: 404 No"}}.Encode(), nil); code != 404 {
		t.Errorf("Status: 404 -> %d", code)
	}
}

func TestN48_CGILongHeaders(t *testing.T) {
	cgiSite(t)
	base := startServer(t)
	// A 4 KiB Set-Cookie (or CSP) is delivered.
	res, _, err := rawGet(base, "localhost", "/x.cgi?bigheader=4096")
	if err != nil || res.StatusCode != 200 || len(res.Header.Get("X-Big")) < 4000 {
		t.Errorf("4 KiB header: %v %v", res, err)
	}
	// Above 16 KiB per line, 500 with the template.
	code, body, _ := get(base, "/x.cgi?bigheader=17000", nil)
	if code != 500 || !isTemplate(body, "500") {
		t.Errorf("17000-byte header: %d %q; expected 500 with the template", code, body)
	}
}

// N47: a CGI answer without Content-Type (a header that isn't one, nor Location) gets the 500 of the template,
// and a chunked body reaches the CGI whole, with its length: Turbo reads it before the CGI starts.
func TestN47_CGIErrorsWithTemplate(t *testing.T) {
	dir := cgiSite(t)
	os.WriteFile(dir+"localhost/@/no-type.cgi", []byte("X-Other: 1\r\n\r\nbody\n"), 0644) // With raw=1, cgiecho writes the script as its answer
	base := startServer(t)
	if code, body, err := get(base, "/no-type.cgi?raw=1", nil); err != nil || code != 500 || !isTemplate(body, "500") {
		t.Errorf("CGI response without Content-Type: %d %q %v; expected 500 with the template", code, body, err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("POST /x.cgi HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, _ := io.ReadAll(conn)
	response := string(raw)
	if !strings.HasPrefix(response, "HTTP/1.1 200 ") || !strings.Contains(response, "CONTENT_LENGTH=3\n") || !strings.Contains(response, "BODY_BYTES=3\n") {
		t.Errorf("chunked body to a CGI:\n%s", response)
	}
}

// FuzzCGIResponse: whatever a CGI writes as its answer (cgiecho with raw=1 writes the script file as it is),
// the client gets a well-formed HTTP/1.1 response with a status of 200-599, a single Server header and no CR or
// LF inside a header; an answer without a line break gets the 500 of the template; nothing panics, and the
// server keeps serving.
func FuzzCGIResponse(f *testing.F) {
	for _, seed := range []string{
		"Content-Type: text/plain\r\n\r\nhola",
		"Status: 404\r\nContent-Type: text/plain\r\n\r\nnot here",
		"Status: 099\r\n\r\n",
		"Status: 200 OK\nContent-Type: text/html\n\n<p>",
		"Location: /other\r\n\r\n",
		"Location: http://example.com/\r\nStatus: 301\r\n\r\n",
		"Content-Type: text/plain",
		"X-A: a\rb\r\nContent-Type: text/plain\r\n\r\n",
		"no colon\r\nContent-Type: text/plain\r\n\r\n",
		"Bad name: x\r\nContent-Type: text/plain\r\n\r\n",
		"Server: other\r\nContent-Type: text/plain\r\n\r\n",
		"Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nabcdef",
		"Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"Status: 204\r\nContent-Type: text/plain\r\n\r\nbody",
		"Content-Type: text/plain\r\nX-Long: " + strings.Repeat("a", 17000) + "\r\n\r\n",
		"\r\n\r\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	dir := cgiSite(f)
	base, errLog := startServerLog(f)
	addr := strings.TrimPrefix(base, "http://")
	script := dir + "localhost/@/x.cgi"
	var client atomic.Uint32
	// Each input comes from another loopback address: at fuzzing speed, one address would be blocked by the
	// per-IP limit (429, and then its new connections closed). They go round 65 536 of them: past
	// ipReferenceLimit addresses, which a worker reaches in a long run, the new ones share the limiter's
	// overflow entry and get the 429 too (the cleaning that frees the entries doesn't run in the tests).
	request := func(t *testing.T, path string) (*http.Response, string) {
		n := client.Add(1)
		conn := dialRetrying(t, &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 1, byte(n>>8), byte(n))}}, addr)
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			return nil, err.Error()
		}
		body, _ := io.ReadAll(res.Body) // A body shorter than the CGI's Content-Length is the CGI's fault
		res.Body.Close()
		return res, string(body)
	}
	f.Fuzz(func(t *testing.T, output []byte) {
		if len(output) > 128<<10 {
			return
		}
		if err := os.WriteFile(script, output, 0644); err != nil {
			t.Fatal(err)
		}
		res, body := request(t, "/x.cgi?raw=1")
		if res == nil {
			t.Fatalf("CGI output %q: unreadable response: %s", output, body)
		}
		if res.StatusCode < 200 || res.StatusCode > 599 {
			t.Errorf("CGI output %q: status %d", output, res.StatusCode)
		}
		if servers := res.Header.Values("Server"); len(servers) != 1 || servers[0] != serverName {
			t.Errorf("CGI output %q: Server %q; expected only %q", output, servers, serverName)
		}
		for name, values := range res.Header {
			for _, value := range values {
				if strings.ContainsAny(name+value, "\r\n") {
					t.Errorf("CGI output %q: header with CR or LF: %q: %q", output, name, value)
				}
			}
		}
		if !bytes.Contains(output, []byte("\n")) && (res.StatusCode != 500 || !isTemplate(body, "500")) {
			t.Errorf("CGI output without line breaks %q: %d %q; expected the 500 of the template", output, res.StatusCode, body)
		}
		if log := errLog.String(); strings.Contains(log, "panic") {
			t.Fatalf("CGI output %q: panic in the server:\n%s", output, log)
		}
		if res, body := request(t, "/"); res == nil || res.StatusCode != 200 || body != "hello" {
			t.Fatalf("after the CGI output %q, the site answers %v %q", output, res, body)
		}
	})
}

// N83: the framing of a response is Turbo's: the hop-by-hop headers a CGI writes (Transfer-Encoding,
// Connection...), a Content-Length given more than once and a header with control characters are dropped.
// Before, a Transfer-Encoding of the CGI went out next to the server's chunked, and the client (or a proxy)
// couldn't tell where the response ended; and a NUL in a header made the response unreadable.
func TestN83_CGIHopByHopHeadersDropped(t *testing.T) {
	dir := cgiSite(t)
	base := startServer(t)
	addr := strings.TrimPrefix(base, "http://")
	for _, output := range []string{
		"Content-Type: text/plain\r\nTransfer-Encoding: 0\r\n\r\nabcd",
		"Content-Type: text/plain\r\nTransfer-Encoding: gzip\r\nConnection: x-custom\r\nKeep-Alive: timeout=1\r\nUpgrade: something\r\n\r\nabcd",
		"Content-Type: text/plain\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
		"Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\nabcd",
		"Content-Type: text/plain\r\nX-Null: a\x00b\r\nX-Control: c\x1bd\r\n\r\nabcd",
	} {
		os.WriteFile(dir+"localhost/@/x.cgi", []byte(output), 0644)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(conn, "GET /x.cgi?raw=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			t.Errorf("CGI output %q: unreadable response: %v", output, err)
			continue
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		conn.Close()
		if err != nil || string(body) != "abcd" {
			t.Errorf("CGI output %q: body %q %v; expected abcd", output, body, err)
		}
		for _, name := range []string{"Connection", "Keep-Alive", "Upgrade", "X-Null", "X-Control"} {
			if value := res.Header.Get(name); value != "" {
				t.Errorf("CGI output %q: the response carries %s: %s", output, name, value)
			}
		}
		if len(res.TransferEncoding) > 1 || len(res.TransferEncoding) == 1 && res.TransferEncoding[0] != "chunked" {
			t.Errorf("CGI output %q: Transfer-Encoding %q", output, res.TransferEncoding)
		}
	}
}
