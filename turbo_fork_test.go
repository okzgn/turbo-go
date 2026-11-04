package main

// Go security patches ported to the fork (#66, T0.11).

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// CVE-2025-22871: the lines of a chunked body must end in CRLF; a bare LF, or
// a CR before the end, is an error (request smuggling behind a proxy).
func TestT011_ChunkedBareLF(t *testing.T) {
	for _, body := range []string{
		"1\nX\r\n0\r\n\r\n",      // Size line ended by a bare LF
		"1\r\nX\r\n0\n\r\n",      // Last size line ended by a bare LF
		"1\rx\r\nX\r\n0\r\n\r\n", // CR before the end
	} {
		if b, err := io.ReadAll(customNetHttp.NewChunkedReader(strings.NewReader(body))); err == nil {
			t.Errorf("%q accepted: %q", body, b)
		}
	}
	b, err := io.ReadAll(customNetHttp.NewChunkedReader(strings.NewReader("1;ext=1 \r\nX\r\n0\r\n\r\n")))
	if err != nil || string(b) != "X" {
		t.Errorf("valid chunked body: %q %v", b, err)
	}
}

// CVE-2023-39326: a sender can't add an unlimited amount of data that isn't
// content (chunk extensions).
func TestT011_ChunkedExcess(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 64; i++ {
		sb.WriteString("1;" + strings.Repeat("a", 2000) + "\r\nX\r\n")
	}
	sb.WriteString("0\r\n\r\n")
	if _, err := io.ReadAll(customNetHttp.NewChunkedReader(strings.NewReader(sb.String()))); err == nil {
		t.Fatal("128 KiB of extensions for 64 bytes of data accepted")
	}
}

// CVE-2026-78667: a Range header with more than 200 ranges is ignored and the
// whole file is served.
func TestT011_RangeLimit(t *testing.T) {
	dir := initForTest(t)
	content := strings.Repeat("0123456789", 100)
	os.WriteFile(dir+"localhost/@/r.txt", []byte(content), 0644)
	base := startServer(t)
	ranges := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("%d-%d", i*2, i*2)
		}
		return "bytes=" + strings.Join(parts, ",")
	}
	code, _, err := get(base, "/r.txt", map[string]string{"Range": ranges(2)})
	if err != nil || code != 206 {
		t.Errorf("2 ranges -> %d %v; expected 206", code, err)
	}
	code, body, err := get(base, "/r.txt", map[string]string{"Range": ranges(201)})
	if err != nil || code != 200 || body != content {
		t.Errorf("201 ranges -> %d (%d bytes) %v; expected 200 with the whole file", code, len(body), err)
	}
}

// CVE-2026-94439: after answering a CONNECT, the server doesn't reuse the
// connection for another request.
func TestT011_ConnectNoReuse(t *testing.T) {
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		w.WriteHeader(200)
	})}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatalf("response to the CONNECT: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("CONNECT -> %d", res.StatusCode)
	}
	if res2, err := http.ReadResponse(br, nil); err == nil {
		t.Fatalf("the connection was reused after the CONNECT: second response %d", res2.StatusCode)
	}
}

// selfSignedTLS returns a server TLS configuration with a self-signed
// certificate for localhost and HTTP/2 enabled.
func selfSignedTLS(t testing.TB) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
}

// HTTP/2 smoke test after porting the flow control and HPACK patches
// (CVE-2026-78663, CVE-2026-97032): requests with a body, large response
// headers (asynchronous write) and requests cancelled halfway.
func TestT011_HTTP2Smoke(t *testing.T) {
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Big", strings.Repeat("v", 8000))
		fmt.Fprintf(w, "%s %d", r.Proto, n)
	})}
	cfg := selfSignedTLS(t)
	srv.TLSConfig = cfg
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	url := "https://" + l.Addr().String() + "/"
	body := strings.Repeat("x", 100<<10)
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
			if i%4 == 0 { // Cancelled while it sends the body
				pr, pw := io.Pipe()
				req, _ = http.NewRequestWithContext(ctx, "POST", url, pr)
				go func() { pw.Write([]byte(body[:20000])); cancel(); pw.Close() }()
				if res, err := c.Do(req); err == nil {
					res.Body.Close()
				}
				return
			}
			res, err := c.Do(req)
			if err != nil {
				errs <- err
				return
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if want := fmt.Sprintf("HTTP/2.0 %d", len(body)); string(b) != want {
				errs <- fmt.Errorf("response %q; expected %q", b, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// P6: the timeouts apply without a restart. An HTTP/2 connection opened with
// IT = 0 must not break when the panel enables IT (the idle timer didn't exist
// yet).
func TestT04_HTTP2IdleTimeoutEnabledLater(t *testing.T) {
	previous := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = previous }) }) })
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.IT = 0 }) })
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		w.Write([]byte("ok"))
	})}
	cfg := selfSignedTLS(t)
	srv.TLSConfig = cfg
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	url := "https://" + l.Addr().String() + "/"
	fetch := func(step string) {
		res, err := c.Get(url)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.ProtoMajor != 2 || string(b) != "ok" {
			t.Fatalf("%s: %s %q", step, res.Proto, b)
		}
	}
	fetch("with IT = 0")
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.IT = 300 * time.Millisecond }) })
	fetch("after enabling IT") // Same connection: it closes a stream while the timer doesn't exist yet
	fetch("third request")
	time.Sleep(time.Second) // The timer created on the fly closes the idle connection
	fetch("after the idle close")
}
