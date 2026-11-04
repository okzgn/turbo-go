package main

// Turbo's customizations of Go's net/http (patches P1-P12 of
// customNetHttp/PATCHES.md, T2.1). The patches P6 (IT in HTTP/2) and P12 (CGI)
// also have their tests in turbo_fork_test.go and turbo_serving_test.go.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// expectedTemplate reproduces Turbo's error response for a code.
func expectedTemplate(code int, detail string) string {
	templates := *customNetHttp.TurboErrorTemplates.Load()
	v, ok := templates[code]
	if !ok {
		v = templates[0]
	}
	if !strings.HasPrefix(v, "<") {
		v = strings.ReplaceAll(v, `\n`, "\n")
	}
	return strings.ReplaceAll(v, "{TURBO_RESPONSE_CODE}", strconv.Itoa(code)) + "\n" + detail + "\n"
}

// withLimit changes an atomic limit of the fork during the test.
func withLimit(t testing.TB, limit interface {
	Load() int64
	Store(int64)
}, value int64) {
	t.Helper()
	previous := limit.Load()
	limit.Store(value)
	t.Cleanup(func() { limit.Store(previous) })
}

// forkServer starts a customNetHttp.Server with the given handler, over
// HTTP or HTTPS (with HTTP/2), and returns its address.
func forkServer(t testing.TB, withTLS bool, h func(customNetHttp.ResponseWriter, *customNetHttp.Request)) string {
	t.Helper()
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(h)}
	var l net.Listener
	var err error
	if withTLS {
		cfg := selfSignedTLS(t)
		srv.TLSConfig = cfg
		l, err = tls.Listen("tcp", "127.0.0.1:0", cfg)
	} else {
		l, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

func okHandler(w customNetHttp.ResponseWriter, r *customNetHttp.Request) { io.WriteString(w, "ok") }

// sendRaw sends an HTTP/1 request as it is and returns the response.
func sendRaw(t *testing.T, addr, request string) (*http.Response, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("unreadable response: %v", err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

// checkError checks an error response against Turbo's template.
func checkError(t *testing.T, what string, res *http.Response, body string, code int, detail string) {
	t.Helper()
	if res.StatusCode != code {
		t.Errorf("%s: code %d; expected %d", what, res.StatusCode, code)
		return
	}
	if want := expectedTemplate(code, detail); body != want {
		t.Errorf("%s: body %q; expected %q", what, body, want)
	}
	if ct := strings.ToLower(res.Header.Get("Content-Type")); ct != "text/plain; charset=utf-8" {
		t.Errorf("%s: Content-Type %q", what, ct)
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s: missing X-Content-Type-Options: nosniff", what)
	}
	if got := res.Header.Get("Server"); got != serverName {
		t.Errorf("%s: Server %q; expected %q", what, got, serverName)
	}
}

// P1, P3 and P4: HTTP/1 errors before the handler with the template, the
// Server header and Connection: close; exact limits of URI and headers.
func TestT21_P1_HTTP1Errors(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxURILength, 40)
	withLimit(t, &customNetHttp.TurboMaxHeaderBytes, 600)
	addr := forkServer(t, false, okHandler)

	cases := []struct {
		what, request, detail string
		code                  int
	}{
		{"malformed request line", "GARBAGE\r\n\r\n", "", 400},
		{"malformed Host header", "GET / HTTP/1.1\r\nHost: a b\r\n\r\n", "", 400},
		{"unknown Transfer-Encoding", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: bogus\r\n\r\n", "Unsupported transfer encoding", 501},
		{"URI of 41 bytes (P3)", "GET /" + strings.Repeat("u", 40) + " HTTP/1.1\r\nHost: x\r\n\r\n", "", 414},
		{"headers of more than 600 bytes (P4)", "GET / HTTP/1.1\r\nHost: x\r\nX-Padding: " + strings.Repeat("r", 700) + "\r\n\r\n", "", 431},
	}
	for _, c := range cases {
		res, body := sendRaw(t, addr, c.request)
		checkError(t, c.what, res, body, c.code, c.detail)
		if !res.Close {
			t.Errorf("%s: missing Connection: close", c.what)
		}
	}

	// Exact limits: a URI of 40 bytes and a header of exactly 600 bytes get
	// through; one byte more doesn't.
	if res, _ := sendRaw(t, addr, "GET /"+strings.Repeat("u", 39)+" HTTP/1.1\r\nHost: x\r\n\r\n"); res.StatusCode != 200 {
		t.Errorf("URI of 40 bytes: %d; expected 200", res.StatusCode)
	}
	header := func(total int) string {
		base := "GET / HTTP/1.1\r\nHost: x\r\nX-Padding: \r\n\r\n"
		return strings.Replace(base, "X-Padding: ", "X-Padding: "+strings.Repeat("r", total-len(base)), 1)
	}
	if res, _ := sendRaw(t, addr, header(600)); res.StatusCode != 200 {
		t.Errorf("header of 600 bytes: %d; expected 200", res.StatusCode)
	}
	if res, _ := sendRaw(t, addr, header(601)); res.StatusCode != 431 {
		t.Errorf("header of 601 bytes: %d; expected 431", res.StatusCode)
	}
}

// h2 is a minimal HTTP/2 client to send frames that the standard library's
// client doesn't allow (headers of an exact size, RST_STREAM).
type h2 struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
	id uint32
}

// dialRetrying connects with dialer, retrying for up to 20 s. The fuzz tests open a connection per input: on
// Windows, at that speed, tens of thousands of connections of the previous inputs (and of the previous target)
// stay in TIME_WAIT and a dial may find no free local port for a moment ("Only one usage of each socket
// address"), which says nothing of the server.
func dialRetrying(t testing.TB, dialer *net.Dialer, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		c, err := dialer.Dial("tcp", addr)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func dialH2(t *testing.T, addr string) *h2 {
	t.Helper()
	c := tls.Client(dialRetrying(t, &net.Dialer{}, addr), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err := c.Handshake(); err != nil {
		c.Close()
		t.Fatal(err)
	}
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("ALPN %q", p)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	h := &h2{t: t, c: c, br: bufio.NewReader(c), id: 1}
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h.frame(4, 0, 0, nil) // SETTINGS
	return h
}

func (h *h2) frame(kind, flags byte, stream uint32, payload []byte) {
	header := make([]byte, 9)
	header[0], header[1], header[2] = byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload))
	header[3], header[4] = kind, flags
	binary.BigEndian.PutUint32(header[5:], stream)
	if _, err := h.c.Write(append(header, payload...)); err != nil {
		h.t.Fatal(err)
	}
}

// hpackLiteral encodes a literal field without indexing and without Huffman.
func hpackLiteral(b *bytes.Buffer, name, value string) {
	writeInt := func(v int) {
		if v < 127 {
			b.WriteByte(byte(v))
			return
		}
		b.WriteByte(127)
		for v -= 127; v >= 128; v /= 128 {
			b.WriteByte(byte(v%128 + 128))
		}
		b.WriteByte(byte(v))
	}
	b.WriteByte(0)
	writeInt(len(name))
	b.WriteString(name)
	writeInt(len(value))
	b.WriteString(value)
}

// request opens a stream with a GET and the given headers (name, value pairs
// after the pseudo-headers) and returns its identifier.
func (h *h2) request(path string, extra ...string) uint32 {
	var b bytes.Buffer
	fields := append([]string{":method", "GET", ":scheme", "https", ":path", path, ":authority", "x"}, extra...)
	for i := 0; i < len(fields); i += 2 {
		hpackLiteral(&b, fields[i], fields[i+1])
	}
	id := h.id
	h.id += 2
	h.frame(1, 0x5, id, b.Bytes()) // HEADERS with END_STREAM and END_HEADERS
	return id
}

// read reads frames until the stream ends and returns the body, or until
// a GOAWAY (it returns its error code with goaway = true).
func (h *h2) read(stream uint32) (body string, goaway bool, code uint32) {
	var b bytes.Buffer
	for {
		header := make([]byte, 9)
		if _, err := io.ReadFull(h.br, header); err != nil {
			h.t.Fatalf("reading frames: %v", err)
		}
		n := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		payload := make([]byte, n)
		if _, err := io.ReadFull(h.br, payload); err != nil {
			h.t.Fatal(err)
		}
		kind, flags, id := header[3], header[4], binary.BigEndian.Uint32(header[5:])&0x7fffffff
		switch {
		case kind == 4 && flags&1 == 0: // The server's SETTINGS
			h.frame(4, 1, 0, nil)
		case kind == 7: // GOAWAY
			return b.String(), true, binary.BigEndian.Uint32(payload[4:8])
		case kind == 6 && flags&1 == 1 && stream == 0: // The response to the PING
			return "", false, 0
		case id == stream && stream != 0 && (kind == 0 || kind == 1):
			if kind == 0 {
				b.Write(payload)
			}
			if flags&1 == 1 {
				return b.String(), false, 0
			}
		}
	}
}

// P2, P3 and P5: over HTTP/2, a :path above TurboMaxURILength gives 414 and a list of
// headers above TurboMaxHeaderBytes (bytes of name and value plus 32 per field, as
// HTTP/2 counts them; C6) gives 431, both with the template; the limit is exact.
func TestT21_P2_HTTP2Limits(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxURILength, 40)
	withLimit(t, &customNetHttp.TurboMaxHeaderBytes, 600)
	addr := forkServer(t, true, okHandler)
	h := dialH2(t, addr)

	if body, _, _ := h.read(h.request("/" + strings.Repeat("u", 39))); body != "ok" {
		t.Errorf(":path of 40 bytes: %q; expected ok", body)
	}
	if body, _, _ := h.read(h.request("/" + strings.Repeat("u", 40))); body != expectedTemplate(414, "") {
		t.Errorf(":path of 41 bytes: %q; expected the template's 414", body)
	}

	// :method GET :scheme https :path / :authority x add up to 7+3+7+5+5+1+10+1 = 39
	// bytes, plus 32 for each of the five fields; x-padding fills up the total.
	padding := func(total int) string { return strings.Repeat("r", total-39-len("x-padding")-5*32) }
	if body, _, _ := h.read(h.request("/", "x-padding", padding(600))); body != "ok" {
		t.Errorf("headers of 600 bytes: %q; expected ok", body)
	}
	if body, _, _ := h.read(h.request("/", "x-padding", padding(601))); body != expectedTemplate(431, "") {
		t.Errorf("headers of 601 bytes: %q; expected the template's 431", body)
	}

	// The limit is read on each request: with a higher MHB, the same connection accepts more.
	customNetHttp.TurboMaxHeaderBytes.Store(2000)
	if body, _, _ := h.read(h.request("/", "x-padding", padding(1500))); body != "ok" {
		t.Errorf("headers of 1500 bytes with TurboMaxHeaderBytes = 2000: %q; expected ok", body)
	}
}

// C6 (H29): over HTTP/2 each field counts 32 bytes besides its name and its
// value, as in Go: with MHB = 5000, 200 headers of 1 byte don't fit.
func TestC6_HTTP2FieldOverhead(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxHeaderBytes, 5000)
	addr := forkServer(t, true, okHandler)
	h := dialH2(t, addr)
	var fields []string
	for i := 0; i < 200; i++ {
		fields = append(fields, "x", "")
	}
	if body, _, _ := h.read(h.request("/", fields...)); body != expectedTemplate(431, "") {
		t.Errorf("200 headers of 1 byte with MHB = 5000: %q; expected the template's 431", body)
	}
	if body, _, _ := h.read(h.request("/", fields[:100]...)); body != "ok" {
		t.Errorf("50 headers of 1 byte with MHB = 5000: %q; expected ok", body)
	}
}

// P11 (N49): only the RST_STREAM frames that cancel an open stream count, and
// the limit is 4 times the connection's concurrent streams (200 with 50):
// cancelling the 50 streams in progress twice in a second doesn't close the
// connection; opening and cancelling 500 in a second closes it with GOAWAY
// (ENHANCE_YOUR_CALM). Those of streams that already ended don't count.
func TestT21_P11_RSTStream(t *testing.T) {
	initForTest(t)
	slow := func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}
	cfg := selfSignedTLS(t)
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(slow), TLSConfig: cfg, HTTP2: &customNetHttp.HTTP2Config{MaxConcurrentStreams: 50}}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	addr := l.Addr().String()
	cancelStreams := func(h *h2, ids []uint32) {
		for _, id := range ids {
			h.frame(3, 0, id, []byte{0, 0, 0, 8}) // RST_STREAM CANCEL
		}
	}
	openStreams := func(h *h2, n int) []uint32 {
		var ids []uint32
		for i := 0; i < n; i++ {
			ids = append(ids, h.request("/"))
		}
		return ids
	}

	h := dialH2(t, addr)
	for round := 0; round < 2; round++ {
		cancelStreams(h, openStreams(h, 50))
		time.Sleep(50 * time.Millisecond)
	}
	h.frame(6, 0, 0, make([]byte, 8)) // PING: the response arrives if the connection is still open
	if _, goaway, code := h.read(0); goaway {
		t.Fatalf("50 streams in progress cancelled twice: GOAWAY with code %d", code)
	}

	fast := okHandler // Streams that end at once: their late RST_STREAM don't count
	fastAddr := forkServer(t, true, fast)
	h = dialH2(t, fastAddr)
	ids := openStreams(h, 300)
	time.Sleep(200 * time.Millisecond)
	cancelStreams(h, ids)
	h.frame(6, 0, 0, make([]byte, 8))
	if _, goaway, code := h.read(0); goaway {
		t.Fatalf("300 RST_STREAM of ended streams: GOAWAY with code %d", code)
	}

	h = dialH2(t, addr)
	for i := 0; i < 500; i++ {
		cancelStreams(h, openStreams(h, 1))
	}
	for {
		_, goaway, code := h.read(0)
		if goaway {
			if code != 0xb {
				t.Errorf("GOAWAY with code %d; expected ENHANCE_YOUR_CALM (11)", code)
			}
			return
		}
		h.frame(6, 0, 0, make([]byte, 8))
	}
}

// P6: the HTTP/1 timeouts are read on each connection: IT and RHT enabled with
// the server running close the idle or slow connections.
func TestT21_P6_TimeoutsHTTP1(t *testing.T) {
	initForTest(t)
	previous := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = previous }) }) })
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.IT, t.RHT, t.RT, t.WT = 0, 0, 0, 0 }) })
	addr := forkServer(t, false, okHandler)
	withGlobalLock(func() {
		setTimeLimits(func(t *customNetHttp.Timeouts) { t.IT, t.RHT = 300*time.Millisecond, 300*time.Millisecond })
	})

	closed := func(c net.Conn) bool {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		return err == io.EOF
	}

	// IT: after a request, the idle connection is closed.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(res.Body)
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF || time.Since(start) > 2*time.Second {
		t.Errorf("IT = 300 ms: the idle connection is still open (%v after %v)", err, time.Since(start))
	}

	// RHT: an unfinished header is cut.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	io.WriteString(c2, "GET / HTTP/1.1\r\nHost: x\r\n")
	if !closed(c2) {
		t.Error("RHT = 300 ms: the unfinished request isn't cut")
	}
}

// B4 (H15): with RHT or IT at 0, the header read and the idle time use RT,
// as in Go, instead of having no limit.
func TestB4_ZeroTimeoutsUseRT(t *testing.T) {
	initForTest(t)
	previous := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = previous }) }) })
	withGlobalLock(func() {
		setTimeLimits(func(t *customNetHttp.Timeouts) { t.RT, t.RHT, t.IT, t.WT = 300*time.Millisecond, 0, 0, 0 })
	})
	addr := forkServer(t, false, okHandler)
	waitForClose := func(c net.Conn) (bool, time.Duration) {
		start := time.Now()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		return err == io.EOF, time.Since(start)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n") // Headers that never end
	if closed, after := waitForClose(c); !closed || after > 2*time.Second {
		t.Errorf("RT = 300 ms and RHT = 0: the unfinished request is still open (%v after %v)", closed, after)
	}

	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	io.WriteString(c2, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c2)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(res.Body)
	start := time.Now()
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF || time.Since(start) > 2*time.Second {
		t.Errorf("RT = 300 ms and IT = 0: the idle connection is still open (%v after %v)", err, time.Since(start))
	}
}

// P7: if the handler doesn't read the body, the connection is closed instead
// of draining it (Go reads up to 256 KiB and reuses it).
func TestT21_P7_UnreadBody(t *testing.T) {
	initForTest(t)
	addr := forkServer(t, false, okHandler)
	res, body := sendRaw(t, addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789")
	if res.StatusCode != 200 || body != "ok" {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
	if !res.Close {
		t.Error("missing Connection: close with the body unread")
	}

	// B1 (H13): with the body read to the end, the connection is reused, as in Go.
	addr = forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok")
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(c)
	for i, request := range []string{
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789",
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n01234\r\n0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	} {
		io.WriteString(c, request)
		res, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("request %d on the same connection: %v", i+1, err)
		}
		io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || (res.Close && i < 2) {
			t.Fatalf("request %d: %d, Connection: close %v; expected the connection to stay open after a body read to the end", i+1, res.StatusCode, res.Close)
		}
	}
}

// P8: the Server header over HTTP/1 and HTTP/2.
func TestT21_P8_ServerHeader(t *testing.T) {
	initForTest(t)
	for _, withTLS := range []bool{false, true} {
		addr := forkServer(t, withTLS, okHandler)
		url := "http://" + addr + "/"
		tr := &http.Transport{}
		if withTLS {
			url = "https://" + addr + "/"
			tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
		}
		res, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(url)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		tr.CloseIdleConnections()
		if got := res.Header.Get("Server"); got != serverName {
			t.Errorf("%s: Server %q; expected %q", res.Proto, got, serverName)
		}
	}
}

// C4 (H27): ParseMultipartForm with maxMemory <= 0 uses MBB as the limit and
// doesn't create temporary files.
func TestC4_ParseMultipartFormZero(t *testing.T) {
	initForTest(t)
	result := make(chan string, 1)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		err := r.ParseMultipartForm(0)
		stored := r.MultipartForm != nil && len(r.MultipartForm.File["f"]) > 0 // In memory or in a temporary file
		if r.MultipartForm != nil {
			r.MultipartForm.RemoveAll()
		}
		result <- fmt.Sprintf("err=%v file=%v", err, stored)
		io.WriteString(w, "ok")
	})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("f", "big.bin")
	fw.Write(bytes.Repeat([]byte("x"), int(maxBodySize.Load())*2))
	mw.Close()
	req, _ := http.NewRequest("POST", "http://"+addr+"/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req); err == nil {
		res.Body.Close()
	}
	select {
	case r := <-result:
		if !strings.Contains(r, "too large") || strings.Contains(r, "file=true") {
			t.Errorf("ParseMultipartForm(0) with twice MBB: %s; expected \"message too large\" without a file", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler didn't answer")
	}
}

// C7 (H30): a urlencoded form is kept whole in memory, so it is limited to
// 10 MiB even when MBB is larger (as in Go).
func TestC7_URLEncodedFormLimit(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxBodySize, 100<<20)
	result := make(chan error, 1)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		result <- r.ParseForm()
		io.WriteString(w, "ok")
	})
	for size, tooBig := range map[int]bool{10 << 20: false, 11 << 20: true} {
		body := "a=" + strings.Repeat("x", size-2)
		req, _ := http.NewRequest("POST", "http://"+addr+"/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
			res.Body.Close()
		}
		if err := <-result; (err != nil) != tooBig {
			t.Errorf("form of %d bytes with MBB = 100 MiB: ParseForm = %v", size, err)
		}
	}
}

// H53: the 10 MiB cap of urlencoded forms applies while reading, also when
// the handler already limits the body with MaxBytesReader to more: no more
// is read (nor kept in memory) than what is going to be accepted.
func TestH53_URLEncodedLimitWithMaxBytesReader(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxBodySize, 100<<20)
	type formResult struct {
		err       error
		bytesRead int64
	}
	result := make(chan formResult, 1)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		counter := &countingReader{r: r.Body}
		r.Body = customNetHttp.MaxBytesReader(w, io.NopCloser(counter), 50<<20)
		err := r.ParseForm()
		result <- formResult{err, counter.n}
		io.WriteString(w, "ok")
	})
	body := "a=" + strings.Repeat("x", 20<<20)
	req, _ := http.NewRequest("POST", "http://"+addr+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req); err == nil {
		res.Body.Close()
	}
	r := <-result
	if r.err == nil {
		t.Error("form of 20 MiB with a MaxBytesReader of 50 MiB: ParseForm without an error; the cap is 10 MiB")
	}
	if r.bytesRead > 11<<20 {
		t.Errorf("form of 20 MiB: %d bytes were read before refusing it; expected no more than 10 MiB", r.bytesRead)
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (l *countingReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

// H54: over HTTP/2, SETTINGS_MAX_HEADER_LIST_SIZE announces the same limit that
// is applied (MHB, with 32 bytes per field): a client that respects what was
// announced doesn't get 431 for a list of headers the server said it accepts.
func TestH54_HTTP2AnnouncedHeaderLimit(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxHeaderBytes, 5000)
	addr := forkServer(t, true, okHandler)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	fetch := func(padding int) (int, error) {
		req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
		if padding > 0 {
			req.Header.Set("X-Padding", strings.Repeat("r", padding))
		}
		res, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		res.Body.Close()
		return res.StatusCode, nil
	}
	if code, err := fetch(0); err != nil || code != 200 { // Opens the connection: the client learns the SETTINGS
		t.Fatalf("first request: %d %v", code, err)
	}
	if code, err := fetch(4500); err != nil || code != 200 {
		t.Errorf("about 4 800 bytes of headers with MHB = 5000: %d %v; expected 200", code, err)
	}
	// About 5 130 bytes: above MHB. The client may refuse it (the limit it was told) but the server must not
	// announce a limit and then answer 431 below it.
	if code, err := fetch(4800); err == nil && code == 431 {
		t.Errorf("about 5 130 bytes of headers with MHB = 5000: the client sent it (the server announced more) and got 431")
	}
}

// C3 (H26): a single Server header, Turbo's, even if the handler sets Server
// (the site's headers, a CGI) or Date, over HTTP/1.1 and HTTP/2.
func TestC3_OneServerHeader(t *testing.T) {
	initForTest(t)
	for _, withTLS := range []bool{false, true} {
		addr := forkServer(t, withTLS, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
			switch r.URL.Path {
			case "/server":
				w.Header().Set("Server", "Other")
			case "/date":
				w.Header().Set("Date", "Mon, 02 Jan 2006 15:04:05 GMT")
			}
			io.WriteString(w, "ok")
		})
		base := "http://" + addr
		tr := &http.Transport{}
		if withTLS {
			base = "https://" + addr
			tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
		}
		for _, path := range []string{"/", "/server", "/date"} {
			res, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(base + path)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if got := res.Header.Values("Server"); len(got) != 1 || got[0] != serverName {
				t.Errorf("%s %s: Server %q; expected a single one, %q", res.Proto, path, got, serverName)
			}
		}
		tr.CloseIdleConnections()
	}
}

// P9: Error, NotFound and the responses of ServeContent use the template; a
// template that starts with '<' is served as HTML.
func TestT21_P9_ErrorTemplate(t *testing.T) {
	initForTest(t)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		switch r.URL.Path {
		case "/error":
			w.Header().Set("Content-Length", "99")
			customNetHttp.Error(w, "detail", 418)
		case "/notfound":
			customNetHttp.NotFound(w, r)
		case "/range":
			customNetHttp.ServeContent(w, r, "a.txt", time.Time{}, strings.NewReader("content"))
		}
	})
	get := func(path string, hdr ...string) (*http.Response, string) {
		extra := ""
		for i := 0; i < len(hdr); i += 2 {
			extra += hdr[i] + ": " + hdr[i+1] + "\r\n"
		}
		return sendRaw(t, addr, "GET "+path+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"+extra+"\r\n")
	}
	res, body := get("/error")
	checkError(t, "Error", res, body, 418, "detail")
	res, body = get("/notfound")
	checkError(t, "NotFound", res, body, 404, "")
	res, body = get("/range", "Range", "bytes=50-60")
	checkError(t, "ServeContent 416", res, body, 416, "invalid range: failed to overlap")

	previous := customNetHttp.TurboErrorTemplates.Load()
	t.Cleanup(func() { customNetHttp.TurboErrorTemplates.Store(previous) })
	html := map[int]string{}
	for k, v := range *previous {
		html[k] = v
	}
	html[418] = "<p>Error {TURBO_RESPONSE_CODE}</p>"
	customNetHttp.TurboErrorTemplates.Store(&html)
	res, body = get("/error")
	if ct := strings.ToLower(res.Header.Get("Content-Type")); ct != "text/html; charset=utf-8" || body != "<p>Error 418</p>\ndetail\n" {
		t.Errorf("HTML template: %q, %q", ct, body)
	}
}

// C8 (H31): in an HTML template, the detail of the error is escaped; in a text
// one it is left as it is.
func TestC8_HTMLTemplateDetailEscaped(t *testing.T) {
	initForTest(t)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		customNetHttp.Error(w, `<script>alert("x")</script> & more`, 418)
	})
	previous := customNetHttp.TurboErrorTemplates.Load()
	t.Cleanup(func() { customNetHttp.TurboErrorTemplates.Store(previous) })
	customNetHttp.TurboErrorTemplates.Store(&map[int]string{0: "<p>Error {TURBO_RESPONSE_CODE}</p>"})
	_, body := sendRaw(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if want := "<p>Error 418</p>\n&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; more\n"; body != want {
		t.Errorf("HTML template: %q; expected %q", body, want)
	}
	customNetHttp.TurboErrorTemplates.Store(&map[int]string{0: `Error {TURBO_RESPONSE_CODE}`})
	if _, body = sendRaw(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(body, "<script>") {
		t.Errorf("text template: %q; the detail should not have changed", body)
	}
}

// P10: forms limited by MBB (TurboMaxBodySize), TurboMaxFormParts parts and TurboMaxFormHeaders headers, and
// multipart only in memory.
func TestT21_P10_Forms(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxBodySize, 2000)
	withLimit(t, &customNetHttp.TurboMaxFormParts, 3)
	withLimit(t, &customNetHttp.TurboMaxFormHeaders, 4)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		if r.URL.Path == "/value" {
			io.WriteString(w, "v="+r.FormValue("a"))
			return
		}
		var err error
		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
			err = r.ParseMultipartForm(customNetHttp.TurboMaxBodySize.Load())
		} else {
			err = r.ParseForm()
		}
		if err != nil {
			io.WriteString(w, "error: "+err.Error())
			return
		}
		files := 0
		if r.MultipartForm != nil {
			for _, fhs := range r.MultipartForm.File {
				files += len(fhs)
			}
		}
		fmt.Fprintf(w, "ok %d values %d files", len(r.Form), files)
	})
	send := func(path, contentType, body string) string {
		_, b := sendRaw(t, addr, fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", path, contentType, len(body), body))
		return b
	}
	urlenc := "application/x-www-form-urlencoded"
	if got := send("/", urlenc, "a="+strings.Repeat("x", 1990)); got != "ok 1 values 0 files" {
		t.Errorf("urlencoded of 1992 bytes: %q", got)
	}
	if got := send("/", urlenc, "a="+strings.Repeat("x", 2000)); got != "error: http: POST too large" {
		t.Errorf("urlencoded of 2002 bytes: %q", got)
	}

	type part struct {
		file    bool
		size    int
		headers int
	}
	multi := func(path string, parts ...part) string {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		for i, p := range parts {
			h := textproto.MIMEHeader{}
			if p.file {
				h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f%d"; filename="f%d.txt"`, i, i))
			} else {
				h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="a%d"`, i))
			}
			for k := 1; k < p.headers; k++ {
				h.Set(fmt.Sprintf("X-Extra-%d", k), "1")
			}
			w, _ := mw.CreatePart(h)
			w.Write(bytes.Repeat([]byte("z"), p.size))
		}
		mw.Close()
		return send(path, mw.FormDataContentType(), b.String())
	}
	// Each part also costs a few hundred bytes of memory for its headers
	// (Go's accounting): with MBB = 20000 the parts fit, but not more than
	// TurboMaxFormParts parts nor more than TurboMaxFormHeaders headers.
	customNetHttp.TurboMaxBodySize.Store(20000)
	if got := multi("/", part{false, 10, 1}, part{true, 100, 1}, part{true, 100, 1}); got != "ok 1 values 2 files" {
		t.Errorf("multipart of 3 parts: %q", got)
	}
	if got := multi("/", part{false, 1, 1}, part{false, 1, 1}, part{false, 1, 1}, part{false, 1, 1}); got != "error: multipart: message too large" {
		t.Errorf("multipart of 4 parts with TurboMaxFormParts = 3: %q", got)
	}
	if got := multi("/", part{true, 10, 5}); got != "error: multipart: message too large" {
		t.Errorf("part with 5 headers with TurboMaxFormHeaders = 4: %q", got)
	}
	// A file that doesn't fit in memory is refused (Go would move it to disk).
	customNetHttp.TurboMaxBodySize.Store(3000)
	if got := multi("/", part{true, 1500, 1}); got != "ok 0 values 1 files" {
		t.Errorf("file of 1500 bytes with MBB = 3000: %q", got)
	}
	if got := multi("/", part{true, 5000, 1}); got != "error: multipart: message too large" {
		t.Errorf("file of 5000 bytes with MBB = 3000: %q", got)
	}
	customNetHttp.TurboMaxBodySize.Store(1000)
	// FormValue parses the multipart with MBB, not with Go's 32 MB.
	if got := multi("/value", part{false, 1500, 1}); got != "v=" {
		t.Errorf("FormValue with a value of 1500 bytes and MBB = 1000: %q", got)
	}
}

// P13: an HTTP/2 connection that doesn't send the preface is closed after 1 s (Go: 10 s).
func TestT21_P13_HTTP2Preface(t *testing.T) {
	initForTest(t)
	addr := forkServer(t, true, okHandler)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.Copy(io.Discard, c) // The server sends its SETTINGS and closes when the deadline passes
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("without the preface, the connection is still open after %v (%v); expected ~1 s", d, err)
	}
}

// Turbo's HTTPS server announces 50 concurrent HTTP/2 streams per
// connection (by configuration, without a patch; Go: 250).
func TestT21_MaxConcurrentStreams(t *testing.T) {
	initForTest(t)
	cfg := selfSignedTLS(t)
	srv := newHTTPSServer(cfg)
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	h := dialH2(t, l.Addr().String())
	for {
		header := make([]byte, 9)
		if _, err := io.ReadFull(h.br, header); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, int(header[0])<<16|int(header[1])<<8|int(header[2]))
		if _, err := io.ReadFull(h.br, payload); err != nil {
			t.Fatal(err)
		}
		if header[3] != 4 || header[4]&1 == 1 { // Only the server's SETTINGS
			continue
		}
		for i := 0; i+6 <= len(payload); i += 6 {
			if binary.BigEndian.Uint16(payload[i:]) == 3 { // SETTINGS_MAX_CONCURRENT_STREAMS
				if v := binary.BigEndian.Uint32(payload[i+2:]); v != 50 {
					t.Fatalf("SETTINGS_MAX_CONCURRENT_STREAMS = %d; expected 50", v)
				}
				return
			}
		}
		t.Fatal("the server doesn't announce SETTINGS_MAX_CONCURRENT_STREAMS")
	}
}

// N45: over HTTP/2, a single field larger than MHB (or a :path larger than
// MUB) gives 431 (or 414) on its stream, with the template, and the
// connection keeps serving; before, it closed the whole connection (GOAWAY
// COMPRESSION_ERROR).
func TestN45_HTTP2FieldOverMHB(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxHeaderBytes, 5000)
	withLimit(t, &customNetHttp.TurboMaxURILength, 8000)
	addr := forkServer(t, true, okHandler)
	h := dialH2(t, addr)
	if body, goaway, _ := h.read(h.request("/", "x-big", strings.Repeat("g", 6000))); goaway || body != expectedTemplate(431, "") {
		t.Errorf("field of 6000 bytes with MHB = 5000: %q (GOAWAY %v); expected the template's 431", body, goaway)
	}
	if body, goaway, code := h.read(h.request("/" + strings.Repeat("u", 9000))); goaway || (body != expectedTemplate(414, "") && body != expectedTemplate(431, "")) {
		t.Errorf(":path of 9000 bytes with MUB = 8000: %q (GOAWAY %v, code %d); expected 414 or 431 on its stream", body, goaway, code)
	}
	if body, goaway, _ := h.read(h.request("/")); goaway || body != "ok" {
		t.Errorf("second request on the same connection: %q (GOAWAY %v); expected ok", body, goaway)
	}
}

// N46: over HTTP/1, the exact limit of MHB also applies to the second request
// of a keep-alive connection and to a pipelined request: the bytes already
// read while waiting for it count.
func TestN46_HTTP1KeepAliveHeaderLimit(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxHeaderBytes, 1000)
	addr := forkServer(t, false, okHandler)
	request := func(padding int) string {
		return "GET / HTTP/1.1\r\nHost: x\r\nX-Padding: " + strings.Repeat("r", padding) + "\r\n\r\n"
	}
	statuses := func(batches ...string) []int {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		var codes []int
		for _, batch := range batches {
			io.WriteString(c, batch)
			for range strings.Count(batch, "GET ") {
				res, err := http.ReadResponse(br, nil)
				if err != nil {
					return append(codes, 0)
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				codes = append(codes, res.StatusCode)
			}
		}
		return codes
	}
	if got := statuses(request(10), request(3000)); len(got) != 2 || got[0] != 200 || got[1] != 431 {
		t.Errorf("keep-alive, second request with 3000 bytes of headers and MHB = 1000: %v; expected [200 431]", got)
	}
	if got := statuses(request(10) + request(3000)); len(got) != 2 || got[0] != 200 || got[1] != 431 {
		t.Errorf("pipelining, second request with 3000 bytes of headers: %v; expected [200 431]", got)
	}
	if got := statuses(request(10), request(800)); len(got) != 2 || got[1] != 200 {
		t.Errorf("keep-alive, second request within the limit: %v; expected 200", got)
	}
}

// N47, F3: plain HTTP to the TLS port and an unknown Expect are answered with
// the template, Server and nosniff; a Trailer: Server doesn't add a second Server.
func TestN47_ResponsesWithTemplate(t *testing.T) {
	initForTest(t)
	exchange := func(addr, request string) (*http.Response, string) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, request)
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%q: %v", request, err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, string(body)
	}
	tlsAddr := forkServer(t, true, okHandler)
	res, body := exchange(tlsAddr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if res.StatusCode != 400 || body != expectedTemplate(400, "") || res.Header.Get("Server") != serverName || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("HTTP on the TLS port: %d %q %v", res.StatusCode, body, res.Header)
	}
	addr := forkServer(t, false, okHandler)
	res, body = exchange(addr, "GET / HTTP/1.1\r\nHost: x\r\nExpect: x\r\n\r\n")
	if res.StatusCode != 417 || body != expectedTemplate(417, "") || res.Header.Get("Server") != serverName {
		t.Errorf("unknown Expect: %d %q %v", res.StatusCode, body, res.Header)
	}
	trailer := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		w.Header().Set("Trailer", "Server, X-End")
		io.WriteString(w, "ok")
		w.Header().Set("Server", "other")
		w.Header().Set("X-End", "1")
	})
	res, _ = exchange(trailer, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if servers := append(res.Header.Values("Server"), res.Trailer.Values("Server")...); len(servers) != 1 || servers[0] != serverName {
		t.Errorf("Trailer: Server: %q; expected only Turbo's", servers)
	}
}

// N72: over HTTP/2, only one :path per header block can go over MUB without
// counting for MHB (P3 answers it with 414). Repeated, for example by referencing
// the one in the HPACK dynamic table with one byte, it counts as any field:
// the block doesn't grow without limit and the connection is closed before it ends.
func TestN72_HTTP2RepeatedLongPathCounts(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxHeaderBytes, 5000)
	withLimit(t, &customNetHttp.TurboMaxURILength, 1000)
	addr := forkServer(t, true, okHandler)
	h := dialH2(t, addr)
	var b bytes.Buffer
	for _, field := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "x"}} {
		hpackLiteral(&b, field[0], field[1])
	}
	longPath := "/" + strings.Repeat("a", 1100)
	b.WriteByte(0x40) // Literal with indexing: it stays in the dynamic table (index 62)
	b.WriteByte(byte(len(":path")))
	b.WriteString(":path")
	b.WriteByte(127)
	rest := len(longPath) - 127
	for ; rest >= 128; rest /= 128 {
		b.WriteByte(byte(rest%128 + 128))
	}
	b.WriteByte(byte(rest))
	b.WriteString(longPath)
	h.frame(1, 0x1, 1, b.Bytes()) // HEADERS with END_STREAM, without END_HEADERS
	references := bytes.Repeat([]byte{0xBE}, 16000)
	closed := false
	for i := 0; i < 300 && !closed; i++ { // Without END_HEADERS: the block never ends
		header := []byte{byte(len(references) >> 16), byte(len(references) >> 8), byte(len(references)), 9, 0, 0, 0, 0, 1}
		if _, err := h.c.Write(append(header, references...)); err != nil {
			closed = true // The server already cut the connection
		}
	}
	if !closed { // Whatever the server answers: a GOAWAY with an error, or closing the connection
		h.c.SetReadDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 9)
		for {
			if _, err := io.ReadFull(h.br, header); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Error("300 CONTINUATION frames with the same long :path referenced 4 800 000 times: the connection is still waiting for the end of the block")
				}
				break
			}
			payload := make([]byte, int(header[0])<<16|int(header[1])<<8|int(header[2]))
			io.ReadFull(h.br, payload)
			if header[3] == 7 { // GOAWAY
				if code := binary.BigEndian.Uint32(payload[4:8]); code == 0 {
					t.Errorf("GOAWAY without an error (%d); expected a protocol error", code)
				}
				break
			}
		}
	}
}

// FuzzHTTP2Headers: whatever header block a client sends over HTTP/2 (fields with or without indexing,
// references to the dynamic table, split between HEADERS and CONTINUATION wherever the input says), the handler
// never gets more than MHB of headers (32 bytes per field besides its name and value, as P5 counts them), and
// the stream is answered without waiting for anything else: a response, RST_STREAM, GOAWAY or the connection
// closed, never a connection left hanging.
func FuzzHTTP2Headers(f *testing.F) {
	// Each pair of bytes is an operation: op%4 = 0, a literal field without indexing (name op/4 of the list,
	// value of n*40 bytes); 1, the same with indexing; 2, a reference to one of the last entries of the dynamic
	// table; 3, a frame boundary.
	f.Add([]byte{})
	f.Add([]byte{0x10, 2, 0x03, 0, 0x14, 1})
	f.Add([]byte{0x01, 30, 0x02, 0, 0x02, 0, 0x03, 0, 0x02, 0, 0x02, 0})
	f.Add([]byte{0x1C, 255, 0x1C, 255, 0x03, 0, 0x1C, 255})
	f.Add([]byte{0x05, 1, 0x00, 1, 0x09, 1})
	initForTest(f)
	const maxHeaderBytes, maxURILength = 2000, 500
	withLimit(f, &customNetHttp.TurboMaxHeaderBytes, maxHeaderBytes)
	withLimit(f, &customNetHttp.TurboMaxURILength, maxURILength)
	var largest atomic.Int64 // The largest header list a handler got over MHB
	addr := forkServer(f, true, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		size := len(":method") + len(r.Method) + len(":scheme") + len("https") + len(":path") + len(r.RequestURI) + len(":authority") + len(r.Host) + 4*32
		for name, values := range r.Header {
			for _, value := range values {
				size += len(name) + len(value) + 32
			}
		}
		if size > maxHeaderBytes && int64(size) > largest.Load() {
			largest.Store(int64(size))
		}
		io.WriteString(w, "ok")
	})
	names := []string{":path", ":method", ":scheme", ":authority", "x-a", "cookie", "user-agent", "x-" + strings.Repeat("n", 300)}
	f.Fuzz(func(t *testing.T, operations []byte) {
		largest.Store(0)
		var block bytes.Buffer
		for _, field := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "x"}, {":path", "/"}} {
			hpackLiteral(&block, field[0], field[1])
		}
		var cuts []int
		indexed := 0
		for i := 0; i+1 < len(operations) && block.Len() < 1<<20; i += 2 {
			op, n := operations[i], int(operations[i+1])
			switch op % 4 {
			case 0, 1:
				name := names[int(op/4)%len(names)]
				value := strings.Repeat("v", n*40)
				if name == ":path" {
					value = "/" + value
				}
				start := block.Len()
				hpackLiteral(&block, name, value)
				if op%4 == 1 {
					block.Bytes()[start] = 0x40 // Literal with incremental indexing
					indexed++
				}
			case 2:
				if indexed > 0 {
					block.WriteByte(0x80 | byte(62+n%min(indexed, 4)))
				}
			case 3:
				cuts = append(cuts, block.Len())
			}
		}
		// Frames of at most 16 000 bytes (the default SETTINGS_MAX_FRAME_SIZE is 16 384), cut also where the input says.
		data := block.Bytes()
		var frames [][]byte
		for start := 0; start < len(data) || start == 0; {
			end := min(start+16000, len(data))
			for _, cut := range cuts {
				if cut > start && cut < end {
					end = cut
					break
				}
			}
			frames = append(frames, data[start:end])
			if start = end; start == len(data) {
				break
			}
		}
		h := dialH2(t, addr)
		h.c.SetDeadline(time.Now().Add(10 * time.Second))
		go func() {
			for i, frame := range frames {
				kind, flags := byte(9), byte(0) // CONTINUATION
				if i == 0 {
					kind, flags = 1, 0x1 // HEADERS with END_STREAM
				}
				if i == len(frames)-1 {
					flags |= 0x4 // END_HEADERS
				}
				header := []byte{byte(len(frame) >> 16), byte(len(frame) >> 8), byte(len(frame)), kind, flags, 0, 0, 0, 1}
				if _, err := h.c.Write(append(header, frame...)); err != nil {
					return // The server closed the connection: an answer too
				}
			}
		}()
		for {
			header := make([]byte, 9)
			if _, err := io.ReadFull(h.br, header); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Fatalf("operations %x: block of %d bytes in %d frames without a response in 10 s", operations, len(data), len(frames))
				}
				break // Closed
			}
			payload := make([]byte, int(header[0])<<16|int(header[1])<<8|int(header[2]))
			if _, err := io.ReadFull(h.br, payload); err != nil {
				break
			}
			kind, flags, stream := header[3], header[4], binary.BigEndian.Uint32(header[5:])&0x7fffffff
			if kind == 4 && flags&1 == 0 { // The server's SETTINGS
				h.c.Write([]byte{0, 0, 0, 4, 1, 0, 0, 0, 0})
			}
			if kind == 7 || (stream == 1 && (kind == 3 || ((kind == 0 || kind == 1) && flags&1 == 1))) {
				break // GOAWAY, RST_STREAM, or the end of the response
			}
		}
		if size := largest.Load(); size > 0 {
			t.Errorf("operations %x: the handler got %d bytes of headers with MHB = %d", operations, size, maxHeaderBytes)
		}
	})
}
