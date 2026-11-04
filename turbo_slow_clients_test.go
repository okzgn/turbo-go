package main

// Production review, B1 and M-11: a client that stops reading doesn't hold the CGI slots, nor, over HTTP/2, the
// handlers of its connection. Over HTTP/2 a connection has a single writer: with a client that doesn't read, the
// write deadline of each stream (WT) only queued a reset that couldn't be written, and every handler of the
// connection, with its CGI and its slot, waited for as long as the client kept it open (WriteByteTimeout closes it
// now). Over HTTP/1, a CGI held its slot until its client had read the whole output (up to WT + 2 s): the output
// now waits for the client in memory or in a temporary file, and the CGI frees its slot when it ends.

import (
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
	"sync/atomic"
	"testing"
	"time"
	"turbo/customNetHttp"
)

// stallingConn is a client connection that stops reading once stalled is closed, until released is closed.
type stallingConn struct {
	net.Conn
	stalled, released chan struct{}
}

func (c *stallingConn) Read(p []byte) (int, error) {
	select {
	case <-c.stalled:
		<-c.released
		return 0, io.EOF
	default:
	}
	return c.Conn.Read(p)
}

// slowClientsSetup gives localhost a CGI (the echo CGI for "cgi") and a large static file.
func slowClientsSetup(t *testing.T) string {
	t.Helper()
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	os.WriteFile(dir+"localhost/@/big.bin", make([]byte, 16<<20), 0644)
	globalMutex.Lock()
	defer globalMutex.Unlock()
	if ok, msg := subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", ""); !ok {
		t.Fatal(msg)
	}
	return dir
}

// cgiSlotsRunning is how many CGI slots are taken.
func cgiSlotsRunning() int64 {
	cgiSlots.mutex.Lock()
	defer cgiSlots.mutex.Unlock()
	return cgiSlots.running
}

// eventually waits up to within for check to hold, and reports whether it did.
func eventually(within time.Duration, check func() bool) bool {
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if check() {
			return true
		}
	}
	return check()
}

// selfSignedLocalhost is a TLS configuration with a certificate for localhost, offering HTTP/2.
func selfSignedLocalhost(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
}

func TestRP_B1_HTTP2ClientThatStopsReading(t *testing.T) {
	slowClientsSetup(t)
	previous := http2WriteByteTimeout
	http2WriteByteTimeout = 2 * time.Second // Read by newHTTPSServer
	t.Cleanup(func() { http2WriteByteTimeout = previous })
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(3)
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	withGlobalLock(func() { setTimeLimits(func(l *customNetHttp.Timeouts) { l.WT = 2 * time.Second }) })

	config := selfSignedLocalhost(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	server := newHTTPSServer(config) // As main() builds it: HTTP/2 with its time limits, Turbo's handler
	var active atomic.Int64
	inner := server.Handler
	server.Handler = customNetHttp.HandlerFunc(func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		active.Add(1)
		defer active.Add(-1)
		inner.ServeHTTP(w, r)
	})
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	stalled, released := make(chan struct{}), make(chan struct{})
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			conn.(*net.TCPConn).SetReadBuffer(4096)
			return &stallingConn{Conn: conn, stalled: stalled, released: released}, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	request := func(path string) *http.Request {
		request, _ := http.NewRequest("GET", "https://"+listener.Addr().String()+path, nil)
		request.Host = "localhost"
		return request
	}
	fetch := func(path string) {
		if response, err := client.Do(request(path)); err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}
	// The client gets the headers of a first response and stops reading: what the server writes after that fills
	// the buffers of the connection, and its only writer waits.
	first, err := client.Do(request("/big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	close(stalled)
	t.Cleanup(func() { close(released); first.Body.Close() })
	for i := 0; i < 3; i++ { // Up to the client's window each (4 MiB), more than the buffers hold
		go fetch("/big.bin")
	}
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < 3; i++ { // CGP CGIs on the same connection
		go fetch("/x.cgi?big=262144")
	}
	time.Sleep(500 * time.Millisecond)
	if active.Load() == 0 {
		t.Fatal("no handler running: the test didn't jam the connection")
	}
	// The connection is closed when nothing could be written for http2WriteByteTimeout: its handlers end, and
	// every CGI slot is free, while the client still keeps its end open.
	if !eventually(15*time.Second, func() bool { return active.Load() == 0 && cgiSlotsRunning() == 0 }) {
		t.Errorf("a client that stopped reading over HTTP/2: %d handlers still running and %d CGI slots taken; expected none after WriteByteTimeout", active.Load(), cgiSlotsRunning())
	}
}

func TestRP_M11_SlowClientDoesNotHoldCGISlots(t *testing.T) {
	slowClientsSetup(t)
	base := startServer(t)
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(2)
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	withGlobalLock(func() { setTimeLimits(func(l *customNetHttp.Timeouts) { l.WT = 10 * time.Second }) })

	address := strings.TrimPrefix(base, "http://")
	var connections []net.Conn
	var mutex sync.Mutex
	t.Cleanup(func() {
		mutex.Lock()
		defer mutex.Unlock()
		for _, conn := range connections {
			conn.Close()
		}
	})
	for _, size := range []int{600 << 10, 32 << 20} { // Within the memory, and in the temporary file
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		conn.(*net.TCPConn).SetReadBuffer(4096)
		mutex.Lock()
		connections = append(connections, conn)
		mutex.Unlock()
		fmt.Fprintf(conn, "GET /x.cgi?big=%d HTTP/1.1\r\nHost: localhost\r\n\r\n", size) // And never read
	}
	time.Sleep(300 * time.Millisecond)
	// Done writing, each CGI ends and frees its slot, though its client reads nothing.
	if !eventually(5*time.Second, func() bool { return cgiSlotsRunning() == 0 }) {
		t.Fatalf("two clients that don't read: %d CGI slots still taken; expected none once the CGIs ended", cgiSlotsRunning())
	}
	if code, body, err := get(base, "/x.cgi", nil); err != nil || code != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
		t.Errorf("another client meanwhile: %d %.80q %v; expected its CGI to run", code, body, err)
	}
	if inUse := cgiOutputFilesInUse.Load(); inUse <= 0 {
		t.Errorf("the 32 MiB output: %d bytes in temporary files; expected it there while its client doesn't read", inUse)
	}
}

// M-11: what a CGI writes reaches its client whole and in order, from memory and from the temporary file, when the
// client reads slowly; nothing stays counted once the responses end.
func TestRP_M11_OutputInOrder(t *testing.T) {
	slowClientsSetup(t)
	base := startServer(t)
	request, _ := http.NewRequest("GET", base+"/x.cgi?big=8388608", nil) // 8 MiB: memory, then the file
	request.Host = "localhost"
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	time.Sleep(500 * time.Millisecond) // The CGI goes ahead of its client
	total := 0
	buffer := make([]byte, 64<<10)
	for {
		read, err := response.Body.Read(buffer)
		for _, b := range buffer[:read] {
			if b != 'x' {
				t.Fatalf("byte %d of the output is %q; expected only x", total, b)
			}
			total++
		}
		if err != nil {
			break
		}
	}
	if total != 8<<20 {
		t.Errorf("%d bytes arrived; expected %d", total, 8<<20)
	}
	if !eventually(3*time.Second, func() bool { return cgiOutputInUse.Load() == 0 && cgiOutputFilesInUse.Load() == 0 }) {
		t.Errorf("after the response: %d bytes still counted in memory and %d in files; expected 0", cgiOutputInUse.Load(), cgiOutputFilesInUse.Load())
	}
}
