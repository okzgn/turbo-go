package main

// Blocking caused by slow responses, and performance (#5, #6, #63, #64).

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowDownload opens a large download and reads it very slowly, keeping the
// response in progress. It returns a channel that is closed when it ends.
func slowDownload(t *testing.T, base string) <-chan struct{} {
	t.Helper()
	conn, err := net.Dial("tcp", base[len("http://"):])
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET /big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
	buf := make([]byte, 1024)
	conn.Read(buf)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			conn.Read(buf)
			time.Sleep(100 * time.Millisecond)
		}
		conn.Close()
	}()
	// Windows doesn't let big.bin be deleted while it is being served.
	t.Cleanup(func() { <-done })
	time.Sleep(300 * time.Millisecond)
	return done
}

// #6, #63: without turbo.visits, a client that downloads slowly must not leave
// the others without a response.
func TestP06_SlowDownloadBlocks(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/big.bin", bytes.Repeat([]byte("x"), 64<<20), 0644)
	base := startServer(t)
	slowDownload(t, base)
	t0 := time.Now()
	code, _, err := get(base, "/index.html", nil)
	if d := time.Since(t0); err != nil || code != 200 || d > 500*time.Millisecond {
		t.Fatalf("normal GET during the slow download: code=%d in %v (err=%v)", code, d, err)
	}
}

// #5: with a panel change pending, a normal GET must not wait for the slow
// download either.
func TestP05_SlowDownloadWithVisits(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	os.WriteFile(dir+"localhost/@/big.bin", bytes.Repeat([]byte("x"), 64<<20), 0644)
	base := startServer(t)
	tok := login(t, base)
	slowDownload(t, base)
	get(base, "/hello-warmup", nil)
	// The panel asks for Lock while the slow download is in progress.
	go post(base, "/admin:inside:addHeader?s=localhost&d=&a=X-A&b=1", tok)
	time.Sleep(200 * time.Millisecond)
	t0 := time.Now()
	code, _, err := get(base, "/index.html", nil)
	if d := time.Since(t0); err != nil || code != 200 || d > 500*time.Millisecond {
		t.Fatalf("normal GET with a pending Lock: code=%d in %v (err=%v)", code, d, err)
	}
}

func load(url, host string, conc int, d time.Duration) (float64, time.Duration) {
	var ok int64
	var mu sync.Mutex
	var lats []time.Duration
	stop := time.Now().Add(d)
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}, Timeout: 5 * time.Second}
			defer c.CloseIdleConnections()
			for time.Now().Before(stop) {
				req, _ := http.NewRequest("GET", url, nil)
				req.Host = host
				t0 := time.Now()
				res, err := c.Do(req)
				if err != nil {
					continue
				}
				io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode == 200 {
					atomic.AddInt64(&ok, 1)
					mu.Lock()
					lats = append(lats, time.Since(t0))
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	p99 := time.Duration(0)
	if len(lats) > 0 {
		p99 = lats[len(lats)*99/100]
	}
	return float64(ok) / d.Seconds(), p99
}

// #6, #64: without turbo.visits, Turbo must be as fast as with it, or faster.
// The stdlib reference is logged too.
func TestP06_Throughput(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("performance measurement: not measured with -short or -race")
	}
	dir := initForTest(t)
	serverRequestLimits.CII.Store(1 << 40) // high, so as not to measure the limiter
	os.WriteFile(dir+"localhost/@/hello.txt", []byte("hello"), 0644)
	base := startServer(t)
	load(base+"/hello.txt", "localhost", 32, 2*time.Second) // warmup: the first, cold measurement comes out slower
	rps, p99 := load(base+"/hello.txt", "localhost", 32, 4*time.Second)
	t.Logf("Turbo without turbo.visits: %.0f req/s, p99 %v", rps, p99)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false) // the periodic reload opens the log
	rps2, p992 := load(base+"/hello.txt", "localhost", 32, 4*time.Second)
	t.Logf("Turbo with turbo.visits: %.0f req/s, p99 %v", rps2, p992)
	serverSetLogState(visitsLogName, nil)
	os.Remove(dir + "turbo.visits")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ref := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, dir+"localhost/@/hello.txt")
	})}
	go ref.Serve(l)
	defer ref.Close()
	rps3, p993 := load("http://"+l.Addr().String()+"/", "localhost", 32, 4*time.Second)
	t.Logf("stdlib net/http: %.0f req/s, p99 %v", rps3, p993)
	if rps < 0.8*rps2 {
		t.Errorf("without log (%.0f req/s) slower than with log (%.0f req/s)", rps, rps2)
	}
}

// BenchmarkServeStatic measures serving a small file, to detect performance
// regressions.
func BenchmarkServeStatic(b *testing.B) {
	dir := initForTest(b)
	serverRequestLimits.CII.Store(1 << 40)
	os.WriteFile(dir+"localhost/@/hello.txt", []byte("hello"), 0644)
	base := startServer(b)
	c := &http.Client{Timeout: 5 * time.Second}
	defer c.CloseIdleConnections()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", base+"/hello.txt", nil)
		req.Host = "localhost"
		res, err := c.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
}
