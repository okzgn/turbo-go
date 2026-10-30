package main

// Bloqueos por respuestas lentas y rendimiento (#5, #6, #63, #64).

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

// slowDownload abre una descarga grande y la lee muy despacio, manteniendo la
// respuesta en curso. Devuelve un canal que se cierra al terminar.
func slowDownload(t *testing.T, base string) <-chan struct{} {
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
	// Windows no deja borrar big.bin mientras se sirve.
	t.Cleanup(func() { <-done })
	time.Sleep(300 * time.Millisecond)
	return done
}

// #6, #63: sin turbo.visits, un cliente que descarga despacio no debe dejar
// sin respuesta a los demás.
func TestPend_SlowDownloadBlocks(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/big.bin", bytes.Repeat([]byte("x"), 64<<20), 0644)
	base := startServer(t)
	slowDownload(t, base)
	t0 := time.Now()
	code, _, err := get(base, "/index.html", nil)
	if d := time.Since(t0); err != nil || code != 200 || d > 500*time.Millisecond {
		t.Fatalf("GET normal durante la descarga lenta: code=%d en %v (err=%v)", code, d, err)
	}
}

// #5: con un cambio del panel pendiente, un GET normal tampoco debe esperar a
// la descarga lenta.
func TestPend_SlowDownloadWithVisits(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	os.WriteFile(dir+"localhost/@/big.bin", bytes.Repeat([]byte("x"), 64<<20), 0644)
	base := startServer(t)
	tok := login(t, base)
	slowDownload(t, base)
	get(base, "/hola-calentamiento", nil)
	// El panel pide Lock mientras la descarga lenta está en curso.
	go post(base, "/admin:inside:addHeader?s=localhost&d=&a=X-A&b=1", tok)
	time.Sleep(200 * time.Millisecond)
	t0 := time.Now()
	code, _, err := get(base, "/index.html", nil)
	if d := time.Since(t0); err != nil || code != 200 || d > 500*time.Millisecond {
		t.Fatalf("GET normal con un Lock pendiente: code=%d en %v (err=%v)", code, d, err)
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

// #6, #64: sin turbo.visits, Turbo debe ir igual o más rápido que con él. Se
// anota también la referencia de la stdlib.
func TestPend_Throughput(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("medida de rendimiento: no se mide con -short ni con -race")
	}
	dir := initForTest(t)
	serverRequestLimits[2] = 1 << 40 // alto para no medir el limitador
	os.WriteFile(dir+"localhost/@/hola.txt", []byte("hola"), 0644)
	base := startServer(t)
	load(base+"/hola.txt", "localhost", 32, 2*time.Second) // calentamiento: la primera medida en frío sale más lenta
	rps, p99 := load(base+"/hola.txt", "localhost", 32, 4*time.Second)
	t.Logf("Turbo sin turbo.visits: %.0f pet/s, p99 %v", rps, p99)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false) // la recarga periódica abre el log
	rps2, p992 := load(base+"/hola.txt", "localhost", 32, 4*time.Second)
	t.Logf("Turbo con turbo.visits: %.0f pet/s, p99 %v", rps2, p992)
	serverSetLogState(visitsLogName, nil)
	os.Remove(dir + "turbo.visits")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ref := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, dir+"localhost/@/hola.txt")
	})}
	go ref.Serve(l)
	defer ref.Close()
	rps3, p993 := load("http://"+l.Addr().String()+"/", "localhost", 32, 4*time.Second)
	t.Logf("stdlib net/http: %.0f pet/s, p99 %v", rps3, p993)
	if rps < 0.8*rps2 {
		t.Errorf("sin log (%.0f pet/s) más lento que con log (%.0f pet/s)", rps, rps2)
	}
}

// BenchmarkServeStatic mide el servido de un archivo pequeño para detectar
// regresiones de rendimiento.
func BenchmarkServeStatic(b *testing.B) {
	dir := initForTest(b)
	serverRequestLimits[2] = 1 << 40
	os.WriteFile(dir+"localhost/@/hola.txt", []byte("hola"), 0644)
	base := startServer(b)
	c := &http.Client{Timeout: 5 * time.Second}
	defer c.CloseIdleConnections()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", base+"/hola.txt", nil)
		req.Host = "localhost"
		res, err := c.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}
}
