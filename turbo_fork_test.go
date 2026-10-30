package main

// Parches de seguridad de Go portados al fork (#66, T0.11).

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

// CVE-2025-22871: las líneas de un cuerpo chunked deben terminar en CRLF; un
// LF solo, o un CR antes del final, es un error (contrabando de peticiones
// tras un proxy).
func TestT011_ChunkedBareLF(t *testing.T) {
	for _, body := range []string{
		"1\nX\r\n0\r\n\r\n",      // tamaño terminado en LF
		"1\r\nX\r\n0\n\r\n",      // último tamaño terminado en LF
		"1\rx\r\nX\r\n0\r\n\r\n", // CR antes del final
	} {
		if b, err := io.ReadAll(customNetHttp.NewChunkedReader(strings.NewReader(body))); err == nil {
			t.Errorf("%q aceptado: %q", body, b)
		}
	}
	b, err := io.ReadAll(customNetHttp.NewChunkedReader(strings.NewReader("1;ext=1 \r\nX\r\n0\r\n\r\n")))
	if err != nil || string(b) != "X" {
		t.Errorf("cuerpo chunked válido: %q %v", b, err)
	}
}

// CVE-2023-39326: un emisor no puede añadir sin límite datos que no son
// contenido (extensiones de chunk).
func TestT011_ChunkedExcess(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 64; i++ {
		sb.WriteString("1;" + strings.Repeat("a", 2000) + "\r\nX\r\n")
	}
	sb.WriteString("0\r\n\r\n")
	if _, err := io.ReadAll(customNetHttp.NewChunkedReader(strings.NewReader(sb.String()))); err == nil {
		t.Fatal("128 KiB de extensiones para 64 bytes de datos aceptados")
	}
}

// CVE-2026-78667: una cabecera Range con más de 200 rangos se ignora y se
// sirve el archivo completo.
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
		t.Errorf("2 rangos -> %d %v; se esperaba 206", code, err)
	}
	code, body, err := get(base, "/r.txt", map[string]string{"Range": ranges(201)})
	if err != nil || code != 200 || body != content {
		t.Errorf("201 rangos -> %d (%d bytes) %v; se esperaba 200 con el archivo completo", code, len(body), err)
	}
}

// CVE-2026-94439: tras responder a un CONNECT, el servidor no reutiliza la
// conexión para otra petición.
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
		t.Fatalf("respuesta al CONNECT: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("CONNECT -> %d", res.StatusCode)
	}
	if res2, err := http.ReadResponse(br, nil); err == nil {
		t.Fatalf("la conexión se reutilizó tras el CONNECT: segunda respuesta %d", res2.StatusCode)
	}
}

// selfSignedTLS devuelve una configuración TLS de servidor con un certificado
// autofirmado para localhost y HTTP/2 habilitado.
func selfSignedTLS(t *testing.T) *tls.Config {
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

// Prueba de humo de HTTP/2 tras portar los parches del control de flujo y de
// HPACK (CVE-2026-78663, CVE-2026-97032): peticiones con cuerpo, cabeceras de
// respuesta grandes (escritura asíncrona) y peticiones canceladas a medias.
func TestT011_HTTP2Smoke(t *testing.T) {
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Grande", strings.Repeat("v", 8000))
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
			if i%4 == 0 { // cancelada mientras envía el cuerpo
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
				errs <- fmt.Errorf("respuesta %q; se esperaba %q", b, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// P6: los timeouts se aplican sin reiniciar. Una conexión HTTP/2 abierta con
// IT = 0 no debe romperse cuando el panel activa IT (el temporizador de
// inactividad no existía todavía).
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
	fetch("con IT = 0")
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.IT = 300 * time.Millisecond }) })
	fetch("tras activar IT") // misma conexión: cierra un stream con el temporizador sin crear
	fetch("tercera petición")
	time.Sleep(time.Second) // el temporizador creado al vuelo cierra la conexión inactiva
	fetch("tras el cierre por inactividad")
}
