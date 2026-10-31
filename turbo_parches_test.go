package main

// Personalizaciones de Turbo sobre net/http de Go (parches P1-P12 de
// customNetHttp/PATCHES.md, T2.1). Los parches P6 (IT en HTTP/2) y P12 (CGI)
// tienen además sus pruebas en turbo_fork_test.go y turbo_servido_test.go.

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
	"testing"
	"time"

	"turbo/customNetHttp"
)

// plantillaEsperada reproduce la respuesta de error de Turbo para un código.
func plantillaEsperada(code int, detalle string) string {
	plantillas := *customNetHttp.TurboErrorTemplates.Load()
	v, ok := plantillas[code]
	if !ok {
		v = plantillas[0]
	}
	if !strings.HasPrefix(v, "<") {
		v = strings.ReplaceAll(v, `\n`, "\n")
	}
	return strings.ReplaceAll(v, "{TURBO_RESPONSE_CODE}", strconv.Itoa(code)) + "\n" + detalle + "\n"
}

// conLimite cambia un límite atómico del fork durante la prueba.
func conLimite(t *testing.T, limite interface {
	Load() int64
	Store(int64)
}, valor int64) {
	anterior := limite.Load()
	limite.Store(valor)
	t.Cleanup(func() { limite.Store(anterior) })
}

// servidorFork arranca un customNetHttp.Server con el manejador dado, en
// HTTP o en HTTPS (con HTTP/2), y devuelve su dirección.
func servidorFork(t *testing.T, conTLS bool, h func(customNetHttp.ResponseWriter, *customNetHttp.Request)) string {
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(h)}
	var l net.Listener
	var err error
	if conTLS {
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

func manejadorOK(w customNetHttp.ResponseWriter, r *customNetHttp.Request) { io.WriteString(w, "ok") }

// crudo envía una petición HTTP/1 tal cual y devuelve la respuesta.
func crudo(t *testing.T, addr, peticion string) (*http.Response, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, peticion); err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("respuesta ilegible: %v", err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

// comprobarError comprueba una respuesta de error con la plantilla de Turbo.
func comprobarError(t *testing.T, que string, res *http.Response, cuerpo string, code int, detalle string) {
	t.Helper()
	if res.StatusCode != code {
		t.Errorf("%s: código %d; se esperaba %d", que, res.StatusCode, code)
		return
	}
	if want := plantillaEsperada(code, detalle); cuerpo != want {
		t.Errorf("%s: cuerpo %q; se esperaba %q", que, cuerpo, want)
	}
	if ct := strings.ToLower(res.Header.Get("Content-Type")); ct != "text/plain; charset=utf-8" {
		t.Errorf("%s: Content-Type %q", que, ct)
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s: falta X-Content-Type-Options: nosniff", que)
	}
	if got := res.Header.Get("Server"); got != serverName {
		t.Errorf("%s: Server %q; se esperaba %q", que, got, serverName)
	}
}

// P1, P3 y P4: errores previos al manejador de HTTP/1 con la plantilla, la
// cabecera Server y Connection: close; límites exactos de URI y cabeceras.
func TestT21_P1_ErroresHTTP1(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxURILength, 40)
	conLimite(t, &customNetHttp.TurboMaxHeaderBytes, 600)
	addr := servidorFork(t, false, manejadorOK)

	casos := []struct {
		que, peticion, detalle string
		code                   int
	}{
		{"línea de petición mal formada", "GARBAGE\r\n\r\n", "", 400},
		{"cabecera Host mal formada", "GET / HTTP/1.1\r\nHost: a b\r\n\r\n", "", 400},
		{"Transfer-Encoding desconocido", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: rara\r\n\r\n", "Unsupported transfer encoding", 501},
		{"URI de 41 bytes (P3)", "GET /" + strings.Repeat("u", 40) + " HTTP/1.1\r\nHost: x\r\n\r\n", "", 414},
		{"cabeceras de más de 600 bytes (P4)", "GET / HTTP/1.1\r\nHost: x\r\nX-Relleno: " + strings.Repeat("r", 700) + "\r\n\r\n", "", 431},
	}
	for _, c := range casos {
		res, cuerpo := crudo(t, addr, c.peticion)
		comprobarError(t, c.que, res, cuerpo, c.code, c.detalle)
		if !res.Close {
			t.Errorf("%s: falta Connection: close", c.que)
		}
	}

	// Límites exactos: una URI de 40 bytes y una cabecera de 600 bytes justos
	// pasan; un byte más, no.
	if res, _ := crudo(t, addr, "GET /"+strings.Repeat("u", 39)+" HTTP/1.1\r\nHost: x\r\n\r\n"); res.StatusCode != 200 {
		t.Errorf("URI de 40 bytes: %d; se esperaba 200", res.StatusCode)
	}
	cabecera := func(total int) string {
		base := "GET / HTTP/1.1\r\nHost: x\r\nX-Relleno: \r\n\r\n"
		return strings.Replace(base, "X-Relleno: ", "X-Relleno: "+strings.Repeat("r", total-len(base)), 1)
	}
	if res, _ := crudo(t, addr, cabecera(600)); res.StatusCode != 200 {
		t.Errorf("cabecera de 600 bytes: %d; se esperaba 200", res.StatusCode)
	}
	if res, _ := crudo(t, addr, cabecera(601)); res.StatusCode != 431 {
		t.Errorf("cabecera de 601 bytes: %d; se esperaba 431", res.StatusCode)
	}
}

// h2 es un cliente HTTP/2 mínimo para enviar tramas que el cliente de la
// biblioteca estándar no permite (cabeceras de tamaño exacto, RST_STREAM).
type h2 struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
	id uint32
}

func dialH2(t *testing.T, addr string) *h2 {
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("ALPN %q", p)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	h := &h2{t: t, c: c, br: bufio.NewReader(c), id: 1}
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h.trama(4, 0, 0, nil) // SETTINGS
	return h
}

func (h *h2) trama(tipo, flags byte, stream uint32, carga []byte) {
	cab := make([]byte, 9)
	cab[0], cab[1], cab[2] = byte(len(carga)>>16), byte(len(carga)>>8), byte(len(carga))
	cab[3], cab[4] = tipo, flags
	binary.BigEndian.PutUint32(cab[5:], stream)
	if _, err := h.c.Write(append(cab, carga...)); err != nil {
		h.t.Fatal(err)
	}
}

// hpackLiteral codifica un campo literal sin indexar y sin Huffman.
func hpackLiteral(b *bytes.Buffer, nombre, valor string) {
	entero := func(v int) {
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
	entero(len(nombre))
	b.WriteString(nombre)
	entero(len(valor))
	b.WriteString(valor)
}

// peticion abre un stream con un GET y las cabeceras dadas (pares nombre,
// valor tras las pseudocabeceras) y devuelve su identificador.
func (h *h2) peticion(path string, extra ...string) uint32 {
	var b bytes.Buffer
	campos := append([]string{":method", "GET", ":scheme", "https", ":path", path, ":authority", "x"}, extra...)
	for i := 0; i < len(campos); i += 2 {
		hpackLiteral(&b, campos[i], campos[i+1])
	}
	id := h.id
	h.id += 2
	h.trama(1, 0x5, id, b.Bytes()) // HEADERS con END_STREAM y END_HEADERS
	return id
}

// leer lee tramas hasta que el stream termina y devuelve el cuerpo, o hasta
// un GOAWAY (devuelve su código de error con goaway = true).
func (h *h2) leer(stream uint32) (cuerpo string, goaway bool, codigo uint32) {
	var b bytes.Buffer
	for {
		cab := make([]byte, 9)
		if _, err := io.ReadFull(h.br, cab); err != nil {
			h.t.Fatalf("leyendo tramas: %v", err)
		}
		n := int(cab[0])<<16 | int(cab[1])<<8 | int(cab[2])
		carga := make([]byte, n)
		if _, err := io.ReadFull(h.br, carga); err != nil {
			h.t.Fatal(err)
		}
		tipo, flags, id := cab[3], cab[4], binary.BigEndian.Uint32(cab[5:])&0x7fffffff
		switch {
		case tipo == 4 && flags&1 == 0: // SETTINGS del servidor
			h.trama(4, 1, 0, nil)
		case tipo == 7: // GOAWAY
			return b.String(), true, binary.BigEndian.Uint32(carga[4:8])
		case tipo == 6 && flags&1 == 1 && stream == 0: // respuesta al PING
			return "", false, 0
		case id == stream && stream != 0 && (tipo == 0 || tipo == 1):
			if tipo == 0 {
				b.Write(carga)
			}
			if flags&1 == 1 {
				return b.String(), false, 0
			}
		}
	}
}

// P2, P3 y P5: en HTTP/2, :path por encima de TurboMaxURILength da 414 y una lista de
// cabeceras por encima de TurboMaxHeaderBytes (bytes de nombre y valor más 32 por campo,
// como cuenta HTTP/2; C6) da 431, ambos con la plantilla; el límite es exacto.
func TestT21_P2_LimitesHTTP2(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxURILength, 40)
	conLimite(t, &customNetHttp.TurboMaxHeaderBytes, 600)
	addr := servidorFork(t, true, manejadorOK)
	h := dialH2(t, addr)

	if cuerpo, _, _ := h.leer(h.peticion("/" + strings.Repeat("u", 39))); cuerpo != "ok" {
		t.Errorf(":path de 40 bytes: %q; se esperaba ok", cuerpo)
	}
	if cuerpo, _, _ := h.leer(h.peticion("/" + strings.Repeat("u", 40))); cuerpo != plantillaEsperada(414, "") {
		t.Errorf(":path de 41 bytes: %q; se esperaba el 414 de la plantilla", cuerpo)
	}

	// :method GET :scheme https :path / :authority x suman 7+3+7+5+5+1+10+1 = 39
	// bytes, más 32 por cada uno de los cinco campos; x-relleno completa el total.
	relleno := func(total int) string { return strings.Repeat("r", total-39-len("x-relleno")-5*32) }
	if cuerpo, _, _ := h.leer(h.peticion("/", "x-relleno", relleno(600))); cuerpo != "ok" {
		t.Errorf("cabeceras de 600 bytes: %q; se esperaba ok", cuerpo)
	}
	if cuerpo, _, _ := h.leer(h.peticion("/", "x-relleno", relleno(601))); cuerpo != plantillaEsperada(431, "") {
		t.Errorf("cabeceras de 601 bytes: %q; se esperaba el 431 de la plantilla", cuerpo)
	}

	// El límite se lee en cada petición: con MHB más alto, la misma conexión acepta más.
	customNetHttp.TurboMaxHeaderBytes.Store(2000)
	if cuerpo, _, _ := h.leer(h.peticion("/", "x-relleno", relleno(1500))); cuerpo != "ok" {
		t.Errorf("cabeceras de 1500 bytes con TurboMaxHeaderBytes = 2000: %q; se esperaba ok", cuerpo)
	}
}

// C6 (H29): en HTTP/2 cada campo cuenta 32 bytes además de su nombre y su
// valor, como en Go: con MHB = 5000, 200 cabeceras de 1 byte no caben.
func TestC6_HTTP2FieldOverhead(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxHeaderBytes, 5000)
	addr := servidorFork(t, true, manejadorOK)
	h := dialH2(t, addr)
	var campos []string
	for i := 0; i < 200; i++ {
		campos = append(campos, "x", "")
	}
	if cuerpo, _, _ := h.leer(h.peticion("/", campos...)); cuerpo != plantillaEsperada(431, "") {
		t.Errorf("200 cabeceras de 1 byte con MHB = 5000: %q; se esperaba el 431 de la plantilla", cuerpo)
	}
	if cuerpo, _, _ := h.leer(h.peticion("/", campos[:100]...)); cuerpo != "ok" {
		t.Errorf("50 cabeceras de 1 byte con MHB = 5000: %q; se esperaba ok", cuerpo)
	}
}

// P11: más de 50 RST_STREAM por segundo en una conexión la cierran con
// GOAWAY (ENHANCE_YOUR_CALM); 40 no.
func TestT21_P11_RSTStream(t *testing.T) {
	initForTest(t)
	addr := servidorFork(t, true, manejadorOK)
	rst := func(h *h2, n int) {
		for i := 0; i < n; i++ {
			id := h.peticion("/")
			h.trama(3, 0, id, []byte{0, 0, 0, 8}) // RST_STREAM CANCEL
		}
	}

	h := dialH2(t, addr)
	rst(h, 40)
	h.trama(6, 0, 0, make([]byte, 8)) // PING: la respuesta llega si la conexión sigue abierta
	if _, goaway, codigo := h.leer(0); goaway {
		t.Fatalf("40 RST_STREAM: GOAWAY con código %d", codigo)
	}

	h = dialH2(t, addr)
	rst(h, 60)
	for {
		_, goaway, codigo := h.leer(0)
		if goaway {
			if codigo != 0xb {
				t.Errorf("GOAWAY con código %d; se esperaba ENHANCE_YOUR_CALM (11)", codigo)
			}
			return
		}
		h.trama(6, 0, 0, make([]byte, 8))
	}
}

// P6: los timeouts de HTTP/1 se leen en cada conexión: IT y RHT activados con
// el servidor en marcha cierran las conexiones inactivas o lentas.
func TestT21_P6_TimeoutsHTTP1(t *testing.T) {
	initForTest(t)
	anterior := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = anterior }) }) })
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.IT, t.RHT, t.RT, t.WT = 0, 0, 0, 0 }) })
	addr := servidorFork(t, false, manejadorOK)
	withGlobalLock(func() {
		setTimeLimits(func(t *customNetHttp.Timeouts) { t.IT, t.RHT = 300*time.Millisecond, 300*time.Millisecond })
	})

	cerrada := func(c net.Conn) bool {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		return err == io.EOF
	}

	// IT: tras una petición, la conexión inactiva se cierra.
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
	inicio := time.Now()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF || time.Since(inicio) > 2*time.Second {
		t.Errorf("IT = 300 ms: la conexión inactiva sigue abierta (%v tras %v)", err, time.Since(inicio))
	}

	// RHT: una cabecera a medias se corta.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	io.WriteString(c2, "GET / HTTP/1.1\r\nHost: x\r\n")
	if !cerrada(c2) {
		t.Error("RHT = 300 ms: la petición a medias no se corta")
	}
}

// B4 (H15): con RHT o IT a 0, la lectura de cabeceras y la inactividad usan
// RT, como en Go, en lugar de no tener límite.
func TestB4_ZeroTimeoutsUseRT(t *testing.T) {
	initForTest(t)
	anterior := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = anterior }) }) })
	withGlobalLock(func() {
		setTimeLimits(func(t *customNetHttp.Timeouts) { t.RT, t.RHT, t.IT, t.WT = 300*time.Millisecond, 0, 0, 0 })
	})
	addr := servidorFork(t, false, manejadorOK)
	cerradaEn := func(c net.Conn) (bool, time.Duration) {
		inicio := time.Now()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := c.Read(make([]byte, 1))
		return err == io.EOF, time.Since(inicio)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n") // Headers that never end
	if cerrada, tras := cerradaEn(c); !cerrada || tras > 2*time.Second {
		t.Errorf("RT = 300 ms y RHT = 0: la petición a medias sigue abierta (%v tras %v)", cerrada, tras)
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
	inicio := time.Now()
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err != io.EOF || time.Since(inicio) > 2*time.Second {
		t.Errorf("RT = 300 ms e IT = 0: la conexión inactiva sigue abierta (%v tras %v)", err, time.Since(inicio))
	}
}

// P7: si el manejador no lee el cuerpo, la conexión se cierra en lugar de
// vaciarlo (Go lee hasta 256 KiB y la reutiliza).
func TestT21_P7_CuerpoSinLeer(t *testing.T) {
	initForTest(t)
	addr := servidorFork(t, false, manejadorOK)
	res, cuerpo := crudo(t, addr, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789")
	if res.StatusCode != 200 || cuerpo != "ok" {
		t.Fatalf("%d %q", res.StatusCode, cuerpo)
	}
	if !res.Close {
		t.Error("falta Connection: close con el cuerpo sin leer")
	}

	// B1 (H13): with the body read to the end, the connection is reused, as in Go.
	addr = servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
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
	for i, peticion := range []string{
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789",
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n01234\r\n0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	} {
		io.WriteString(c, peticion)
		res, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("petición %d en la misma conexión: %v", i+1, err)
		}
		io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || (res.Close && i < 2) {
			t.Fatalf("petición %d: %d, Connection: close %v; se esperaba mantener la conexión tras un cuerpo leído entero", i+1, res.StatusCode, res.Close)
		}
	}
}

// P8: la cabecera Server en HTTP/1 y HTTP/2.
func TestT21_P8_CabeceraServer(t *testing.T) {
	initForTest(t)
	for _, conTLS := range []bool{false, true} {
		addr := servidorFork(t, conTLS, manejadorOK)
		url := "http://" + addr + "/"
		tr := &http.Transport{}
		if conTLS {
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
			t.Errorf("%s: Server %q; se esperaba %q", res.Proto, got, serverName)
		}
	}
}

// C4 (H27): ParseMultipartForm con maxMemory <= 0 usa MBB como límite y no
// crea archivos temporales.
func TestC4_ParseMultipartFormZero(t *testing.T) {
	initForTest(t)
	resultado := make(chan string, 1)
	addr := servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		err := r.ParseMultipartForm(0)
		guardado := r.MultipartForm != nil && len(r.MultipartForm.File["f"]) > 0 // In memory or in a temporary file
		if r.MultipartForm != nil {
			r.MultipartForm.RemoveAll()
		}
		resultado <- fmt.Sprintf("err=%v archivo=%v", err, guardado)
		io.WriteString(w, "ok")
	})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("f", "grande.bin")
	fw.Write(bytes.Repeat([]byte("x"), int(maxBodySize.Load())*2))
	mw.Close()
	req, _ := http.NewRequest("POST", "http://"+addr+"/", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req); err == nil {
		res.Body.Close()
	}
	select {
	case r := <-resultado:
		if !strings.Contains(r, "too large") || strings.Contains(r, "archivo=true") {
			t.Errorf("ParseMultipartForm(0) con el doble de MBB: %s; se esperaba \"message too large\" sin archivo", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el manejador no respondió")
	}
}

// C7 (H30): un formulario urlencoded se guarda entero en memoria, así que se
// limita a 10 MiB aunque MBB sea mayor (como Go).
func TestC7_URLEncodedFormLimit(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxBodySize, 100<<20)
	resultado := make(chan error, 1)
	addr := servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		resultado <- r.ParseForm()
		io.WriteString(w, "ok")
	})
	for tamaño, demasiado := range map[int]bool{10 << 20: false, 11 << 20: true} {
		cuerpo := "a=" + strings.Repeat("x", tamaño-2)
		req, _ := http.NewRequest("POST", "http://"+addr+"/", strings.NewReader(cuerpo))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
			res.Body.Close()
		}
		if err := <-resultado; (err != nil) != demasiado {
			t.Errorf("formulario de %d bytes con MBB = 100 MiB: ParseForm = %v", tamaño, err)
		}
	}
}

// H53: el tope de 10 MiB de los formularios urlencoded se aplica al leer,
// también cuando el manejador ya limita el cuerpo con MaxBytesReader a más:
// no se lee (ni se guarda en memoria) más de lo que se va a aceptar.
func TestH53_URLEncodedLimitWithMaxBytesReader(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxBodySize, 100<<20)
	type resultadoForm struct {
		err   error
		leido int64
	}
	resultado := make(chan resultadoForm, 1)
	addr := servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		cuenta := &lectorContado{r: r.Body}
		r.Body = customNetHttp.MaxBytesReader(w, io.NopCloser(cuenta), 50<<20)
		err := r.ParseForm()
		resultado <- resultadoForm{err, cuenta.n}
		io.WriteString(w, "ok")
	})
	cuerpo := "a=" + strings.Repeat("x", 20<<20)
	req, _ := http.NewRequest("POST", "http://"+addr+"/", strings.NewReader(cuerpo))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req); err == nil {
		res.Body.Close()
	}
	r := <-resultado
	if r.err == nil {
		t.Error("formulario de 20 MiB con MaxBytesReader de 50 MiB: ParseForm sin error; el tope es 10 MiB")
	}
	if r.leido > 11<<20 {
		t.Errorf("formulario de 20 MiB: se leyeron %d bytes antes de rechazarlo; se esperaba no pasar de 10 MiB", r.leido)
	}
}

type lectorContado struct {
	r io.Reader
	n int64
}

func (l *lectorContado) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

// H54: en HTTP/2, SETTINGS_MAX_HEADER_LIST_SIZE anuncia el mismo límite que
// se aplica (MHB, con 32 bytes por campo): un cliente que respeta lo anunciado
// no recibe 431 por una lista de cabeceras que el servidor dijo aceptar.
func TestH54_HTTP2AnnouncedHeaderLimit(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxHeaderBytes, 5000)
	addr := servidorFork(t, true, manejadorOK)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	pedir := func(relleno int) (int, error) {
		req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
		if relleno > 0 {
			req.Header.Set("X-Relleno", strings.Repeat("r", relleno))
		}
		res, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		res.Body.Close()
		return res.StatusCode, nil
	}
	if code, err := pedir(0); err != nil || code != 200 { // Opens the connection: the client learns the SETTINGS
		t.Fatalf("petición inicial: %d %v", code, err)
	}
	if code, err := pedir(4500); err != nil || code != 200 {
		t.Errorf("unos 4 800 bytes de cabeceras con MHB = 5000: %d %v; se esperaba 200", code, err)
	}
	// About 5 130 bytes: above MHB. The client may refuse it (the limit it was told) but the server must not
	// announce a limit and then answer 431 below it.
	if code, err := pedir(4800); err == nil && code == 431 {
		t.Errorf("unos 5 130 bytes de cabeceras con MHB = 5000: el cliente la envió (el servidor anunció más) y recibió 431")
	}
}

// C3 (H26): una sola cabecera Server, la de Turbo, aunque el manejador fije
// Server (cabeceras del sitio, un CGI) o Date, en HTTP/1.1 y HTTP/2.
func TestC3_OneServerHeader(t *testing.T) {
	initForTest(t)
	for _, conTLS := range []bool{false, true} {
		addr := servidorFork(t, conTLS, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
			switch r.URL.Path {
			case "/server":
				w.Header().Set("Server", "Otro")
			case "/date":
				w.Header().Set("Date", "Mon, 02 Jan 2006 15:04:05 GMT")
			}
			io.WriteString(w, "ok")
		})
		base := "http://" + addr
		tr := &http.Transport{}
		if conTLS {
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
				t.Errorf("%s %s: Server %q; se esperaba una sola, %q", res.Proto, path, got, serverName)
			}
		}
		tr.CloseIdleConnections()
	}
}

// P9: Error, NotFound y las respuestas de ServeContent usan la plantilla; una
// plantilla que empieza por '<' se sirve como HTML.
func TestT21_P9_PlantillaError(t *testing.T) {
	initForTest(t)
	addr := servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		switch r.URL.Path {
		case "/error":
			w.Header().Set("Content-Length", "99")
			customNetHttp.Error(w, "detalle", 418)
		case "/notfound":
			customNetHttp.NotFound(w, r)
		case "/rango":
			customNetHttp.ServeContent(w, r, "a.txt", time.Time{}, strings.NewReader("contenido"))
		}
	})
	get := func(path string, hdr ...string) (*http.Response, string) {
		extra := ""
		for i := 0; i < len(hdr); i += 2 {
			extra += hdr[i] + ": " + hdr[i+1] + "\r\n"
		}
		return crudo(t, addr, "GET "+path+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"+extra+"\r\n")
	}
	res, cuerpo := get("/error")
	comprobarError(t, "Error", res, cuerpo, 418, "detalle")
	res, cuerpo = get("/notfound")
	comprobarError(t, "NotFound", res, cuerpo, 404, "")
	res, cuerpo = get("/rango", "Range", "bytes=50-60")
	comprobarError(t, "ServeContent 416", res, cuerpo, 416, "invalid range: failed to overlap")

	anterior := customNetHttp.TurboErrorTemplates.Load()
	t.Cleanup(func() { customNetHttp.TurboErrorTemplates.Store(anterior) })
	html := map[int]string{}
	for k, v := range *anterior {
		html[k] = v
	}
	html[418] = "<p>Error {TURBO_RESPONSE_CODE}</p>"
	customNetHttp.TurboErrorTemplates.Store(&html)
	res, cuerpo = get("/error")
	if ct := strings.ToLower(res.Header.Get("Content-Type")); ct != "text/html; charset=utf-8" || cuerpo != "<p>Error 418</p>\ndetalle\n" {
		t.Errorf("plantilla HTML: %q, %q", ct, cuerpo)
	}
}

// C8 (H31): en una plantilla HTML, el detalle del error se escapa; en una de
// texto se deja tal cual.
func TestC8_HTMLTemplateDetailEscaped(t *testing.T) {
	initForTest(t)
	addr := servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		customNetHttp.Error(w, `<script>alert("x")</script> & más`, 418)
	})
	anterior := customNetHttp.TurboErrorTemplates.Load()
	t.Cleanup(func() { customNetHttp.TurboErrorTemplates.Store(anterior) })
	customNetHttp.TurboErrorTemplates.Store(&map[int]string{0: "<p>Error {TURBO_RESPONSE_CODE}</p>"})
	_, cuerpo := crudo(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if want := "<p>Error 418</p>\n&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt; &amp; más\n"; cuerpo != want {
		t.Errorf("plantilla HTML: %q; se esperaba %q", cuerpo, want)
	}
	customNetHttp.TurboErrorTemplates.Store(&map[int]string{0: `Error {TURBO_RESPONSE_CODE}`})
	if _, cuerpo = crudo(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.Contains(cuerpo, "<script>") {
		t.Errorf("plantilla de texto: %q; el detalle no debía cambiar", cuerpo)
	}
}

// P10: formularios limitados por MBB (TurboMaxBodySize), TurboMaxFormParts partes y TurboMaxFormHeaders cabeceras, y
// multipart solo en memoria.
func TestT21_P10_Formularios(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxBodySize, 2000)
	anteriorYX, anteriorYY := customNetHttp.TurboMaxFormParts, customNetHttp.TurboMaxFormHeaders
	t.Cleanup(func() { customNetHttp.TurboMaxFormParts, customNetHttp.TurboMaxFormHeaders = anteriorYX, anteriorYY })
	customNetHttp.TurboMaxFormParts, customNetHttp.TurboMaxFormHeaders = 3, 4
	addr := servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		if r.URL.Path == "/valor" {
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
		archivos := 0
		if r.MultipartForm != nil {
			for _, fhs := range r.MultipartForm.File {
				archivos += len(fhs)
			}
		}
		fmt.Fprintf(w, "ok %d valores %d archivos", len(r.Form), archivos)
	})
	enviar := func(path, tipo, cuerpo string) string {
		_, b := crudo(t, addr, fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s", path, tipo, len(cuerpo), cuerpo))
		return b
	}
	urlenc := "application/x-www-form-urlencoded"
	if got := enviar("/", urlenc, "a="+strings.Repeat("x", 1990)); got != "ok 1 valores 0 archivos" {
		t.Errorf("urlencoded de 1992 bytes: %q", got)
	}
	if got := enviar("/", urlenc, "a="+strings.Repeat("x", 2000)); got != "error: http: POST too large" {
		t.Errorf("urlencoded de 2002 bytes: %q", got)
	}

	type parte struct {
		archivo   bool
		tam       int
		cabeceras int
	}
	multi := func(path string, partes ...parte) string {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		for i, p := range partes {
			h := textproto.MIMEHeader{}
			if p.archivo {
				h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f%d"; filename="f%d.txt"`, i, i))
			} else {
				h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="a%d"`, i))
			}
			for k := 1; k < p.cabeceras; k++ {
				h.Set(fmt.Sprintf("X-Extra-%d", k), "1")
			}
			w, _ := mw.CreatePart(h)
			w.Write(bytes.Repeat([]byte("z"), p.tam))
		}
		mw.Close()
		return enviar(path, mw.FormDataContentType(), b.String())
	}
	// Cada parte cuesta además unos cientos de bytes de memoria por sus
	// cabeceras (las cuentas de Go): con MBB = 20000 caben las partes, pero
	// no más de TurboMaxFormParts partes ni más de TurboMaxFormHeaders cabeceras.
	customNetHttp.TurboMaxBodySize.Store(20000)
	if got := multi("/", parte{false, 10, 1}, parte{true, 100, 1}, parte{true, 100, 1}); got != "ok 1 valores 2 archivos" {
		t.Errorf("multipart de 3 partes: %q", got)
	}
	if got := multi("/", parte{false, 1, 1}, parte{false, 1, 1}, parte{false, 1, 1}, parte{false, 1, 1}); got != "error: multipart: message too large" {
		t.Errorf("multipart de 4 partes con TurboMaxFormParts = 3: %q", got)
	}
	if got := multi("/", parte{true, 10, 5}); got != "error: multipart: message too large" {
		t.Errorf("parte con 5 cabeceras con TurboMaxFormHeaders = 4: %q", got)
	}
	// Un archivo que no cabe en memoria se rechaza (Go lo pasaría a disco).
	customNetHttp.TurboMaxBodySize.Store(3000)
	if got := multi("/", parte{true, 1500, 1}); got != "ok 0 valores 1 archivos" {
		t.Errorf("archivo de 1500 bytes con MBB = 3000: %q", got)
	}
	if got := multi("/", parte{true, 5000, 1}); got != "error: multipart: message too large" {
		t.Errorf("archivo de 5000 bytes con MBB = 3000: %q", got)
	}
	customNetHttp.TurboMaxBodySize.Store(1000)
	// FormValue analiza el multipart con MBB, no con los 32 MB de Go.
	if got := multi("/valor", parte{false, 1500, 1}); got != "v=" {
		t.Errorf("FormValue con un valor de 1500 bytes y MBB = 1000: %q", got)
	}
}

// P13: una conexión HTTP/2 que no envía el prefacio se cierra a 1 s (Go: 10 s).
func TestT21_P13_PrefacioHTTP2(t *testing.T) {
	initForTest(t)
	addr := servidorFork(t, true, manejadorOK)
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	inicio := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.Copy(io.Discard, c) // el servidor envía sus SETTINGS y cierra al vencer el plazo
	if d := time.Since(inicio); d > 3*time.Second {
		t.Errorf("sin prefacio, la conexión sigue abierta tras %v (%v); se esperaba ~1 s", d, err)
	}
}

// El servidor HTTPS de Turbo anuncia 50 streams HTTP/2 simultáneos por
// conexión (por configuración, sin parche; Go: 250).
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
		cab := make([]byte, 9)
		if _, err := io.ReadFull(h.br, cab); err != nil {
			t.Fatal(err)
		}
		carga := make([]byte, int(cab[0])<<16|int(cab[1])<<8|int(cab[2]))
		if _, err := io.ReadFull(h.br, carga); err != nil {
			t.Fatal(err)
		}
		if cab[3] != 4 || cab[4]&1 == 1 { // solo los SETTINGS del servidor
			continue
		}
		for i := 0; i+6 <= len(carga); i += 6 {
			if binary.BigEndian.Uint16(carga[i:]) == 3 { // SETTINGS_MAX_CONCURRENT_STREAMS
				if v := binary.BigEndian.Uint32(carga[i+2:]); v != 50 {
					t.Fatalf("SETTINGS_MAX_CONCURRENT_STREAMS = %d; se esperaba 50", v)
				}
				return
			}
		}
		t.Fatal("el servidor no anuncia SETTINGS_MAX_CONCURRENT_STREAMS")
	}
}
