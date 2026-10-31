package main

// C5 (H28, D10): un formulario multipart admite como mucho 1 000 partes, como
// Go; la subida de archivos autenticada (hardUpload), hasta 10 000.

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// manyParts devuelve un formulario multipart con n archivos "f" de un byte.
func manyParts(n int, fields ...string) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for i := 0; i+1 < len(fields); i += 2 {
		w.WriteField(fields[i], fields[i+1])
	}
	for i := 0; i < n; i++ {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f"; filename="sitio/a%d.txt"`, i))
		p, _ := w.CreatePart(h)
		p.Write([]byte("x"))
	}
	w.Close()
	return &buf, w.FormDataContentType()
}

func TestC5_FormPartsLimit(t *testing.T) {
	initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxBodySize, 50<<20) // Each part costs about 1 KiB: MBB mustn't be the limit
	anteriorYY := customNetHttp.TurboMaxFormHeaders       // Nor the headers (one per field)
	t.Cleanup(func() { customNetHttp.TurboMaxFormHeaders = anteriorYY })
	customNetHttp.TurboMaxFormHeaders = 5000
	resultado := make(chan error, 1)
	addr := servidorFork(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		resultado <- r.ParseMultipartForm(maxBodySize.Load())
		io.WriteString(w, "ok")
	})
	for partes, demasiadas := range map[int]bool{999: false, 1001: true} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for i := 0; i < partes; i++ {
			mw.WriteField(fmt.Sprintf("c%d", i), "x")
		}
		mw.Close()
		req, _ := http.NewRequest("POST", "http://"+addr+"/", &buf)
		contentType := mw.FormDataContentType()
		req.Header.Set("Content-Type", contentType)
		if res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
			res.Body.Close()
		}
		if err := <-resultado; (err != nil) != demasiadas {
			t.Errorf("formulario de %d partes: ParseMultipartForm = %v", partes, err)
		}
	}
}

// D10: hardUpload, ya autenticado, sube más de 1 000 archivos de una vez.
func TestC5_HardUploadManyFiles(t *testing.T) {
	dir := initForTest(t)
	conLimite(t, &customNetHttp.TurboMaxBodySize, 50<<20)
	anterior := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = anterior }) }) })
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.WT = time.Minute }) }) // Writing the files takes a while
	base := startServer(t)
	tok := login(t, base)
	buf, contentType := manyParts(1500, "s", "localhost", "d", "")
	req, _ := http.NewRequest("POST", base+"/admin:inside:hardUpload", buf)
	req.Host = "localhost"
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("ok", tok)
	res, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(string(b), "Datos volcados") || !fileExists(dir+"localhost/@/a1499.txt") {
		t.Errorf("hardUpload de 1 100 archivos: %d %.80q", res.StatusCode, b)
	}
}
