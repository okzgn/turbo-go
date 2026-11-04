package main

// C5 (H28, D10): a multipart form takes at most 1 000 parts, as in Go; the
// authenticated file upload (hardUpload), up to 10 000.

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

// manyParts returns a multipart form with n one-byte "f" files.
func manyParts(n int, fields ...string) (*bytes.Buffer, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for i := 0; i+1 < len(fields); i += 2 {
		w.WriteField(fields[i], fields[i+1])
	}
	for i := 0; i < n; i++ {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f"; filename="site/a%d.txt"`, i))
		p, _ := w.CreatePart(h)
		p.Write([]byte("x"))
	}
	w.Close()
	return &buf, w.FormDataContentType()
}

func TestC5_FormPartsLimit(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxBodySize, 50<<20) // Each part costs about 1 KiB: MBB mustn't be the limit
	result := make(chan error, 1)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		result <- r.ParseMultipartForm(maxBodySize.Load())
		io.WriteString(w, "ok")
	})
	for parts, tooMany := range map[int]bool{999: false, 1001: true} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for i := 0; i < parts; i++ {
			mw.WriteField(fmt.Sprintf("c%d", i), "x")
		}
		mw.Close()
		req, _ := http.NewRequest("POST", "http://"+addr+"/", &buf)
		contentType := mw.FormDataContentType()
		req.Header.Set("Content-Type", contentType)
		if res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
			res.Body.Close()
		}
		if err := <-result; (err != nil) != tooMany {
			t.Errorf("form with %d parts: ParseMultipartForm = %v", parts, err)
		}
	}
}

// D10: hardUpload, already authenticated, uploads more than 1 000 files at once.
func TestC5_HardUploadManyFiles(t *testing.T) {
	dir := initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxBodySize, 50<<20)
	previous := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { *t = previous }) }) })
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.WT = time.Minute }) }) // Writing the files takes a while
	base := startServer(t)
	tok := login(t, base)
	buf, contentType := manyParts(1500, "s", "localhost", "d", "", "b", "Admin")
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
	if res.StatusCode != 200 || !strings.HasPrefix(string(b), "Data uploaded") || !fileExists(dir+"localhost/@/a1499.txt") {
		t.Errorf("hardUpload of 1 100 files: %d %.80q", res.StatusCode, b)
	}
}

// F4: with the usual limits, a form of 1 000 file parts (two headers each) is
// accepted and one of 1 001 is rejected: the header limit doesn't stop at
// about 500 file parts.
func TestF04_ThousandFileParts(t *testing.T) {
	initForTest(t)
	withLimit(t, &customNetHttp.TurboMaxBodySize, 50<<20)
	result := make(chan error, 1)
	addr := forkServer(t, false, func(w customNetHttp.ResponseWriter, r *customNetHttp.Request) {
		result <- r.ParseMultipartForm(maxBodySize.Load())
		io.WriteString(w, "ok")
	})
	for _, c := range []struct {
		parts   int
		tooMany bool
	}{{1000, false}, {1001, true}} {
		var buf bytes.Buffer // As browsers send files: Content-Disposition and Content-Type
		mw := multipart.NewWriter(&buf)
		for i := 0; i < c.parts; i++ {
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="f"; filename="a%d.txt"`, i))
			h.Set("Content-Type", "text/plain")
			p, _ := mw.CreatePart(h)
			p.Write([]byte("x"))
		}
		mw.Close()
		contentType := mw.FormDataContentType()
		req, _ := http.NewRequest("POST", "http://"+addr+"/", &buf)
		req.Header.Set("Content-Type", contentType)
		if res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
			res.Body.Close()
		}
		if err := <-result; (err != nil) != c.tooMany {
			t.Errorf("form with %d file parts: ParseMultipartForm = %v", c.parts, err)
		}
	}
}
