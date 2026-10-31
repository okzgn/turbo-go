package main

// C9 (H32): un cuerpo de parámetros mal formado o demasiado grande se rechaza
// en vez de tratarse como si faltaran datos.

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestC9_PanelFormErrors(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	send := func(body string) (int, string) {
		req, _ := http.NewRequest("POST", base+"/admin:inside:addSite", strings.NewReader(body))
		req.Host = "localhost"
		req.Header.Set("ok", tok)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := (&http.Client{Timeout: clientTimeout() * 3}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := send("s=c9.test&x=%zz"); code != 400 || body != "Parámetros incorrectos" {
		t.Errorf("parámetros mal codificados: %d %q; se esperaba 400 \"Parámetros incorrectos\"", code, body)
	}
	if code, body := send("s=c9.test&x=" + strings.Repeat("x", int(maxBodySize.Load()))); code != 413 {
		t.Errorf("parámetros por encima de MBB: %d %.60q; se esperaba 413", code, body)
	}
	if code, body := send("s=c9.test"); code != 200 {
		t.Errorf("addSite correcto: %d %q", code, body)
	}
}
