package main

// B6 (H22): la sesión se busca sin ambigüedad entre la IP y el token.

import (
	"strings"
	"testing"
)

// H22: una sesión de una IP no vale desde otra cuyo nombre, junto al token,
// forme la misma cadena (10.0.0.1 + "5…" frente a 10.0.0.15 + "…").
func TestB6_SessionKeyUnambiguous(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	rec := loginFrom(handler, "10.0.0.1", "Turbo", "Admin")
	token := strings.TrimPrefix(rec.body.String(), "ok")
	if len(token) != 64 {
		t.Fatalf("login: %d %q", rec.code, rec.body.String())
	}
	sites := func(remoteAddr, token string) *responseRecorder {
		req := newPanelRequest("/admin:inside:sites", remoteAddr)
		req.Header.Set("ok", token)
		rec := &responseRecorder{}
		handler(rec, req)
		return rec
	}
	if rec := sites("10.0.0.1:40000", token); !strings.HasPrefix(rec.body.String(), "{") {
		t.Fatalf("la sesión no vale desde su IP: %d %.40q", rec.code, rec.body.String())
	}
	if rec := sites("10.0.0.1"+token[:1]+":40000", token[1:]); strings.HasPrefix(rec.body.String(), "{") {
		t.Error("la sesión de 10.0.0.1 vale desde otra IP con el token recortado")
	}
}
