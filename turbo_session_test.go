package main

// B6 (H22): the session is looked up without ambiguity between the IP and the token.

import (
	"strings"
	"testing"
)

// H22: a session of one IP isn't valid from another whose name, next to the
// token, forms the same string (10.0.0.1 + "5…" versus 10.0.0.15 + "…").
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
		t.Fatalf("the session isn't valid from its IP: %d %.40q", rec.code, rec.body.String())
	}
	if rec := sites("10.0.0.1"+token[:1]+":40000", token[1:]); strings.HasPrefix(rec.body.String(), "{") {
		t.Error("the session of 10.0.0.1 is valid from another IP with the token cut")
	}
}
