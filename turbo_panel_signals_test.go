package main

// T12 (N10, I13): the panel's responses carry nosniff and their type, and a
// missing session is signaled with a header, not with the content.

import (
	"strings"
	"testing"
)

func TestI13_PanelResponseHeaders(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.70"
	token := newSession(t, ip)
	cases := []struct {
		path, contentType string
	}{
		{"/admin:inside:sites", "application/json; charset=utf-8"},
		{"/admin:inside:subdomainData?s=localhost&d=", "application/json; charset=utf-8"},
		{"/admin:inside:addIndex?s=localhost&d=&a=start.html", "text/plain; charset=utf-8"},
		{"/admin:inside:addIndex?s=nobody.test&d=&a=start.html", "text/plain; charset=utf-8"},
	}
	for _, c := range cases {
		rec := apiFrom(serverHandlerFn(""), ip, token, c.path)
		if got := rec.Header().Get("Content-Type"); got != c.contentType {
			t.Errorf("%s: Content-Type %q; expected %q", c.path, got, c.contentType)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", c.path)
		}
		if rec.Header().Get("X-Turbo-Login") != "" {
			t.Errorf("%s: X-Turbo-Login with a session", c.path)
		}
	}
	rec := apiFrom(serverHandlerFn(""), ip, "other", "/admin:inside:sites")
	if rec.Header().Get("X-Turbo-Login") != "required" || !strings.Contains(rec.body.String(), "http-equiv") {
		t.Errorf("no session: X-Turbo-Login %q, body %q; expected required and the usual redirect", rec.Header().Get("X-Turbo-Login"), rec.body.String())
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("no session: no nosniff")
	}
}

// N10: an error template with <meta> or data-err travels in sites, and the
// response is still that of a valid session.
func TestN10_TemplateWithMetaIsData(t *testing.T) {
	initForTest(t)
	const ip = "198.51.100.71"
	token := newSession(t, ip)
	withGlobalLock(func() {
		adminAddHandlers["#"]("404", `<html><head><meta charset="utf-8"></head><body data-err>{TURBO_RESPONSE_CODE}</body></html>`)
	})
	rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:sites")
	if rec.code != 200 || rec.Header().Get("X-Turbo-Login") != "" || !strings.Contains(rec.body.String(), "<meta charset") {
		t.Errorf("sites with a <meta> template: %d, X-Turbo-Login %q", rec.code, rec.Header().Get("X-Turbo-Login"))
	}
}
