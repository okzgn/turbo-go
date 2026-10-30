package main

// Fuzzing de las funciones que interpretan entrada externa o de configuración.
// Cada objetivo solo comprueba que la función no entra en panic.

import (
	"path/filepath"
	"testing"

	"turbo/customNetHttp"
)

// initFuzz deja el estado global limpio, con los sitios localhost,
// example.com y *.example.com en un directorio temporal.
func initFuzz(f *testing.F) {
	resetTestState(filepath.ToSlash(f.TempDir()) + "/")
	globalMutex.Lock()
	defer globalMutex.Unlock()
	_constructSite("localhost", "")
	_constructSite("example.com", "")
	_constructSite("example.com", "*")
}

func FuzzHost(f *testing.F) {
	for _, s := range []string{"localhost", "a.b.c", "*.x.com", "[::1]:80", ".", "a..b", "x:80", ""} {
		f.Add(s)
	}
	initFuzz(f)
	f.Fuzz(func(t *testing.T, h string) {
		host(h)
		hostOk(h, true)
	})
}

func FuzzExtChars(f *testing.F) {
	for _, s := range []string{"png", ".png", "a-b", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, e string) {
		extChars(e)
	})
}

func FuzzHostParts(f *testing.F) {
	for _, s := range []string{"a.b.c.d", "...", "a.", ".a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		hostParts(h)
		hostDisposition(h)
	})
}

func FuzzDetectWildcards(f *testing.F) {
	f.Add("foo.example.com", "")
	f.Add("foo", "example.com")
	initFuzz(f)
	f.Fuzz(func(t *testing.T, h, d string) {
		detectWildcards(h, d)
	})
}

func FuzzShortcutWords(f *testing.F) {
	f.Add("N/x/{FILE}?a={DIR}", "/a/b.txt?q=1")
	f.Add("{", "/")
	f.Add("}{", "/x")
	f.Fuzz(func(t *testing.T, target, uri string) {
		if len(uri) == 0 || uri[0] != '/' {
			return
		}
		req := &customNetHttp.Request{RequestURI: uri, Header: customNetHttp.Header{}}
		shortcutWords(req, target, "example.com", "*", "foo.example.com", "foo", "", "", "/")
	})
}

func FuzzValidators(f *testing.F) {
	f.Add("=", "/a", "/b")
	f.Add("$", "png", "image/png")
	f.Add("?", "php", "/usr/bin/php-cgi")
	f.Add(".", "X-A", "v")
	f.Add("-", "index.html", "")
	f.Add("&", "alias.test", "")
	initFuzz(f)
	f.Fuzz(func(t *testing.T, kind, k, v string) {
		chk, ok := subdomainContentCheckers[kind]
		if !ok || kind == "!" {
			return // "!" lanza Certbot
		}
		var val interface{} = v
		if kind == "-" || kind == "&" {
			val = false
		}
		chk(true, map[string]interface{}{k: val}, false, "localhost", "")
	})
}

// Altas y bajas de IPs denegadas, respuestas por código HTTP y reemplazos de
// caracteres: también se ejecutan al cargar turbo.config, así que un panic
// tumbaría el arranque.
func FuzzAdminHandlers(f *testing.F) {
	f.Add("@", "203.0.113.7", "9999999999")
	f.Add("@", "::", "9999999999")
	f.Add("#", "404", "<h1>{TURBO_RESPONSE_CODE}</h1>")
	f.Add("_", ";", "-.-")
	initFuzz(f)
	f.Fuzz(func(t *testing.T, kind, key, value string) {
		add, ok := adminAddHandlers[kind]
		if !ok {
			return
		}
		globalMutex.Lock()
		defer globalMutex.Unlock()
		add(key, value)
		adminDeleteHandlers[kind](key)
	})
}
