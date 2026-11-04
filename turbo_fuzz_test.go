package main

// Fuzzing of the functions that parse external or configuration input.
// Each target only checks that the function doesn't panic.

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"turbo/customNetHttp"
)

// initFuzz leaves the global state clean, with the sites localhost,
// example.com and *.example.com in a temporary directory.
func initFuzz(f *testing.F) {
	resetTestState(filepath.ToSlash(f.TempDir()) + "/")
	globalMutex.Lock()
	defer globalMutex.Unlock()
	constructSiteWithoutIndex("localhost", "")
	constructSiteWithoutIndex("example.com", "")
	constructSiteWithoutIndex("example.com", "*")
}

func FuzzHost(f *testing.F) {
	for _, s := range []string{"localhost", "a.b.c", "*.x.com", "[::1]:80", ".", "a..b", "x:80", "", "X&a=1.example.com", "Example.COM.", "xn--a.example.com", "a_b.example.com"} {
		f.Add(s)
	}
	initFuzz(f)
	f.Fuzz(func(t *testing.T, h string) {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		// A host accepted for a request has only the characters of a host name (or is an IP): nothing else
		// reaches the sites nor the placeholders of the rewrites.
		if valid, wildcard, subdomain, domain := host(h); valid && !(validHostChars(subdomain) && validHostChars(domain) && (wildcard == "" || validHostChars(strings.TrimPrefix(wildcard, "*.")) || wildcard == "*")) {
			if _, err := netip.ParseAddr(domain); err != nil {
				t.Fatalf("host(%q) accepted: %q %q %q", h, wildcard, subdomain, domain)
			}
		}
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
		shortcutWords(req, target, "example.com", "*", "foo.example.com", "foo", "", "", "/", "/")
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
			return // "!" runs Certbot
		}
		var val interface{} = v
		if kind == "-" || kind == "&" {
			val = false
		}
		chk(true, map[string]interface{}{k: val}, false, "localhost", "")
	})
}

// Adding and deleting denied IPs, responses per HTTP code and character
// replacements: they also run when turbo.config is loaded, so a panic would
// bring the startup down.
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
