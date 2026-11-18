package main

// Fuzzing of the functions that parse external or configuration input.
// Each target only checks that the function doesn't panic.

import (
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
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
	for _, s := range []string{"localhost", "a.b.c", "*.x.com", "[::1]:80", ".", "a..b", "x:80", "", "X&a=1.example.com", "Example.COM.", "xn--a.example.com", "a_b.example.com", "x:65535", "x:99999"} {
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
		// A Host accepted for a request has a port that exists, if it has one (R6 V-12c)
		if canonical, ok := canonicalHost(h); ok {
			if _, port, err := net.SplitHostPort(canonical); err == nil {
				if number, err := strconv.Atoi(port); err != nil || number > 65535 {
					t.Fatalf("canonicalHost(%q) = %q: a port that no host has", h, canonical)
				}
			}
		}
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
		shortcutWords(req, target, siteMatch{siteDomain: "example.com", siteSubdomain: "*", domain: "foo.example.com", subdomain: "foo"}, "/", "/")
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

// R6 D-09: the name of a Host, without its port, is in lower case.
func FuzzRequestHostName(f *testing.F) {
	for _, s := range []string{"localhost", "Example.COM.:80", "[::1]:443", "[::1]", "a:b:c", "", "[", "x]:80", "A..", "[FE80::1%25eth0]:80"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		if name := requestHostName(h); name != strings.ToLower(name) {
			t.Fatalf("requestHostName(%q) = %q: not in lower case", h, name)
		}
	})
}

// R6 D-09: a query without the parameters of another keeps what it doesn't drop, as it was, and drops all of them.
func FuzzWithoutParametersOf(f *testing.F) {
	for _, s := range [][2]string{{"a=1&b=2", "b=3"}, {"a=1;b=2&a=3", "a"}, {"%61=1&a=2", "a=0"}, {"", "a"}, {"a=1", ""}, {"&&;", "&"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, query, other string) {
		kept := withoutParametersOf(query, other)
		if other == "" && kept != query || len(kept) > len(query) {
			t.Fatalf("withoutParametersOf(%q, %q) = %q", query, other, kept)
		}
		names := map[string]bool{}
		for _, parameter := range strings.FieldsFunc(other, func(r rune) bool { return r == '&' || r == ';' }) {
			names[queryParameterName(parameter)] = true
		}
		for _, parameter := range strings.FieldsFunc(kept, func(r rune) bool { return r == '&' || r == ';' }) {
			if names[queryParameterName(parameter)] {
				t.Fatalf("withoutParametersOf(%q, %q) = %q keeps %q", query, other, kept, parameter)
			}
		}
	})
}

// R6 D-09: an accepted "PA" is read again as it was saved.
func FuzzParsePanelAccess(f *testing.F) {
	for _, s := range []string{"", "*", "panel.test", "panel.test, 10.0.0.0/8", "[::1],127.0.0.1", "a,,b", "*.x", "x/99", "PANEL.test"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, setting string) {
		list, problem := parsePanelAccess(setting)
		if list == nil {
			if problem == "" {
				t.Fatalf("parsePanelAccess(%q) refused without a reason", setting)
			}
			return
		}
		again, problem := parsePanelAccess(list.setting)
		if again == nil || again.setting != list.setting {
			t.Fatalf("parsePanelAccess(%q) saved %q, which reads as %v (%q)", setting, list.setting, again, problem)
		}
	})
}

// R6 D-09: an address of TURBO_HTTP_ADDR that is accepted is a host and a port from 1 to 65535, and reads the same.
func FuzzListenAddress(f *testing.F) {
	for _, s := range []string{"80", ":8080", "127.0.0.1:8080", "[::1]:443", "0", "65536", "a:b:c", "[::1]", "host:"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if value == "" || strings.ContainsRune(value, 0) {
			return
		}
		t.Setenv("TURBO_FUZZ_ADDR", value)
		address, err := listenAddress("TURBO_FUZZ_ADDR", ":1")
		if err != nil {
			return
		}
		_, port, splitErr := net.SplitHostPort(address)
		if number, convErr := strconv.Atoi(port); splitErr != nil || convErr != nil || number < 1 || number > 65535 {
			t.Fatalf("listenAddress(%q) = %q", value, address)
		}
		t.Setenv("TURBO_FUZZ_ADDR", address)
		if again, err := listenAddress("TURBO_FUZZ_ADDR", ":1"); err != nil || again != address {
			t.Fatalf("listenAddress(%q) = %q, which reads as %q (%v)", value, address, again, err)
		}
	})
}
