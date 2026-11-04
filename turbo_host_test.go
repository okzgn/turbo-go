package main

// T30 (N32, N33): the Host of the request is normalized (lower case, without
// the final dot, without the port, also with IPv6) and only names of
// [a-z0-9-] are accepted, with "--" inside a label (IDN names).

import (
	"os"
	"strings"
	"testing"
)

func TestN32_HostNormalized(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"xn--bcher-kva.example/@", 0755)
	os.WriteFile(dir+"xn--bcher-kva.example/@/index.html", []byte("idn"), 0644)
	os.MkdirAll(dir+"example.com/@", 0755)
	os.WriteFile(dir+"example.com/@/index.html", []byte("example"), 0644)
	updateSettings(true)
	base := startServer(t)
	for _, c := range []struct{ host, body string }{
		{"Example.COM.", "example"},
		{"example.com.:80", "example"},
		{"EXAMPLE.com", "example"},
		{"xn--bcher-kva.example", "idn"},
		{"localhost", "hello"},
	} {
		res, body, err := rawGet(base, c.host, "/")
		if err != nil || res.StatusCode != 200 || body != c.body {
			t.Errorf("Host: %s -> %v %q %v; expected %q", c.host, res, body, err, c.body)
		}
	}
	for _, bad := range []string{"x&a=1.example.com", "a_b.example.com", "-a.example.com", "a-.example.com", "[::1]:80", "[::1]", "a..example.com"} {
		res, _, err := rawGet(base, bad, "/")
		if err == nil && res.StatusCode != 404 {
			t.Errorf("Host: %s -> %d; expected 404", bad, res.StatusCode)
		}
	}
}

// N32: IDN sites (xn--) can be created from the panel.
func TestN32_IDNSiteFromPanel(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addSite?s=xn--mnchen-3ya.example", tok); code != 200 {
		t.Errorf("addSite xn--mnchen-3ya.example: %d %q", code, body)
	}
	for _, bad := range []string{"a--.example", "--a.example"} {
		if code, _, _ := post(base, "/admin:inside:addSite?s="+bad, tok); code != 400 {
			t.Errorf("addSite %s: %d; expected 400", bad, code)
		}
	}
}

// N33: with a wildcard site, a Host with characters outside [a-z0-9.-] doesn't
// reach the keywords of the rewrites.
func TestN33_WildcardHostCharacters(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"example.com/@", 0755) // The root, without which its subdomains aren't sites
	os.MkdirAll(dir+"example.com/#/@", 0755)
	os.WriteFile(dir+"example.com/#/@/index.html", []byte("wildcard"), 0644)
	updateSettings(true)
	base := startServer(t)
	if res, body, err := rawGet(base, "abc.example.com", "/"); err != nil || res.StatusCode != 200 || body != "wildcard" {
		t.Fatalf("valid wildcard subdomain: %v %q %v", res, body, err)
	}
	for _, bad := range []string{"x&admin=1.example.com", "x%26a.example.com", "x;y.example.com", "x?y.example.com"} {
		if res, _, err := rawGet(base, bad, "/"); err == nil && res.StatusCode != 404 {
			t.Errorf("Host: %s -> %d; expected 404", bad, res.StatusCode)
		}
	}
}

// BenchmarkHostParse measures how the Host of a request is resolved.
func BenchmarkHostParse(b *testing.B) {
	initForTest(b)
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	for i := 0; i < b.N; i++ {
		host("Www.Example.com.:8080")
	}
}

// validHostChars says whether a name has only the characters of a host.
func validHostChars(name string) bool {
	return strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789.-") == ""
}
