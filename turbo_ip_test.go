package main

// B7 (H23): the denied IPs and the client's are compared in their canonical
// form: IPv6 in lower case and compressed, and IPv4 too when it comes inside
// IPv6 (::ffff:1.2.3.4).

import (
	"testing"

	"turbo/customNetHttp"
)

func TestB7_IPAddrCanonical(t *testing.T) {
	for address, want := range map[string]string{
		"203.0.113.7:80":          "203.0.113.7",
		"[::ffff:203.0.113.7]:80": "203.0.113.7",
		"::ffff:203.0.113.7":      "203.0.113.7",
		"[2001:DB8:0:0::1]:443":   "2001:db8::1",
		"2001:0db8::1":            "2001:db8::1",
		"[fe80::1%eth0]:80":       "fe80::1",
		"localhost:80":            "localhost",
		"":                        "",
	} {
		if got := ipAddr(address); got != want {
			t.Errorf("ipAddr(%q) = %q; expected %q", address, got, want)
		}
	}
}

// H23: a denied IP written in any valid form blocks the client, and it can be
// deleted written in another form.
func TestB7_DeniedIPNormalized(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	request := func(remoteAddr string) int {
		req, _ := customNetHttp.NewRequest("GET", "http://localhost/", nil)
		req.RequestURI = "/"
		req.RemoteAddr = remoteAddr
		rec := &responseRecorder{}
		handler(rec, req)
		return rec.code
	}
	for _, c := range []struct{ denied, client string }{
		{"2001:DB8::1", "[2001:db8::1]:40000"},
		{"2001:0db8:0:0::2", "[2001:db8::2]:40000"},
		{"::ffff:203.0.113.7", "203.0.113.7:40000"},
		{"203.0.113.8", "[::ffff:203.0.113.8]:40000"},
	} {
		globalMutex.Lock()
		ok, msg := adminAddHandlers["@"](c.denied, "9999999999")
		globalMutex.Unlock()
		if !ok {
			t.Fatalf("deny %q: %q", c.denied, msg)
		}
		if code := request(c.client); code != 429 {
			t.Errorf("%s denied; %s gets %d, expected 429", c.denied, c.client, code)
		}
	}
	if _, found := deniedIPList()[""]; found {
		t.Error("a denied IP was saved with an empty key")
	}
	globalMutex.Lock()
	ok, msg := adminDeleteHandlers["@"]("2001:0DB8:0::1")
	globalMutex.Unlock()
	if !ok {
		t.Errorf("delete 2001:0DB8:0::1 (denied as 2001:DB8::1): %q", msg)
	}
}
