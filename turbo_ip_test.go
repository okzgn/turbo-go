package main

// B7 (H23): las IPs denegadas y la del cliente se comparan en su forma
// canónica: IPv6 en minúsculas y comprimida, e IPv4 también cuando llega
// dentro de IPv6 (::ffff:1.2.3.4).

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
			t.Errorf("ipAddr(%q) = %q; se esperaba %q", address, got, want)
		}
	}
}

// H23: una IP denegada escrita de cualquier forma válida bloquea al cliente,
// y se puede borrar escrita de otra forma.
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
			t.Fatalf("denegar %q: %q", c.denied, msg)
		}
		if code := request(c.client); code != 429 {
			t.Errorf("%s denegada; %s recibe %d, se esperaba 429", c.denied, c.client, code)
		}
	}
	if _, found := deniedIPList()[""]; found {
		t.Error("una IP denegada se guardó con clave vacía")
	}
	globalMutex.Lock()
	ok, msg := adminDeleteHandlers["@"]("2001:0DB8:0::1")
	globalMutex.Unlock()
	if !ok {
		t.Errorf("borrar 2001:0DB8:0::1 (denegada como 2001:DB8::1): %q", msg)
	}
}
