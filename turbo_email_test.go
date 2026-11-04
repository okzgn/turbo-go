package main

// T22 (N19, DOC13): the Certbot e-mail is validated the same way in cfgE and
// in the z parameter of cfgC, and it is saved as it arrives.

import (
	"net/url"
	"strings"
	"testing"
)

func TestN19_CertbotEmail(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	cases := []struct {
		email string
		ok    bool
	}{
		{"a+b@x.com", true},
		{"admin@example.com", true},
		{"a b@x.com", false},
		{"a--b@x.com", false},
		{"a#b@x.com", false},
		{"no-at-sign.com", false},
		{"a@b@x.com", false},
		{"@x.com", false},
		{"a@xcom", false},
		{"-a@x.com", false},
		{"a@x.c", true},
		{"a@x." + strings.Repeat("c", 40), false},
		{"a%41@x.com", true}, // Literal %: the value is not decoded again
	}
	for _, c := range cases {
		code, body, _ := post(base, "/admin:inside:cfgE?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {c.email}}.Encode(), tok)
		if (code == 200) != c.ok {
			t.Errorf("cfgE %q: %d %q; expected accepted=%v", c.email, code, body, c.ok)
		}
		if c.ok {
			globalMutex.RLock()
			saved := siteSSLConfig["localhost"]["E"]
			globalMutex.RUnlock()
			if saved != c.email {
				t.Errorf("cfgE %q saved %q", c.email, saved)
			}
		}
		// cfgC with z: without a certificate it answers "No certificate" (a=2 doesn't issue), but only after the e-mail
		// was accepted.
		code, body, _ = post(base, "/admin:inside:cfgC?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"2"}, "z": {c.email}}.Encode(), tok)
		accepted := !strings.Contains(body, "mail")
		if accepted != c.ok {
			t.Errorf("cfgC z=%q: %d %q; expected accepted=%v", c.email, code, body, c.ok)
		}
	}

	// Saved and read again, the e-mail stays the same.
	post(base, "/admin:inside:cfgE?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"a+b%41@x.com"}}.Encode(), tok)
	if code, body, _ := post(base, "/admin:inside:setC?a=&b=Admin", tok); code != 200 {
		t.Fatalf("setC: %d %q", code, body)
	}
	lightReset(dir)
	if err := updateSettings(false); err != nil {
		t.Fatal(err)
	}
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	if saved := siteSSLConfig["localhost"]["E"]; saved != "a+b%41@x.com" {
		t.Errorf("e-mail after saving and reloading: %q", saved)
	}
}
