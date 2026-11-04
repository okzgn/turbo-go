package main

// T46 (I1): a site's ACME challenge (/.well-known/acme-challenge/<token>,
// with its file in @) is served as is, without rewrites or redirects (W, R,
// HTTPS), so that Certbot can validate even if the site has a front
// controller or redirects. If the file doesn't exist, nothing changes.

import (
	"os"
	"testing"
	"time"
)

func TestI01_ACMEChallengeBypassesRewritesAndRedirects(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	os.MkdirAll(dir+"localhost/@/.well-known/acme-challenge", 0755)
	os.WriteFile(dir+"localhost/@/.well-known/acme-challenge/tok_en-1", []byte("challenge-content"), 0644)
	os.WriteFile(dir+"localhost/@/index.php", []byte("controller"), 0644)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"=":{"/":"/index.php"},"-":{"index.html":"1"}}}}`)
	base := startServer(t)

	res, body, err := rawGet(base, "localhost", "/.well-known/acme-challenge/tok_en-1")
	if err != nil || res.StatusCode != 200 || body != "challenge-content" {
		t.Errorf("challenge with a front controller: %v %q %v", res, body, err)
	}
	if _, body, _ = rawGet(base, "localhost", "/.well-known/acme-challenge/missing"); body != "controller" {
		t.Errorf("a token without a file doesn't follow the rewrite: %q", body)
	}

	withGlobalLock(func() {
		siteSSLSettingCheckers["S"](false, "1", "localhost", "")
		siteSSLSettingCheckers["W"](false, "1", "localhost", "")
	})
	httpsListening.Store(true)
	t.Cleanup(func() { httpsListening.Store(false) })
	res, body, err = rawGet(base, "localhost", "/.well-known/acme-challenge/tok_en-1")
	if err != nil || res.StatusCode != 200 || body != "challenge-content" {
		t.Errorf("challenge with HTTPS and W: %v %q %v; expected the file, without a redirect", res, body, err)
	}
	if res, _, _ = rawGet(base, "localhost", "/.well-known/acme-challenge/missing"); res.StatusCode != 301 {
		t.Errorf("a token without a file doesn't follow the redirect: %d", res.StatusCode)
	}
}
