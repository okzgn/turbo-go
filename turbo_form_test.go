package main

// C9 (H32): a malformed or too large body of parameters is refused instead of
// being treated as if data were missing.

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestC9_PanelFormErrors(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	send := func(body string) (int, string) {
		req, _ := http.NewRequest("POST", base+"/admin:inside:addSite", strings.NewReader(body))
		req.Host = "localhost"
		req.Header.Set("ok", tok)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := (&http.Client{Timeout: clientTimeout() * 3}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := send("s=c9.test&x=%zz"); code != 400 || body != "Invalid parameters" {
		t.Errorf("badly encoded parameters: %d %q; expected 400 \"Invalid parameters\"", code, body)
	}
	if code, body := send("s=c9.test&x=" + strings.Repeat("x", int(maxBodySize.Load()))); code != 413 {
		t.Errorf("parameters above MBB: %d %.60q; expected 413", code, body)
	}
	if code, body := send("s=c9.test"); code != 200 {
		t.Errorf("valid addSite: %d %q", code, body)
	}
}
