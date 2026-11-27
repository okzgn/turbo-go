package server

// The tests of the findings about the panel of the external review of v2.5.2 (GGCH): each failed before its fix, but
// those that say they keep what already worked.

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"turbo/customNetHttp"
)

// GGCH H-02: the body of hardUpload is bounded as a whole. A part without a name (or one that isn't form-data) wasn't
// counted, and was read to its end without a limit while the session was renewed: past MBB it now answers 413. An
// upload that fits in MBB goes on as always.
func TestGGCH_H02_TheBodyOfAnUploadIsBounded(t *testing.T) {
	dir := initForTest(t)
	maxBodySize.Store(64 << 10)
	if ok, msg := setting("RT", "60s"); !ok {
		t.Fatal(msg)
	}
	base := startServer(t)
	tok := login(t, base)
	upload := func(disposition string, size int) (int, string) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		w.WriteField("b", "Admin")
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", disposition)
		part, _ := w.CreatePart(h)
		part.Write(bytes.Repeat([]byte("x"), size))
		w.Close()
		return hardUploadBody(t, base, tok, w.FormDataContentType(), buf.Bytes())
	}
	for _, disposition := range []string{`form-data`, `form-data; filename="a.bin"`, `attachment; name="f"; filename="a.bin"`} {
		if code, answer := upload(disposition, 1<<20); code != 413 {
			t.Errorf("%s, 1 MiB: %d %q; expected 413", disposition, code, answer)
		}
	}
	if code, answer := upload(`form-data; name="f"; filename="fits.bin"`, 60<<10); code != 200 { // Keeps what worked
		t.Errorf("a file that fits in MBB: %d %q", code, answer)
	}
	if !fileExists(dir + "localhost/@/fits.bin") {
		t.Error("the file that fits wasn't uploaded")
	}
}

// GGCH H-15.b: a POST to the login without its credentials, or to the API without an action, answers 400 (API §10),
// not the page with 200. A GET still gets the page.
func TestGGCH_H15b_APostWithoutWhatItNeedsAnswers400(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	for _, c := range []struct{ body, contentType string }{
		{"x=1", "application/x-www-form-urlencoded"}, {"u=Turbo", "application/x-www-form-urlencoded"}, {"", ""},
	} {
		if code, answer, cookie := loginRequest(t, base, "POST", "/admin:", strings.NewReader(c.body), c.contentType); code != 400 || cookie {
			t.Errorf("POST /admin: with %q: %d %.40q; expected 400", c.body, code, answer)
		}
	}
	if code, answer, err := post(base, "/admin:inside:", tok); err != nil || code != 400 {
		t.Errorf("POST /admin:inside: without an action: %d %.40q %v; expected 400", code, answer, err)
	}
	if code, answer, err := get(base, "/admin:inside:", map[string]string{"ok": tok}); err != nil || code != 200 || !strings.Contains(answer, "<html") {
		t.Errorf("GET /admin:inside: %d %.40q %v; expected the page", code, answer, err)
	}
	if code, answer, err := get(base, "/admin:", nil); err != nil || code != 200 || !strings.Contains(answer, `name="u"`) {
		t.Errorf("GET /admin: %d %.40q %v; expected the login page", code, answer, err)
	}
}

// GGCH H-15.a: an index that the site already has keeps its place, and the answer says so (400 "Index unchanged",
// as for a header or a preprocessor): "Index assigned" made the panel move it to the end of its list.
func TestGGCH_H15a_AnIndexAlreadyThereIsUnchanged(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, answer, _ := post(base, "/admin:inside:addIndex?s=localhost&d=&a=index.html", tok); code != 400 || !strings.Contains(answer, "Index unchanged") {
		t.Errorf("index.html again: %d %q; expected 400 \"Index unchanged\"", code, answer)
	}
	if code, answer, _ := post(base, "/admin:inside:addIndex?s=localhost&d=&a=home.html", tok); code != 200 || !strings.Contains(answer, "Index assigned") {
		t.Errorf("a new index: %d %q", code, answer)
	}
	var order []string
	withReadLock(func() { order = orderedIndexes("localhost") })
	if strings.Join(order, ",") != "index.html,home.html" {
		t.Errorf("the order: %v", order)
	}
}

// loginFromAddress is loginFrom for a remote address written whole (an IPv6 one between brackets).
func loginFromAddress(handler func(customNetHttp.ResponseWriter, *customNetHttp.Request), remote string, password string) *responseRecorder {
	body := url.Values{"u": {"Turbo"}, "p": {password}}.Encode()
	req, _ := customNetHttp.NewRequest("POST", "http://localhost/admin:", strings.NewReader(body))
	req.RequestURI = "/admin:"
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := &responseRecorder{}
	handler(rec, req)
	return rec
}

// loginFailureEntries is how many clients and networks the failed logins keep.
func loginFailureEntries() int {
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	return len(loginFailuresByIP)
}

// GGCH H-13: an attempt that a block of its /48 refuses adds no entry for its /64: each /64 of a blocked /48 (65 536 of
// them) added one, which stayed until the next cleanup.
func TestGGCH_H13_ABlockedNetworkAddsNoEntries(t *testing.T) {
	initForTest(t)
	useTestPassword(t)
	handler := serverHandlerFn(false)
	t.Cleanup(func() {
		loginFailuresMutex.Lock()
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
	})
	for i := 0; i < loginMaxNetworkFailures; i++ { // The /48 is blocked
		loginFromAddress(handler, fmt.Sprintf("[2001:db8:1:%x::1]:40000", i), "bad")
	}
	before := loginFailureEntries()
	for i := 100; i < 300; i++ {
		if rec := loginFromAddress(handler, fmt.Sprintf("[2001:db8:1:%x::1]:40000", i), "bad"); rec.code != 429 {
			t.Fatalf("a /64 of the blocked /48: %d; expected 429", rec.code)
		}
	}
	if after := loginFailureEntries(); after != before {
		t.Errorf("the refused attempts added %d entries", after-before)
	}
}

// GGCH H-13: the failed logins keep at most loginFailuresLimit clients: beyond it, a new client's attempts count
// together with those of every other new client (loginOverflowKey), as the limiter's entries do. And the map is made
// anew once it holds far fewer than it once did: Go never gives back the room of a map, and a burst of addresses kept
// it for good.
func TestGGCH_H13_TheFailedLoginsAreBounded(t *testing.T) {
	initForTest(t)
	useTestPassword(t)
	handler := serverHandlerFn(false)
	previousLimit := loginFailuresLimit
	loginFailuresLimit = 10
	t.Cleanup(func() {
		loginFailuresMutex.Lock()
		loginFailuresLimit = previousLimit
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
	})
	for i := 1; i <= 30; i++ {
		loginFromAddress(handler, fmt.Sprintf("198.51.100.%d:40000", i), "bad")
	}
	if entries := loginFailureEntries(); entries > 11 {
		t.Errorf("%d entries; expected at most 10 and the one shared by the new clients", entries)
	}
	// Enough failures of the new clients, together, block them together, but not the clients already known
	for i := 31; i <= 60; i++ {
		loginFromAddress(handler, fmt.Sprintf("198.51.100.%d:40000", i), "bad")
	}
	if rec := loginFromAddress(handler, "198.51.100.200:40000", "bad"); rec.code != 429 {
		t.Errorf("a new client while the new ones are blocked: %d; expected 429", rec.code)
	}
	if rec := loginFromAddress(handler, "198.51.100.1:40000", "bad"); rec.code != 403 {
		t.Errorf("a client already known: %d; expected 403", rec.code)
	}
	// Made anew once far fewer are left
	loginFailuresMutex.Lock()
	for i := 0; i < 2000; i++ {
		loginFailuresByIP[fmt.Sprintf("203.0.113.%d/%d", i%256, i)] = &loginFailures{}
	}
	loginFailuresPeak = len(loginFailuresByIP)
	before := reflect.ValueOf(loginFailuresByIP).UnsafePointer()
	loginFailuresMutex.Unlock()
	cleanLoginFailures()
	loginFailuresMutex.Lock()
	after, left := reflect.ValueOf(loginFailuresByIP).UnsafePointer(), len(loginFailuresByIP)
	loginFailuresMutex.Unlock()
	if after == before || left > 20 {
		t.Errorf("after the cleanup: %d entries, the same map: %v", left, after == before)
	}
}
