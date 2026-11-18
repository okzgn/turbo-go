package server

// Review of 6046dbe (R6), O-9: the response held while a request is resolved copies the headers of the real one only
// when something is written to it. Most requests get a plan and write nothing there.

import (
	"os"
	"testing"

	"turbo/customNetHttp"
)

// headerCounter is a response that counts how many times its headers are asked for.
type headerCounter struct {
	responseRecorder
	asked int
}

func (c *headerCounter) Header() customNetHttp.Header {
	c.asked++
	return c.responseRecorder.Header()
}

// R6 O-9: a held response that nothing was written to neither reads nor touches the headers of the real one; one
// that got a header, or lost one, leaves them as the copy made at that moment says.
func TestR6_O9_HeldResponseCopiesHeadersOnlyWhenUsed(t *testing.T) {
	untouched := &headerCounter{}
	untouched.responseRecorder.Header().Set("X-Before", "kept")
	held := newHeldResponse(untouched)
	held.sendTo(untouched)
	if untouched.asked != 0 || untouched.code != 0 || untouched.header.Get("X-Before") != "kept" || len(untouched.header) != 1 {
		t.Errorf("nothing held: headers asked %d times, status %d, headers %v; expected them left alone", untouched.asked, untouched.code, untouched.header)
	}

	redirected := &responseRecorder{}
	redirected.Header().Set("X-Before", "kept")
	redirected.Header().Set("Etag", `"gone"`)
	held = newHeldResponse(redirected)
	held.Header().Set("Location", "/there")
	held.Header().Del("Etag")
	held.WriteHeader(301)
	held.WriteHeader(500) // Only the first counts
	held.Write([]byte("moved"))
	if redirected.code != 0 || redirected.header.Get("Location") != "" || redirected.header.Get("Etag") == "" {
		t.Errorf("while held, the response already has %d %v", redirected.code, redirected.header)
	}
	held.sendTo(redirected)
	if redirected.code != 301 || redirected.body.String() != "moved" || redirected.header.Get("Location") != "/there" ||
		redirected.header.Get("X-Before") != "kept" || len(redirected.header) != 2 {
		t.Errorf("a redirection held: %d %q %v; expected 301 with Location and X-Before, without Etag", redirected.code, redirected.body.String(), redirected.header)
	}

	written := &responseRecorder{} // A body without a status is a 200, and a response without headers has them made
	held = newHeldResponse(written)
	held.Write([]byte("text"))
	held.sendTo(written)
	if written.code != 200 || written.body.String() != "text" {
		t.Errorf("a body held: %d %q", written.code, written.body.String())
	}
}

// R6 O-9: through the handler, a file of a site is served without copying the headers of its response; and what the
// response had before resolving the request (the panel's CSP on its host, for one) is in the redirection and in the
// 404 that resolving it writes.
func TestR6_O9_HandlerHeadersThroughTheHeldResponse(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/file.txt", []byte("content"), 0644)
	handler := serverHandlerFn(false)
	served := &headerCounter{}
	handler(served, benchRequest("localhost", "/file.txt", "203.0.113.9:40000"))
	if served.code != 200 || served.body.String() != "content" {
		t.Fatalf("the file: %d %q", served.code, served.body.String())
	}
	plain := &headerCounter{}
	plain.responseRecorder.Header()
	(&servePlan{root: dir + "localhost/@", path: "/file.txt"}).serve(plain, benchRequest("localhost", "/file.txt", "203.0.113.9:40000"))
	if served.asked != plain.asked {
		t.Errorf("the handler asked for the headers %d times to serve a file, and serving it alone asks %d: resolving the request touched them", served.asked, plain.asked)
	}

	globalMutex.Lock()
	ok, msg := defaultSettingValidators["."]["PA"]("panel.test", internalAuth)
	if ok {
		constructSiteLocked("panel.test", "")
		constructSiteLocked("panel.test", "www")
		siteSSLConfig["panel.test"].rootToWWW = true
	}
	globalMutex.Unlock()
	if !ok {
		t.Fatal(msg)
	}
	redirected := &responseRecorder{}
	handler(redirected, benchRequest("panel.test", "/page", "203.0.113.9:40000"))
	if redirected.code != 301 || redirected.header.Get("Content-Security-Policy") != panelCSP || redirected.header.Get("Location") != "http://www.panel.test/page" {
		t.Errorf("a redirection on the panel's host: %d to %q, CSP %q; expected 301 with the panel's CSP", redirected.code, redirected.header.Get("Location"), redirected.header.Get("Content-Security-Policy"))
	}
	missing := &responseRecorder{}
	missing.Header().Set("X-Before", "kept")
	handler(missing, benchRequest("localhost", "/%2e%2e/x", "203.0.113.9:40000"))
	if missing.code != 404 || missing.header.Get("X-Before") != "kept" || missing.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("a path outside the site: %d %v; expected 404 with its headers and the one that was there", missing.code, missing.header)
	}
}
