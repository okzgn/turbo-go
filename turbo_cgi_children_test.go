package main

// T15 (N12, D20 (a)): a CGI that leaves a child holding its inherited output
// doesn't leave the request hanging. If the CGI exits, Turbo answers with what
// it got, waiting no more than 1 s and without killing the child; if the time
// runs out or the client goes away, the whole process group is killed (a Job
// Object on Windows).

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// childCGISetup sets up x.cgi with cgiecho and returns the server and a path
// for the child's mark.
func childCGISetup(t *testing.T, writeTimeout string) (base string, childMark string) {
	t.Helper()
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	if ok, msg := defaultSettingValidators["."]["WT"](writeTimeout, "Admin"); !ok && !strings.Contains(msg, "unchanged") {
		t.Fatal(msg)
	}
	return startServer(t), dir + "child-done"
}

// markAppears reports whether the mark appears before within elapses.
func markAppears(path string, within time.Duration) bool {
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// The CGI exits and its child keeps the output open: the response arrives at
// once, complete, and the child isn't killed.
func TestN12_CGIChildDoesNotHoldResponse(t *testing.T) {
	base, mark := childCGISetup(t, "10s")
	start := time.Now()
	code, body, err := get(base, "/x.cgi?"+url.Values{"child": {"4000"}, "childmark": {mark}}.Encode(), nil)
	elapsed := time.Since(start)
	if err != nil || code != 200 || !strings.Contains(body, "BODY_BYTES=") {
		t.Fatalf("GET: %d %q %v", code, body, err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("the response took %v: it waited for the child that inherited the output", elapsed)
	}
	if !markAppears(mark, 8*time.Second) {
		t.Error("the child didn't finish on its own: it was killed when the CGI exited normally")
	}
}

// WT runs out: 504, and the CGI and its child die.
func TestN12_CGITimeoutKillsChild(t *testing.T) {
	base, mark := childCGISetup(t, "1s")
	parentMark := mark + "-parent"
	start := time.Now()
	code, _, _ := get(base, "/x.cgi?"+url.Values{"child": {"3000"}, "childmark": {mark}, "sleep": {"3000"}, "mark": {parentMark}}.Encode(), nil)
	if code != 504 {
		t.Errorf("code %d; expected 504", code)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the 504 took %v", elapsed)
	}
	if markAppears(mark, 5*time.Second) || markAppears(parentMark, 0) {
		t.Error("the CGI or its child kept running after the time limit")
	}
}

// The client goes away: the CGI and its child die.
func TestN12_CGIClientGoneKillsChild(t *testing.T) {
	base, mark := childCGISetup(t, "10s")
	parentMark := mark + "-parent"
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/x.cgi?"+url.Values{"child": {"3000"}, "childmark": {mark}, "sleep": {"3000"}, "mark": {parentMark}}.Encode(), nil)
	req.Host = "localhost"
	if res, err := http.DefaultClient.Do(req); err == nil {
		res.Body.Close()
	}
	if markAppears(mark, 5*time.Second) || markAppears(parentMark, 0) {
		t.Error("the CGI or its child kept running after the client left")
	}
}

// N70: a CGI that stays silent longer than the grace period (1 s) and then
// writes and exits delivers all its output, also with a single CPU for Go: the
// grace period counts from when it exits, not from the last time it wrote.
func TestN70_CGISilentThenWritesAndExits(t *testing.T) {
	base, _ := childCGISetup(t, "30s")
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	const requests, parallel = 72, 24
	var failed atomic.Int32
	var wg sync.WaitGroup
	slots := make(chan struct{}, parallel)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			if code, body, err := get(base, "/x.cgi?sleep=1100", nil); err != nil || code != 200 || !strings.Contains(body, "BODY_BYTES=") {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := failed.Load(); n > 0 {
		t.Errorf("%d of %d responses lost the CGI's output", n, requests)
	}
}

// N73: when the response can't come from the CGI (a malformed Status, no
// headers...), the 500 arrives at once and its process group is killed: the
// request, and its CGP slot, don't wait for the CGI to exit.
func TestN73_CGIErrorDoesNotWaitForExit(t *testing.T) {
	base, _ := childCGISetup(t, "30s")
	start := time.Now()
	code, _, err := get(base, "/x.cgi?"+url.Values{"header": {"Status: abc"}, "after": {"5000"}}.Encode(), nil)
	if elapsed := time.Since(start); err != nil || code != 500 || elapsed > 2*time.Second {
		t.Errorf("malformed Status and the CGI keeps running 5 s: %d %v in %v; expected 500 at once", code, err, elapsed)
	}
}

// N74: if WT runs out when the CGI already sent part of the response and is
// still running, the response is cut (the client sees an error), not closed
// as if it were complete.
func TestN74_CGITimeoutAfterBodyIsNotComplete(t *testing.T) {
	base, _ := childCGISetup(t, "1s")
	req, _ := http.NewRequest("GET", base+"/x.cgi?after=4000", nil)
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: clientTimeout()}).Do(req)
	if err != nil {
		return // Cut before the headers: it doesn't look complete either
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err == nil {
		t.Errorf("WT ran out with the CGI still running: %d and %d bytes read without error; expected a cut response", res.StatusCode, len(body))
	}
}
