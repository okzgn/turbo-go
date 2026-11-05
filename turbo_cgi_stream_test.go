package main

// Streaming (production review of 775a809): the output of a CGI was never flushed to its client until the CGI ended
// or the server's buffers filled, so server-sent events, progress and the heartbeats of long polling didn't work.
// Now, when a CGI that goes on has been quiet for cgiQuietFlushDelay, what it wrote is flushed, and from then on what
// it writes is flushed at once. A CGI that ends within that time is sent whole, with its length.

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// flushRecorder is a client's ResponseWriter that keeps what it gets and counts the flushes.
type flushRecorder struct {
	header  customNetHttp.Header
	mutex   sync.Mutex
	got     bytes.Buffer
	flushed []string // What it had got at each flush
}

func (w *flushRecorder) Header() customNetHttp.Header { return w.header }
func (w *flushRecorder) WriteHeader(int)              {}
func (w *flushRecorder) Write(p []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.got.Write(p)
}

func (w *flushRecorder) Flush() {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.flushed = append(w.flushed, w.got.String())
}

func (w *flushRecorder) flushes() []string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return append([]string(nil), w.flushed...)
}

func TestRP3_Stream_QuietCGIFlushed(t *testing.T) {
	client := &flushRecorder{header: customNetHttp.Header{}}
	output := newCGIOutput(client, "192.0.2.47", nil)
	t.Cleanup(output.finish)
	if _, err := output.Write([]byte("event: first\n\n")); err != nil {
		t.Fatal(err)
	}
	if !eventually(3*time.Second, func() bool { flushed := client.flushes(); return len(flushed) == 1 && flushed[0] == "event: first\n\n" }) {
		t.Fatalf("a CGI quiet while it goes on: flushes %q; expected one with what it wrote", client.flushes())
	}
	start := time.Now()
	if _, err := output.Write([]byte("event: second\n\n")); err != nil {
		t.Fatal(err)
	}
	if !eventually(3*time.Second, func() bool { return len(client.flushes()) == 2 }) {
		t.Fatalf("what it writes once it streams: flushes %q; expected it flushed at once", client.flushes())
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("what it writes once it streams was flushed after %v; expected at once", elapsed)
	}
	output.finish()
	checkCGIOutputsEnded(t)
}

func TestRP3_Stream_CGIThatEndsSentWhole(t *testing.T) {
	client := &flushRecorder{header: customNetHttp.Header{}}
	output := newCGIOutput(client, "192.0.2.48", nil)
	if _, err := output.Write([]byte("all of it")); err != nil {
		t.Fatal(err)
	}
	output.finish() // The CGI ends at once
	time.Sleep(3 * cgiQuietFlushDelay)
	if flushed := client.flushes(); len(flushed) != 0 {
		t.Errorf("a CGI that ended at once was flushed: %q; expected it sent whole, with its length", flushed)
	}
	checkCGIOutputsEnded(t)
}

// End to end: the echo CGI writes its answer and goes on for 4 s; its client gets it long before the CGI ends.
func TestRP3_Stream_ClientGetsTheOutputBeforeTheCGIEnds(t *testing.T) {
	cgiSite(t)
	base := startServer(t)
	start := time.Now()
	req, _ := http.NewRequest("GET", base+"/x.cgi?after=4000", nil)
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	line, err := bufio.NewReader(res.Body).ReadString('\n')
	elapsed := time.Since(start)
	if err != nil || !strings.HasPrefix(line, "QUERY_STRING=") {
		t.Fatalf("first line %q (%v)", line, err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("the first line of a CGI that goes on arrived after %v; expected it long before the CGI ends (4 s)", elapsed)
	}
	// A CGI that ends at once still gets its length.
	quick, err := (&http.Client{Timeout: 20 * time.Second}).Do(func() *http.Request {
		r, _ := http.NewRequest("GET", base+"/x.cgi", nil)
		r.Host = "localhost"
		return r
	}())
	if err != nil {
		t.Fatal(err)
	}
	quick.Body.Close()
	if quick.ContentLength <= 0 {
		t.Errorf("a CGI that ends at once: Content-Length %d; expected its length", quick.ContentLength)
	}
}
