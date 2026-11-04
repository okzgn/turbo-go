package main

// B3 (H12), B5 (H16): the global lock is not held while a panel response is written
// nor while PBKDF2 is computed.

import (
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// blockingWriter is a ResponseWriter whose Write stops (as with a client that
// doesn't read) until release is closed.
type blockingWriter struct {
	responseRecorder
	writing chan struct{}
	release chan struct{}
}

func (w *blockingWriter) Write(b []byte) (int, error) {
	close(w.writing)
	<-w.release
	return w.responseRecorder.Write(b)
}

// H12: "sites", "subdomains" and "subdomainData" don't hold the global lock
// while they write the response: a client that doesn't read doesn't leave the
// rest of the server waiting behind a pending Lock.
func TestB3_PanelWritesWithoutLock(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	token := strings.TrimPrefix(loginFrom(handler, "192.0.2.10", "Turbo", "Admin").body.String(), "ok")
	for _, path := range []string{"/admin:inside:sites", "/admin:inside:subdomains?s=localhost", "/admin:inside:subdomainData?s=localhost&d="} {
		req := newPanelRequest(path, "192.0.2.10:40000")
		req.Header.Set("ok", token)
		w := &blockingWriter{writing: make(chan struct{}), release: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			handler(w, req)
			close(done)
		}()
		select {
		case <-w.writing:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: it never got to write the response", path)
		}
		if globalMutex.TryLock() {
			globalMutex.Unlock()
		} else {
			t.Errorf("%s writes the response holding the global lock", path)
		}
		close(w.release)
		<-done
		if !strings.HasPrefix(w.body.String(), "{") {
			t.Errorf("%s: response %q", path, w.body.String())
		}
	}
}

// newPanelRequest prepares a POST to the panel from remoteAddr, without the
// network and, like the server's, with a body (empty).
func newPanelRequest(path, remoteAddr string) *customNetHttp.Request {
	req, _ := customNetHttp.NewRequest("POST", "http://localhost"+path, customNetHttp.NoBody) // As the server gives it: never a nil body
	req.RequestURI = path
	req.RemoteAddr = remoteAddr
	return req
}

// maxLatency requests GET / several times during d and returns the longest wait.
func maxLatency(t *testing.T, base string, d time.Duration) time.Duration {
	t.Helper()
	get(base, "/", nil) // The first request also opens the connection
	var worst time.Duration
	for end := time.Now().Add(d); time.Now().Before(end); {
		start := time.Now()
		if code, _, err := get(base, "/", nil); err != nil || code != 200 {
			t.Fatalf("GET /: %d %v", code, err)
		}
		worst = max(worst, time.Since(start))
		time.Sleep(5 * time.Millisecond)
	}
	return worst
}

// latencyLimit is the longest wait allowed for GET / (more with -race).
func latencyLimit() time.Duration {
	if raceEnabled {
		return 500 * time.Millisecond
	}
	return 60 * time.Millisecond
}

// H16: setP computes PBKDF2 without the global lock: during a password
// change, GET / answers in milliseconds.
func TestB5_SetPasswordDoesNotBlock(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	verifiedPassword.Store(nil) // The current password is also checked with PBKDF2
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		post(base, "/admin:inside:setP?a=NewPass&b=Admin", tok)
		done <- time.Since(start)
	}()
	time.Sleep(10 * time.Millisecond)
	worst := maxLatency(t, base, 150*time.Millisecond)
	took := <-done
	if worst > latencyLimit() {
		t.Errorf("GET / took %v during setP (which took %v)", worst, took)
	}
	if !passwordMatches("NewPass") {
		t.Error("setP did not change the password")
	}
}
