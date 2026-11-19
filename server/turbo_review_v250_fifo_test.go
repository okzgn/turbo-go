//go:build !windows

package server

// The tests of the review of v2.5.0 about what isn't a file where Turbo expects one (a FIFO): each failed before its
// fix.

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// V2.5.0 review SV-2: a FIFO named turbo.visits or turbo.denials isn't opened as a log: opening it for writing waited
// for a reader, with the reload that opens the logs (at start, before the ports are open; then, the periodic work,
// which is also what hears the signals to stop).
func TestR250_SV2_AFIFOIsNotOpenedAsALog(t *testing.T) {
	dir := initForTest(t)
	if err := syscall.Mkfifo(dir+"turbo.visits", 0600); err != nil {
		t.Skip(err)
	}
	logs := captureLog(t)
	done := make(chan struct{})
	go func() {
		updateSettings(true)
		updateSettings(true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(clientTimeout()):
		t.Error("the reload hasn't returned with a FIFO named turbo.visits")
		if reader, err := os.OpenFile(dir+"turbo.visits", os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil { // Lets the open end
			<-done
			reader.Close()
		}
	}
	if serverGetLogState(visitsLogName) != nil {
		t.Error("the FIFO is open as the log")
		serverSetLogState(visitsLogName, nil)
	}
	if count := strings.Count(logs.String(), "it isn't a regular file"); count != 1 {
		t.Errorf("the warning was written %d times in two reloads; expected once: %s", count, logs.String())
	}
	// A file in its place is opened by the next reload
	os.Remove(dir + "turbo.visits")
	os.WriteFile(dir+"turbo.visits", nil, 0600)
	updateSettings(true)
	if serverGetLogState(visitsLogName) == nil {
		t.Error("the file that took the place of the FIFO isn't open as the log")
	}
	serverSetLogState(visitsLogName, nil)
}

// V2.5.0 review SV-8: a FIFO among the panel's ACME challenges is answered 404 at once, as one in the folder of a site
// is: opened as a file, each request for it held a thread waiting for a writer.
func TestR250_SV8_AFIFOAmongThePanelsChallenges(t *testing.T) {
	dir := initForTest(t)
	list, problem := parsePanelAccess("panel.r250.test")
	if list == nil {
		t.Fatal(problem)
	}
	previous := panelAccess.Load()
	panelAccess.Store(list)
	t.Cleanup(func() { panelAccess.Store(previous) })
	challenges := dir + "turbo.panel/webroot/.well-known/acme-challenge/"
	os.MkdirAll(challenges, 0755)
	if err := syscall.Mkfifo(challenges+"tok", 0600); err != nil {
		t.Skip(err)
	}
	os.WriteFile(challenges+"real", []byte("challenge"), 0644)
	handler := serverHandlerFn(false)
	done := make(chan int, 1)
	go func() {
		rec := &responseRecorder{}
		handler(rec, benchRequest("panel.r250.test", "/.well-known/acme-challenge/tok", "192.0.2.10:4000"))
		done <- rec.code
	}()
	select {
	case code := <-done:
		if code != 404 {
			t.Errorf("a challenge that is a FIFO: %d; expected 404", code)
		}
	case <-time.After(clientTimeout()):
		t.Error("the panel's challenge that is a FIFO hasn't been answered")
		if writer, err := os.OpenFile(challenges+"tok", os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil { // Lets the open end
			writer.Close()
			<-done
		}
	}
	rec := &responseRecorder{}
	handler(rec, benchRequest("panel.r250.test", "/.well-known/acme-challenge/real", "192.0.2.10:4000"))
	if rec.code != 200 || rec.body.String() != "challenge" {
		t.Errorf("a challenge that is a file: %d %q", rec.code, rec.body.String())
	}
}
