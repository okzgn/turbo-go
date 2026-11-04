package main

// T20 (N30, N16, O2, O4): no slow I/O under the global lock: with a slow Stat
// of the site folders, checkSites doesn't hold up the requests (even while
// someone else waits for the write lock), and saving writes turbo.config
// without the global lock.

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestN30_SlowDiskDoesNotHoldRequests(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	slow := atomic.Bool{}
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if slow.Load() {
			time.Sleep(600 * time.Millisecond)
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
	slow.Store(true)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); checkSites() }()
	go func() { // A panel action waiting for the write lock: new readers wait behind it
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		withGlobalLock(func() {})
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Host = "localhost"
	res, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		res.Body.Close()
	}
	slow.Store(false)
	wg.Wait()
	if err != nil || elapsed > 150*time.Millisecond {
		t.Errorf("a request during checkSites with the slow disk took %v (%v); expected less than 150 ms", elapsed, err)
	}
}

// Saving (setC) doesn't hold the global lock while it writes.
func TestN30_SaveWritesWithoutGlobalLock(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	previous := createTempFile
	inside := make(chan struct{})
	release := make(chan struct{})
	createTempFile = func(dir, pattern string) (*os.File, error) {
		close(inside)
		<-release
		return previous(dir, pattern)
	}
	t.Cleanup(func() { createTempFile = previous })
	saved := make(chan bool)
	go func() {
		code, _, err := post(base, "/admin:inside:setC?a=&b=Admin", tok)
		saved <- err == nil && code == 200
	}()
	<-inside
	locked := make(chan struct{})
	go func() { withGlobalLock(func() {}); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Error("saving holds the global lock while it writes turbo.config")
	}
	close(release)
	if !<-saved {
		t.Error("it wasn't saved")
	}
}

// slowStatOf makes siteDirStat take 600 ms for the paths for which slow says so, until the test ends.
func slowStatOf(t *testing.T, slow func(path string) bool) {
	t.Helper()
	previous := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if slow(name) {
			time.Sleep(600 * time.Millisecond)
		}
		return previous(name)
	}
	t.Cleanup(func() { siteDirStat = previous })
}

// requestWhileLockWaits runs action and, while it runs, has someone wait for the global write lock (a panel
// action: new readers wait behind it) and then times a request. It returns how long the request took.
func requestWhileLockWaits(t *testing.T, base string, action func()) time.Duration {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); action() }()
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		withGlobalLock(func() {})
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Host = "localhost"
	res, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		res.Body.Close()
	}
	wg.Wait()
	return elapsed
}

// P15 (A1): the validators of turbo.config look at the disk (certificate files, preprocessor executables) before the
// reload takes the global lock, so a slow disk doesn't hold requests.
func TestP15_SlowDiskReloadDoesNotHoldRequests(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	base := startServer(t)
	slowStatOf(t, func(path string) bool {
		return strings.HasSuffix(path, certFileName) || strings.HasSuffix(path, keyFileName) || strings.Contains(path, "cgiecho")
	})
	config := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"?":{"cgi":"` + toolPath("cgiecho") + `"},"!":{"S":"1","C":"0"}}}}`
	elapsed := requestWhileLockWaits(t, base, func() {
		os.WriteFile(dir+"turbo.config", []byte(config), 0600)
		withGlobalLock(func() { configFileModTime = 0 })
		updateSettings(false)
	})
	if elapsed > 150*time.Millisecond {
		t.Errorf("a request during the reload with the slow disk took %v; expected less than 150 ms", elapsed)
	}
	globalMutex.RLock()
	_, https := siteCertificates["localhost"]
	_, cgi := preprocessors["localhost"]["cgi"]
	globalMutex.RUnlock()
	if !https || !cgi {
		t.Errorf("the reload didn't apply the certificate (%v) or the preprocessor (%v)", https, cgi)
	}
}

// P15 (A1): cfgC, cfgS and setM look at the disk before taking the global lock.
func TestP15_SlowDiskPanelDoesNotHoldRequests(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", 90*24*time.Hour, "localhost")
	other := filepath.ToSlash(t.TempDir()) + "/"
	base := startServer(t)
	tok := login(t, base)
	slowStatOf(t, func(path string) bool {
		return strings.HasSuffix(path, certFileName) || strings.HasSuffix(path, keyFileName) || strings.HasPrefix(path, strings.TrimSuffix(other, "/"))
	})
	for _, action := range []string{"cfgC?s=localhost&d=&a=1&z=a@b.co", "cfgS?s=localhost&d=&a=1", "setM?a=" + url.QueryEscape(other) + "&b=Admin"} {
		var code int
		var body string
		elapsed := requestWhileLockWaits(t, base, func() { code, body, _ = post(base, "/admin:inside:"+action, tok) })
		if elapsed > 150*time.Millisecond {
			t.Errorf("%s with the slow disk: a request at the same time took %v; expected less than 150 ms", action, elapsed)
		}
		if code != 200 {
			t.Errorf("%s: %d %q", action, code, body)
		}
	}
}

// N87: a redirect is written after releasing the global read lock: a client that doesn't read it (here, over
// HTTP/2 with a window of 0) can't hold the lock, so a pending Lock (a reload, a panel action) doesn't stop every
// other request until WT.
func TestN87_RedirectWrittenWithoutGlobalLock(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"example.com/@", 0755)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"}}},"example.com":{"":{"!":{"W":"1"}}}}`)
	if ok, msg := setting("WT", "3s"); !ok {
		t.Fatal(msg)
	}
	plain := startServer(t)
	if res, _, err := rawGet(plain, "example.com", "/"); err != nil || res.StatusCode != 301 {
		t.Fatalf("example.com doesn't redirect: %v %v", res, err)
	}
	h := dialH2(t, forkServer(t, true, serverHandlerFn("s")))
	h.frame(4, 0, 0, []byte{0, 4, 0, 0, 0, 0}) // SETTINGS_INITIAL_WINDOW_SIZE = 0: the response body never leaves
	var block bytes.Buffer
	for _, field := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/?" + strings.Repeat("&", 900)}, {":authority", "example.com"}} {
		hpackLiteral(&block, field[0], field[1])
	}
	h.frame(1, 0x5, 1, block.Bytes()) // A redirect of about 4.5 KB: more than the 4 KiB the handler can leave in its buffer
	time.Sleep(300 * time.Millisecond)
	go withGlobalLock(func() {})
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	req, _ := http.NewRequest("GET", plain+"/", nil)
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	elapsed := time.Since(start)
	if err == nil {
		res.Body.Close()
	}
	if err != nil || elapsed > 500*time.Millisecond {
		t.Errorf("a request while a redirect waits for a client that doesn't read took %v (%v); expected less than 500 ms", elapsed, err)
	}
}
