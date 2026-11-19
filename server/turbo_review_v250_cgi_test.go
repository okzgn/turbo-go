package server

// The tests of the findings about the preprocessors of the review of v2.5.0: each failed before its fix.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// r250HoldBody sends a POST with a body of size bytes to path, and never reads the answer.
func r250HoldBody(t *testing.T, base string, path string, size int) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(4 << 10)
	}
	head := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", path, size)
	if _, err := conn.Write(append([]byte(head), bytes.Repeat([]byte("b"), size)...)); err != nil {
		t.Fatal(err)
	}
	return conn
}

// r250CGIState returns the CGIs running and the outputs not delivered yet.
func r250CGIState() (running, outputs int64) {
	cgiSlots.mutex.Lock()
	defer cgiSlots.mutex.Unlock()
	return cgiSlots.running, cgiSlots.outputs
}

// r250EchoSite makes localhost/@/x.cgi, run by cgiecho.
func r250EchoSite(t *testing.T) {
	t.Helper()
	dir := initForTest(t)
	if err := os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
}

// V2.5.0 review CG-1: the body of a request is given back when its CGI has ended, not when the response has reached
// the client: kept until then, a client that didn't read its responses held the budgets of the bodies, which are for
// every site, with CGIs that weren't running any more.
func TestR250_CG1_TheBodyIsGivenBackWhenItsCGIEnds(t *testing.T) {
	r250EchoSite(t)
	withCGIOutputTemp(t)
	withWT(t, 20*time.Second)
	base := startServer(t)
	conn := r250HoldBody(t, base, "/x.cgi?big=33554432", 512<<10)
	defer conn.Close()
	if !eventually(10*time.Second, func() bool { running, outputs := r250CGIState(); return running == 0 && outputs == 1 }) {
		running, outputs := r250CGIState()
		t.Fatalf("the CGI didn't end with its answer waiting: running %d, outputs %d", running, outputs)
	}
	if !eventually(2*time.Second, func() bool { return cgiBodyInUse.Load() == 0 && cgiBodyFilesInUse.Load() == 0 }) {
		t.Errorf("the body of a request whose CGI has ended is still counted: %d bytes in memory, %d in files", cgiBodyInUse.Load(), cgiBodyFilesInUse.Load())
	}
	if _, outputs := r250CGIState(); outputs != 1 {
		t.Errorf("the answer no longer waits for its client: %d outputs", outputs)
	}
}

// V2.5.0 review CG-1: a client may take a quarter of each budget of the bodies (its /48, half), as of the CGI slots
// and of the output. Beyond it, its own request gets what a full budget gives (the file, and then 503), and the other
// clients go on.
func TestR250_CG1_AClientTakesItsShareOfTheBodies(t *testing.T) {
	initForTest(t)
	withBodyBudget(t, 1) // Every body to a file
	previousMin, previousMBB := cgiBodyFileBudgetMin, maxBodySize.Load()
	cgiBodyFileBudgetMin = 0
	maxBodySize.Store(64 << 10) // The budget of the files: 16 bodies of MBB, 1 MiB; a client's share, 256 KiB
	t.Cleanup(func() { cgiBodyFileBudgetMin = previousMin; maxBodySize.Store(previousMBB) })
	body := bytes.Repeat([]byte("b"), 64<<10)
	clientA, clientB := cgiSlotKeys("192.0.2.1"), cgiSlotKeys("198.51.100.7")
	var cleanups []func()
	for i := 0; i < 4; i++ {
		_, _, cleanup, err := bufferedRequestBodyOf(clientA, bytes.NewReader(body), int64(len(body)))
		if err != nil {
			t.Fatalf("body %d of the client, within its share: %v", i+1, err)
		}
		cleanups = append(cleanups, cleanup)
	}
	if _, _, _, err := bufferedRequestBodyOf(clientA, bytes.NewReader(body), int64(len(body))); !errors.Is(err, errCGIBodyFilesFull) {
		t.Errorf("a body beyond the client's share: %v; expected errCGIBodyFilesFull", err)
	}
	if used := cgiBodyFilesInUse.Load(); used != 4*int64(len(body)) {
		t.Errorf("after the body refused: %d bytes counted; expected the four kept", used)
	}
	_, _, cleanupB, err := bufferedRequestBodyOf(clientB, bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("another client, while the first has its share: %v", err)
	}
	cleanupB()
	cleanups[0]()
	_, _, cleanupAgain, err := bufferedRequestBodyOf(clientA, bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Errorf("the client, once one of its bodies is given back: %v", err)
	} else {
		cleanupAgain()
	}
	for _, cleanup := range cleanups[1:] {
		cleanup()
	}
	cgiBodyShares.mutex.Lock()
	left := len(cgiBodyShares.memory) + len(cgiBodyShares.files)
	cgiBodyShares.mutex.Unlock()
	if left != 0 || cgiBodyFilesInUse.Load() != 0 || cgiBodyInUse.Load() != 0 {
		t.Errorf("after every body was given back: %d shares, %d bytes in files, %d in memory", left, cgiBodyFilesInUse.Load(), cgiBodyInUse.Load())
	}
	// In IPv6, the /64s of a /48 share half of the budget (512 KiB): eight bodies, of four clients
	var networkCleanups []func()
	for i := 0; i < 8; i++ {
		keys := cgiSlotKeys(fmt.Sprintf("2001:db8:1:%x::1", i/2))
		_, _, cleanup, err := bufferedRequestBodyOf(keys, bytes.NewReader(body), int64(len(body)))
		if err != nil {
			t.Fatalf("body %d of the /48, within its share: %v", i+1, err)
		}
		networkCleanups = append(networkCleanups, cleanup)
	}
	if _, _, _, err := bufferedRequestBodyOf(cgiSlotKeys("2001:db8:1:9::1"), bytes.NewReader(body), int64(len(body))); !errors.Is(err, errCGIBodyFilesFull) {
		t.Errorf("a body beyond the share of the /48: %v; expected errCGIBodyFilesFull", err)
	}
	for _, cleanup := range networkCleanups {
		cleanup()
	}
}

// V2.5.0 review CG-2: the budget of the bodies is taken as the body arrives, not for what the request says: a request
// that sent only its headers held a megabyte of it until RT, and thirty-two of them all of it.
func TestR250_CG2_TheBudgetIsTakenAsTheBodyArrives(t *testing.T) {
	r250EchoSite(t)
	base := startServer(t)
	var conns []net.Conn
	for i := 0; i < 4; i++ {
		conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		fmt.Fprintf(conn, "POST /x.cgi HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n", 1<<20)
	}
	if !eventually(5*time.Second, func() bool { return cgiBodyInUse.Load() > 0 }) {
		t.Fatal("no request reached the reading of its body")
	}
	time.Sleep(300 * time.Millisecond)
	if used := cgiBodyInUse.Load(); used > 4*(32<<10) {
		t.Errorf("4 requests that sent only their headers took %d bytes of the budget; expected a first block of 32 KiB each at most", used)
	}
	for _, conn := range conns {
		conn.Close()
	}
	if !eventually(5*time.Second, func() bool { return cgiBodyInUse.Load() == 0 }) {
		t.Errorf("after the clients went away: %d bytes still counted", cgiBodyInUse.Load())
	}
}

// V2.5.0 review CG-2: a request without a body takes nothing of the budgets and needs no temporary file: with the
// memory of the bodies taken, each GET for a script made one, and answered 500 where none could be made.
func TestR250_CG2_ARequestWithoutABodyKeepsNothing(t *testing.T) {
	initForTest(t)
	withBodyBudget(t, 0) // As when the bodies of other requests take it all
	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(name, missing)
	}
	body, size, cleanup, err := bufferedRequestBodyOf(cgiSlotKeys("192.0.2.1"), bytes.NewReader(nil), 0)
	if err != nil || size != 0 {
		t.Fatalf("a request without a body: size %d, %v", size, err)
	}
	if n, _ := body.Read(make([]byte, 1)); n != 0 {
		t.Error("the body of a request without one has bytes")
	}
	cleanup()
	if cgiBodyInUse.Load() != 0 || cgiBodyFilesInUse.Load() != 0 {
		t.Errorf("a request without a body took %d bytes of memory and %d of files", cgiBodyInUse.Load(), cgiBodyFilesInUse.Load())
	}
	// A body whose length isn't said still needs the file there, and says so
	if _, _, _, err := bufferedRequestBodyOf(nil, strings.NewReader("abc"), -1); !errors.As(err, &cgiBodyFileError{}) {
		t.Errorf("a body with the memory taken and no temporary folder: %v; expected the file's error", err)
	}
}

// V2.5.0 review DX-3: a program that names itself in its lines does so without the ".exe" of Windows: its name was
// there twice ("[dx-lua.exe] [dx-lua] site/x.lua: ..."), and the kind of the line had a word less of what was printed.
func TestR250_DX3_AProgramOfWindowsNamesItselfOnce(t *testing.T) {
	initForTest(t)
	logs := captureLog(t)
	stderr := newScriptStderr("/opt/turbo-dx/dx-lua.EXE") // With slashes: a path of either system
	stderr.Write([]byte("[dx-lua] localhost/printer.lua: hello\nanother line\n"))
	text := logs.String()
	if !strings.Contains(text, `msg="[dx-lua] localhost/printer.lua: hello"`) {
		t.Errorf("the line of a program that names itself: %s", text)
	}
	if !strings.Contains(text, `msg="[dx-lua.EXE] another line"`) {
		t.Errorf("the line of a program that doesn't name itself: %s", text)
	}
}
