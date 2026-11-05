package main

// V19 (production review of 775a809): the temporary files of the CGIs (their request bodies, and their output waiting
// for the client).
// - They have no name (on Unix the name goes as soon as the file is created; on Windows the file goes when it is
//   closed): a Turbo that stops without closing them leaves nothing behind.
// - A temporary file that can't be created or written is logged (grouped, as the CGIs' errors), and a request body
//   that can't be kept answers 500, the server's problem, not 400.
// - The shutdown waits for the outputs of the CGIs to end too: a CGI frees its slot before its output reaches its
//   client, and its temporary files go when the output ends.

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// freshErrorLines forgets what the grouped log of the errors has written, so that the first line of each kind is
// written at once.
func freshErrorLines(t *testing.T) {
	t.Helper()
	errorLines.reopen()
}

func TestRP3_V19_TempFilesWithoutName(t *testing.T) {
	temp := withCGIOutputTemp(t)
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 16 << 10, budget: 64 << 20, fileMax: 1 << 20, fileBudget: 1 << 30})
	gate := make(chan struct{})
	output := newCGIOutput(newTestClientWriter(gate, 0), "192.0.2.44", nil)
	chunk := make([]byte, 16<<10)
	for i := 0; i < 4; i++ { // One in memory, three in a file
		if _, err := output.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	output.mutex.Lock()
	files := len(output.segments)
	output.mutex.Unlock()
	if files != 1 {
		t.Errorf("%d temporary files; expected one", files)
	}
	if left := cgiOutputTempFiles(t, temp); runtime.GOOS != "windows" && len(left) != 0 {
		t.Errorf("a temporary file in use has a name, which a Turbo that stops without closing it would leave: %v", left)
	}
	close(gate)
	output.finish()
	checkCGIOutputsEnded(t)
	if left := cgiOutputTempFiles(t, temp); len(left) != 0 {
		t.Errorf("temporary files left after the response: %v", left)
	}
}

func TestRP3_V19_TempFileFailureLogged(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(name, missing)
	}
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 16 << 10, budget: 64 << 20, fileMax: 1 << 20, fileBudget: 1 << 30})
	freshErrorLines(t)
	logs := captureLog(t)
	gate := make(chan struct{})
	output := newCGIOutput(newTestClientWriter(gate, 0), "192.0.2.45", nil)
	chunk := make([]byte, 16<<10)
	if _, err := output.Write(chunk); err != nil { // In memory
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() { _, err := output.Write(chunk); wrote <- err }() // No file: it waits for its client
	if !eventually(3*time.Second, func() bool { return strings.Contains(logs.String(), "Can't create a temporary file") }) {
		t.Errorf("a temporary file that can't be created wasn't logged:\n%s", logs.String())
	}
	close(gate)
	if err := <-wrote; err != nil {
		t.Error(err)
	}
	output.finish()
	checkCGIOutputsEnded(t)
}

func TestRP3_V19_BodyFileFailureIs500(t *testing.T) {
	_, base := cgiLoadSetup(t)
	maxBodySize.Store(5 << 20)
	t.Cleanup(func() { maxBodySize.Store(1048576) })
	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(name, missing)
	}
	freshErrorLines(t)
	logs := captureLog(t)
	body := bytes.Repeat([]byte("x"), 2<<20) // Beyond what is kept in memory
	req, _ := http.NewRequest("POST", base+"/x.cgi", io.NopCloser(bytes.NewReader(body)))
	req.Host = "localhost"
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 500 {
		t.Errorf("a body that can't be kept in a temporary file: %d; expected 500", res.StatusCode)
	}
	if !eventually(3*time.Second, func() bool { return strings.Contains(logs.String(), "Can't keep the body") }) {
		t.Errorf("the body that couldn't be kept wasn't logged:\n%s", logs.String())
	}
}

func TestRP3_V19_ShutdownWaitsForOutputs(t *testing.T) {
	gate := make(chan struct{})
	output := newCGIOutput(newTestClientWriter(gate, 0), "192.0.2.46", nil)
	if _, err := output.Write([]byte("output that waits for its client")); err != nil {
		t.Fatal(err)
	}
	waited := make(chan struct{})
	go func() { waitCGIsEnded(10 * time.Second); close(waited) }()
	select {
	case <-waited:
		t.Error("the shutdown didn't wait for an output that hasn't reached its client")
	case <-time.After(300 * time.Millisecond):
	}
	close(gate)
	output.finish()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Error("the shutdown still waits once the output ended")
	}
	checkCGIOutputsEnded(t)
}
