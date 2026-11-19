package server

// What an independent review of the mode dx found: each test failed before its fix.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// S2: an answer that comes after the one of its request never reaches the next request. Each request has an id that
// its answer brings back first, and a worker that answers with another is killed: the next request gets 500, never
// what was written for another, maybe of another site.
func TestDXLateAnswerDoesntReachTheNextRequest(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	if code, body := dxRequest(t, "GET", base, "/x.dx?late=1", nil, nil); code != 200 || strings.Contains(body, "LATE") {
		t.Fatalf("the request itself: %d %q", code, body)
	}
	if code, body := dxRequest(t, "GET", base, "/x.dx?pid=1", nil, nil); strings.Contains(body, "LATE") {
		t.Errorf("the next request got the late answer of the one before: %d %q", code, body)
	}
	if code, body := dxRequest(t, "GET", base, "/x.dx?pid=1", nil, nil); code != 200 || dxLines(body)["PID"] == "" {
		t.Errorf("after it: %d %q", code, body)
	}
}

// S2: an answer with the id of another request is refused, and its worker isn't used again.
func TestDXAnswerWithAnotherIDIsRefused(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	before := pidAfter(t, base)
	if code, body := dxRequest(t, "GET", base, "/x.dx?badid=1", nil, nil); code != 500 {
		t.Errorf("an answer with another id: %d %q; expected 500", code, body)
	}
	if pidAfter(t, base) == before {
		t.Error("the worker that answered with another id answered the next request")
	}
}

// S2: what a worker writes after its greeting, before any request, isn't the answer of the first request.
func TestDXBytesAfterTheGreeting(t *testing.T) {
	_, base := setupDX(t, dxVariant(t, "greetplus"))
	if code, body := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 500 || strings.Contains(body, "FAKE") {
		t.Errorf("a worker that wrote an answer after its greeting: %d %q; expected 500", code, body)
	}
}

// The worker gets less time than Turbo gives the request (DX_TIMEOUT_MS), so that it can stop its script and answer
// before Turbo gives up and kills it: a script out of time then costs a 500, not the worker.
func TestDXTimeLeavesTheWorkerAMargin(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	if ok, message := setting("WT", "2s"); !ok {
		t.Fatal(message)
	}
	_, body := dxRequest(t, "GET", base, "/x.dx", nil, nil)
	if left, err := strconv.Atoi(dxLines(body)["DX_TIMEOUT_MS"]); err != nil || left <= 0 || left > 1800 {
		t.Errorf("DX_TIMEOUT_MS with WT of 2 s: %q; expected at most 1800 (a tenth less)", dxLines(body)["DX_TIMEOUT_MS"])
	}
}

// A worker that ended while it waited (killed by the system, or one that ends itself after some requests) isn't
// given to a request: that request would get 500.
func TestDXIdleWorkerThatEndedIsNotUsed(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	before := pidAfter(t, base)
	var waiting *dxWorker
	dxWorkers.mutex.Lock()
	for _, pool := range dxWorkers.pools {
		if n := len(pool.idle); n > 0 {
			waiting = pool.idle[n-1]
		}
	}
	dxWorkers.mutex.Unlock()
	if waiting == nil {
		t.Fatal("no worker waits")
	}
	waiting.process.Kill()
	<-waiting.process.Exited()
	code, body := dxRequest(t, "GET", base, "/x.dx?pid=1", nil, nil)
	if code != 200 || dxLines(body)["PID"] == before {
		t.Errorf("after the waiting worker ended: %d %q; expected 200 from another", code, body)
	}
}

// A worker that is slow to start doesn't take more than WT of the request that started it (504), and starts for the
// next requests all the same: with a short WT, a program that takes longer to start would never be ready otherwise.
func TestDXSlowStartIsNotTheRequestsTime(t *testing.T) {
	_, base := setupDX(t, dxVariant(t, "slowgreet"))
	if ok, message := setting("WT", "1s"); !ok {
		t.Fatal(message)
	}
	start := time.Now()
	if code, _ := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 504 || time.Since(start) > 2*time.Second {
		t.Errorf("the request that started a slow worker: %d after %v; expected 504 after about 1 s", code, time.Since(start))
	}
	waiting := func() bool { // The worker greets 2.5 s after it starts, and then waits for a request
		dxWorkers.mutex.Lock()
		defer dxWorkers.mutex.Unlock()
		for _, pool := range dxWorkers.pools {
			if len(pool.idle) > 0 {
				return true
			}
		}
		return false
	}
	for deadline := time.Now().Add(8 * time.Second); !waiting(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the worker that started for the request that gave up never waited for the next")
		}
	}
	start = time.Now()
	if code, body := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 200 || time.Since(start) > 900*time.Millisecond {
		t.Errorf("the next request: %d %q after %v; expected the worker already started", code, body, time.Since(start))
	}
}

// A program written as a relative path is the one validation checked, from Turbo's folder: it was resolved again from
// its own folder, where it isn't, and its requests got 500.
func TestDXRelativeProgram(t *testing.T) {
	// From the folder above the test tools, the program is "<tools folder>/dxecho": a path that doesn't climb to the
	// root, where the ".." left over of a path resolved twice would do nothing.
	saved, _ := os.Getwd()
	tools := filepath.Dir(toolPath("dxecho"))
	if err := os.Chdir(filepath.Dir(tools)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(saved) })
	relative := filepath.Base(tools) + "/" + filepath.Base(toolPath("dxecho"))
	_, base := setupDX(t, relative)
	if code, body := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 200 {
		t.Errorf("a program given as %q: %d %q", relative, code, body)
	}
}
