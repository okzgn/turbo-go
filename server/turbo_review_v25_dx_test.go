package server

// The tests of the findings about the mode dx and the CGI slots of the review of v2.5
// (_revision/INFORME_REVISION_4cb626c.md, blocks 3 and 4): each failed before its fix.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// V2.5 review X-1: a request whose client went away while it waited for a slot reaches no worker: the worker that
// waits goes on waiting for the next request, instead of being cut for that client.
func TestV25R_X1_AClientGoneWhileWaitingKeepsTheWorker(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	if ok, message := setting("CGP", "1"); !ok {
		t.Fatal(message)
	}
	before := pidAfter(t, base)
	done := make(chan string, 1)
	go func() {
		_, body := dxRequest(t, "GET", base, "/x.dx?pid=1&sleep=800", nil, nil)
		done <- dxLines(body)["PID"]
	}()
	time.Sleep(150 * time.Millisecond)
	request, _ := http.NewRequest("GET", base+"/x.dx", nil)
	request.Host = "localhost"
	(&http.Client{Timeout: 200 * time.Millisecond}).Do(request) // Gone while it waits for the slot
	holder := <-done
	if after := pidAfter(t, base); holder != before || after != before {
		t.Errorf("the worker: %s, then %s for the request that held the slot, then %s; expected the same worker", before, holder, after)
	}
}

// V2.5 review E-10: the requests that wait for a slot get one in their order of arrival, each handed the slot that a
// CGI frees (every end woke them all, and the first to run took it).
func TestV25R_E10_TheSlotsGoInOrder(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	if ok, message := setting("CGP", "1"); !ok {
		t.Fatal(message)
	}
	for round := 0; round < 3; round++ {
		var mutex sync.Mutex
		var order []int
		var wait sync.WaitGroup
		for i := 0; i < 5; i++ {
			wait.Add(1)
			go func(i int) {
				defer wait.Done()
				sleep := "50"
				if i == 0 {
					sleep = "400" // Holds the slot while the others come, one after another
				}
				if code, _, _ := get(base, "/x.cgi?sleep="+sleep, nil); code == 200 {
					mutex.Lock()
					order = append(order, i)
					mutex.Unlock()
				}
			}(i)
			time.Sleep(40 * time.Millisecond)
		}
		wait.Wait()
		if fmt.Sprint(order) != "[0 1 2 3 4]" {
			t.Errorf("round %d: the requests ended in the order %v; expected their order of arrival", round, order)
		}
	}
}

// V2.5 review E-4 (decision D1): a client that holds its share of the slots (a quarter) waits behind the requests of
// others: another client is served as soon as a slot is free, instead of waiting behind its queue until 503.
func TestV25R_E4_OneClientDoesntTakeEveryTurn(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	baseA, _ := startServerAs(t, func() net.IP { return net.ParseIP("192.0.2.1") })
	baseB, _ := startServerAs(t, func() net.IP { return net.ParseIP("192.0.2.2") })
	if ok, message := setting("CGP", "4"); !ok {
		t.Fatal(message)
	}
	var wait sync.WaitGroup
	for i := 0; i < 12; i++ { // Four running, and eight that wait for the slots, all of one client
		wait.Add(1)
		go func() {
			defer wait.Done()
			get(baseA, "/x.cgi?sleep=900", nil)
		}()
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	code, _, _ := get(baseB, "/x.cgi?sleep=10", nil)
	if code != 200 || time.Since(start) > 1500*time.Millisecond {
		t.Errorf("another client, behind the queue of the first: %d after %v; expected served at the first slot freed", code, time.Since(start))
	}
	wait.Wait()
	cgiSlots.mutex.Lock()
	left := len(cgiSlots.held) + len(cgiSlots.waiting)
	cgiSlots.mutex.Unlock()
	if left != 0 {
		t.Errorf("after every request: %d entries of slots left", left)
	}
}

// V2.5 review X-3: a first chunk larger than a worker may send is refused before the answer starts (500, and nothing
// of it goes out), and an answer that breaks after it started leaves a line in the log.
func TestV25R_X3_AFirstChunkTooLargeIsA500(t *testing.T) {
	const id = 0x0123456789abcdef
	answer := append([]byte{0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}, dxAnswer(200, [][2]string{{"Content-Type", "text/plain"}}, strings.Repeat("x", dxMaxChunk+1))...)
	request, _ := customNetHttp.NewRequest("GET", "http://localhost/x.dx", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	worker := &dxWorker{reader: bufio.NewReader(bytes.NewReader(answer)), writer: bufio.NewWriter(io.Discard)}
	output := &responseRecorder{}
	answered, err := worker.exchange(&dynamicJob{request: request, output: output, executable: "x", basePath: "/srv/", requestPath: "x.dx"}, id)
	if answered || err == nil || output.code != 0 || len(output.header) != 0 {
		t.Errorf("a first chunk of %d bytes: answered %v (%v), status %d, headers %v; expected refused before the answer", dxMaxChunk+1, answered, err, output.code, output.header)
	}
	logs := captureLog(t)
	_, base := setupDX(t, toolPath("dxecho"))
	if code, _ := dxRequest(t, "GET", base, "/x.dx?die=after", nil, nil); code != 0 {
		t.Errorf("an answer cut in the middle: %d; expected the connection cut", code)
	}
	if !strings.Contains(logs.String(), "answer broke after it started") {
		t.Errorf("no line in the log for an answer cut in the middle:\n%s", logs.String())
	}
}

// V2.5 review X-4: an answer without a body (204, 304) whose worker sends one anyway goes out whole, and the worker is
// used again: the body is read and dropped.
func TestV25R_X4_NoContentWithABodyKeepsTheWorker(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	before := pidAfter(t, base)
	for i := 0; i < 3; i++ {
		if code, body := dxRequest(t, "GET", base, "/x.dx?status=204&chunks=4&size=100000", nil, nil); code != 204 || body != "" {
			t.Errorf("204 with 400 kB of body: %d %.60q", code, body)
		}
	}
	if after := pidAfter(t, base); after != before {
		t.Errorf("the worker after the answers 204: %s; it was %s", after, before)
	}
}

// V2.5 review X-5: the site's template, which answers an error that a worker sends without a body, goes without the
// worker's headers that describe a body.
func TestV25R_X5_TheTemplateWithoutTheWorkersBodyHeaders(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	request, _ := http.NewRequest("GET", base+"/x.dx?status=404&empty=1&header=Content-Encoding:%20gzip&header=ETag:%20%22x%22&header=X-Own:%201", nil)
	request.Host = "localhost"
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 404 || response.Header.Get("Content-Encoding") != "" || response.Header.Get("ETag") != "" || response.Header.Get("X-Own") != "1" || !strings.Contains(string(body), "404") {
		t.Errorf("the template of a 404 without a body: %d, Content-Encoding %q, ETag %q, X-Own %q, %.60q", response.StatusCode, response.Header.Get("Content-Encoding"), response.Header.Get("ETag"), response.Header.Get("X-Own"), body)
	}
	// Second pass, D-2: the status is the script's, and so are its headers about keeping the answer, which the error
	// pages of Turbo itself go without (E-5): a 404 that its script marks "no-store" went out without it.
	code, header := v25ReviewHead(t, base, "/x.dx?status=404&empty=1&header=Cache-Control:%20no-store&header=Content-Range:%20bytes%200-1/2")
	if code != 404 || header.Get("Cache-Control") != "no-store" || header.Get("Content-Range") != "" {
		t.Errorf("the template of a worker's 404: %d, Cache-Control %q, Content-Range %q; expected the worker's Cache-Control, and no Content-Range", code, header.Get("Cache-Control"), header.Get("Content-Range"))
	}
}

// V2.5 review, second pass, D-1: the status of a worker's answer is the one of the protocol; a header named Status is
// one more header. Read as a CGI's, it made a 200 with a body a 204, which takes none: the connection was cut, and the
// worker ended.
func TestV25R_D1_AWorkersStatusHeaderIsNoStatus(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	before := pidAfter(t, base)
	if code, body := dxRequest(t, "GET", base, "/x.dx?header=Status:%20204&chunks=4&size=100000", nil, nil); code != 200 || len(body) != 400000 {
		t.Errorf("an answer with a header Status: %d and %d bytes (%.80q); expected 200 and its 400000 bytes", code, len(body), body)
	}
	if after := pidAfter(t, base); after != before {
		t.Errorf("the worker: %s, then %s; expected the same", before, after)
	}
}

// V2.5 review, second pass, D-3: the log says that the time of a request (WT) ended after its answer had started: the
// connection is cut, and nothing told why.
func TestV25R_D3_TheLogSaysThatTheTimeEndedAfterTheAnswerStarted(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	if ok, message := setting("WT", "1s"); !ok {
		t.Fatal(message)
	}
	logs := captureLog(t)
	if code, body := dxRequest(t, "GET", base, "/x.dx?chunks=2&size=10&pause=4000", nil, nil); code != 0 {
		t.Errorf("an answer that stops after it started: %d %q; expected it cut", code, body)
	}
	for deadline := time.Now().Add(3 * time.Second); !strings.Contains(logs.String(), "out of time (WT) after its answer started"); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no line in the log:\n%s", logs.String())
		}
	}
}

// V2.5 review, second pass, D-6: no worker is taken, nor started, for a request whose client is already gone.
func TestV25R_D6_NoWorkerStartsForAClientAlreadyGone(t *testing.T) {
	setupDX(t, toolPath("dxecho"))
	mode := preprocessorModes["dx"].(*dxMode)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, _ := customNetHttp.NewRequestWithContext(ctx, "GET", "http://localhost/x.dx", nil)
	func() {
		defer func() {
			if recovered := recover(); recovered != customNetHttp.ErrAbortHandler {
				t.Errorf("a request whose client is gone: %v; expected it aborted", recovered)
			}
		}()
		mode.serve(&dynamicJob{request: request, executable: toolPath("dxecho")})
	}()
	time.Sleep(700 * time.Millisecond) // A worker started for it would have greeted by now
	mode.mutex.Lock()
	defer mode.mutex.Unlock()
	if pool := mode.pools[toolPath("dxecho")]; pool != nil && (len(pool.idle) != 0 || pool.busy != 0) {
		t.Errorf("%d workers that wait and %d in use after a request whose client was gone; expected none", len(pool.idle), pool.busy)
	}
}

// V2.5 review X-16: a worker gets of Turbo's environment what the CGI host gives a CGI.
func TestV25R_X16_AWorkerGetsTheEnvironmentOfACGI(t *testing.T) {
	environment := strings.Join(dxEnvironment(), "\n")
	for _, name := range customNetHttp.TurboInheritedEnvironment() {
		if value := os.Getenv(name); value != "" && !strings.Contains(environment, name+"="+value) {
			t.Errorf("%s isn't in the environment of a worker", name)
		}
	}
	if strings.Contains(environment, "TURBO_PASSWORD") {
		t.Error("the environment of a worker has TURBO_PASSWORD")
	}
}
