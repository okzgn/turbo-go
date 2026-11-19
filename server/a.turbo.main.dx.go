/*
Turbo - A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.
Copyright (C) 2026 OKZGN

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please visit one of the following:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact
*/

package server

// The mode dx of the preprocessors ("dx><program>"): the script of a request runs in a worker, a process of the
// preprocessor's program that Turbo keeps running, which gets each request by its input and answers by its output,
// one request at a time, in the protocol DX 3 (API_SPECIFICATION, §6.4). The worker reads the script
// (SCRIPT_FILENAME) and runs it as it wants, as a CGI does. What Turbo controls of the request is dynamic's, as for a
// CGI; here is only the protocol, the workers of each program, and when they end. Nothing here runs on its own: no
// goroutine watches a worker, no clock is set for one while it waits; one goroutine for each worker reads its standard
// error, and ends with it.
//
// The protocol, little-endian unsigned integers (the id of a request of 64 bits, the rest of 32):
//
//	worker, once, when it starts:  "DX3\n"
//	Turbo, a request:               u64 id, u32 M, M bytes of pairs, then the body (CONTENT_LENGTH bytes)
//	worker, its answer:             u64 id, u32 H, H bytes (u32 status, pairs of headers), then chunks: u32 n, n bytes … u32 0
//	pairs:                          u32 count, then for each: u32 length, name, u32 length, value
//
// The worker reads the whole request before it answers, and its answer starts with the id of the request, a random
// number: an answer that comes after another, late, carries the id of an earlier request, and never reaches a later
// one. Its output carries only the protocol (its messages go to its standard error, which Turbo writes to its log,
// grouped: scriptLines), and it ends when its input closes.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"turbo/customNetHttp"
)

// dxGreeting is what a worker writes first, before any request.
const dxGreeting = "DX3\n"

// The limits of what a worker answers: the head of an answer (its status and headers) and each chunk of its body.
const (
	dxMaxHead  = 64 << 10
	dxMaxChunk = 1 << 20
)

// How long a worker may take to greet, how long one is kept without a request, and how long no worker of a program
// is started after one failed to (doubled with each failure in a row, up to dxStartBackoffMax). Variables, so that
// tests can shorten them.
var (
	dxGreetingWait     = 5 * time.Second
	dxIdleAfter        = 60 * time.Second
	dxStartBackoffMin  = time.Second
	dxStartBackoffMax  = 30 * time.Second
	errDXProtocol      = errors.New("the worker didn't answer in the protocol DX 3")
	errDXOtherAnswer   = errors.New("the worker answered with the id of another request")
	errDXStartDeferred = errors.New("a worker of this program failed to start a moment ago")
	errDXStartsFull    = errors.New("as many workers of this program as CGI slots (CGP) are in use or starting")
	errDXGone          = errors.New("the worker ended before it took the request")
	errDXNoAnswer      = errors.New("the worker ended without a byte of an answer")
)

// dxTimeoutMargin is the most of what is left of WT that a worker isn't told of (DX_TIMEOUT_MS), a tenth below it:
// so that it stops its script and answers before Turbo gives up the request and kills it.
const dxTimeoutMargin = 250 * time.Millisecond

// dxMode keeps the workers of each program, by its path.
type dxMode struct {
	mutex sync.Mutex
	pools map[string]*dxPool
}

// dxPool is what is kept of the workers of a program.
type dxPool struct {
	idle        []*dxWorker // Waiting for a request, the last used last
	busy        int         // Taken by requests now
	failures    int         // Starts that failed in a row
	failedUntil int64       // Before this (monotonicNow), no worker is started: the last start failed
}

// dxWorker is a process of a program in its own group, with the ends of its input and output that Turbo keeps.
type dxWorker struct {
	process *customNetHttp.TurboProcess
	input   *os.File
	output  *os.File
	reader  *bufio.Reader
	writer  *bufio.Writer
	lastUse int64 // monotonicNow when its last request ended
}

var dxWorkers = &dxMode{pools: map[string]*dxPool{}}

func init() { registerPreprocessorMode("dx", dxWorkers) }

// serve gives the request to a worker of the program, and writes its answer. A worker is used again only after an
// exchange that ended as the protocol says, and nothing more was written: any other end kills it. An error before the
// answer starts is a 500 (504 if WT ran out), and after it the connection is cut, so that a response cut short never
// looks complete.
//
// A worker that waited may have ended meanwhile without its end being seen yet (one that ends after some requests,
// right after its answer): the request goes to another, once, when nothing of it reached the worker, or when the
// worker ended without a byte of an answer and the request may be made twice (idempotent, and without a body), as a
// proxy retries a request with its next server. One that changes something is never made twice.
func (mode *dxMode) serve(job *dynamicJob) {
	if mode.serveOnce(job, true) {
		mode.serveOnce(job, false)
	}
}

// serveOnce gives the request to a worker; it returns true only when that worker, one that waited, ended before it
// answered as serve says, and retry allows another.
func (mode *dxMode) serveOnce(job *dynamicJob, retry bool) (again bool) {
	ctx := job.request.Context()
	if ctx.Err() == context.Canceled { // The client went away before a worker was taken, or started, for it
		panic(customNetHttp.ErrAbortHandler)
	}
	worker, waited, err := mode.take(job.executable, ctx)
	if err != nil {
		switch {
		case ctx.Err() == context.DeadlineExceeded:
			dxLogFailure(job, "dx preprocessor out of time (WT) while its worker started: 504", err)
			siteErrorMsg(job.output, 504)
		case ctx.Err() != nil:
			panic(customNetHttp.ErrAbortHandler) // The client went away
		case errors.Is(err, errDXStartsFull): // As without a free slot: the server stays responsive
			dxLogFailure(job, "dx preprocessor whose workers are all in use or starting: 503", err)
			job.output.Header().Set("Retry-After", "2")
			siteErrorMsg(job.output, 503)
		default:
			dxLogFailure(job, "No worker of a dx preprocessor: 500", err)
			siteErrorMsg(job.output, 500)
		}
		return false
	}
	if ctx.Err() != nil { // Before anything reached the worker: it goes on waiting for the next request
		mode.give(job.executable, worker)
		if ctx.Err() == context.DeadlineExceeded {
			dxLogFailure(job, "dx preprocessor out of time (WT) while its worker started: 504", ctx.Err())
			siteErrorMsg(job.output, 504)
			return false
		}
		panic(customNetHttp.ErrAbortHandler) // The client went away
	}
	stopWatching := context.AfterFunc(ctx, worker.cut) // WT ran out, or the client went away
	var id [8]byte
	_, _ = rand.Read(id[:]) // Never fails (crypto/rand): an id that nothing in the worker can guess
	answered, err := worker.exchange(job, binary.LittleEndian.Uint64(id[:]))
	if stopWatching() && err == nil && worker.reader.Buffered() == 0 {
		mode.give(job.executable, worker)
		return false
	}
	worker.kill()
	go worker.release()
	mode.lose(job.executable)
	if waited && retry && ctx.Err() == nil && (errors.Is(err, errDXGone) || errors.Is(err, errDXNoAnswer) && job.request.ContentLength == 0 && idempotentMethod(job.request.Method)) {
		return true // Nothing of an answer reached the client
	}
	switch {
	case err == nil: // Complete, but the worker had to end: it wrote more than its answer, or ctx ended right then
	case ctx.Err() == context.DeadlineExceeded && !answered:
		dxLogFailure(job, "dx preprocessor out of time (WT): 504", err)
		siteErrorMsg(job.output, 504)
	case ctx.Err() == context.DeadlineExceeded: // Cut, so that it doesn't look complete
		dxLogFailure(job, "dx preprocessor out of time (WT) after its answer started: the connection was cut", err)
		panic(customNetHttp.ErrAbortHandler)
	case ctx.Err() != nil:
		panic(customNetHttp.ErrAbortHandler) // The client went away
	case answered: // Cut, so that it doesn't look complete
		dxLogFailure(job, "dx preprocessor whose answer broke after it started: the connection was cut", err)
		panic(customNetHttp.ErrAbortHandler)
	default:
		dxLogFailure(job, "dx preprocessor that failed: 500", err)
		siteErrorMsg(job.output, 500)
	}
	return false
}

// take returns a worker of the program for a request, and whether it waited for one: one that waits, the last used
// first (those left unused end when idle runs), or a new one. One that ended while it waited is let go. A new one
// starts apart from the request: if ctx ends first, the request gives up (take returns ctx's error), and the worker,
// once it greets, waits for the next; a program slower to start than WT would never have one otherwise.
func (mode *dxMode) take(executable string, ctx context.Context) (*dxWorker, bool, error) {
	mode.mutex.Lock()
	pool := mode.pools[executable]
	if pool == nil {
		pool = &dxPool{}
		mode.pools[executable] = pool
	}
	for n := len(pool.idle); n > 0; n = len(pool.idle) {
		worker := pool.idle[n-1]
		pool.idle[n-1] = nil
		pool.idle = pool.idle[:n-1]
		select {
		case <-worker.process.Exited(): // Killed while it waited, or it ended by itself
			go worker.release()
			continue
		default:
		}
		pool.busy++
		mode.mutex.Unlock()
		return worker, true, nil
	}
	if monotonicNow() < pool.failedUntil {
		mode.mutex.Unlock()
		return nil, false, errDXStartDeferred
	}
	// A start that its request gave up on goes on, and counts, until it ends: for a program slower to start than WT,
	// each request started one more, beyond the slots (CGP) that bound the requests.
	if int64(pool.busy) >= cgiProcessLimit() {
		mode.mutex.Unlock()
		return nil, false, errDXStartsFull
	}
	pool.busy++
	mode.mutex.Unlock()
	type start struct {
		worker *dxWorker
		err    error
	}
	started := make(chan start, 1)
	go func() {
		worker, err := startDXWorker(executable)
		mode.mutex.Lock()
		if err != nil {
			pool.busy--
			if now := monotonicNow(); now >= pool.failedUntil { // The starts that failed together count once: 1 s, then 2, 4...
				pool.failures++
				backoff := min(dxStartBackoffMin<<min(pool.failures-1, 16), dxStartBackoffMax)
				pool.failedUntil = now + int64(backoff)
			}
		} else {
			pool.failures, pool.failedUntil = 0, 0
		}
		mode.mutex.Unlock()
		started <- start{worker, err}
	}()
	select {
	case result := <-started:
		return result.worker, false, result.err
	case <-ctx.Done():
		go func() {
			if result := <-started; result.err == nil {
				mode.give(executable, result.worker) // Ready for the next request
			}
		}()
		return nil, false, ctx.Err()
	}
}

// give returns a worker whose request ended well. Turbo may be stopping (stop let go of its program): then it ends.
func (mode *dxMode) give(executable string, worker *dxWorker) {
	worker.lastUse = monotonicNow()
	mode.mutex.Lock()
	defer mode.mutex.Unlock()
	pool := mode.pools[executable]
	if pool == nil {
		go worker.end(dxGreetingWait)
		return
	}
	pool.busy--
	pool.idle = append(pool.idle, worker)
}

// lose counts a worker that ended with its request.
func (mode *dxMode) lose(executable string) {
	mode.mutex.Lock()
	defer mode.mutex.Unlock()
	if pool := mode.pools[executable]; pool != nil {
		pool.busy--
	}
}

// idle lets go of the workers unused for dxIdleAfter, and of every worker of a program that no preprocessor names.
func (mode *dxMode) idle(inUse func(executable string) bool) {
	now := monotonicNow()
	var ending []*dxWorker
	mode.mutex.Lock()
	for executable, pool := range mode.pools {
		kept := pool.idle[:0]
		for _, worker := range pool.idle {
			if inUse(executable) && now-worker.lastUse < int64(dxIdleAfter) {
				kept = append(kept, worker)
			} else {
				ending = append(ending, worker)
			}
		}
		clear(pool.idle[len(kept):])
		pool.idle = kept
		if len(pool.idle) == 0 && pool.busy == 0 && (!inUse(executable) || pool.failures == 0) {
			delete(mode.pools, executable)
		}
	}
	mode.mutex.Unlock()
	for _, worker := range ending {
		go worker.end(dxGreetingWait)
	}
}

// stop ends every worker that waits, within wait: its input closes, which ends a worker that keeps the protocol, and
// what goes on after wait is killed. One still with a request ends with it: the connections that shutdown closes end
// their requests, and their contexts kill their workers.
func (mode *dxMode) stop(wait time.Duration) {
	mode.mutex.Lock()
	var ending []*dxWorker
	for executable, pool := range mode.pools {
		ending = append(ending, pool.idle...)
		delete(mode.pools, executable)
	}
	mode.mutex.Unlock()
	var wg sync.WaitGroup
	for _, worker := range ending {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker.end(wait)
		}()
	}
	wg.Wait()
}

// startDXWorker starts a worker of the program, and waits for its greeting (dxGreetingWait at most). It runs in the
// folder of its program, as a CGI does, with what a CGI gets of Turbo's environment: what each request has goes in its
// pairs.
func startDXWorker(executable string) (*dxWorker, error) {
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		closeAll(inputRead, inputWrite)
		return nil, err
	}
	// The program as validation checked it, from Turbo's folder, once: exec.Command would look a bare name up in the
	// PATH, and a relative path would be resolved again from Dir.
	program, err := filepath.Abs(executable)
	if err != nil {
		closeAll(inputRead, inputWrite, outputRead, outputWrite)
		return nil, err
	}
	// Its standard error, grouped (scriptLines): read by a goroutine of its own until the worker, and what it started,
	// have closed it. A pipe made here, as the others, so that exec makes no goroutine of its own that Wait would wait for.
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		closeAll(inputRead, inputWrite, outputRead, outputWrite)
		return nil, err
	}
	cmd := &exec.Cmd{Path: program, Args: []string{program}, Dir: filepath.Dir(program)}
	cmd.Env = dxEnvironment()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inputRead, outputWrite, stderrWrite
	process, err := customNetHttp.TurboStartProcess(cmd)
	closeAll(inputRead, outputWrite, stderrWrite) // The worker's ends: its input closes when Turbo's end does, and its output when the worker ends
	if err != nil {
		closeAll(inputWrite, outputRead, stderrRead)
		return nil, err
	}
	go func() {
		stderr := newScriptStderr(program)
		_, _ = io.Copy(stderr, stderrRead) // Until its writers end: the worker, and its group, which release kills
		stderr.flush()
		_ = stderrRead.Close()
	}()
	worker := &dxWorker{process: process, input: inputWrite, output: outputRead, reader: bufio.NewReaderSize(outputRead, 32<<10), writer: bufio.NewWriterSize(inputWrite, 32<<10)}
	timer := time.AfterFunc(dxGreetingWait, worker.cut)
	greeting := make([]byte, len(dxGreeting))
	_, err = io.ReadFull(worker.reader, greeting)
	// Nothing may come after the greeting before a request: it would be taken for the answer of the first one.
	if !timer.Stop() || err != nil || string(greeting) != dxGreeting || worker.reader.Buffered() > 0 {
		worker.kill()
		go worker.release()
		if err == nil {
			err = errDXProtocol
		}
		return nil, err
	}
	return worker, nil
}

// idempotentMethod reports whether a request with method may be made twice with the same effect (RFC 9110, 9.2.2).
func idempotentMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE":
		return true
	}
	return false
}

// closeAll closes the ends of pipes that Turbo lets go: a pipe has nothing to flush, so an error there changes nothing.
func closeAll(files ...*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

// dxEnvironment is the environment of a worker: what a CGI gets of Turbo's (the PATH, the temporary folder and what
// the system needs to run a program); never anything of a request. Never nil either: exec would give the worker
// Turbo's whole environment, TURBO_PASSWORD with it, when none of those is set.
func dxEnvironment() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/bin:/usr/bin:/usr/ucb:/usr/bsd:/usr/local/bin" // As the CGI host gives a CGI
	}
	environment := []string{"PATH=" + path}
	names := append(customNetHttp.TurboInheritedEnvironment(), cgiTempVariables...) // What the CGI host gives a CGI
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

// kill kills the worker and what it started in its group.
func (worker *dxWorker) kill() {
	worker.process.Kill()
}

// cut kills the worker and closes Turbo's ends of its pipes, so that whatever waits on them returns at once: also when
// something that the worker started outside its group (setsid) still holds them, and would hold the request, and
// its slot, until it ended.
func (worker *dxWorker) cut() {
	worker.kill()
	closeAll(worker.input, worker.output)
}

// release waits for the end of a worker (killed, or that ends by itself), lets its group go and closes Turbo's ends.
func (worker *dxWorker) release() {
	worker.process.Release()
	closeAll(worker.input, worker.output)
}

// end lets a worker go: its input closes, and if it hasn't ended within wait, it is killed.
func (worker *dxWorker) end(wait time.Duration) {
	closeAll(worker.input)
	select {
	case <-worker.process.Exited():
	case <-time.After(wait):
		worker.kill()
	}
	worker.release()
}

// exchange writes the request of job to the worker, with id, and its answer to job.output; an answer with another id is
// refused before anything of it goes out. answered is whether the answer had started to go out (its status was
// written).
func (worker *dxWorker) exchange(job *dynamicJob, id uint64) (answered bool, err error) {
	block := dxRequestPairs(job)
	var idBytes [8]byte
	binary.LittleEndian.PutUint64(idBytes[:], id)
	// The errors of the writes come back from Flush: bufio.Writer keeps the first one. The pairs go first, alone: if
	// they can't, the worker had ended (errDXGone), and nothing of the request reached it.
	_, _ = worker.writer.Write(idBytes[:])
	_, _ = worker.writer.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(block)))) // #nosec G115 -- the pairs of a request: its headers, within the limits of a request's head
	_, _ = worker.writer.Write(block)
	if err := worker.writer.Flush(); err != nil {
		return false, errors.Join(errDXGone, err)
	}
	if job.request.ContentLength > 0 {
		if _, err := io.CopyN(worker.writer, job.request.Body, job.request.ContentLength); err != nil {
			return false, err
		}
	}
	if err := worker.writer.Flush(); err != nil {
		return false, err
	}

	readU32 := func() (uint32, error) { // Unsigned: on a system of 32 bits an int would take a large one as negative
		var b [4]byte
		if _, err := io.ReadFull(worker.reader, b[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint32(b[:]), nil
	}
	if _, err := io.ReadFull(worker.reader, idBytes[:]); err != nil {
		if err == io.EOF { // Not a byte: the worker ended before it answered, maybe before it read the request
			err = errors.Join(errDXNoAnswer, err)
		}
		return false, err
	}
	if binary.LittleEndian.Uint64(idBytes[:]) != id {
		return false, errDXOtherAnswer
	}
	size, err := readU32()
	if err != nil {
		return false, err
	}
	if size < 8 || size > dxMaxHead {
		return false, errDXProtocol
	}
	head := make([]byte, size)
	if _, err := io.ReadFull(worker.reader, head); err != nil {
		return false, err
	}
	status := binary.LittleEndian.Uint32(head)
	headers, ok := dxReadPairs(head[4:])
	if !ok || status < 200 || status > 599 {
		return false, errDXProtocol
	}
	chunk, err := readU32() // Read before anything goes out: an error without a body gets the site's template
	if err != nil {
		return false, err
	}
	if chunk > dxMaxChunk { // Checked before the answer starts too: a 500 instead of a cut connection
		return false, errDXProtocol
	}
	header := job.output.Header()
	siteSet := make(map[string]bool, len(header)) // The site's headers win over the worker's, as over a CGI's
	for name := range header {
		siteSet[name] = true
	}
	for _, pair := range headers {
		name := customNetHttp.CanonicalHeaderKey(pair[0])
		if !customNetHttp.ValidHeaderFieldName(name) || siteSet[name] {
			continue
		}
		header.Add(name, pair[1]) // Filtered as a CGI's when written (cgiResponseWriter)
	}
	if chunk == 0 && status >= 400 {
		// The site's template goes instead of the worker's body: the worker's headers that describe a body don't. The
		// status is the script's, not an error of Turbo's (siteErrorMsg): its other headers stay, those about keeping
		// the answer among them (a 404 that its script marks "no-store" would be kept by a cache otherwise).
		for _, name := range dxBodyHeaders {
			if !siteSet[name] {
				header.Del(name)
			}
		}
		reqMsg(job.output, int(status))
		return true, nil
	}
	job.output.WriteHeader(int(status))
	// A status without a body (204, 304) takes none: what the worker sends is read and dropped, and the worker kept
	var body io.Writer = job.output
	if status == 204 || status == 304 {
		body = io.Discard
	}
	for chunk != 0 {
		if chunk > dxMaxChunk {
			return true, errDXProtocol
		}
		if _, err := io.CopyN(body, worker.reader, int64(chunk)); err != nil {
			return true, err
		}
		if chunk, err = readU32(); err != nil {
			return true, err
		}
	}
	return true, nil
}

// dxBodyHeaders are the headers of a worker's answer that describe its body, dropped when the site's template answers
// an error without one: a template marked as gzip, for one, couldn't be read.
var dxBodyHeaders = []string{"Content-Encoding", "Content-Range", "Content-Disposition", "Etag", "Last-Modified"}

// dxReadPairs reads the pairs of a block: false if the block isn't exactly that.
func dxReadPairs(block []byte) ([][2]string, bool) {
	if len(block) < 4 {
		return nil, false
	}
	count := uint64(binary.LittleEndian.Uint32(block)) // Unsigned, as in exchange
	block = block[4:]
	if count > uint64(len(block)/8) { // #nosec G115 -- a length: never negative
		return nil, false
	}
	pairs := make([][2]string, 0, count)
	for range count {
		var pair [2]string
		for j := range pair {
			if len(block) < 4 {
				return nil, false
			}
			n := uint64(binary.LittleEndian.Uint32(block))
			if n > uint64(len(block)-4) { // #nosec G115 -- len(block) >= 4: checked above
				return nil, false
			}
			pair[j] = string(block[4 : 4+n])
			block = block[4+n:]
		}
		pairs = append(pairs, pair)
	}
	return pairs, len(block) == 0
}

// dxRequestPairs is the block of pairs of a request: what a CGI gets of it in its environment, with the same names
// and values (but those of Turbo's own environment), and DX_TIMEOUT_MS, the milliseconds the worker has: what is left
// of WT, less a tenth of it (dxTimeoutMargin at most), so that it answers before Turbo gives up (0: no limit).
func dxRequestPairs(job *dynamicJob) []byte {
	request := job.request
	port := "80"
	if request.TLS != nil {
		port = "443"
	}
	if colon := strings.LastIndexByte(request.Host, ':'); colon != -1 && onlyDigits(request.Host[colon+1:]) {
		port = request.Host[colon+1:]
	}
	pairs := [][2]string{
		{"SERVER_SOFTWARE", "go"}, {"SERVER_PROTOCOL", "HTTP/1.1"}, {"HTTP_HOST", request.Host}, {"GATEWAY_INTERFACE", "CGI/1.1"},
		{"REQUEST_METHOD", request.Method}, {"QUERY_STRING", job.queryString}, {"REQUEST_URI", request.URL.RequestURI()},
		{"PATH_INFO", ""}, {"SCRIPT_NAME", job.requestPath}, {"SCRIPT_FILENAME", job.basePath + job.requestPath},
		{"SERVER_PORT", port}, {"DOCUMENT_ROOT", job.basePath}, {"REDIRECT_STATUS", "CGI"},
	}
	if remoteIP, remotePort, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		pairs = append(pairs, [2]string{"REMOTE_ADDR", remoteIP}, [2]string{"REMOTE_HOST", remoteIP}, [2]string{"REMOTE_PORT", remotePort})
	} else {
		pairs = append(pairs, [2]string{"REMOTE_ADDR", request.RemoteAddr}, [2]string{"REMOTE_HOST", request.RemoteAddr})
	}
	if hostName, _, err := net.SplitHostPort(request.Host); err == nil {
		pairs = append(pairs, [2]string{"SERVER_NAME", hostName})
	} else {
		pairs = append(pairs, [2]string{"SERVER_NAME", request.Host})
	}
	if request.TLS != nil {
		pairs = append(pairs, [2]string{"HTTPS", "on"})
	}
	names := make([]string, 0, len(request.Header))
	for name := range request.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		key := strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z':
				return r - ('a' - 'A')
			case r == '-', r == '=':
				return '_'
			}
			return r
		}, name)
		if key == "PROXY" { // As a CGI: HTTP_PROXY would be taken for the proxy of the program's own requests
			continue
		}
		separator := ", "
		if key == "COOKIE" {
			separator = "; "
		}
		pairs = append(pairs, [2]string{"HTTP_" + key, strings.Join(request.Header[name], separator)})
	}
	if request.ContentLength > 0 {
		pairs = append(pairs, [2]string{"CONTENT_LENGTH", strconv.FormatInt(request.ContentLength, 10)})
	}
	if contentType := request.Header.Get("Content-Type"); contentType != "" {
		pairs = append(pairs, [2]string{"CONTENT_TYPE", contentType})
	}
	left := "0"
	if deadline, hasDeadline := request.Context().Deadline(); hasDeadline {
		remaining := time.Until(deadline)
		remaining -= min(remaining/10, dxTimeoutMargin)
		left = strconv.FormatInt(max(remaining.Milliseconds(), 1), 10)
	}
	pairs = append(pairs, [2]string{"DX_TIMEOUT_MS", left})

	size := 4
	for _, pair := range pairs {
		size += 8 + len(pair[0]) + len(pair[1])
	}
	block := make([]byte, 0, size)
	block = binary.LittleEndian.AppendUint32(block, uint32(len(pairs))) // #nosec G115 -- a few dozen, and the headers of a request
	for _, pair := range pairs {
		for _, text := range pair {
			block = binary.LittleEndian.AppendUint32(block, uint32(len(text))) // #nosec G115 -- a header or a variable of a request: far below 4 GiB
			block = append(block, text...)
		}
	}
	return block
}

// The failures of the workers of a program are logged at most once a minute per program, site and kind: each request
// that meets one would add a line otherwise. The program is shared by every site that names it: the line says the
// folder of the site whose request met it.
func dxLogFailure(job *dynamicJob, message string, err error) {
	if logDueOnceAMinute("dx|" + job.executable + "|" + job.basePath + "|" + message) {
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		slog.Error(message+" (reported once a minute)", "program", job.executable, "site", job.basePath, "reason", reason)
	}
}
