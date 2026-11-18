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

// CGI: how the preprocessor of a site is run for a request, and what bounds it: its output while a slow client reads
// it (in memory, then in temporary files), the request bodies that wait for the script, and how many run at once.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"turbo/customNetHttp"
)

// withoutParametersOf is query without the parameters that other sets, by their decoded names; "&" and ";" both
// separate them, as some CGI libraries take ";" too. What is left keeps its bytes, separators and order.
func withoutParametersOf(query string, other string) string {
	if query == "" || other == "" {
		return query
	}
	names := make(map[string]bool)
	for _, parameter := range strings.FieldsFunc(other, func(r rune) bool { return r == '&' || r == ';' }) {
		names[queryParameterName(parameter)] = true
	}
	var kept strings.Builder
	dropped, start := false, 0
	for i := 0; i <= len(query); i++ {
		if i < len(query) && query[i] != '&' && query[i] != ';' {
			continue
		}
		if parameter := query[start:i]; parameter != "" && names[queryParameterName(parameter)] {
			dropped = true
		} else if parameter != "" {
			if kept.Len() > 0 {
				kept.WriteByte(query[start-1]) // The separator before it
			}
			kept.WriteString(parameter)
		}
		start = i + 1
	}
	if !dropped {
		return query
	}
	return kept.String()
}

// queryParameterName is the name of a parameter of a query ("name=value", or the name alone), decoded as a CGI's
// library decodes it; as it is if it can't be decoded.
func queryParameterName(parameter string) string {
	name, _, _ := strings.Cut(parameter, "=")
	if decoded, err := url.QueryUnescape(name); err == nil {
		return decoded
	}
	return name
}

func dynamic(basePath string, requestPath string, queryString string, scriptPath string, responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request) {
	handler := new(customNetHttp.CgiHandler)
	handler.Path = scriptPath
	handler.Logger = cgiErrorLog                             // Counted as the connections' errors: one per request a client could make
	handler.Timeout = serverTimeLimits.Load().WT             // Zero (no write timeout) leaves the CGI without limit
	handler.Env = append(handler.Env, "REDIRECT_STATUS=CGI") // PHP refuses to run as a CGI without it while cgi.force_redirect is on (the default)
	handler.InheritEnv = cgiTempVariables
	if request.ContentLength > maxBodySize.Load() {
		reqMsg(responseWriter, 413)
		return
	}
	// The body is read whole, up to MBB, before the CGI takes a slot and starts: a client that sends it slowly, or
	// not at all, holds no slot (with the network body, the CGI waited for it until RT), and a CGI always gets
	// CONTENT_LENGTH (chunked, or HTTP/2 without Content-Length). It reaches the CGI through a pipe.
	request.Body = customNetHttp.MaxBytesReader(responseWriter, request.Body, maxBodySize.Load())
	body, size, cleanup, err := bufferedRequestBody(request.Body, request.ContentLength)
	if err != nil {
		var tooLarge *customNetHttp.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			reqMsg(responseWriter, 413)
		case errors.Is(err, errCGIBodyFilesFull): // Too many bodies on disk at once: as without a free slot
			responseWriter.Header().Set("Retry-After", "2")
			reqMsg(responseWriter, 503)
		case errors.As(err, &cgiBodyFileError{}): // The server's temporary folder (full, or not there)
			cgiErrorLog.Printf("Can't keep the body of a request for a CGI: %v", err)
			reqMsg(responseWriter, 500)
		default: // The client's body (cut, or malformed)
			reqMsg(responseWriter, 400)
		}
		return
	}
	defer cleanup()
	request.Body, request.ContentLength, request.TransferEncoding = body, size, nil
	if !acquireCGISlot(cgiSlotWait) { // Too many CGIs running: the server stays responsive
		responseWriter.Header().Set("Retry-After", "2")
		reqMsg(responseWriter, 503)
		return
	}
	// The CGI's output waits in output for the client (newCGIOutput), so that the CGI, done, frees its slot at once,
	// however slowly the client reads: holding it until the client had read everything let a few clients that don't
	// read keep every slot, and every site's CGIs answered 503. The CGI runs with a context of its own, which the output
	// cancels when it cuts the response (its client already has its share of CGIs waiting for it).
	// That context ends also when the CGI's time runs out, as the one the CGI host derives from it (P12): the output
	// watches it, so that a CGI ended while it waited in Write for its client frees its slot then.
	var cgiContext context.Context
	var cancelCGI context.CancelFunc
	if handler.Timeout > 0 {
		cgiContext, cancelCGI = context.WithTimeout(request.Context(), handler.Timeout)
	} else {
		cgiContext, cancelCGI = context.WithCancel(request.Context())
	}
	defer cancelCGI()
	request = request.WithContext(cgiContext)
	output := newCGIOutput(cgiResponseWriter{responseWriter}, ipAddr(request.RemoteAddr), cancelCGI)
	output.watch(cgiContext)
	slotHeld, completed := true, false
	defer func() {
		// First the slot: on the way out without completing, the CGI host has already waited for the CGI's process
		// (and, when the context ended, killed its group: P12), and the sender may wait for a client that doesn't read
		// until WT + 2 s.
		if slotHeld {
			releaseCGISlot()
		}
		if completed {
			output.finish() // What is left reaches the client, the slot already free
		} else {
			output.abort() // Cut (the client went away, or WT ran out): nothing more is written
		}
	}()
	withoutSessionCookie(request)
	// A header with "_" in its name becomes the same variable as the one with "-" (X_Forwarded_For and
	// X-Forwarded-For are both HTTP_X_FORWARDED_FOR), and the client's could win over what a proxy in front set: as
	// Apache does, they don't reach the CGI.
	for name := range request.Header {
		if strings.IndexByte(name, '_') != -1 {
			delete(request.Header, name)
		}
	}
	// The client's query goes first, without the parameters that the rewrite's query sets, and the rewrite's after it:
	// an application gets the rewrite's value whether it reads the first of a repeated parameter (Python's parse_qs,
	// Perl's CGI.pm, Go's Query().Get) or the last (PHP). Only the last was the rewrite's.
	if clientQuery := withoutParametersOf(request.URL.RawQuery, queryString); clientQuery != "" && queryString != "" {
		queryString = clientQuery + "&" + queryString
	} else if clientQuery != "" {
		queryString = clientQuery
	}
	handler.Env = append(handler.Env, "QUERY_STRING="+queryString) // If not set, not includes rewrite query string
	handler.Env = append(handler.Env, "DOCUMENT_ROOT="+basePath)
	handler.Env = append(handler.Env, "SCRIPT_FILENAME="+basePath+requestPath)
	// The script's URL path, after the rewrite, and no extra path: what the handler derives from Root is a path on
	// disk, which an application would show (PHP_SELF) or put in its links. REQUEST_URI stays the original one.
	handler.Env = append(handler.Env, "SCRIPT_NAME="+requestPath, "PATH_INFO=")
	if handler.Timeout > 0 {
		// The connection's write deadline (WT from the end of the request) would pass right when the CGI is cut:
		// moved 2 s after the CGI's own, which starts now (not before the body was read nor a slot was free), the 504
		// of a CGI that runs out of time reaches the client.
		_ = customNetHttp.NewResponseController(responseWriter).SetWriteDeadline(time.Now().Add(handler.Timeout + 2*time.Second)) // Not supported only by test writers
	}
	handler.ServeHTTP(output, request)
	completed = true
	releaseCGISlot() // The CGI has ended: its slot is free while its output reaches the client
	slotHeld = false
}

// How much of a CGI's output may wait for its client: in memory, memory per response and budget for all of them;
// beyond, in temporary files, fileMax per response (their size on disk) and fileBudget for all of them. A client
// (limiterKey) may take a quarter of each budget and, in IPv6, its /48 half. Within them a CGI never waits for its
// client, so it ends, and frees its slot, as soon as it is done; beyond them it waits for its client, as it did
// writing straight to it (as nginx's FastCGI buffers do), and only a quarter of the CGI slots may wait like that for
// the responses of one client (a half for a /48): a response beyond is cut. A variable, so that tests can lower them
// (under cgiOutputSharesMutex).
type cgiOutputLimitSet struct {
	memory, budget, fileMax, fileBudget int64
}

var cgiOutputLimits = cgiOutputLimitSet{memory: 1 << 20, budget: 64 << 20, fileMax: 256 << 20, fileBudget: 1 << 30}

// segmentMax is the size of each temporary file of a response, an eighth of fileMax (32 MiB): the sender removes a
// file as soon as its client has taken all of it, and gives back what it took, so what was sent never takes more than
// one file. With a single file, emptied only once its client had taken all of it, a client almost as fast as its CGI
// kept on disk, and in the budgets, everything already sent, up to fileMax, where the CGI then waited.
func (limits cgiOutputLimitSet) segmentMax() int64 {
	return limits.fileMax / 8
}

// cgiOutputSegment is one of the temporary files of a response.
type cgiOutputSegment struct {
	file    *os.File
	read    int64 // What of file was sent
	written int64 // What of file was written: its size on disk, counted in the budgets until it is removed or emptied
}

// cgiOutputInUse and cgiOutputFilesInUse are what the outputs of the CGIs take, in memory and in temporary files (their
// size on disk), while they wait for their clients. They change only under cgiOutputSharesMutex.
var cgiOutputInUse, cgiOutputFilesInUse atomic.Int64

// cgiOutputShares are, by client (limiterKey) and, in IPv6, by /48, what the outputs of their CGIs take and how many of
// them have had to wait for their clients. Without them, the clients of one address that didn't read filled the
// budgets, and the CGIs of everyone else waited for those clients again: every site's CGIs answered 503. Guarded by
// cgiOutputSharesMutex, which also makes checking a part of a budget and taking it one step; it is taken after the
// mutex of an output.
var (
	cgiOutputSharesMutex sync.Mutex
	cgiOutputShares      = map[string]*cgiOutputShare{}
)

type cgiOutputShare struct {
	memory, files int64 // What the outputs of its responses take, in memory and in temporary files
	waiting       int64 // Its responses whose CGI has had to wait for the client
	responses     int   // Its responses in progress: the entry goes with the last one
}

// cgiOutputNetworkKey is the /48 of an IPv6 client, whose /64s are each a client; "" for IPv4.
func cgiOutputNetworkKey(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if address = address.Unmap().WithZone(""); address.Is4() {
		return ""
	}
	prefix, _ := address.Prefix(48)
	return prefix.String()
}

// cgiOutputKeys are the entries of cgiOutputShares that a response counts in.
func (output *cgiOutput) cgiOutputKeys() []string {
	keys := make([]string, 0, 2)
	for _, key := range []string{output.client, output.network} {
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

// joinShares and leaveShares count a response in its client and its network while it is in progress. joinShares
// also takes the limits in force (cgiOutputLimits changes only under cgiOutputSharesMutex).
func (output *cgiOutput) joinShares() {
	cgiOutputSharesMutex.Lock()
	defer cgiOutputSharesMutex.Unlock()
	output.limits = cgiOutputLimits
	for _, key := range output.cgiOutputKeys() {
		share := cgiOutputShares[key]
		if share == nil {
			share = &cgiOutputShare{}
			cgiOutputShares[key] = share
		}
		share.responses++
	}
}

func (output *cgiOutput) leaveShares() {
	cgiOutputSharesMutex.Lock()
	defer cgiOutputSharesMutex.Unlock()
	for _, key := range output.cgiOutputKeys() {
		if share := cgiOutputShares[key]; share != nil {
			if share.responses--; share.responses <= 0 {
				delete(cgiOutputShares, key)
			}
		}
	}
}

// cgiOutputReservation is the answer of reserveLocked.
type cgiOutputReservation int

const (
	outputReserved   cgiOutputReservation = iota
	outputOverShare                       // Its client (or its /48) has taken its share: the wait is that client's
	outputOverBudget                      // The budget of all of them is full: the wait is no client's in particular
)

// reserveLocked takes size bytes of memory (or, with file, of temporary files) if the quarter of its client, the half
// of its network and the budget allow it, and says which of them doesn't (the client's share before the budget: a
// client over its share waits on its own account, also when the budget is full too); with force, whatever they say (a
// response with nothing waiting always gets a chunk in, so that every CGI makes progress). Callers hold output.mutex.
func (output *cgiOutput) reserveLocked(size int64, file bool, force bool) cgiOutputReservation {
	cgiOutputSharesMutex.Lock()
	defer cgiOutputSharesMutex.Unlock()
	total, budget := &cgiOutputInUse, output.limits.budget
	if file {
		total, budget = &cgiOutputFilesInUse, output.limits.fileBudget
	}
	part := func(share *cgiOutputShare) *int64 {
		if file {
			return &share.files
		}
		return &share.memory
	}
	if !force {
		for _, key := range output.cgiOutputKeys() {
			limit := budget / 4 // The client's quarter
			if key == output.network {
				limit = budget / 2 // The network's half
			}
			if share := cgiOutputShares[key]; share != nil && *part(share)+size > limit {
				return outputOverShare
			}
		}
		if total.Load()+size > budget {
			return outputOverBudget
		}
	}
	total.Add(size)
	for _, key := range output.cgiOutputKeys() {
		if share := cgiOutputShares[key]; share != nil {
			*part(share) += size
		}
	}
	return outputReserved
}

// releaseLocked gives back what reserveLocked took. Callers hold output.mutex.
func (output *cgiOutput) releaseLocked(size int64, file bool) {
	if size == 0 {
		return
	}
	cgiOutputSharesMutex.Lock()
	defer cgiOutputSharesMutex.Unlock()
	if file {
		cgiOutputFilesInUse.Add(-size)
	} else {
		cgiOutputInUse.Add(-size)
	}
	for _, key := range output.cgiOutputKeys() {
		if share := cgiOutputShares[key]; share != nil {
			if file {
				share.files -= size
			} else {
				share.memory -= size
			}
		}
	}
}

// startWaitingLocked counts the response among those whose CGI waits for their client, unless its client already has a
// quarter of the CGI slots like that (its network, half). Callers hold output.mutex.
func (output *cgiOutput) startWaitingLocked() bool {
	cgiOutputSharesMutex.Lock()
	defer cgiOutputSharesMutex.Unlock()
	slots := cgiProcessLimit()
	for _, key := range output.cgiOutputKeys() {
		limit := max(1, slots/4)
		if key == output.network {
			limit = max(1, slots/2)
		}
		if share := cgiOutputShares[key]; share != nil && share.waiting >= limit {
			return false
		}
	}
	for _, key := range output.cgiOutputKeys() {
		if share := cgiOutputShares[key]; share != nil {
			share.waiting++
		}
	}
	return true
}

func (output *cgiOutput) stopWaitingLocked() {
	cgiOutputSharesMutex.Lock()
	defer cgiOutputSharesMutex.Unlock()
	for _, key := range output.cgiOutputKeys() {
		if share := cgiOutputShares[key]; share != nil {
			share.waiting--
		}
	}
}

// cgiOutput is the ResponseWriter a CGI writes to: the headers go to the client's writer at once, and the body is
// kept (in memory, then in temporary files) and sent by a goroutine of its own, so that a client that reads slowly,
// or not at all, doesn't hold the CGI (with its slot). Writing to the client fails when it goes away or when WT runs
// out; then the CGI's next write fails too, and the CGI handler ends it.
type cgiOutput struct {
	customNetHttp.ResponseWriter // cgiResponseWriter: the headers the CGI may set, and the client's writer

	limits       cgiOutputLimitSet  // cgiOutputLimits when the response started
	client       string             // limiterKey of its client
	network      string             // The /48 of its client in IPv6 (cgiOutputNetworkKey)
	cancel       context.CancelFunc // Ends the CGI (its context) when the response is cut
	stopWatch    func() bool        // Stops watching the CGI's context (watch)
	contextEnded bool               // The CGI's context ended (watch): a Write that would wait gives up instead
	mutex        sync.Mutex
	more         *sync.Cond          // Signals a new chunk, the end, or that something was sent
	chunks       [][]byte            // In memory, waiting to be sent, in order; all of them before what is in the files
	pending      int                 // Bytes in chunks
	inFlight     int                 // Bytes the sender took from chunks and hasn't written yet: still this response's memory
	segments     []*cgiOutputSegment // The temporary files, once the memory is full: written at the last, sent from the first
	oneFile      bool                // A new temporary file couldn't be created: the output goes on in the last one
	buffer       []byte              // For reading the files, allocated the first time one is read
	noFile       bool                // No temporary file could be used: beyond the memory, the CGI waits
	waiting      bool                // Its CGI has had to wait for the client: counted in startWaitingLocked until the end
	flushing     bool                // A Flush was asked: done after what was written before it
	unflushed    bool                // Something was written to the client since the last flush
	streaming    bool                // Its CGI went quiet while it went on (quiet): what is sent is flushed at once
	quietTimer   *time.Timer         // The flush that waits for the CGI to stay quiet (cgiQuietFlushDelay)
	closed       bool                // The CGI is done (or cut): nothing more comes
	ended        bool                // end ran: its shares are given back
	err          error               // Writing to the client failed, or the response was cut
	sending      bool                // The sender is running
	cut          atomic.Bool         // The response was cut: the sender stops between two writes
	done         chan struct{}
}

// errCGIOutputCut is the error of a CGI's write once its response was cut.
var errCGIOutputCut = errors.New("the response was cut")

// errCGIOutputWaitLimit is the error of a CGI's write when its response is cut because the responses of its client
// (or of its /48) already hold their share of the CGI slots waiting for their clients.
var errCGIOutputWaitLimit = errors.New("the response was cut: its client already has its share of CGIs waiting for it")

// newCGIOutput is the output of a CGI for the client at ip (an address, as ipAddr gives it); cancel ends the CGI.
func newCGIOutput(w customNetHttp.ResponseWriter, ip string, cancel context.CancelFunc) *cgiOutput {
	output := &cgiOutput{ResponseWriter: w, client: limiterKey(ip), network: cgiOutputNetworkKey(ip), cancel: cancel, done: make(chan struct{})}
	output.more = sync.NewCond(&output.mutex)
	output.joinShares()
	cgiSlots.mutex.Lock()
	cgiSlots.outputs++
	cgiSlots.mutex.Unlock()
	return output
}

// watch wakes a Write that waits for room when ctx, the CGI's, ends (its time ran out, or its client went away), and
// cuts the response then: a CGI that waited in Write for its client, already ended by P12, held its slot until the
// sender's write deadline, WT + 2 s later. What is written after that without waiting (the template of a 504 that
// the CGI host sends when the CGI wrote nothing) is kept.
func (output *cgiOutput) watch(ctx context.Context) {
	stop := context.AfterFunc(ctx, output.contextDone)
	output.mutex.Lock()
	output.stopWatch = stop
	output.mutex.Unlock()
}

func (output *cgiOutput) contextDone() {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	output.contextEnded = true
	output.more.Broadcast() // A Write that waits for room gives up; what is written afterwards (the template of a 504) is kept
}

// notWaitingLocked stops counting the response among those whose CGI waits for their client: its CGI has ended.
// Callers hold output.mutex.
func (output *cgiOutput) notWaitingLocked() {
	if output.waiting {
		output.stopWaitingLocked()
		output.waiting = false
	}
}

// inFilesLocked is what waits in the temporary files to be sent. Callers hold output.mutex.
func (output *cgiOutput) inFilesLocked() int64 {
	var waiting int64
	for _, segment := range output.segments {
		waiting += segment.written - segment.read
	}
	return waiting
}

// onDiskLocked is the size on disk of the temporary files, which is what they take of the budgets: what waits in them
// and what the sender has sent of the first one. Callers hold output.mutex.
func (output *cgiOutput) onDiskLocked() int64 {
	var size int64
	for _, segment := range output.segments {
		size += segment.written
	}
	return size
}

// Write keeps a copy of p to be sent: in memory while this response, its client and all of them are within their
// limits (a response with nothing waiting always gets a chunk in), else at the end of its temporary files, while
// within its limits; else it waits until the client takes some. A response that would wait while its client already
// has its share of CGIs waiting is cut, and its CGI ended.
func (output *cgiOutput) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	size := int64(len(p))
	keep := func() {
		output.chunks = append(output.chunks, append([]byte(nil), p...)) // io.Copy reuses its buffer
		output.pending += len(p)
	}
	output.mutex.Lock()
admit:
	for {
		if output.err != nil {
			err := output.err
			output.mutex.Unlock()
			return 0, err
		}
		// Whether what keeps p out is this response or its client (its limits, or its share) rather than the budget of
		// all of them: only then does its CGI count among those that wait for that client. A CGI that waits because
		// other clients filled the budget goes on as its own client reads, a chunk at a time, and is never cut for it.
		ownWait := true
		if output.inFilesLocked() == 0 {
			memory := output.pending + output.inFlight
			if memory == 0 { // A response with nothing waiting always gets a chunk in: every CGI makes progress
				output.reserveLocked(size, false, true)
				keep()
				break admit
			}
			if memory+len(p) <= int(output.limits.memory) {
				switch output.reserveLocked(size, false, false) {
				case outputReserved:
					keep()
					break admit
				case outputOverBudget:
					ownWait = false
				}
			}
		}
		if !output.noFile && output.onDiskLocked()+size <= output.limits.fileMax {
			switch output.reserveLocked(size, true, false) {
			case outputReserved:
				if output.spill(p) { // Counted from now on as part of the size of its file
					break admit
				}
				output.releaseLocked(size, true)
				continue // noFile: the memory, or waiting
			case outputOverBudget:
				ownWait = false
			}
		}
		if ownWait && !output.waiting {
			if !output.startWaitingLocked() {
				output.err = errCGIOutputWaitLimit
				output.dropLocked()
				output.more.Broadcast()
				cancel := output.cancel
				output.mutex.Unlock()
				if cancel != nil {
					cancel() // The CGI and what it started end (P12)
				}
				return 0, errCGIOutputWaitLimit
			}
			output.waiting = true
		}
		if output.contextEnded { // Its CGI is being ended (its time ran out, or its client went away): no more waiting
			output.err = errCGIOutputCut
			output.dropLocked()
			output.more.Broadcast()
			output.mutex.Unlock()
			return 0, errCGIOutputCut
		}
		output.more.Wait()
	}
	if !output.sending {
		output.sending = true
		go output.send()
	}
	output.more.Broadcast()
	output.mutex.Unlock()
	return len(p), nil
}

// spill writes p at the end of the last temporary file, or of a new one when p doesn't fit in the last (segmentMax),
// and reports whether it could. A chunk is never split: an empty file takes any. A new file that can't be created
// leaves the output in the last one, as a single file (oneFile), without making the CGI wait for that. Callers hold
// output.mutex (the sender reads another part of the files meanwhile).
func (output *cgiOutput) spill(p []byte) bool {
	size := int64(len(p))
	var last *cgiOutputSegment
	if count := len(output.segments); count > 0 {
		last = output.segments[count-1]
	}
	if last == nil || (!output.oneFile && last.written > 0 && last.written+size > output.limits.segmentMax()) {
		file, err := openCGITempFile("turbo-cgi-output-*") // 0600, in Turbo's temporary folder, gone when closed
		if err != nil {
			cgiErrorLog.Printf("Can't create a temporary file for the output of a CGI: %v", err)
		}
		switch {
		case err == nil:
			last = &cgiOutputSegment{file: file}
			output.segments = append(output.segments, last)
		case last == nil:
			output.noFile = true
			return false
		default:
			output.oneFile = true
		}
	}
	if _, err := last.file.WriteAt(p, last.written); err != nil {
		cgiErrorLog.Printf("Can't write the temporary file of the output of a CGI: %v", err)
		output.noFile = true
		return false
	}
	last.written += size
	return true
}

// Flush asks for what was written so far to be flushed to the client once it is sent.
func (output *cgiOutput) Flush() {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	output.flushing = true
	if !output.sending {
		output.sending = true
		go output.send()
	}
	output.more.Broadcast()
}

// Unwrap lets NewResponseController reach the server's ResponseWriter.
func (output *cgiOutput) Unwrap() customNetHttp.ResponseWriter {
	return output.ResponseWriter
}

// cgiQuietFlushDelay is how long a CGI that goes on may be quiet before what it wrote is flushed to its client.
const cgiQuietFlushDelay = 100 * time.Millisecond

// quiet flushes what was sent once its CGI has been quiet for cgiQuietFlushDelay while it went on, and from then on
// what is sent is flushed at once: an output that streams (server-sent events, progress, the heartbeats of long
// polling) reaches its client as it is written. Before, nothing was flushed until the CGI ended or the server's
// buffers filled. A CGI that ends within that time is sent whole, with its length.
func (output *cgiOutput) quiet() {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	output.quietTimer = nil
	if output.closed || output.err != nil {
		return
	}
	output.streaming, output.flushing = true, true
	output.more.Broadcast()
}

// send writes the output to the client in order, the memory first and then the files, until the CGI is done and
// all of it is sent, or writing fails.
func (output *cgiOutput) send() {
	defer close(output.done)
	const fileRead = 32 << 10
	for {
		output.mutex.Lock()
		for len(output.chunks) == 0 && output.inFilesLocked() == 0 && !output.flushing && !output.closed && output.err == nil {
			if output.unflushed { // All of it sent and its CGI goes on: flushed at once while it streams, else once it is quiet
				if output.streaming {
					output.flushing = true
					break
				}
				if output.quietTimer == nil {
					output.quietTimer = time.AfterFunc(cgiQuietFlushDelay, output.quiet)
				}
			}
			output.more.Wait()
		}
		if output.err != nil || (len(output.chunks) == 0 && output.inFilesLocked() == 0 && !output.flushing && output.closed) {
			output.mutex.Unlock()
			return
		}
		chunks, flush := output.chunks, output.flushing
		output.inFlight += output.pending // Taken: still this response's memory until written
		output.chunks, output.pending, output.flushing = nil, 0, false
		var segment *cgiOutputSegment // With the memory sent, the next part of the first file
		var file *os.File
		var fromFile, readAt int64
		if len(chunks) == 0 && len(output.segments) > 0 {
			segment = output.segments[0]
			file, readAt = segment.file, segment.read
			if fromFile = min(segment.written-segment.read, fileRead); fromFile > 0 && output.buffer == nil {
				output.buffer = make([]byte, fileRead)
			}
		}
		buffer := output.buffer
		output.mutex.Unlock()

		var err error
		for _, chunk := range chunks {
			if err == nil && output.cut.Load() {
				err = errCGIOutputCut
			}
			if err == nil {
				_, err = output.ResponseWriter.Write(chunk)
			}
			output.mutex.Lock()
			output.inFlight -= len(chunk)
			output.unflushed = true
			output.releaseLocked(int64(len(chunk)), false)
			output.more.Broadcast()
			output.mutex.Unlock()
		}
		if err == nil && fromFile > 0 && !output.cut.Load() {
			read, readErr := file.ReadAt(buffer[:fromFile], readAt)
			if read > 0 {
				_, err = output.ResponseWriter.Write(buffer[:read])
			}
			if err == nil && readErr != nil && !errors.Is(readErr, io.EOF) {
				err = readErr
			}
			output.mutex.Lock()
			output.unflushed = output.unflushed || read > 0
			if output.err == nil && len(output.segments) > 0 && output.segments[0] == segment { // Not dropped meanwhile
				if segment.read += int64(read); segment.read == segment.written {
					output.segmentSentLocked()
				}
			}
			output.mutex.Unlock()
		}
		if err == nil && flush {
			err = customNetHttp.NewResponseController(output.ResponseWriter).Flush()
			if errors.Is(err, customNetHttp.ErrNotSupported) {
				err = nil
			}
		}
		output.mutex.Lock()
		if err != nil && output.err == nil {
			output.err = err
			output.dropLocked()
		} else if err == nil && flush {
			output.unflushed = false
		}
		output.more.Broadcast()
		output.mutex.Unlock()
	}
}

// segmentSentLocked deals with the first temporary file once its client has taken all of it: one that isn't the last
// is closed, which deletes it (it has no name), and the last is emptied, to go on with (or closed, if it can't be
// emptied). What it took is given back once it no longer is on disk: until then its size stays counted, however much
// of it was sent. Callers hold output.mutex.
func (output *cgiOutput) segmentSentLocked() {
	segment := output.segments[0]
	count := len(output.segments)
	emptied := false
	if count == 1 {
		err := segment.file.Truncate(0)
		if emptied = err == nil; !emptied {
			cgiErrorLog.Printf("Can't empty the temporary file of the output of a CGI: %v", err)
		}
	}
	if !emptied {
		_ = segment.file.Close() // It has no name (openCGITempFile): closed, it is gone
		copy(output.segments, output.segments[1:])
		output.segments[count-1] = nil
		output.segments = output.segments[:count-1]
	}
	output.releaseLocked(segment.written, true)
	segment.read, segment.written = 0, 0
}

// dropLocked forgets what wasn't sent: the chunks in memory, given back, and what waits in the temporary files, which
// stay counted, at their size on disk, until end removes them. Callers hold output.mutex.
func (output *cgiOutput) dropLocked() {
	var memory int64
	for _, chunk := range output.chunks {
		memory += int64(len(chunk))
	}
	output.releaseLocked(memory, false)
	output.chunks, output.pending = nil, 0
	for _, segment := range output.segments {
		segment.read = segment.written
	}
}

// end waits until the sender stops, closes the temporary files (which deletes them) and gives back what the response
// took.
func (output *cgiOutput) end() {
	output.mutex.Lock()
	sending := output.sending
	output.more.Broadcast()
	output.mutex.Unlock()
	if sending {
		<-output.done
	}
	output.mutex.Lock()
	defer output.mutex.Unlock()
	output.dropLocked() // Nothing is left after a sender that finished; after one that failed, what it didn't send
	onDisk := output.onDiskLocked()
	for _, segment := range output.segments {
		_ = segment.file.Close() // It has no name (openCGITempFile): closed, it is gone
	}
	output.segments = nil
	output.releaseLocked(onDisk, true)
	if output.ended {
		return
	}
	output.ended = true
	if output.quietTimer != nil {
		output.quietTimer.Stop()
		output.quietTimer = nil
	}
	cgiSlots.mutex.Lock() // One output less for the shutdown to wait for (waitCGIsEnded)
	cgiSlots.outputs--
	cgiSlotsFreedLocked()
	cgiSlots.mutex.Unlock()
	if output.stopWatch != nil {
		output.stopWatch()
	}
	output.notWaitingLocked()
	output.leaveShares()
}

// finish waits until all the output is sent, or writing to the client failed: the CGI is done, and no longer counts
// among those that wait for their client while the rest reaches it.
func (output *cgiOutput) finish() {
	output.mutex.Lock()
	output.closed = true
	output.notWaitingLocked()
	output.mutex.Unlock()
	output.end()
}

// abort drops what wasn't sent and waits until the sender stops writing: the response was cut, and the handler,
// which owns the client's writer, is about to end.
func (output *cgiOutput) abort() {
	output.cut.Store(true)
	output.mutex.Lock()
	output.closed = true
	output.notWaitingLocked()
	if output.err == nil {
		output.err = errCGIOutputCut
	}
	output.dropLocked()
	output.mutex.Unlock()
	output.end()
}

// cgiTempVariables are the variables of the temporary folder that a CGI inherits from Turbo, when they are set:
// PHP keeps uploads and sessions there (without them, on Windows, it fell back to the Windows folder).
var cgiTempVariables = []string{"TMPDIR", "TEMP", "TMP"}

// cgiResponseWriter is what a CGI's answer is written to. How the response is framed is the server's: the
// hop-by-hop headers a CGI may write (Transfer-Encoding, Connection and the like) are dropped, and so is a
// Content-Length given more than once, which would leave the client, or a proxy, unable to tell where the
// response ends, and a header value with control characters, which would make it unreadable.
type cgiResponseWriter struct {
	customNetHttp.ResponseWriter
}

// cgiHopByHopHeaders are the headers about the connection, not the content, that a CGI can't set.
var cgiHopByHopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Transfer-Encoding", "Upgrade"}

func (w cgiResponseWriter) WriteHeader(code int) {
	header := w.Header()
	for _, name := range cgiHopByHopHeaders {
		header.Del(name)
	}
	if lengths := header.Values("Content-Length"); len(lengths) > 1 || len(lengths) == 1 && !onlyDigits(lengths[0]) {
		header.Del("Content-Length") // Go takes "+4" or "-0" as a number, but would send it as written
	}
	for name, values := range header {
		kept := values[:0]
		for _, value := range values {
			if headerValueAllowed(value) {
				kept = append(kept, value)
			}
		}
		if len(kept) == 0 {
			delete(header, name)
		} else {
			header[name] = kept
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets NewResponseController reach the server's ResponseWriter.
func (w cgiResponseWriter) Unwrap() customNetHttp.ResponseWriter {
	return w.ResponseWriter
}

// cgiBodyMemory is how much of a request body is kept in memory for a CGI, at most (and within cgiBodyBudget); a
// longer one goes to a temporary file.
const cgiBodyMemory = 1 << 20

// cgiFileBody is a body kept in a temporary file, as the CGI gets it: not an *os.File, so that exec hands it over
// through a pipe. The CGI, and what it starts, never inherit the file, which on Windows couldn't be removed while
// one of them kept it open. Closing it is cleanup's.
type cgiFileBody struct{ io.Reader }

func (cgiFileBody) Close() error { return nil }

// cgiBodyFileError is a temporary file for a request body that couldn't be created or written: the server's
// problem (500), not the client's.
type cgiBodyFileError struct{ err error }

func (e cgiBodyFileError) Error() string {
	return "the temporary file of a request body: " + e.err.Error()
}

// cgiBodyBudget is how much of the request bodies of the CGIs may be in memory at once, all of them: the rest go to
// temporary files. Each body was read whole into memory, up to cgiBodyMemory, before its CGI got a slot, and kept
// there while it waited for one and while it ran, with nothing that bounded how many there were. A variable, so that
// tests can lower it.
var cgiBodyBudget int64 = 32 << 20

// cgiBodyInUse is what the request bodies of the CGIs take in memory.
var cgiBodyInUse atomic.Int64

// cgiBodyFilesInUse is what the request bodies of the CGIs take in temporary files, all of them, and
// cgiBodyFileBudgetMin the least they may take: the budget is that or, if more, sixteen bodies of MBB
// (cgiBodyFileBudget). Each body is bounded by MBB, but nothing bounded how many were on disk at once (in memory,
// where /tmp is a tmpfs): beyond the budget a request gets 503, as when no CGI slot is free. A variable, so that
// tests can lower it.
var (
	cgiBodyFilesInUse    atomic.Int64
	cgiBodyFileBudgetMin int64 = 1 << 30
)

// cgiBodyFileBudget is how much the request bodies of the CGIs may take in temporary files at once.
func cgiBodyFileBudget() int64 {
	return max(cgiBodyFileBudgetMin, 16*maxBodySize.Load())
}

// errCGIBodyFilesFull is the error of a request body that doesn't fit in the budget of the temporary files.
var errCGIBodyFilesFull = errors.New("the temporary files of the request bodies are full")

// reserveBodyMemory takes size bytes of cgiBodyBudget, if they fit.
func reserveBodyMemory(size int64) bool {
	for {
		used := cgiBodyInUse.Load()
		if used+size > cgiBodyBudget {
			return false
		}
		if cgiBodyInUse.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

// bufferedRequestBody reads a request body, already bounded by MBB, before the CGI starts, so that the CGI gets
// CONTENT_LENGTH and doesn't wait for the client: in memory up to cgiBodyMemory, while cgiBodyBudget allows it, and in
// a temporary file beyond. expected is the length the request gives (Content-Length), or -1. cleanup gives back the
// memory, or closes that file, which deletes it (it has no name).
func bufferedRequestBody(body io.Reader, expected int64) (io.ReadCloser, int64, func(), error) {
	var memory []byte
	var reserved int64
	release := func() {
		cgiBodyInUse.Add(-reserved)
		reserved = 0
	}
	// In blocks taken from the budget: the first as long as the request says (and one byte more, to see its end), or
	// 32 KiB, and then twice as long each time. A body longer than cgiBodyMemory goes straight to the file.
	block := int64(32 << 10)
	if expected >= 0 {
		block = expected + 1
	}
	for expected <= cgiBodyMemory && int64(len(memory)) <= cgiBodyMemory {
		grow := min(block, cgiBodyMemory+1-int64(len(memory)))
		if !reserveBodyMemory(grow) { // The bodies of the other requests take the budget: the file
			break
		}
		reserved += grow
		grown := make([]byte, len(memory), int64(len(memory))+grow)
		copy(grown, memory)
		n, err := io.ReadFull(body, grown[len(memory):cap(grown)])
		memory = grown[:len(memory)+n]
		if err == io.EOF || err == io.ErrUnexpectedEOF { // All of it
			return io.NopCloser(bytes.NewReader(memory)), int64(len(memory)), release, nil
		}
		if err != nil {
			release()
			return nil, 0, nil, err
		}
		block *= 2
	}
	file, err := openCGITempFile("turbo-cgi-*")
	if err != nil {
		release()
		return nil, 0, nil, cgiBodyFileError{err}
	}
	writer := &cgiBodyWriter{file: file}
	cleanup := func() {
		_ = file.Close()
		cgiBodyFilesInUse.Add(-writer.reserved) // What it took of the budget of the files, once it is gone
		writer.reserved = 0
	}
	size, err := io.Copy(writer, io.MultiReader(bytes.NewReader(memory), body))
	release() // In the file now
	if err == nil {
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			err = cgiBodyFileError{err}
		}
	}
	if err != nil {
		cleanup()
		return nil, 0, nil, err
	}
	return cgiFileBody{file}, size, cleanup, nil
}

// cgiBodyWriter writes a request body to its temporary file, telling the file's errors (cgiBodyFileError) from those
// of reading the body, and takes what it writes from the budget of the files (cgiBodyFileBudget): reserved is what
// it took, given back when the file is closed.
type cgiBodyWriter struct {
	file     *os.File
	reserved int64
}

func (w *cgiBodyWriter) Write(p []byte) (int, error) {
	size := int64(len(p))
	if cgiBodyFilesInUse.Add(size) > cgiBodyFileBudget() {
		cgiBodyFilesInUse.Add(-size)
		return 0, errCGIBodyFilesFull
	}
	w.reserved += size
	n, err := w.file.Write(p)
	if err != nil {
		err = cgiBodyFileError{err}
	}
	return n, err
}

// cgiSlotWait is how long a CGI request waits for a free slot before getting 503.
const cgiSlotWait = 2 * time.Second

// cgiSlots counts the CGI processes running, and the outputs of CGIs not delivered yet; freed is closed (and
// replaced) each time one of them ends.
var cgiSlots struct {
	mutex   sync.Mutex
	running int64
	outputs int64 // From newCGIOutput to its end: the shutdown waits for them too, with their temporary files
	freed   chan struct{}
}

// cgiSlotsFreedLocked wakes those that wait for a slot, or for the CGIs and their outputs to end. Callers hold
// cgiSlots.mutex.
func cgiSlotsFreedLocked() {
	if cgiSlots.freed != nil {
		close(cgiSlots.freed)
		cgiSlots.freed = nil
	}
}

// cgiProcessLimit is how many CGI processes may run at a time: CGP, or max(16, 4 × CPUs) with CGP at 0.
func cgiProcessLimit() int64 {
	if limit := cgiProcesses.Load(); limit > 0 {
		return limit
	}
	return max(16, 4*int64(runtime.NumCPU()))
}

// acquireCGISlot takes a CGI slot, waiting up to wait for one; it reports whether it got it.
func acquireCGISlot(wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		cgiSlots.mutex.Lock()
		if cgiSlots.running < cgiProcessLimit() {
			cgiSlots.running++
			cgiSlots.mutex.Unlock()
			return true
		}
		if cgiSlots.freed == nil {
			cgiSlots.freed = make(chan struct{})
		}
		freed := cgiSlots.freed
		cgiSlots.mutex.Unlock()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		timer := time.NewTimer(remaining)
		select {
		case <-freed:
			timer.Stop()
		case <-timer.C:
			return false
		}
	}
}

// releaseCGISlot gives back the slot of a CGI that ended.
func releaseCGISlot() {
	cgiSlots.mutex.Lock()
	defer cgiSlots.mutex.Unlock()
	cgiSlots.running--
	cgiSlotsFreedLocked()
}

// withoutSessionCookie removes the panel session cookie from the request, so a CGI never receives it. Only that
// pair is cut from the raw header: the other cookies reach the CGI exactly as the browser sent them.
func withoutSessionCookie(request *customNetHttp.Request) {
	var kept []string
	removed := false
	for _, value := range request.Header["Cookie"] {
		var pairs []string
		for _, pair := range strings.Split(value, ";") {
			if name, _, _ := strings.Cut(pair, "="); strings.TrimSpace(name) == sessionCookieName || strings.TrimSpace(name) == sessionCookieNameTLS {
				removed = true
				continue
			}
			pairs = append(pairs, pair)
		}
		if len(pairs) > 0 {
			kept = append(kept, strings.TrimLeft(strings.Join(pairs, ";"), " "))
		}
	}
	if !removed {
		return
	}
	if len(kept) == 0 {
		request.Header.Del("Cookie")
	} else {
		request.Header["Cookie"] = kept
	}
}
