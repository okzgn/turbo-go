package main

// V1, V6, V17 and V18 (production review of 775a809): the output of a CGI that waits for its client.
// - V1: the temporary file of a response stays within its limit on disk (it grew with everything the CGI wrote while
//   the limits counted only what wasn't sent), and so do the files of all of them.
// - V17: the memory of a response counts what the sender has taken and not yet written.
// - V6: a client (an IPv4 address or an IPv6 /64) may take a quarter of each budget and a /48 half, and only a quarter
//   of the CGI slots may wait for one client's responses (a half for a /48): beyond, the response is cut and its CGI
//   ended. Before, the clients of one address that didn't read filled the budgets and then held every slot.
// - V18: a cut response frees its slot at once, not after the sender gives up on its client.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"turbo/customNetHttp"
)

// withCGIOutputLimits lowers the limits of the outputs started during the test.
func withCGIOutputLimits(t *testing.T, limits cgiOutputLimitSet) {
	t.Helper()
	cgiOutputSharesMutex.Lock()
	previous := cgiOutputLimits
	cgiOutputLimits = limits
	cgiOutputSharesMutex.Unlock()
	t.Cleanup(func() {
		cgiOutputSharesMutex.Lock()
		cgiOutputLimits = previous
		cgiOutputSharesMutex.Unlock()
	})
}

// checkCGIOutputsEnded fails if, once the responses ended, anything is still counted.
func checkCGIOutputsEnded(t *testing.T) {
	t.Helper()
	counters := func() (memory, files int64, clients int) {
		cgiOutputSharesMutex.Lock()
		defer cgiOutputSharesMutex.Unlock()
		return cgiOutputInUse.Load(), cgiOutputFilesInUse.Load(), len(cgiOutputShares)
	}
	if !eventually(5*time.Second, func() bool { memory, files, clients := counters(); return memory == 0 && files == 0 && clients == 0 }) {
		memory, files, clients := counters()
		t.Errorf("after the responses: %d bytes counted in memory, %d in files and %d clients; expected none", memory, files, clients)
	}
}

// shareOf is what the responses of a client (or network) take and how many wait.
func shareOf(key string) cgiOutputShare {
	cgiOutputSharesMutex.Lock()
	defer cgiOutputSharesMutex.Unlock()
	if share := cgiOutputShares[key]; share != nil {
		return *share
	}
	return cgiOutputShare{}
}

// testClientWriter is a client's ResponseWriter that keeps what it gets; each write waits for gate, when there is
// one, and takes delay.
type testClientWriter struct {
	header  customNetHttp.Header
	gate    chan struct{}
	delay   time.Duration
	entered chan struct{} // Closed when the first write comes
	once    sync.Once
	mutex   sync.Mutex
	got     bytes.Buffer
}

func newTestClientWriter(gate chan struct{}, delay time.Duration) *testClientWriter {
	return &testClientWriter{header: customNetHttp.Header{}, gate: gate, delay: delay, entered: make(chan struct{})}
}

func (w *testClientWriter) Header() customNetHttp.Header { return w.header }
func (w *testClientWriter) WriteHeader(int)              {}
func (w *testClientWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	if w.gate != nil {
		<-w.gate
	}
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.got.Write(p)
}

func (w *testClientWriter) received() []byte {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return bytes.Clone(w.got.Bytes())
}

// waitsForClient is whether the CGI of output has had to wait for its client.
func waitsForClient(output *cgiOutput) bool {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return output.waiting
}

func TestRP2_V1_FileNeverExceedsItsLimit(t *testing.T) {
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 64 << 20, fileMax: 1 << 20, fileBudget: 1 << 30})
	client := newTestClientWriter(nil, 200*time.Microsecond) // Slower than the CGI
	output := newCGIOutput(client, "192.0.2.10", nil)
	var written bytes.Buffer
	chunk := make([]byte, 16<<10) // What the CGI host writes at a time
	for i := 0; written.Len() < 16<<20; i++ {
		for j := range chunk {
			chunk[j] = byte('a' + (i+j)%26)
		}
		if _, err := output.Write(chunk); err != nil {
			t.Fatal(err)
		}
		written.Write(chunk)
		output.mutex.Lock()
		size, onDisk := output.fileWritten, int64(0)
		if output.file != nil {
			if info, err := output.file.Stat(); err == nil {
				onDisk = info.Size()
			}
		}
		output.mutex.Unlock()
		if size > 1<<20 || onDisk > 1<<20 {
			t.Fatalf("after %d KiB: the temporary file holds %d bytes (%d on disk); its limit is 1 MiB", written.Len()>>10, size, onDisk)
		}
		if files := cgiOutputFilesInUse.Load(); files > 1<<20 {
			t.Fatalf("after %d KiB: %d bytes counted in files; the limit of the response is 1 MiB", written.Len()>>10, files)
		}
	}
	output.finish()
	if !bytes.Equal(client.received(), written.Bytes()) {
		t.Errorf("the client got %d bytes, changed or out of order; expected the %d the CGI wrote", len(client.received()), written.Len())
	}
	checkCGIOutputsEnded(t)
}

func TestRP2_V17_MemoryOfEachResponse(t *testing.T) {
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 64 << 20})
	gate := make(chan struct{})
	client := newTestClientWriter(gate, 0) // It takes nothing until the gate opens
	output := newCGIOutput(client, "192.0.2.11", nil)
	chunk := bytes.Repeat([]byte("m"), 16<<10)
	if _, err := output.Write(chunk); err != nil {
		t.Fatal(err)
	}
	<-client.entered // The sender has taken the first chunk and waits for the client: it still counts
	wrote := make(chan error, 1)
	go func() {
		var err error
		for i := 1; i < 16 && err == nil; i++ {
			_, err = output.Write(chunk)
		}
		wrote <- err
	}()
	if !eventually(3*time.Second, func() bool { return waitsForClient(output) }) {
		close(gate)
		t.Fatal("the CGI never waited for its client")
	}
	time.Sleep(100 * time.Millisecond)
	if memory := cgiOutputInUse.Load(); memory > 64<<10 {
		t.Errorf("a response whose client takes nothing holds %d bytes in memory; its limit is 64 KiB", memory)
	}
	close(gate)
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	output.finish()
	if got := len(client.received()); got != 16*16<<10 {
		t.Errorf("the client got %d bytes; expected %d", got, 16*16<<10)
	}
	checkCGIOutputsEnded(t)
}

func TestRP2_V6_ClientShares(t *testing.T) {
	// A client may take a quarter of each budget: 64 KiB of memory and 512 KiB of files here.
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 256 << 10, fileMax: 1 << 20, fileBudget: 2 << 20})
	gate := make(chan struct{})
	var outputs []*cgiOutput
	var writers sync.WaitGroup
	for i := 0; i < 3; i++ { // Three responses of a client that reads nothing, of 2 MiB each
		output := newCGIOutput(newTestClientWriter(gate, 0), "192.0.2.21", nil)
		outputs = append(outputs, output)
		writers.Add(1)
		go func() {
			defer writers.Done()
			chunk := make([]byte, 16<<10)
			for written := 0; written < 2<<20; written += len(chunk) {
				if _, err := output.Write(chunk); err != nil {
					return
				}
			}
		}()
	}
	if !eventually(5*time.Second, func() bool { return shareOf("192.0.2.21").waiting == 3 }) {
		close(gate)
		t.Fatalf("the three CGIs of the client don't wait: %+v", shareOf("192.0.2.21"))
	}
	if share := shareOf("192.0.2.21"); share.files > 512<<10 || share.memory > 64<<10+3*16<<10 {
		t.Errorf("a client takes %d bytes of memory and %d of files; its quarter is 64 KiB and 512 KiB (and one chunk per response)", share.memory, share.files)
	}
	// Another client goes on with its own quarter: its CGI doesn't wait for the first one's client.
	other := newCGIOutput(newTestClientWriter(gate, 0), "192.0.2.22", nil)
	done := make(chan error, 1)
	go func() {
		chunk := make([]byte, 16<<10)
		var err error
		for written := 0; written < 512<<10 && err == nil; written += len(chunk) {
			_, err = other.Write(chunk)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(3 * time.Second):
		t.Error("another client's CGI waits while the first client holds the budgets")
	}
	close(gate)
	writers.Wait()
	for _, output := range append(outputs, other) {
		output.finish()
	}
	checkCGIOutputsEnded(t)
}

func TestRP2_V6_WaitingLimit(t *testing.T) {
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(4) // One CGI may wait per client, and two per /48
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 16 << 10, budget: 1 << 20}) // No temporary file
	gate := make(chan struct{})
	type response struct {
		output   *cgiOutput
		err      chan error
		canceled *atomic.Bool
	}
	start := func(ip string) response {
		canceled := &atomic.Bool{}
		output := newCGIOutput(newTestClientWriter(gate, 0), ip, func() { canceled.Store(true) })
		errs := make(chan error, 1)
		go func() {
			chunk := make([]byte, 16<<10)
			var err error
			for i := 0; i < 2 && err == nil; i++ {
				_, err = output.Write(chunk)
			}
			errs <- err
		}()
		return response{output, errs, canceled}
	}
	waits := func(name string, r response) {
		t.Helper()
		if !eventually(3*time.Second, func() bool { return waitsForClient(r.output) }) {
			t.Errorf("%s: its CGI doesn't wait for its client", name)
		}
	}
	cut := func(name string, r response) {
		t.Helper()
		select {
		case err := <-r.err:
			if !errors.Is(err, errCGIOutputWaitLimit) || !r.canceled.Load() {
				t.Errorf("%s: %v (CGI ended: %v); expected the response cut and its CGI ended", name, err, r.canceled.Load())
			}
		case <-time.After(3 * time.Second):
			t.Errorf("%s: its CGI waits; expected the response cut", name)
		}
	}
	a1 := start("192.0.2.31")
	waits("the first CGI of a client", a1)
	a2 := start("192.0.2.31")
	cut("a second CGI of the same client", a2)
	b1 := start("192.0.2.32")
	waits("another client's CGI", b1)
	c1 := start("2001:db8:1:1::1")
	waits("the CGI of a /64", c1)
	c2 := start("2001:db8:1:2::1")
	waits("the CGI of another /64 of the same /48", c2)
	c3 := start("2001:db8:1:3::1")
	cut("a third /64 of that /48", c3)
	close(gate)
	for _, r := range []response{a1, b1, c1, c2} {
		if err := <-r.err; err != nil {
			t.Error(err)
		}
	}
	for _, r := range []response{a1, a2, b1, c1, c2, c3} {
		r.output.finish()
	}
	checkCGIOutputsEnded(t)
}

// End to end: the CGIs of one client that reads nothing can't hold every slot; another client, and other requests,
// get theirs.
func TestRP2_V6_ClientCannotHoldAllSlots(t *testing.T) {
	slowClientsSetup(t)
	base := startServer(t)
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(4) // One CGI may wait per client
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 64 << 20}) // No temporary file
	withGlobalLock(func() { setTimeLimits(func(l *customNetHttp.Timeouts) { l.WT = 10 * time.Second }) })
	address := strings.TrimPrefix(base, "http://")
	var connections []net.Conn
	t.Cleanup(func() {
		for _, conn := range connections {
			conn.Close()
		}
	})
	open := func(local string) {
		t.Helper()
		dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(local)}}
		conn, err := dialer.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		conn.(*net.TCPConn).SetReadBuffer(4096)
		connections = append(connections, conn)
		fmt.Fprintf(conn, "GET /x.cgi?big=%d HTTP/1.1\r\nHost: localhost\r\n\r\n", 16<<20) // And never read
	}
	for i := 0; i < 3; i++ {
		open("127.0.0.1")
	}
	time.Sleep(time.Second)
	if !eventually(5*time.Second, func() bool { return cgiSlotsRunning() == 1 && shareOf("127.0.0.1").waiting == 1 }) {
		t.Fatalf("three CGIs of a client that reads nothing: %d slots taken; expected 1 (the others cut)", cgiSlotsRunning())
	}
	open("127.0.0.2")
	if !eventually(5*time.Second, func() bool { return cgiSlotsRunning() == 2 }) {
		t.Errorf("another client's CGI: %d slots taken; expected 2", cgiSlotsRunning())
	}
	if code, body, err := get(base, "/x.cgi", nil); err != nil || code != 200 || !strings.Contains(body, "SCRIPT_FILENAME=") {
		t.Errorf("another request meanwhile: %d %.80q %v; expected its CGI to run", code, body, err)
	}
}

// V18: a response cut when WT runs out (its CGI keeps running after writing) frees its slot when the CGI ends, while
// the sender still waits for a client that reads nothing until WT + 2 s.
func TestRP2_V18_CutResponseFreesItsSlot(t *testing.T) {
	slowClientsSetup(t)
	base := startServer(t)
	withGlobalLock(func() { setTimeLimits(func(l *customNetHttp.Timeouts) { l.WT = time.Second }) })
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetReadBuffer(4096)
	fmt.Fprintf(conn, "GET /x.cgi?big=%d&after=10000 HTTP/1.1\r\nHost: localhost\r\n\r\n", 4<<20) // And never read
	if !eventually(3*time.Second, func() bool { return cgiSlotsRunning() == 1 }) {
		t.Fatal("the CGI didn't start")
	}
	start := time.Now()
	// Its CGI ends at WT, 1 s after it started; the sender gives up on the client at WT + 2 s.
	if !eventually(1600*time.Millisecond, func() bool { return cgiSlotsRunning() == 0 }) {
		t.Errorf("%v after the CGI started: the slot of a response cut at WT (1 s) is still taken; expected it free when its CGI ended", time.Since(start).Round(100*time.Millisecond))
	}
}
