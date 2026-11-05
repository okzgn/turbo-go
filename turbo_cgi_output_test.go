package main

// V1, V6, V17 and V18 (production review of 775a809): the output of a CGI that waits for its client.
// - V1: the temporary file of a response stays within its limit on disk (it grew with everything the CGI wrote while
//   the limits counted only what wasn't sent), and so do the files of all of them.
// - V17: the memory of a response counts what the sender has taken and not yet written.
// - V6: a client (an IPv4 address or an IPv6 /64) may take a quarter of each budget and a /48 half, and only a quarter
//   of the CGI slots may wait for one client's responses (a half for a /48): beyond, the response is cut and its CGI
//   ended. Before, the clients of one address that didn't read filled the budgets and then held every slot.
// - V18: a cut response frees its slot at once, not after the sender gives up on its client.
// And, in v2.4.2, the output waits in temporary files of an eighth of the limit of a response each, removed as soon
// as they are sent (TestRP3_*).

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// withWT sets the write time limit (WT) for the test.
func withWT(t *testing.T, wt time.Duration) {
	t.Helper()
	previous := *serverTimeLimits.Load()
	t.Cleanup(func() { withGlobalLock(func() { setTimeLimits(func(l *customNetHttp.Timeouts) { *l = previous }) }) })
	withGlobalLock(func() { setTimeLimits(func(l *customNetHttp.Timeouts) { l.WT = wt }) })
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

// withCGIOutputTemp has the temporary files of the outputs go to a folder of the test, which it returns.
func withCGIOutputTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(name, dir)
	}
	return dir
}

// cgiOutputTempFiles are the sizes of the temporary files of the outputs in dir.
func cgiOutputTempFiles(t *testing.T, dir string) []int64 {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "turbo-cgi-output-*"))
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int64
	for _, name := range names {
		if info, err := os.Stat(name); err == nil {
			sizes = append(sizes, info.Size())
		}
	}
	return sizes
}

// fillChunk fills chunk with a pattern of its position in the output, so that a part sent twice, lost or out of
// order shows.
func fillChunk(chunk []byte, position int) {
	for j := range chunk {
		chunk[j] = byte('a' + (position+j)%26)
	}
}

func TestRP2_V1_FileNeverExceedsItsLimit(t *testing.T) {
	temp := withCGIOutputTemp(t)
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 64 << 20, fileMax: 1 << 20, fileBudget: 1 << 30})
	client := newTestClientWriter(nil, 200*time.Microsecond) // Slower than the CGI
	output := newCGIOutput(client, "192.0.2.10", nil)
	t.Cleanup(output.finish) // Also when the test fails: finish can run twice
	var written bytes.Buffer
	chunk := make([]byte, 16<<10) // What the CGI host writes at a time
	for i := 0; written.Len() < 16<<20; i++ {
		fillChunk(chunk, i)
		if _, err := output.Write(chunk); err != nil {
			t.Fatal(err)
		}
		written.Write(chunk)
		output.mutex.Lock()
		size, onDisk, files := output.onDiskLocked(), int64(0), len(output.segments)
		for _, segment := range output.segments {
			if info, err := segment.file.Stat(); err == nil {
				onDisk += info.Size()
			}
		}
		output.mutex.Unlock()
		if size > 1<<20 || onDisk > 1<<20 {
			t.Fatalf("after %d KiB: the temporary files hold %d bytes (%d on disk); the limit of the response is 1 MiB", written.Len()>>10, size, onDisk)
		}
		if files > 9 { // Files of 128 KiB, each with more than 112 KiB but the last, and the one being sent
			t.Fatalf("after %d KiB: %d temporary files; expected 9 at most", written.Len()>>10, files)
		}
		if counted := cgiOutputFilesInUse.Load(); counted > 1<<20 {
			t.Fatalf("after %d KiB: %d bytes counted in files; the limit of the response is 1 MiB", written.Len()>>10, counted)
		}
	}
	output.finish()
	if !bytes.Equal(client.received(), written.Bytes()) {
		t.Errorf("the client got %d bytes, changed or out of order; expected the %d the CGI wrote", len(client.received()), written.Len())
	}
	checkCGIOutputsEnded(t)
	if left := cgiOutputTempFiles(t, temp); len(left) != 0 {
		t.Errorf("temporary files left after the response: %v", left)
	}
}

// v2.4.2: the output waits in temporary files of an eighth of the limit of a response each, and one that its client
// has taken whole is removed, and given back, at once: what was sent never takes more than one of them. The single
// file was emptied only once its client had taken all of it, so with a client almost as fast as its CGI it held, on
// disk and in the budgets, everything already sent, up to the limit of the response, where the CGI then waited.
func TestRP3_SentOutputReleased(t *testing.T) {
	temp := withCGIOutputTemp(t)
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 16 << 10, budget: 64 << 20, fileMax: 1 << 20, fileBudget: 1 << 30}) // Files of 128 KiB
	client := &tokenClientWriter{header: customNetHttp.Header{}, gate: make(chan struct{})}
	output := newCGIOutput(client, "192.0.2.41", nil)
	var opened sync.Once
	end := func() { // All of it through to the client, and the response ended (also when the test fails)
		opened.Do(func() { close(client.gate) })
		output.finish()
	}
	t.Cleanup(end)
	received := func() int64 {
		client.mutex.Lock()
		defer client.mutex.Unlock()
		return int64(client.got.Len())
	}
	var written bytes.Buffer
	chunk := make([]byte, 16<<10)
	for i := 0; i < 160; i++ {
		fillChunk(chunk, i)
		if _, err := output.Write(chunk); err != nil {
			t.Fatal(err)
		}
		written.Write(chunk)
		if i%5 == 4 { // The client takes two writes of the sender (64 KiB at most) every five of the CGI (80 KiB)
			for range 2 {
				select {
				case client.gate <- struct{}{}:
				case <-time.After(5 * time.Second):
					t.Fatal("the sender doesn't write to its client")
				}
			}
		}
		got := received() // First what the client got, and then what the files take: both only grow
		files := shareOf("192.0.2.41").files
		if limit := int64(written.Len()) - got + 128<<10 + 16<<10; files > limit {
			t.Errorf("after %d KiB written and %d KiB sent: the temporary files take %d KiB; expected %d KiB at most (what wasn't sent, and one file)", written.Len()>>10, got>>10, files>>10, limit>>10)
			break
		}
	}
	for deadline := time.Now().Add(5 * time.Second); received() < int64(written.Len()); { // The client takes the rest
		if time.Now().After(deadline) {
			t.Fatalf("the client got %d of %d bytes: the sender doesn't write the rest", received(), written.Len())
		}
		select {
		case client.gate <- struct{}{}: // One more write of the sender
		case <-time.After(10 * time.Millisecond): // Or the client is still taking the last one
		}
	}
	if !eventually(3*time.Second, func() bool { return shareOf("192.0.2.41").files == 0 }) {
		t.Errorf("with all of it sent, the temporary files take %d bytes; expected none", shareOf("192.0.2.41").files)
	}
	if left := cgiOutputTempFiles(t, temp); len(left) != 1 || left[0] != 0 {
		t.Errorf("with all of it sent, temporary files of %v bytes; expected one, empty, to go on with", left)
	}
	end()
	if !bytes.Equal(client.received(), written.Bytes()) {
		t.Errorf("the client got %d bytes, changed or out of order; expected the %d the CGI wrote", len(client.received()), written.Len())
	}
	checkCGIOutputsEnded(t)
	if left := cgiOutputTempFiles(t, temp); len(left) != 0 {
		t.Errorf("temporary files left after the response: %v", left)
	}
}

// v2.4.2: when a new temporary file can't be created, the output goes on in the one it has, as a single file, and the
// CGI doesn't wait for its client for that.
func TestRP3_OutputGoesOnWhenNoNewFile(t *testing.T) {
	temp := withCGIOutputTemp(t)
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 16 << 10, budget: 64 << 20, fileMax: 1 << 20, fileBudget: 1 << 30}) // Files of 128 KiB
	gate := make(chan struct{})
	client := newTestClientWriter(gate, 0) // It takes nothing until the gate opens
	output := newCGIOutput(client, "192.0.2.42", nil)
	var opened sync.Once
	open := func() { opened.Do(func() { close(gate) }) }
	t.Cleanup(func() { open(); output.finish() }) // Also when the test fails
	var written bytes.Buffer
	chunk := make([]byte, 16<<10)
	write := func(i int) error {
		fillChunk(chunk, i)
		done := make(chan error, 1)
		go func() { _, err := output.Write(chunk); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				written.Write(chunk)
			}
			return err
		case <-time.After(3 * time.Second):
			open()
			<-done
			return errors.New("the CGI waits for its client")
		}
	}
	for i := 0; i < 9; i++ { // One in memory and 128 KiB in the first file, full
		if err := write(i); err != nil {
			t.Fatal(err)
		}
	}
	missing := filepath.Join(temp, "missing")
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		t.Setenv(name, missing)
	}
	if err := write(9); err != nil {
		t.Fatalf("a write that needs a new temporary file, which can't be created: %v; expected it in the file there is", err)
	}
	output.mutex.Lock()
	var sizes []int64
	for _, segment := range output.segments {
		sizes = append(sizes, segment.written)
	}
	output.mutex.Unlock()
	if len(sizes) != 1 || sizes[0] != 144<<10 {
		t.Errorf("temporary files of %v bytes; expected one of 144 KiB", sizes)
	}
	open()
	output.finish()
	if !bytes.Equal(client.received(), written.Bytes()) {
		t.Errorf("the client got %d bytes, changed or out of order; expected the %d the CGI wrote", len(client.received()), written.Len())
	}
	checkCGIOutputsEnded(t)
	if left := cgiOutputTempFiles(t, temp); len(left) != 0 {
		t.Errorf("temporary files left after the response: %v", left)
	}
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
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(16) // Four CGIs may wait per client: the three below
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
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
// get theirs. The other client is a server of the same Turbo that sees its connections as coming from 127.0.0.2:
// macOS has no 127.0.0.2 to connect from.
func TestRP2_V6_ClientCannotHoldAllSlots(t *testing.T) {
	slowClientsSetup(t)
	base := startServer(t)
	other, _ := startServerAs(t, func() net.IP { return net.ParseIP("127.0.0.2") })
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(4) // One CGI may wait per client
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 64 << 20}) // No temporary file
	withWT(t, 10*time.Second)
	var connections []net.Conn
	t.Cleanup(func() {
		for _, conn := range connections {
			conn.Close()
		}
	})
	open := func(server string) {
		t.Helper()
		conn, err := net.Dial("tcp", strings.TrimPrefix(server, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		conn.(*net.TCPConn).SetReadBuffer(4096)
		connections = append(connections, conn)
		fmt.Fprintf(conn, "GET /x.cgi?big=%d HTTP/1.1\r\nHost: localhost\r\n\r\n", 16<<20) // And never read
	}
	for i := 0; i < 3; i++ {
		open(base)
	}
	time.Sleep(time.Second)
	if !eventually(5*time.Second, func() bool { return cgiSlotsRunning() == 1 && shareOf("127.0.0.1").waiting == 1 }) {
		t.Fatalf("three CGIs of a client that reads nothing: %d slots taken; expected 1 (the others cut)", cgiSlotsRunning())
	}
	open(other)
	if !eventually(5*time.Second, func() bool { return cgiSlotsRunning() == 2 && shareOf("127.0.0.2").waiting == 1 }) {
		t.Errorf("another client's CGI: %d slots taken, %d of them waiting for that client; expected 2 and 1", cgiSlotsRunning(), shareOf("127.0.0.2").waiting)
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
	withWT(t, time.Second)
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

// tokenClientWriter is a client's ResponseWriter that lets one write through for each token sent on gate.
type tokenClientWriter struct {
	header customNetHttp.Header
	gate   chan struct{}
	mutex  sync.Mutex
	got    bytes.Buffer
}

func (w *tokenClientWriter) Header() customNetHttp.Header { return w.header }
func (w *tokenClientWriter) WriteHeader(int)              {}
func (w *tokenClientWriter) Write(p []byte) (int, error) {
	<-w.gate
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.got.Write(p)
}

func (w *tokenClientWriter) received() []byte {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return bytes.Clone(w.got.Bytes())
}

// V6, after the independent review: a response whose CGI has ended no longer counts among those that wait for their
// client, while the rest of its output reaches it. It counted until all of it was sent, and the next response of
// that client that had to wait was cut, although no CGI of that client waited.
func TestRP2_V6_EndedCGINoLongerWaits(t *testing.T) {
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(4) // One CGI may wait per client
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 16 << 10, budget: 1 << 20}) // No temporary file
	gateA := make(chan struct{})
	a := newCGIOutput(&tokenClientWriter{header: customNetHttp.Header{}, gate: gateA}, "192.0.2.77", nil)
	chunk := make([]byte, 16<<10)
	if _, err := a.Write(chunk); err != nil { // The sender takes it and waits for the client
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() { _, err := a.Write(chunk); wrote <- err }() // Its CGI has to wait for the client
	if !eventually(3*time.Second, func() bool { return waitsForClient(a) }) {
		t.Fatal("the CGI of A never waited")
	}
	gateA <- struct{}{} // The client takes the first chunk: the CGI of A writes its last one and ends
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() { a.finish(); close(finished) }() // As dynamic does once the CGI ended: the rest waits for the client
	if !eventually(3*time.Second, func() bool { return shareOf("192.0.2.77").waiting == 0 }) {
		t.Errorf("the CGI of A ended, and its client still has %d CGIs waiting", shareOf("192.0.2.77").waiting)
	}
	gateB := make(chan struct{})
	b := newCGIOutput(&tokenClientWriter{header: customNetHttp.Header{}, gate: gateB}, "192.0.2.77", func() {})
	if _, err := b.Write(chunk); err != nil {
		t.Fatal(err)
	}
	errB := make(chan error, 1)
	go func() { _, err := b.Write(chunk); errB <- err }()
	answered := false
	select {
	case err := <-errB:
		answered = true
		if errors.Is(err, errCGIOutputWaitLimit) {
			t.Errorf("B was cut (%v) although no CGI of its client waits", err)
		}
	case <-time.After(500 * time.Millisecond): // B waits for its client
	}
	close(gateA)
	close(gateB)
	<-finished
	if !answered {
		<-errB
	}
	b.finish()
	checkCGIOutputsEnded(t)
}

// V6, after the independent review: when the budget is full because of other clients (here, as if they had filled
// it), a client whose responses are within their limits and its share goes on as it reads, a chunk at a time, and
// none of its responses is cut, however many there are. Every response that had to wait counted, and those of a
// client that read at once were cut beyond a quarter of the slots.
func TestRP2_V6_FullBudgetCutsNoOne(t *testing.T) {
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(4) // One CGI may wait per client
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 1 << 20}) // No temporary file
	cgiOutputSharesMutex.Lock()
	cgiOutputInUse.Add(1 << 20) // Taken by other clients
	cgiOutputSharesMutex.Unlock()
	t.Cleanup(func() {
		cgiOutputSharesMutex.Lock()
		cgiOutputInUse.Add(-1 << 20)
		cgiOutputSharesMutex.Unlock()
	})
	chunk := make([]byte, 16<<10)
	results := make(chan error, 3)
	var outputs []*cgiOutput
	for i := 0; i < 3; i++ { // More than the one CGI that may wait for this client
		output := newCGIOutput(newTestClientWriter(nil, 2*time.Millisecond), "192.0.2.88", func() {})
		outputs = append(outputs, output)
		go func() {
			var err error
			for j := 0; j < 8 && err == nil; j++ {
				_, err = output.Write(chunk)
			}
			results <- err
		}()
	}
	for i := 0; i < 3; i++ {
		if err := <-results; err != nil {
			t.Errorf("a response of a client that reads at once, with the budget full because of others: %v", err)
		}
	}
	for _, output := range outputs {
		output.finish()
	}
	if !eventually(5*time.Second, func() bool { return cgiOutputInUse.Load() == 1<<20 }) {
		t.Errorf("after the responses: %d bytes counted in memory; expected only the others'", cgiOutputInUse.Load()-1<<20)
	}
}

// V18, after the independent review: a CGI that waits in Write for a client that reads nothing when WT runs out is
// ended by P12, and its slot is freed then; it stayed taken until the sender's write deadline, WT + 2 s.
func TestRP2_V18_CGIEndedWhileWaitingFreesItsSlot(t *testing.T) {
	slowClientsSetup(t)
	base := startServer(t)
	withCGIOutputLimits(t, cgiOutputLimitSet{memory: 64 << 10, budget: 64 << 20}) // No temporary file: the CGI waits
	withWT(t, time.Second)
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetReadBuffer(4096)
	fmt.Fprintf(conn, "GET /x.cgi?big=%d HTTP/1.1\r\nHost: localhost\r\n\r\n", 64<<20) // And never read
	if !eventually(3*time.Second, func() bool { return cgiSlotsRunning() == 1 }) {
		t.Fatal("the CGI didn't start")
	}
	start := time.Now()
	if !eventually(1600*time.Millisecond, func() bool { return cgiSlotsRunning() == 0 }) {
		t.Errorf("%v after the CGI started: the slot of a CGI ended at WT (1 s) while it waited for its client is still taken", time.Since(start).Round(100*time.Millisecond))
	}
}
