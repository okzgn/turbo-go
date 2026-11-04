package main

// A5 (H6): the global limiter has its own setting (CGL, requests per second
// in total), disabled by default, and it does not mark any IP.

import (
	"bytes"
	"strconv"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// responseRecorder is an in-memory ResponseWriter to call the handler
// without a network, with any client IP.
type responseRecorder struct {
	header customNetHttp.Header
	code   int
	body   bytes.Buffer
}

func (r *responseRecorder) Header() customNetHttp.Header {
	if r.header == nil {
		r.header = make(customNetHttp.Header)
	}
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}

// serveFrom asks localhost for GET / from the given IP, without a network.
func serveFrom(handler func(customNetHttp.ResponseWriter, *customNetHttp.Request), ip string) *responseRecorder {
	req, _ := customNetHttp.NewRequest("GET", "http://localhost/", nil)
	req.RequestURI = "/"
	req.RemoteAddr = ip + ":40000"
	rec := &responseRecorder{}
	handler(rec, req)
	return rec
}

// waitNextSecond waits for the start of the next second, so that a burst
// falls in a single window of the global limiter.
func waitNextSecond() {
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 10*time.Millisecond)))
}

// H6: with the default values, 300 requests from 300 IPs in less than a
// second are all served: there is no global limit.
func TestA5_NoGlobalLimitByDefault(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	waitNextSecond()
	for i := 0; i < 300; i++ {
		if rec := serveFrom(handler, "10.1."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250+1)); rec.code != 200 {
			t.Fatalf("request %d from a different IP: %d; expected 200", i+1, rec.code)
		}
	}
}

// H6, D4: with CGL=50, the requests above 50 in a second get 503 with
// Retry-After: 1, not 429; in the next second nobody is blocked.
func TestA5_GlobalLimitCGL(t *testing.T) {
	initForTest(t)
	validator, exists := defaultSettingValidators["."]["CGL"]
	if !exists {
		t.Fatal("the CGL setting does not exist")
	}
	globalMutex.Lock()
	ok, msg := validator("50", internalAuth)
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("setCGL 50: %q", msg)
	}
	handler := serverHandlerFn("")
	waitNextSecond()
	served, limited := 0, 0
	for i := 0; i < 120; i++ {
		rec := serveFrom(handler, "10.2.0."+strconv.Itoa(i+1))
		switch {
		case rec.code == 200:
			served++
		case rec.code == 503 && rec.Header().Get("Retry-After") == "1":
			limited++
		default:
			t.Fatalf("request %d: %d (Retry-After %q); expected 200 or 503 with Retry-After: 1", i+1, rec.code, rec.Header().Get("Retry-After"))
		}
	}
	if served != 50 || limited != 70 {
		t.Errorf("served %d and limited %d; expected 50 and 70", served, limited)
	}
	waitNextSecond()
	for _, ip := range []string{"10.2.0.120", "10.2.0.1", "10.3.0.1"} {
		if rec := serveFrom(handler, ip); rec.code != 200 {
			t.Errorf("%s in the next second: %d; expected 200", ip, rec.code)
		}
	}
}

// D4: CGL accepts 0 (disabled) or 10 to 1 000 000, is saved in turbo.config
// and is read again.
func TestA5_CGLSetting(t *testing.T) {
	dir := initForTest(t)
	validator, exists := defaultSettingValidators["."]["CGL"]
	if !exists {
		t.Fatal("the CGL setting does not exist")
	}
	globalMutex.Lock()
	defer globalMutex.Unlock()
	for _, c := range []struct {
		value string
		want  bool
	}{{"5", false}, {"9", false}, {"-1", false}, {"x", false}, {"1000001", false}, {"10", true}, {"1000000", true}, {"0", true}, {"250", true}} {
		if ok, msg := validator(c.value, internalAuth); ok != c.want {
			t.Errorf("CGL %q: %v %q; expected %v", c.value, ok, msg, c.want)
		}
	}
	globalMutex.Unlock()
	saved := saveDefaultConfig() // Takes the locks itself (T20)
	globalMutex.Lock()
	if !saved {
		t.Fatal("could not save")
	}
	if raw := savedConfig(t, dir); raw["."]["CGL"] != "250" {
		t.Fatalf("saved CGL: %v", raw["."]["CGL"])
	}
	globalRequestLimit.Store(0)
	configFileModTime = 0
	globalMutex.Unlock()
	updateSettings(false)
	globalMutex.Lock()
	if globalRequestLimit.Load() != 250 {
		t.Errorf("CGL after reloading: %d", globalRequestLimit.Load())
	}
}

// H59: the global counter does not go back to an earlier second: a request
// that read the time just before the second changed counts in the new
// second, without resetting it, and no concurrent request is lost from the
// count.
func TestH59_GlobalWindowOnlyMovesForward(t *testing.T) {
	initForTest(t)
	globalRequestLimit.Store(3)
	t.Cleanup(func() { globalRequestLimit.Store(0) })
	for i := 1; i <= 3; i++ {
		if globalRateExceededAt(1001) {
			t.Fatalf("request %d in second 1001 with CGL = 3: rejected", i)
		}
	}
	if !globalRateExceededAt(1000) {
		t.Error("request with the time of second 1000 after 3 in 1001: accepted; it reset the count")
	}
	if !globalRateExceededAt(1001) {
		t.Error("fifth request of second 1001: accepted")
	}
	if globalRateExceededAt(1002) {
		t.Error("first request of second 1002: rejected")
	}

	globalRequestLimit.Store(1000000)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				globalRateExceededAt(2000 + int64(i)/250)
			}
		}()
	}
	wg.Wait()
	// The last second (2003) counted at least its 2000 requests (some late ones of 2002 count there too).
	globalRequestLimit.Store(2000)
	if !globalRateExceededAt(2003) {
		t.Error("the count of second 2003 lost concurrent requests: the 2001st does not exceed a limit of 2000")
	}
}
