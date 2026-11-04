package main

// T18 (I9, I11; D25 (b), D26 (a)): concurrent CGI processes have a limit
// (CGP, 0 = max(16, 4×NumCPU)): without a free slot within 2 s, 503 with
// Retry-After. A body of unknown length (chunked, or HTTP/2 without
// Content-Length) reaches the CGI whole, up to MBB, with CONTENT_LENGTH.

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// cgiLoadSetup sets up x.cgi with cgiecho.
func cgiLoadSetup(t *testing.T) (string, string) {
	t.Helper()
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	return dir, startServer(t)
}

// I9: with CGP=3, of 20 slow CGIs at once, 3 run and the rest get 503 with
// Retry-After without hanging.
func TestI09_CGIConcurrencyLimit(t *testing.T) {
	_, base := cgiLoadSetup(t)
	if ok, msg := defaultSettingValidators["."]["CGP"]("3", "Admin"); !ok {
		t.Fatal(msg)
	}
	var wg sync.WaitGroup
	var mutex sync.Mutex
	codes := map[int]int{}
	retryAfter := true
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", base+"/x.cgi?sleep=3000", nil)
			req.Host = "localhost"
			res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				codes[0]++
				return
			}
			res.Body.Close()
			codes[res.StatusCode]++
			if res.StatusCode == 503 && res.Header.Get("Retry-After") == "" {
				retryAfter = false
			}
		}()
	}
	wg.Wait()
	if codes[200] != 3 || codes[503] != 17 {
		t.Errorf("codes %v; expected 3 × 200 and 17 × 503", codes)
	}
	if !retryAfter {
		t.Error("503 without Retry-After")
	}
}

// CGP: 0 is automatic; out of range, 400.
func TestI09_CGPSetting(t *testing.T) {
	initForTest(t)
	if cgiProcessLimit() < 16 {
		t.Errorf("automatic limit %d; expected at least 16", cgiProcessLimit())
	}
	for _, bad := range []string{"-1", "100001", "x"} {
		if ok, _ := defaultSettingValidators["."]["CGP"](bad, "Admin"); ok {
			t.Errorf("CGP=%s accepted", bad)
		}
	}
	if ok, msg := defaultSettingValidators["."]["CGP"]("5", "Admin"); !ok || cgiProcessLimit() != 5 {
		t.Errorf("CGP=5: %v %q, limit %d", ok, msg, cgiProcessLimit())
	}
}

// I11: chunked POSTs of 100 KiB and 3 MiB (MBB of 5 MiB): the CGI gets the
// whole body; one larger than MBB, 413.
func TestI11_CGIChunkedBody(t *testing.T) {
	_, base := cgiLoadSetup(t)
	maxBodySize.Store(5 << 20)
	t.Cleanup(func() { maxBodySize.Store(1048576) })
	for _, size := range []int{100 << 10, 3 << 20} {
		req, _ := http.NewRequest("POST", base+"/x.cgi", io.MultiReader(bytes.NewReader(make([]byte, size)))) // No ContentLength: chunked
		req.Host = "localhost"
		req.ContentLength = -1
		res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("POST %d: %v", size, err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(body), "BODY_BYTES="+strconv.Itoa(size)) || !strings.Contains(string(body), "CONTENT_LENGTH="+strconv.Itoa(size)) {
			t.Errorf("chunked POST of %d: %d %q", size, res.StatusCode, body)
		}
	}
	req, _ := http.NewRequest("POST", base+"/x.cgi", io.MultiReader(bytes.NewReader(make([]byte, 6<<20))))
	req.Host = "localhost"
	req.ContentLength = -1
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err == nil {
		res.Body.Close()
		if res.StatusCode != 413 {
			t.Errorf("chunked POST larger than MBB: %d; expected 413", res.StatusCode)
		}
	}
}

// I11: over HTTP/2, a POST without Content-Length reaches the CGI.
func TestI11_CGIHTTP2BodyWithoutLength(t *testing.T) {
	cgiSite(t)
	cfg := selfSignedTLS(t)
	srv := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(serverHandlerFn("s")), TLSConfig: cfg, ConnState: connHandler}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true} // #nosec G402 -- self-signed test certificate
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("POST", "https://"+l.Addr().String()+"/x.cgi", io.MultiReader(strings.NewReader("hello via HTTP/2")))
	req.Host = "localhost"
	req.ContentLength = -1
	res, err := (&http.Client{Transport: tr, Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.ProtoMajor != 2 || res.StatusCode != 200 || !strings.Contains(string(body), "BODY_BYTES=16") || !strings.Contains(string(body), "CONTENT_LENGTH=16") {
		t.Errorf("HTTP/2 without Content-Length: %s %d %q", res.Proto, res.StatusCode, body)
	}
}
