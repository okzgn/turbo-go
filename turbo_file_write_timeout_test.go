package main

// Review of 6046dbe (R6 M-01): WFT, the time a site's file has to be written, apart from WT.

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// withWFT sets WFT for a test.
func withWFT(t *testing.T, limit time.Duration) {
	t.Helper()
	previous := fileWriteTimeout.Load()
	t.Cleanup(func() { fileWriteTimeout.Store(previous) })
	fileWriteTimeout.Store(int64(limit))
}

// slowDownloadOf downloads url as a client that reads 256 KiB every 50 ms (about 5 MiB/s) does, and returns how many
// bytes of the body it got.
func slowDownloadOf(t *testing.T, client *http.Client, url string) int64 {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Host = "localhost"
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("GET %s: %d", url, res.StatusCode)
	}
	var received int64
	buffer := make([]byte, 256<<10)
	for {
		n, err := io.ReadFull(res.Body, buffer)
		received += int64(n)
		if err != nil {
			return received
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// R6 M-01: a file that a client takes longer than WT to download is whole when WFT gives it the time, in HTTP/1 and in
// HTTP/2. Without WFT, WT cuts it, as always; and a WFT shorter than WT cuts it sooner.
func TestR6_M01_FileWriteTimeout(t *testing.T) {
	dir := initForTest(t)
	const size = 16 << 20 // About 3 s for the slow client
	if err := os.WriteFile(dir+"localhost/@/big.bin", bytes.Repeat([]byte("x"), size), 0644); err != nil {
		t.Fatal(err)
	}
	base := startServer(t)
	cfg := selfSignedTLS(t)
	secure := &customNetHttp.Server{Handler: customNetHttp.HandlerFunc(serverHandlerFn(true)), TLSConfig: cfg, ConnState: connHandler}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	go secure.Serve(listener)
	t.Cleanup(func() { secure.Close() })
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	clients := map[string]struct {
		client *http.Client
		url    string
	}{
		"HTTP/1": {&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}, base + "/big.bin"},
		"HTTP/2": {&http.Client{Transport: transport}, "https://" + listener.Addr().String() + "/big.bin"},
	}
	for protocol, c := range clients {
		withWT(t, time.Second)
		withWFT(t, 0)
		if got := slowDownloadOf(t, c.client, c.url); got >= size {
			t.Errorf("%s, WT 1s without WFT: the whole file arrived; expected WT to cut it, as always", protocol)
		}
		withWFT(t, 30*time.Second)
		if got := slowDownloadOf(t, c.client, c.url); got != size {
			t.Errorf("%s, WT 1s and WFT 30s: %d of %d bytes; expected the whole file", protocol, got, size)
		}
		withWT(t, 30*time.Second)
		withWFT(t, time.Second)
		if got := slowDownloadOf(t, c.client, c.url); got >= size {
			t.Errorf("%s, WT 30s and WFT 1s: the whole file arrived; expected WFT to cut it", protocol)
		}
	}
}

// R6 M-01: WFT doesn't change how long a CGI may run, which is WT's, nor the time of its answer.
func TestR6_M01_FileWriteTimeoutLeavesCGIsToWT(t *testing.T) {
	cgiSite(t)
	withWT(t, 500*time.Millisecond)
	withWFT(t, 30*time.Second)
	base := startServer(t)
	start := time.Now()
	code, _, err := get(base, "/x.cgi?sleep=5000", nil)
	if err != nil || code != 504 || time.Since(start) > 3*time.Second {
		t.Errorf("a CGI that takes 5 s with WT 500ms and WFT 30s: %d %v in %v; expected 504 at WT", code, err, time.Since(start).Round(100*time.Millisecond))
	}
}

// R6 M-01: setWFT takes a duration from 100 ms to 24 h, or 0 (WT applies), with the current password; it is saved
// in turbo.config and read from it, and its default is 0.
func TestR6_M01_FileWriteTimeoutSetting(t *testing.T) {
	dir := initForTest(t)
	if fileWriteTimeout.Load() != 0 {
		t.Fatalf("default WFT: %v; expected 0", time.Duration(fileWriteTimeout.Load()))
	}
	base := startServer(t)
	tok := login(t, base)
	set := func(value, password string) (int, string) {
		code, body, _ := post(base, "/admin:inside:setWFT?"+url.Values{"a": {value}, "b": {password}}.Encode(), tok)
		return code, body
	}
	for _, bad := range []string{"50ms", "25h", "-5s", "ten", "", "5"} {
		if code, body := set(bad, "Admin"); code != 400 {
			t.Errorf("setWFT %q: %d %q; expected 400", bad, code, body)
		}
	}
	if code, body := set("5m", "Wrong-password-1"); code == 200 {
		t.Errorf("setWFT with a wrong password: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:setWFT?a=5m", tok); code != 400 {
		t.Errorf("setWFT without the password: %d %q; expected 400", code, body)
	}
	if code, body := set("5m", "Admin"); code != 200 || body != "File write timeout saved" || fileWriteTimeout.Load() != int64(5*time.Minute) {
		t.Fatalf("setWFT 5m: %d %q, WFT %v", code, body, time.Duration(fileWriteTimeout.Load()))
	}
	if code, body := set("5m", "Admin"); code != 400 || body != "Value unchanged" {
		t.Errorf("setWFT 5m again: %d %q; expected \"Value unchanged\"", code, body)
	}
	if !saveDefaultConfig() {
		t.Fatal("saving failed")
	}
	if general := savedConfig(t, dir)["."]; general["WFT"] != "5m0s" {
		t.Errorf("WFT saved: %v; expected \"5m0s\"", general["WFT"])
	}
	fileWriteTimeout.Store(0)
	withGlobalLock(func() { configFileStamp = configStamp{} })
	updateSettings(false)
	if fileWriteTimeout.Load() != int64(5*time.Minute) {
		t.Errorf("WFT after reading turbo.config: %v; expected 5m", time.Duration(fileWriteTimeout.Load()))
	}
	// A turbo.config without it, as those of earlier versions, leaves the default; an invalid one, too, with a warning
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"}}},".":{"WT":"10s"}}`)
	if fileWriteTimeout.Load() != 0 {
		t.Errorf("WFT after a turbo.config without it: %v; expected 0", time.Duration(fileWriteTimeout.Load()))
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"}}},".":{"WFT":"30h"}}`)
	if fileWriteTimeout.Load() != 0 || !strings.Contains(logs.String(), "WFT") {
		t.Errorf("WFT \"30h\" in turbo.config: %v, log:\n%s", time.Duration(fileWriteTimeout.Load()), logs.String())
	}
	if code, body := set("0s", "Admin"); code != 400 || body != "Value unchanged" {
		t.Errorf("setWFT 0s at the default: %d %q", code, body)
	}
}
