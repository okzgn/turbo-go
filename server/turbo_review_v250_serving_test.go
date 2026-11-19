package server

// The tests of the findings about the serving path of the review of v2.5.0: each failed before its fix.

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// r250KeepLimits puts the limits of the limiter back when the test ends.
func r250KeepLimits(t *testing.T) {
	cil, cis, cii := serverRequestLimits.CIL.Load(), serverRequestLimits.CIS.Load(), serverRequestLimits.CII.Load()
	t.Cleanup(func() {
		serverRequestLimits.CIL.Store(cil)
		serverRequestLimits.CIS.Store(cis)
		serverRequestLimits.CII.Store(cii)
	})
}

// V2.5.0 review SV-1: the line of turbo.denials of a client that goes over CII is written once its entry of the limiter
// is unlocked. Written with it locked, a log that waited (a slow disk) held the entry, the accept loop waited for it
// with the next connection of that client (connHandler), and no one else was accepted meanwhile.
func TestR250_SV1_ADenialLineDoesNotHoldTheAcceptLoop(t *testing.T) {
	dir := initForTest(t)
	r250KeepLimits(t)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	refreshLogFiles(dir)
	if serverGetLogState(denialsLogName) == nil {
		t.Fatal("turbo.denials isn't open")
	}
	t.Cleanup(func() { serverSetLogState(denialsLogName, nil) })
	var accepted atomic.Int64
	clientX, clientY := net.ParseIP("198.51.100.7"), net.ParseIP("203.0.113.50")
	base, _ := startServerAs(t, func() net.IP {
		if accepted.Add(1) <= 3 {
			return clientX
		}
		return clientY
	})
	serverRequestLimits.CIL.Store(int64(10 * time.Second))
	serverRequestLimits.CIS.Store(int64(time.Second))
	serverRequestLimits.CII.Store(1)
	request := func(timeout time.Duration) (int, error) {
		req, _ := http.NewRequest("GET", base+"/", nil)
		req.Host = "localhost"
		client := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
		res, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return res.StatusCode, nil
	}
	if code, err := request(3 * time.Second); code == 0 {
		t.Fatalf("the first request of the client: %d %v", code, err)
	}
	logMutex.Lock() // Another line of a log, being written to a disk that doesn't answer
	released := false
	release := func() {
		if !released {
			released = true
			logMutex.Unlock()
		}
	}
	defer release()
	second := make(chan int, 1)
	go func() { code, _ := request(10 * time.Second); second <- code }() // Over CII: its line waits for the log
	time.Sleep(300 * time.Millisecond)
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://")) // A new connection of that client
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(200 * time.Millisecond)
	codeY, errY := request(clientTimeout()) // Another client, on a new connection
	release()
	<-second
	if codeY != 200 {
		t.Errorf("another client while a denial line waits for the log: %d %v; expected 200", codeY, errY)
	}
}

// V2.5.0 review SV-4: Retry-After carries the seconds left of the block that rejects the request, also when the entry
// blocked is the one a client shares with its network: it said 1 during the 5 s of the block.
func TestR250_SV4_RetryAfterOfASharedEntry(t *testing.T) {
	initForTest(t)
	r250KeepLimits(t)
	previousLimit := ipReferenceLimit
	ipReferenceLimit = 1
	t.Cleanup(func() { ipReferenceLimit = previousLimit })
	serverRequestLimits.CIL.Store(int64(10 * time.Second))
	serverRequestLimits.CIS.Store(int64(time.Second))
	serverRequestLimits.CII.Store(1)
	handler := serverHandlerFn(false)
	if rec := serveFrom(handler, "198.51.100.1"); rec.code != 200 { // Its own entry: the level of the clients is full
		t.Fatalf("the first client: %d", rec.code)
	}
	if rec := serveFrom(handler, "198.51.100.2"); rec.code != 200 { // Shares that of 198.51.100.0/24
		t.Fatalf("the second client: %d", rec.code)
	}
	blocked := serveFrom(handler, "198.51.100.2")
	again := serveFrom(handler, "198.51.100.3") // Of the same /24: blocked too
	if blocked.code != 429 || blocked.header.Get("Retry-After") != "5" {
		t.Errorf("the request that blocks a shared entry: %d, Retry-After %q; expected 429 and 5", blocked.code, blocked.header.Get("Retry-After"))
	}
	if again.code != 429 || again.header.Get("Retry-After") != "5" {
		t.Errorf("another client of that entry: %d, Retry-After %q; expected 429 and 5", again.code, again.header.Get("Retry-After"))
	}
}

// V2.5.0 review SV-3: /a/index.html is served by its name when the folder serves another index before it: redirected
// to "./", as where index.html is the index that the folder serves, it could never be had.
func TestR250_SV3_IndexHTMLBehindAnotherIndexIsServedByItsName(t *testing.T) {
	dir := initForTest(t)
	for _, folder := range []string{"a", "b"} {
		os.MkdirAll(dir+"localhost/@/"+folder, 0755)
		os.WriteFile(dir+"localhost/@/"+folder+"/index.html", []byte("INDEX"), 0644)
	}
	os.WriteFile(dir+"localhost/@/a/home.html", []byte("HOME"), 0644)
	withGlobalLock(func() {
		indexFiles["localhost"] = map[string]int{}
		addIndex("localhost", "home.html")
		addIndex("localhost", "index.html")
	})
	handler := serverHandlerFn(false)
	serve := func(uri string) *responseRecorder {
		rec := &responseRecorder{}
		req := benchRequest("localhost", uri, "192.0.2.10:4000")
		req.Body = customNetHttp.NoBody
		handler(rec, req)
		return rec
	}
	if rec := serve("/a/"); rec.code != 200 || rec.body.String() != "HOME" {
		t.Fatalf("/a/: %d %q", rec.code, rec.body.String())
	}
	if rec := serve("/a/index.html"); rec.code != 200 || rec.body.String() != "INDEX" {
		t.Errorf("/a/index.html, behind home.html: %d %q, Location %q; expected the file", rec.code, rec.body.String(), rec.header.Get("Location"))
	}
	// Where the folder serves index.html itself, its name goes to the folder, as always
	if rec := serve("/b/index.html"); rec.code != 301 || rec.header.Get("Location") != "./" {
		t.Errorf("/b/index.html, the index that its folder serves: %d, Location %q; expected 301 to ./", rec.code, rec.header.Get("Location"))
	}
	if rec := serve("/b/"); rec.code != 200 || rec.body.String() != "INDEX" {
		t.Errorf("/b/: %d %q", rec.code, rec.body.String())
	}
}

// V2.5.0 review SV-6: an empty field of a line of turbo.visits (the host of an HTTP/1.0 request without Host) is
// written as "": left empty, whoever split the line by its spaces took the URL for the host.
func TestR250_SV6_AnEmptyHostIsAFieldOfTheVisit(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	refreshLogFiles(dir)
	base := startServer(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn, "GET /x HTTP/1.0\r\n\r\n")
	bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	serverSetLogState(visitsLogName, nil)
	data, _ := os.ReadFile(dir + "turbo.visits")
	fields := strings.Fields(strings.TrimRight(string(data), "\r\n"))
	if len(fields) != 6 || fields[4] != `""` || fields[5] != "/x" {
		t.Errorf("the line of turbo.visits: %q; expected six fields, the host \"\" and the URL /x", fields)
	}
}

// V2.5.0 review SV-7: the site * serves any host that no other site does, IP addresses included, and has no www to
// redirect: W and R on are refused for it (they sent "http://www.::1/x" to a request by an IPv6 address).
func TestR250_SV7_TheSiteOfAnyHostHasNoWWW(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"#/@", 0755)
	os.WriteFile(dir+"#/@/index.html", []byte("star"), 0644)
	updateSettings(true)
	for _, setting := range []string{"W", "R"} {
		applied, answer := lockedCheck(func() (bool, string) { return siteSSLSettingCheckers[setting](false, "1", "*", "") })
		if applied || !strings.Contains(answer, "has no www") {
			t.Errorf("%s on the site *: %v, %q; expected it refused", setting, applied, answer)
		}
		if applied, answer = lockedCheck(func() (bool, string) { return siteSSLSettingCheckers[setting](false, "0", "*", "") }); !applied {
			t.Errorf("%s off on the site *: %q", setting, answer)
		}
	}
	handler := serverHandlerFn(false)
	rec := &responseRecorder{}
	req := benchRequest("[::1]", "/", "192.0.2.10:4000")
	req.Body = customNetHttp.NoBody
	handler(rec, req)
	if rec.code != 200 || rec.header.Get("Location") != "" {
		t.Errorf("a request by an IPv6 address: %d, Location %q", rec.code, rec.header.Get("Location"))
	}
}
