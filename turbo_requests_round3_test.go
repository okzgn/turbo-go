package main

// R2-06, R3-04, CONNECT, R3 I-1, S8 and O5 (production reviews of 2026-11-04): requests and the limiter. R3 I-3,
// TLS 1.2 with AEAD suites only, is in the "Versions" of TestW_SSL_TLSFlow.
// - R2-06 / R3-04: canonicalHost served some Hosts that aren't hosts as another one ("[localhost]x" as localhost),
//   and kept the zone of an IPv6 address, any text, in the HTTP_HOST and SERVER_NAME of a CGI of the site "*"; the
//   Content-Security-Policy of the panel's host was decided on the raw Host ("[0::1]" wasn't ::1), and an Origin
//   with a final dot wasn't the panel's.
// - CONNECT: its target (host:port) was served as GET /.
// - R3 I-1: a client's parameter came before the same one of the rewrite's query, and the CGIs that take the first
//   value (Python's parse_qs, Perl's CGI.pm, Go's Query().Get) read the client's.
// - S8: past the cap of the limiter's entries, every new client shared one, which a flood of new addresses kept
//   blocked for every new visitor.
// - O5: a timeout of 0, without a limit, wasn't warned about.

import (
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

func TestRP3_R206_CanonicalHost(t *testing.T) {
	for host, want := range map[string]string{
		"": "", "localhost": "localhost", "LocalHost": "localhost", "localhost.": "localhost", "localhost:8080": "localhost:8080",
		"Example.COM.:443": "example.com:443", "localhost:": "localhost", "127.0.0.1:80": "127.0.0.1:80", "[::1]": "[::1]",
		"[0:0::1]:80": "[::1]:80", "[2001:DB8::1]": "[2001:db8::1]", "[::1]:": "[::1]", "[::ffff:127.0.0.1]": "[::ffff:127.0.0.1]",
	} {
		if got, ok := canonicalHost(host); !ok || got != want {
			t.Errorf("canonicalHost(%q) = %q, %v; expected %q", host, got, ok, want)
		}
	}
	for _, host := range []string{
		"[localhost]", "[localhost]x'()", "[::1]x", "[::1]:x", "[::1", "localhost]:a:b", "local[host", "[127.0.0.1]",
		"[fe80::1%25eth0]", "[::1%25x]:80", "a:b:c", "::1", "localhost:x", "localhost:abc", "localhost:123456",
		"localhost:+80", "localhost..", ".", ":80",
	} {
		if got, ok := canonicalHost(host); ok {
			t.Errorf("canonicalHost(%q) = %q; expected it refused", host, got)
		}
	}
}

// A Host that isn't a host gets 400, on HTTP/1.1 as on HTTP/2 (TestRL_S4 and the :authority of TestN89).
func TestRP3_R206_HostsThatArentHostsGet400(t *testing.T) {
	initForTest(t)
	addr := strings.TrimPrefix(startServer(t), "http://")
	for _, host := range []string{"[::1%25x]", "localhost..", "[localhost]", "localhost:x", "localhost]:a:b"} {
		if res, body := sendRaw(t, addr, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); res.StatusCode != 400 {
			t.Errorf("Host %q: %d %q; expected 400", host, res.StatusCode, body)
		}
	}
	if res, body := sendRaw(t, addr, "GET / HTTP/1.1\r\nHost: LOCALHOST.\r\nConnection: close\r\n\r\n"); res.StatusCode != 200 {
		t.Errorf("Host LOCALHOST.: %d %q; expected 200", res.StatusCode, body)
	}
}

// The panel's own host is recognized as PA lists it, whatever form the Host gives its address: a site's page served
// there carries panelCSP.
func TestRP3_R206_PanelCSPOnTheCanonicalHost(t *testing.T) {
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"#/@", 0755); err != nil { // The site "*", which serves the IP addresses
		t.Fatal(err)
	}
	os.WriteFile(dir+"#/@/index.html", []byte("any"), 0644)
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	list, problem := parsePanelAccess("::1,127.0.0.1")
	if problem != "" {
		t.Fatal(problem)
	}
	previous := panelAccess.Load()
	panelAccess.Store(list)
	t.Cleanup(func() { panelAccess.Store(previous) })
	addr := strings.TrimPrefix(startServer(t), "http://")
	for _, host := range []string{"[0::1]", "[::1]:80", "[::ffff:127.0.0.1]", "127.0.0.1"} {
		res, body := sendRaw(t, addr, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
		if res.StatusCode != 200 || res.Header.Get("Content-Security-Policy") != panelCSP {
			t.Errorf("Host %q, a PA host: %d %q, CSP %q; expected 200 with panelCSP", host, res.StatusCode, body, res.Header.Get("Content-Security-Policy"))
		}
	}
}

// An Origin with a final dot names the panel's host: its login isn't taken for one from another origin.
func TestRP3_R206_OriginWithAFinalDot(t *testing.T) {
	initForTest(t)
	password := useTestPassword(t)
	for origin, cross := range map[string]bool{"http://localhost.": false, "http://LOCALHOST": false, "http://localhost.:80": true, "http://other.test": true, "https://localhost": true} {
		rec := loginWith("192.0.2.84", "Turbo", password, map[string]string{"Origin": origin})
		if refused := rec.code == 403; refused != cross {
			t.Errorf("a login with Origin %q: %d; expected it refused %v", origin, rec.code, cross)
		}
	}
}

// CONNECT names no file of a site: 400, not the index.
func TestRP3_Connect400(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	if code, body := rawRequest(t, base, "CONNECT localhost:443 HTTP/1.1"); code != 400 {
		t.Errorf("CONNECT localhost:443: %d %q; expected 400", code, body)
	}
	if code, _ := rawRequest(t, base, "GET http://localhost/ HTTP/1.1"); code != 200 { // The absolute form still works
		t.Errorf("GET in absolute form: %d; expected 200", code)
	}
}

// R3 I-1: the parameters that the rewrite's query sets come only from it; the rest of the client's query keeps its
// bytes and its order, before the rewrite's.
func TestRP3_I1_RewriteQueryWins(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/app.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	subdomainContentCheckers["="](true, map[string]interface{}{"/x": "/app.cgi?role=user"}, false, "localhost", "")
	globalMutex.Unlock()
	base := startServer(t)
	for query, want := range map[string]string{
		"role=admin&z=3&%72ole=a;role=b": "z=3&role=user",
		"z=3;role=admin&y=%41":           "z=3&y=%41&role=user", // ";" separates too, as some CGI libraries take it
		"role=admin;z=3":                 "z=3&role=user",
		"":                               "role=user",
		"z=1":                            "z=1&role=user",
		"rolex=1&ROLE=2&role":            "rolex=1&ROLE=2&role=user",
		"a+b=1&r%6Fle%3D=2":              "a+b=1&r%6Fle%3D=2&role=user",
	} {
		path := "/x"
		if query != "" {
			path += "?" + query
		}
		code, body, err := get(base, path, nil)
		if err != nil || code != 200 {
			t.Fatalf("GET %s: %d %v", path, code, err)
		}
		if got := cgiEnv(body)["QUERY_STRING"]; got != want {
			t.Errorf("GET %s: QUERY_STRING=%q; expected %q", path, got, want)
		}
	}
}

// S8: past ipReferenceLimit, a new client shares the entry of its network, an IPv4 /24 or an IPv6 /48, while there
// are fewer than an eighth of the cap of those; then that of a wider one, a /16 or a /32, up to a sixty-fourth; and
// only then the entry of every other one. A shared entry answers 429 but closes no connection, and a known client
// keeps its own.
func TestRP3_S8_LimiterLevels(t *testing.T) {
	initForTest(t)
	limits(1000, 5)
	previousLimit := ipReferenceLimit
	ipReferenceLimit = 16 // Networks: 2 of the first level, 1 of the second
	t.Cleanup(func() { ipReferenceLimit = previousLimit })
	clock := int64(100 * time.Second)
	previousClock := monotonicNow
	monotonicNow = func() int64 { return clock }
	t.Cleanup(func() { monotonicNow = previousClock })
	refused := func(ip string) bool { return perIPNotAvailable(ip, true) }
	for i := 1; i <= 16; i++ {
		if refused("198.51.100." + strconv.Itoa(i)) {
			t.Fatalf("client %d refused", i)
		}
	}
	for i := 1; i <= 5; i++ { // A flood from one /24: its new clients share its entry, and only they are refused
		if refused("203.0.113." + strconv.Itoa(i)) {
			t.Fatalf("request %d of the /24 refused", i)
		}
	}
	if !refused("203.0.113.6") || !refused("203.0.113.7") {
		t.Error("the sixth new client of a /24 with CII 5: expected 429")
	}
	if blocked, _ := ipBlocked("203.0.113.6"); blocked {
		t.Error("a client of a shared entry would have its connections closed")
	}
	if refused("198.51.100.1") {
		t.Error("a known client was refused")
	}
	for _, ip := range []string{"203.0.114.1", "203.0.115.1", "203.0.116.1", "2001:db8:1:2::1"} {
		if refused(ip) {
			t.Errorf("%s refused", ip)
		}
	}
	for key, present := range map[string]bool{
		"203.0.113.0/24": true, "203.0.114.0/24": true, // The first level, full
		"203.0.0.0/16": true, "203.0.115.0/24": false, // The second: 203.0.115.1 and 203.0.116.1 share it
		"2001:db8:1::/48": false, "2001:db8::/32": false, overflowIPKey: true, // Both levels full: the shared one
	} {
		if _, found := ipReferences.Load(key); found != present {
			t.Errorf("entry %q there %v; expected %v", key, found, present)
		}
	}
	for i := 0; i < 4; i++ { // The shared entry: 2001:db8:1:2::1 already counted one
		refused("192.0.2." + strconv.Itoa(i+1))
	}
	if !refused("2001:db9::1") {
		t.Error("a new client of the full shared entry: expected 429")
	}
	clock += int64(time.Hour) // Every window and block over
	cleanIPReferences()
	count := 0
	ipReferences.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Errorf("%d entries after the cleanup; expected none", count)
	}
	for level := range ipReferenceCounts {
		if n := ipReferenceCounts[level].Load(); n != 0 {
			t.Errorf("level %d counts %d entries after the cleanup; expected 0", level, n)
		}
	}
}

// O5: the timeouts of 0, without a limit, are warned about at the start and when the panel saves one.
func TestRP3_O5_UnlimitedTimeoutsWarned(t *testing.T) {
	initForTest(t)
	logs := captureLog(t)
	warnUnlimitedTimeouts()
	if strings.Contains(logs.String(), "without a limit") {
		t.Errorf("a warning with the default timeouts:\n%s", logs.String())
	}
	const ip = "192.0.2.85"
	token := newSession(t, ip)
	if rec := apiFrom(serverHandlerFn(""), ip, token, "/admin:inside:setWT?"+url.Values{"a": {"0"}, "b": {"Admin"}}.Encode()); rec.code != 200 {
		t.Fatalf("setWT 0: %d %q", rec.code, rec.body.String())
	}
	if !strings.Contains(logs.String(), "without a limit") || !strings.Contains(logs.String(), "WT") {
		t.Errorf("setWT 0 without a warning:\n%s", logs.String())
	}
	setTimeLimits(func(limits *customNetHttp.Timeouts) {
		limits.RT, limits.RHT, limits.IT, limits.WT = 0, 0, 0, time.Minute
	})
	logs.Reset()
	warnUnlimitedTimeouts()
	if text := logs.String(); !strings.Contains(text, "RT,RHT,IT") || strings.Contains(text, "WT") {
		t.Errorf("RT, RHT and IT at 0: %s; expected the three", text)
	}
	setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.RT = time.Minute }) // RHT and IT then use RT
	logs.Reset()
	warnUnlimitedTimeouts()
	if text := logs.String(); text != "" {
		t.Errorf("RHT and IT at 0 with RT set: %s; expected no warning", text)
	}
}
