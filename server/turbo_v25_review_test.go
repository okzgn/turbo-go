package server

// What the second review of v2.5 found (expressions and the mode dx): each test failed before its fix.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A program slower to start than WT: the start of each request that gave up goes on until the worker greets, and it
// counts with the workers in use, up to CGP at once; the requests beyond get 503, as without a free slot. Each request
// started one more, beyond the slots.
func TestDXStartsAreBoundedBySlots(t *testing.T) {
	_, base := setupDX(t, dxVariant(t, "slowgreet-bounded"))
	if ok, message := setting("WT", "200ms"); !ok {
		t.Fatal(message)
	}
	previousCGP := cgiProcesses.Load()
	cgiProcesses.Store(2)
	t.Cleanup(func() { cgiProcesses.Store(previousCGP) })
	var codes []int
	for range 4 { // Within a second: each start takes 2.5 s
		code, _ := dxRequest(t, "GET", base, "/x.dx", nil, nil)
		codes = append(codes, code)
	}
	starting := func() (busy int) {
		dxWorkers.mutex.Lock()
		defer dxWorkers.mutex.Unlock()
		for _, pool := range dxWorkers.pools {
			busy += pool.busy
		}
		return busy
	}
	if busy := starting(); !slices.Equal(codes, []int{504, 504, 503, 503}) || busy > 2 {
		t.Errorf("four requests to a program slower than WT, with CGP 2: %v, %d workers starting; expected 504, 504, 503, 503 and 2", codes, busy)
	}
	for deadline := time.Now().Add(8 * time.Second); starting() > 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) { // The starts end, so that nothing of them reaches another test
			t.Fatal("the workers that started never greeted")
		}
	}
}

// A worker has an environment of its own also when Turbo's has none of what a CGI gets of it (PATH, the temporary
// folder, what the system needs): an empty one was nil, and exec gave the worker Turbo's whole environment,
// TURBO_PASSWORD with it.
func TestDXEnvironmentIsNeverTurbos(t *testing.T) {
	for _, name := range append([]string{"PATH", "SystemRoot", "COMSPEC", "PATHEXT", "WINDIR", "DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"}, cgiTempVariables...) {
		t.Setenv(name, "")
	}
	t.Setenv("TURBO_PASSWORD", "the password of the panel")
	environment := dxEnvironment()
	if environment == nil {
		t.Fatal("nil: exec gives the worker Turbo's whole environment")
	}
	for _, variable := range environment {
		if strings.HasPrefix(variable, "TURBO_") {
			t.Errorf("the worker gets %s", variable)
		}
	}
}

// A worker that ends right after a whole answer (as one that ends after some requests) isn't the end of the next
// request: its end, not seen yet, cost that request a 500. The request goes to another worker when nothing of it
// reached the ended one (it couldn't be written: any request), or when that one ended without a byte of an answer and
// the request may be made twice (GET, without a body); a POST that reached it isn't made again.
func TestDXWorkerThatEndsAfterItsAnswer(t *testing.T) {
	_, base := setupDX(t, toolPath("dxecho"))
	for i := range 10 {
		if code, body := dxRequest(t, "GET", base, "/x.dx?exit=after", nil, nil); code != 200 {
			t.Fatalf("%d: the answer of a worker that ends after it: %d %q", i, code, body)
		}
		if code, body := dxRequest(t, "GET", base, "/x.dx?pid=1", nil, nil); code != 200 || dxLines(body)["PID"] == "" {
			t.Errorf("%d: the next request: %d %q; expected 200", i, code, body)
		}
	}
	for i := range 3 { // Its input closed, and still running: the next request, a POST, can't be written to it
		if code, body := dxRequest(t, "GET", base, "/x.dx?closein=1", nil, nil); code != 200 {
			t.Fatalf("%d: the answer of a worker that closes its input after it: %d %q", i, code, body)
		}
		if code, body := dxRequest(t, "POST", base, "/x.dx?echo=body", []byte("the body"), nil); code != 200 || body != "the body" {
			t.Errorf("%d: a POST after it: %d %q; expected 200 with its body", i, code, body)
		}
	}
	// A POST that a worker took, and ended without answering, isn't made again: it gets 500
	before := pidAfter(t, base)
	if code, _ := dxRequest(t, "POST", base, "/x.dx?die=before", []byte("once"), nil); code != 500 {
		t.Errorf("a POST whose worker ended without answering: %d; expected 500", code)
	}
	if pidAfter(t, base) == before {
		t.Error("the worker that ended answered the next request")
	}
}

// The starts of a program that fail together (requests at once while its binary is replaced, for one) count once: the
// next start waits 1 s, as after one failure. Each counted on its own: five made it wait 16 s.
func TestDXStartsThatFailTogetherCountOnce(t *testing.T) {
	saved := dxGreetingWait
	dxGreetingWait = 300 * time.Millisecond
	t.Cleanup(func() { dxGreetingWait = saved })
	_, base := setupDX(t, dxVariant(t, "nogreet-together"))
	var requests sync.WaitGroup
	for range 5 {
		requests.Add(1)
		go func() {
			defer requests.Done()
			dxRequest(t, "GET", base, "/x.dx", nil, nil)
		}()
	}
	requests.Wait()
	dxWorkers.mutex.Lock()
	var wait time.Duration
	for _, pool := range dxWorkers.pools {
		wait = max(wait, time.Duration(pool.failedUntil-monotonicNow()))
	}
	dxWorkers.mutex.Unlock()
	if wait <= 0 || wait > dxStartBackoffMin {
		t.Errorf("after five starts that failed together, no start for %v; expected up to %v", wait, dxStartBackoffMin)
	}
}

// When WT runs out, Turbo kills its worker and closes its ends of the worker's pipes: something that the worker
// started outside its group (setsid), and that still held them, held the request and its slot until it ended. On
// Windows the Job Object ends whatever the worker started.
func TestDXPipesHeldOutsideTheGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Job Object ends every process that a worker starts")
	}
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("no setsid here")
	}
	script := filepath.ToSlash(filepath.Join(filepath.Dir(toolPath("dxecho")), "dxholds.sh"))
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'DX3\\n'\nsetsid sleep 8 &\nexec sleep 30\n"), 0755); err != nil {
		t.Fatal(err)
	}
	_, base := setupDX(t, script)
	if ok, message := setting("WT", "1s"); !ok {
		t.Fatal(message)
	}
	start := time.Now()
	if code, body := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 504 || time.Since(start) > 4*time.Second {
		t.Errorf("a worker whose pipes something outside its group holds: %d %q after %v; expected 504 after about 1 s", code, body, time.Since(start))
	}
}

// HEADER('Host') is the host of the request: Go keeps it apart from the other headers, and it gave nothing, so that a
// condition on it never held (and the response varied by Host all the same).
func TestExpressionReadsTheHost(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/page.html", []byte("page"), 0644)
	addSiteHeaders(t, map[string]string{"X-Host": "=HEADER('Host') == 'localhost' ? 'named' : 'empty'"})
	base := startServer(t)
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/page.html", nil); response.Header.Get("X-Host") != "named" {
		t.Errorf("X-Host %q; expected named", response.Header.Get("X-Host"))
	}
}

// lower and upper of REWRITE_COMPLEMENT keep its rule: the rest of the path in other capitals, and the request's query
// as it came, after it in a redirection. Changed, it was placed as any value: the query went into the path, encoded.
func TestRewriteComplementInOtherCapitals(t *testing.T) {
	dir := initForTest(t)
	os.MkdirAll(dir+"localhost/@/files", 0755)
	os.WriteFile(dir+"localhost/@/files/abc.txt", []byte("the file"), 0644)
	addSiteRewrites(t, map[string]string{
		"/f/": "='/files/' + lower(REWRITE_COMPLEMENT)",
		"/g/": "='https://example.com/new/' + lower(REWRITE_COMPLEMENT)",
	})
	base := startServer(t)
	if response, body := requestWithHeaders(t, "GET", base, "localhost", "/f/ABC.txt?v=2", nil); response.StatusCode != 200 || body != "the file" {
		t.Errorf("an internal target with a query: %d %q", response.StatusCode, body)
	}
	if response, _ := requestWithHeaders(t, "GET", base, "localhost", "/g/A/B?X=1", nil); response.Header.Get("Location") != "https://example.com/new/a/b?X=1" {
		t.Errorf("a redirection: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
}

// A redirection whose host a keyword left empty is logged once a minute for its rewrite, whatever the host and port
// the client names: keyed by them, each request with another port wrote a line.
func TestRedirectionWithoutAHostIsLoggedOnceWhateverTheHost(t *testing.T) {
	initForTest(t)
	addSiteRewrites(t, map[string]string{"/x": "https://{FIRST_SITE}/x"})
	logs := captureLog(t)
	base := startServer(t)
	for _, host := range []string{"localhost:1001", "localhost:1002", "localhost:1003"} {
		if response, _ := requestWithHeaders(t, "GET", base, host, "/x", nil); response.StatusCode != 500 {
			t.Errorf("%s: %d; expected 500", host, response.StatusCode)
		}
	}
	waitIdle()
	if strings.Count(logs.String(), "without a host") != 1 || strings.Contains(logs.String(), "1002") {
		t.Errorf("the log: %s", logs.String())
	}
}

// quoted isn't for the headers whose grammar doesn't keep a quoted text together: in Set-Cookie a ";" inside the
// quotes added an attribute ("lang=\"x; Domain=example.com\""), and Content-Security-Policy has no quoted texts.
func TestQuotedIsRefusedWhereItDoesntHold(t *testing.T) {
	initForTest(t)
	for _, header := range []string{"Set-Cookie", "set-cookie", "Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		globalMutex.Lock()
		ok, message := subdomainContentCheckers["."](true, map[string]interface{}{header: "='lang=' + quoted(QUERY('l'))"}, false, "localhost", "")
		globalMutex.Unlock()
		if ok || !strings.Contains(message, "quoted can't be used in this header") {
			t.Errorf("%s: %v %q", header, ok, message)
		}
	}
	addSiteHeaders(t, map[string]string{"Content-Disposition": "='attachment; filename=' + quoted(FILE)", "Set-Cookie": "='lang=' + token(QUERY('l'))"})
}

// The host of a redirection checked again for each request: labels that the client may choose need a "." and the
// rest of the host after them (Compile refuses the expressions that don't).
func TestHostAfterLabels(t *testing.T) {
	for _, c := range []struct {
		state int
		text  string
		next  int
		ok    bool
	}{
		{0, "anything", 0, true},
		{1, ".example.com/x", 0, true},
		{1, ".", 2, true},
		{1, "", 1, true},
		{1, "/x", 0, false},
		{1, "m", 0, false},
		{1, "./x", 0, false},
		{1, ".:8080", 0, false},
		{1, "..x", 0, false},
		{2, "example.com", 0, true},
		{2, "/x", 0, false},
		{2, ".x", 0, false},
	} {
		if next, ok := hostAfterLabels(c.state, c.text); ok != c.ok || ok && next != c.next {
			t.Errorf("%d %q: %d %v; expected %d %v", c.state, c.text, next, ok, c.next, c.ok)
		}
	}
}

// The targets written as a text follow the rules of an expression's (§6.3 of the API): the host of a redirection only
// gets the names of the site, of its wildcards and the rewrite's key; {SUBDOMAIN} and {FIRST_SUBDOMAIN}, which a
// wildcard lets the client choose, only start it; and {TURBO_CURRENT_DIR} is no keyword of a rewrite. They let the
// client choose where the visitors go, or put a folder of the server in a URL. Refused when added, dropped from
// turbo.config with a warning, and 500 for one kept before.
func TestTextTargetsFollowTheRulesOfExpressions(t *testing.T) {
	initForTest(t)
	add := func(target string) (bool, string) {
		globalMutex.Lock()
		defer globalMutex.Unlock()
		return subdomainContentCheckers["="](true, map[string]interface{}{"/r/": target}, false, "localhost", "")
	}
	for target, want := range map[string]string{
		"https://{FILE}/x":                         "can't have {FILE}",
		"http://{FIRST_REQUEST}":                   "can't have {FIRST_REQUEST}",
		"https://a.example{FILE}":                  "can't have {FILE}",
		"https://{DOMAIN}{REWRITE_COMPLEMENT}":     "can't have {REWRITE_COMPLEMENT}",
		"https://{SUBDOMAIN}/x":                    "can't end the host",
		"https://{SUBDOMAIN}":                      "can't end the host",
		"https://{FIRST_SUBDOMAIN}.":               "can't end the host",
		"https://{SUBDOMAIN}{DOMAIN}/":             "can't end the host",
		"https://{SUBDOMAIN}m/x":                   "can't end the host",
		"/x/{TURBO_CURRENT_DIR}":                   "{TURBO_CURRENT_DIR} can't be in a rewrite",
		"https://x.example/?d={TURBO_CURRENT_DIR}": "{TURBO_CURRENT_DIR} can't be in a rewrite",
		"https://x.example{REWRITE}":               "{REWRITE} starts with", // Always "/": no URL in the host (review of v2.5.1, XP-3)
	} {
		if ok, message := add(target); ok || !strings.Contains(message, want) {
			t.Errorf("%s: %v %q; expected %q", target, ok, message, want)
		}
	}
	for _, target := range []string{
		"https://{SUBDOMAIN}.example.org/{REWRITE_COMPLEMENT}", "https://{SUBDOMAIN}.{DOMAIN}/x", "https://{DOMAIN}/x",
		"https://{FIRST_SITE}/a", "/x/{FILE}", "https://x.example/{FILE}?f={FIRST_QUERY}", "https://x.example/new{REWRITE}",
	} {
		if ok, message := add(target); !ok {
			t.Errorf("%s refused: %q", target, message)
		}
	}
	logs := captureLog(t)
	globalMutex.Lock()
	subdomainContentCheckers["="](false, map[string]interface{}{"/f/": "https://{FILE}/x"}, true, "localhost", "")
	_, kept := sitesMap["localhost"][""]["/f/"]
	globalMutex.Unlock()
	if kept || !strings.Contains(logs.String(), "can't have {FILE}") {
		t.Errorf("from turbo.config: kept=%v, the log:\n%s", kept, logs.String())
	}
	globalMutex.Lock()
	sitesMap["localhost"][""]["/old/"] = "S{FILE}/x" // As an earlier version kept it
	globalMutex.Unlock()
	base := startServer(t)
	if code, location := rawLocation(t, base, "/old/evil.example"); code != 500 || location != "" {
		t.Errorf("a target kept with {FILE} in its host: %d %q; expected 500, not the host the client chose", code, location)
	}
}
