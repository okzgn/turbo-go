package server

// The tests of the findings about the engine of the review of v2.5 (_revision/INFORME_REVISION_4cb626c.md, block 4):
// each failed before its fix.

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// v25ReviewSiteWithCGI makes localhost/@/x.cgi run cgiecho, and starts a server.
func v25ReviewSiteWithCGI(t *testing.T) (string, string) {
	t.Helper()
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.cgi", []byte("x"), 0644)
	globalMutex.Lock()
	subdomainContentCheckers["?"](true, map[string]interface{}{"cgi": toolPath("cgiecho")}, false, "localhost", "")
	globalMutex.Unlock()
	return dir, startServer(t)
}

// v25ReviewHead makes a GET of path and returns its status and headers.
func v25ReviewHead(t *testing.T, base string, path string) (int, http.Header) {
	t.Helper()
	request, _ := http.NewRequest("GET", base+path, nil)
	request.Host = "localhost"
	request.Header.Set("Accept-Encoding", "identity")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode, response.Header
}

// V2.5 review E-5: an error page of Turbo goes without the site's headers that describe how to keep or decode a body
// (a 504 kept an hour in the caches in front, with the site's Cache-Control); its other headers, the security ones
// among them, stay, and a script's own error keeps them all.
func TestV25R_E5_TurbosErrorsWithoutTheSitesCaching(t *testing.T) {
	_, base := v25ReviewSiteWithCGI(t)
	addSiteHeaders(t, map[string]string{"Cache-Control": "public, max-age=3600", "X-Frame-Options": "DENY"})
	if ok, message := setting("WT", "1s"); !ok {
		t.Fatal(message)
	}
	code, header := v25ReviewHead(t, base, "/x.cgi?sleep=3000")
	if code != 504 || header.Get("Cache-Control") != "" || header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("the 504 of a CGI out of time: %d, Cache-Control %q, X-Frame-Options %q; expected without the site's Cache-Control, with its X-Frame-Options", code, header.Get("Cache-Control"), header.Get("X-Frame-Options"))
	}
	if code, header := v25ReviewHead(t, base, "/x.cgi?header=Status:%20404%20Not%20Found"); code != 404 || header.Get("Cache-Control") != "public, max-age=3600" {
		t.Errorf("a CGI's own 404: %d, Cache-Control %q; expected the site's", code, header.Get("Cache-Control"))
	}
}

// V2.5 review E-6: what CGIs and workers write to their standard error goes to the log grouped, as Turbo's own error
// lines: a line of each kind at once, and the rest counted. Each line went to Turbo's standard error as it was.
func TestV25R_E6_TheStandardErrorOfScriptsIsGrouped(t *testing.T) {
	_, base := v25ReviewSiteWithCGI(t)
	logs := captureLog(t)
	for i := 0; i < 5; i++ {
		if code, _, _ := get(base, "/x.cgi?stderr=10", nil); code != 200 {
			t.Fatalf("the CGI: %d", code)
		}
	}
	waitForScriptLines(t, 49) // Read by a goroutine of each CGI, which may end after its answer
	if lines := strings.Count(logs.String(), "PHP Warning"); lines != 1 {
		t.Errorf("50 lines of a CGI's standard error: %d in the log; expected one, and the rest counted:\n%s", lines, logs.String())
	}
	scriptLines.flush()
	if !strings.Contains(logs.String(), `kind="[cgiecho`) || !strings.Contains(logs.String(), "count=49") {
		t.Errorf("the lines of the CGI weren't counted:\n%s", logs.String())
	}
	logs.Reset()
	_, dxBase := setupDX(t, toolPath("dxecho"))
	for i := 0; i < 5; i++ {
		if code, _ := dxRequest(t, "GET", dxBase, "/x.dx?stderr=10", nil, nil); code != 200 {
			t.Fatalf("the worker: %d", code)
		}
	}
	waitForScriptLines(t, 49)
	if lines := strings.Count(logs.String(), "a line"); lines != 1 {
		t.Errorf("50 lines of a worker's standard error: %d in the log; expected one, and the rest counted:\n%s", lines, logs.String())
	}
	scriptLines.flush()
	if !strings.Contains(logs.String(), `kind="[dxecho`) || !strings.Contains(logs.String(), "count=49") {
		t.Errorf("the lines of the worker weren't counted:\n%s", logs.String())
	}
}

// V2.5 review E-7: {REWRITE_COMPLEMENT} is what follows what the key matched in the path, also where names fold and the
// path writes the key with other characters of another length (a kelvin sign of three bytes for a k).
func TestV25R_E7_TheComplementOfAKeyWrittenOtherwise(t *testing.T) {
	initForTest(t)
	previous := foldRewrites
	withGlobalLock(func() { foldRewrites = true }) // As on Windows and macOS
	t.Cleanup(func() { withGlobalLock(func() { foldRewrites = previous }) })
	globalMutex.Lock()
	ok, message := subdomainContentCheckers["="](true, map[string]interface{}{"/kilo/": "https://other.test/new/{REWRITE_COMPLEMENT}"}, false, "localhost", "")
	globalMutex.Unlock()
	if !ok {
		t.Fatal(message)
	}
	base := startServer(t)
	for path, want := range map[string]string{
		"/kilo/x/y":           "https://other.test/new/x/y",
		"/KILO/x":             "https://other.test/new/x",
		"/%E2%84%AAilo/x":     "https://other.test/new/x",
		"/%E2%84%AAILO/a?q=1": "https://other.test/new/a?q=1",
	} {
		response, _, err := rawGet(base, "localhost", path)
		if err != nil {
			t.Fatal(err)
		}
		if location := response.Header.Get("Location"); location != want {
			t.Errorf("%s: %q; expected %q", path, location, want)
		}
	}
	for _, c := range []struct {
		path, key string
		length    int
	}{
		{"/kilo/x", "/kilo/", 6},
		{"/kilo", "/kilo/", 6},
		{"/Kilo/x", "/kilo/", 8},
		{"/a/Kilo/b", "/a/kilo/", 10},
		{"/", "/", 1},
	} {
		if length := matchedPrefixLength(c.path, c.key); length != c.length {
			t.Errorf("matchedPrefixLength(%q, %q) = %d; expected %d", c.path, c.key, length, c.length)
		}
	}
}

// V2.5 review E-9: each line of turbo.denials says when, as those of turbo.visits.
func TestV25R_E9_DenialsWithTheirTime(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	updateSettings(false) // The periodic reload opens the log
	before := time.Now().Unix()
	serverWriteLogs(denialsLogName, nil, 0, "203.0.113.9 conn denial")
	serverSetLogState(denialsLogName, nil) // Flushes and closes it
	data, _ := os.ReadFile(dir + "turbo.denials")
	match := regexp.MustCompile(`^203\.0\.113\.9 (\d+) conn denial\r?\n$`).FindStringSubmatch(string(data))
	if match == nil {
		t.Fatalf("the line of a denial: %q; expected its IP, its time and what", data)
	}
	if when, _ := strconv.ParseInt(match[1], 10, 64); when < before || when > time.Now().Unix() {
		t.Errorf("the time of the line of a denial: %d; expected between %d and now", when, before)
	}
}

// V2.5 review E-11: on macOS, a name written with a letter and its accent apart (NFD) and the same name with them in one
// character (NFC) are one name for the rewrites, as the file system opens the same folder for both.
func TestV25R_E11_NFCAndNFDAreOneNameOnMacOS(t *testing.T) {
	previous := foldNormalizes
	foldNormalizes = true
	t.Cleanup(func() { foldNormalizes = previous })
	if foldKey("/café/") != foldKey("/café/") || foldKey("/CAFÉ/") != foldKey("/café/") {
		t.Errorf("foldKey of NFD and NFC: %q and %q", foldKey("/café/"), foldKey("/café/"))
	}
	if length := matchedPrefixLength("/café/menu", "/café/"); length != len("/café/") {
		t.Errorf("the complement of an NFD path: %d bytes matched; expected %d", length, len("/café/"))
	}
	foldNormalizes = false
	if foldKey("/café/") == foldKey("/café/") {
		t.Error("NFD and NFC taken for one name where the file system doesn't")
	}
}

// V2.5 review E-14: a CGI's status in another case ("status: 404") is its status, as the names of the headers of a CGI
// are in any case: the response went out 200, with a header Status.
func TestV25R_E14_AStatusInOtherCase(t *testing.T) {
	_, base := v25ReviewSiteWithCGI(t)
	for _, line := range []string{"status:%20404%20Not%20Found", "STATUS:%20404"} {
		if code, header := v25ReviewHead(t, base, "/x.cgi?header="+line); code != 404 || header.Get("Status") != "" {
			t.Errorf("%s: %d, Status header %q; expected 404 without the header", line, code, header.Get("Status"))
		}
	}
	// Read by the CGI host, as "Status" is (second pass, M-5): with a Location it isn't the host's 302, and one that
	// is no status is the 500 that "Status: 999" gets. Read after the host, it was 302, and 200.
	request, _ := http.NewRequest("GET", base+"/x.cgi?header=status:%20301&header=Location:%20https://other.test/", nil)
	request.Host = "localhost"
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 301 || response.Header.Get("Location") != "https://other.test/" {
		t.Errorf("status: 301 with a Location: %d to %q; expected 301", response.StatusCode, response.Header.Get("Location"))
	}
	if code, _ := v25ReviewHead(t, base, "/x.cgi?header=status:%20999"); code != 500 {
		t.Errorf("a status out of range in another case: %d; expected 500, as with Status", code)
	}
}

// waitForScriptLines waits until scriptLines has counted lines (those that the log hasn't written yet): the goroutines
// that read the standard error of the scripts may still be reading when their answers have gone out.
func waitForScriptLines(t *testing.T, lines int) {
	t.Helper()
	counted := func() (total int) {
		scriptLines.mutex.Lock()
		defer scriptLines.mutex.Unlock()
		for _, kind := range scriptLines.kinds {
			total += kind.count
		}
		return total
	}
	for deadline := time.Now().Add(5 * time.Second); counted() < lines; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d lines counted of the standard error of the scripts; expected %d", counted(), lines)
		}
	}
}

// V2.5 review, second pass, M-1: a CGI that leaves a process running with its standard error doesn't hold its answer
// nor its slot, and that process keeps its standard error. Read through a pipe of exec's, the answer waited a second
// for the pipe to close, and the pipe was then closed under the process, which its next line ended.
func TestV25R_M1_AProcessLeftWithTheStandardErrorHoldsNothing(t *testing.T) {
	base, mark := childCGISetup(t, "10s")
	timed := func(query string) time.Duration {
		start := time.Now()
		if code, body, err := get(base, "/x.cgi?"+query, nil); err != nil || code != 200 {
			t.Fatalf("GET %q: %d %q %v", query, code, body, err)
		}
		return time.Since(start)
	}
	alone := min(timed(""), timed(""))
	left := timed(url.Values{"childstderr": {"1500"}, "childmark": {mark}}.Encode())
	if left > alone+700*time.Millisecond {
		t.Errorf("the answer took %v (%v without the process left): it waited for the standard error to close", left, alone)
	}
	if !markAppears(mark, 8*time.Second) {
		t.Error("the process left didn't finish: its standard error was closed under it")
	}
}

// V2.5 review, second pass, M-7: a higher limit of CGIs (CGP) gives its slots at once to the requests that wait: they
// got them only when another request came or a CGI ended, and with neither, 503 with slots free.
func TestV25R_M7_AHigherLimitServesThoseThatWait(t *testing.T) {
	_, base := v25ReviewSiteWithCGI(t)
	if ok, message := setting("CGP", "1"); !ok {
		t.Fatal(message)
	}
	holder := make(chan int, 1)
	go func() {
		code, _, _ := get(base, "/x.cgi?sleep=2500", nil)
		holder <- code
	}()
	time.Sleep(300 * time.Millisecond) // The slot is taken
	waiting := make(chan int, 1)
	started := time.Now()
	go func() {
		code, _, _ := get(base, "/x.cgi", nil)
		waiting <- code
	}()
	time.Sleep(300 * time.Millisecond) // And the second request waits for it
	if ok, message := setting("CGP", "4"); !ok {
		t.Fatal(message)
	}
	if code := <-waiting; code != 200 || time.Since(started) > 1500*time.Millisecond {
		t.Errorf("the request that waited when the limit went up: %d after %v; expected 200 at once", code, time.Since(started))
	}
	if code := <-holder; code != 200 {
		t.Errorf("the request that held the slot: %d", code)
	}
}

// V2.5 review, second pass, D-10: a line of a script's standard error isn't given the name of its program twice, and
// its kind tells the scripts, and the sites, with a digit in their names apart.
func TestV25R_D10_TheLinesOfAScript(t *testing.T) {
	initForTest(t)
	logs := captureLog(t)
	stderr := newScriptStderr("/opt/turbo-dx/dx-lua")
	stderr.Write([]byte("[dx-lua] site2.example/a.lua: one\n[dx] /srv/site2/@/b.lua:12: attempt to index a nil value\n"))
	if text := logs.String(); !strings.Contains(text, `msg="[dx-lua] site2.example/a.lua: one"`) || !strings.Contains(text, `msg="[dx-lua] [dx] /srv/site2/@/b.lua:12: attempt to index a nil value"`) {
		t.Errorf("the lines of two scripts of a site with a digit in its name, each the first of its kind:\n%s", text)
	}
	for line, kind := range map[string]string{
		"[dx-lua] site2.example/a.lua: attempt to call a nil value": "[dx-lua] site0.example/a.lua: attempt to",
		"[dx-lua] [dx] /srv/site2/@/b.lua:12: attempt to index":     "[dx-lua] [dx] /srv/site0/@/b.lua:00: attempt",
		"[php-cgi] PHP Warning:  Undefined variable $x7 in /x.php":  "[php-cgi] PHP Warning: Undefined",
	} {
		if got := scriptLineKind(line); got != kind {
			t.Errorf("the kind of %q: %q; expected %q", line, got, kind)
		}
	}
}
