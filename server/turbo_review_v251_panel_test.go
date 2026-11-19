package server

// The tests of the findings about the panel of the review of v2.5.1: each failed before its fix.

import (
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// V2.5.1 review PN-1: setM over HTTPS to a directory whose turbo.config takes the panel's host out of PA (here PA
// "", any host) and that has no turbo.panel leaves the host without a certificate, and its answer says so to the
// browser (max-age=0). The host was no longer of PA, and the answer kept the year of HSTS set as it came in.
func TestR251_PN1_SetMThatTakesTheHostOutOfPAClearsHSTS(t *testing.T) {
	_, base := panelHTTPSSetup(t)
	send := r250PanelTLS(t, base)
	if before := send("/admin:inside:sites"); before.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("with the panel's certificate: HSTS %q", before.Header().Get("Strict-Transport-Security"))
	}
	newDir := strings.ReplaceAll(t.TempDir(), "\\", "/") + "/"
	if err := os.WriteFile(newDir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"PA":""}}`), 0600); err != nil {
		t.Fatal(err)
	}
	setM := send("/admin:inside:setM?a=" + newDir + "&b=Admin")
	if setM.code != 200 || certificateFor("panel.test") != nil || panelAccess.Load().hosts["panel.test"] {
		t.Fatalf("setM: %d %q, certificate in use %v, PA now %q", setM.code, setM.body.String(), certificateFor("panel.test") != nil, panelAccess.Load().setting)
	}
	if got := setM.Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Errorf("the answer of the setM that left the host out of PA and without a certificate: HSTS %q; expected max-age=0", got)
	}
	if got := send("/admin:inside:sites").Header().Get("Strict-Transport-Security"); got != "max-age=0" {
		t.Errorf("the next request on the connection still open, on a host of no PA now: HSTS %q; expected max-age=0", got)
	}
}

// V2.5.1 review PN-1: setM over HTTPS to a directory whose turbo.panel has a certificate of the host, and whose
// turbo.config takes the host out of PA: the answer doesn't keep the year set as it came in, as the panel sends HSTS
// only on the hosts of PA.
func TestR251_PN1_SetMThatTakesTheHostOutOfPAWithItsCertificate(t *testing.T) {
	_, base := panelHTTPSSetup(t)
	send := r250PanelTLS(t, base)
	if before := send("/admin:inside:sites"); before.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("with the panel's certificate: HSTS %q", before.Header().Get("Strict-Transport-Security"))
	}
	newDir := strings.ReplaceAll(t.TempDir(), "\\", "/") + "/"
	os.MkdirAll(newDir+"turbo.panel", 0755)
	writeTestCertificate(t, newDir+"turbo.panel/", time.Hour, "panel.test")
	if err := os.WriteFile(newDir+"turbo.config", []byte(`{"^":{"v":"2"},".":{"PA":""}}`), 0600); err != nil {
		t.Fatal(err)
	}
	setM := send("/admin:inside:setM?a=" + newDir + "&b=Admin")
	if setM.code != 200 || certificateFor("panel.test") == nil || panelAccess.Load().hosts["panel.test"] {
		t.Fatalf("setM: %d %q, certificate in use %v, PA now %q", setM.code, setM.body.String(), certificateFor("panel.test") != nil, panelAccess.Load().setting)
	}
	if got, sent := setM.Header()["Strict-Transport-Security"]; sent {
		t.Errorf("the answer of the setM that left the host out of PA, with a certificate: HSTS %q; expected none", got)
	}
	if got, sent := send("/admin:inside:sites").Header()["Strict-Transport-Security"]; sent {
		t.Errorf("the next request, on a host of no PA now: HSTS %q; expected none, as before the setM on such a host", got)
	}
}

// V2.5.1 review PN-2: the server reads the extension of addPreprocessor and delPreprocessor as it is sent
// (literalActions), and the page sends it so. With a replacement whose token is in the extension ("!" -> "hp" and
// php), the page took it for one the server would read as another, didn't send it, and the preprocessor of php
// could no longer be added nor deleted from the panel.
func TestR251_PN2_APreprocessorExtensionIsSentAsTyped(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	if code, body, _ := post(base, "/admin:inside:addCharsReplace?"+url.Values{"s": {"!"}, "d": {"hp"}, "b": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("addCharsReplace ! -> hp: %d %q", code, body)
	}
	if code, body, _ := post(base, "/admin:inside:addPreprocessor?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"php"}, "b": {toolPath("cgiecho")}, "c": {"Admin"}}.Encode(), tok); code != 200 {
		t.Fatalf("addPreprocessor a=php: %d %q", code, body)
	}
	kept := func() (extensions []string) {
		withReadLock(func() {
			for extension := range preprocessors["localhost"] {
				extensions = append(extensions, extension)
			}
		})
		return extensions
	}
	if extensions := kept(); !slices.Contains(extensions, "php") {
		t.Errorf("the server kept %q; expected the extension php as sent", extensions)
	}
	if code, body, _ := post(base, "/admin:inside:delPreprocessor?"+url.Values{"s": {"localhost"}, "d": {""}, "a": {"php"}, "b": {"Admin"}}.Encode(), tok); code != 200 || slices.Contains(kept(), "php") {
		t.Errorf("delPreprocessor a=php: %d %q, kept %q", code, body, kept())
	}

	page, err := fs.ReadFile(embeddedGUI, "turbo.dev/inside/#.html")
	if err != nil {
		t.Fatal(err)
	}
	sentAs := regexp.MustCompile(`'&a=' \+ encodeURIComponent\(([^)]*)\)`) // What the page sends as a
	for action, start := range map[string]string{"addPreprocessor": "addPreprocessorLink.href", "delPreprocessor": "'/admin:inside:delPreprocessor')"} {
		at := strings.Index(string(page), start)
		if at == -1 {
			t.Fatalf("%s isn't in the page", start)
		}
		if match := sentAs.FindSubmatch(page[at:min(at+3000, len(page))]); match == nil || strings.Contains(string(match[1]), "nameAsSent") {
			t.Errorf("the page builds the extension of %s as %q; expected it as typed, without nameAsSent", action, match)
		}
	}
	for _, action := range []string{"addMimeLink", "addHeaderLink"} { // These the server reads with its replacements undone
		if !regexp.MustCompile(action + `\.href[^\n]*'&a=' \+ encodeURIComponent\(nameAsSent\(b\)\)`).Match(page) {
			t.Errorf("the page no longer checks the name of %s with nameAsSent", action)
		}
	}
}

// V2.5.1 review PN-5: a setM while hardUpload writes the files of a site leaves the upload without a place: the
// sites directory in use is another, and nothing of either is replaced. The @ of the directory left was replaced,
// and the answer said "Data uploaded".
func TestR251_PN5_AnUploadDuringASetMReplacesNothing(t *testing.T) {
	dir := initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	newDir := strings.ReplaceAll(t.TempDir(), "\\", "/") + "/"
	os.MkdirAll(newDir+"localhost/@", 0755) // The same site in the new directory
	os.WriteFile(newDir+"localhost/@/index.html", []byte("new directory"), 0644)
	previousHook := beforeUploadSwap
	t.Cleanup(func() { beforeUploadSwap = previousHook })
	setM := ""
	beforeUploadSwap = func() {
		beforeUploadSwap = func() {}
		code, body, _ := post(base, "/admin:inside:setM?"+url.Values{"a": {newDir}, "b": {"Admin"}}.Encode(), tok)
		setM = strings.TrimSpace(body)
		if code != 200 {
			setM = "failed: " + setM
		}
	}
	code, body := hardUploadFiles(t, base, tok, [][2]string{{"site/index.html", "uploaded"}})
	if strings.HasPrefix(setM, "failed") || sitesDir.Get() != newDir {
		t.Fatalf("the setM during the upload: %q, sites directory %q", setM, sitesDir.Get())
	}
	if code != 400 || body != "The sites directory changed during the upload: nothing was replaced" {
		t.Errorf("the upload during the setM: %d %q; expected 400, the sites directory changed", code, body)
	}
	for folder, expected := range map[string]string{dir: "hello", newDir: "new directory"} {
		if data, _ := os.ReadFile(folder + "localhost/@/index.html"); string(data) != expected {
			t.Errorf("the @ of %s: index.html %q; expected %q, as it was", folder, data, expected)
		}
	}
	if names := siteEntries(dir); len(names) != 1 {
		t.Errorf("work folders are left in the site of the directory left: %v", names)
	}
}

// V2.5.1 review SR-3: the line "login denial" of turbo.denials is written once loginFailuresMutex is released. Written
// with it held, a disk that took long to write it held the logins of every client and the checks of the current
// password with it (the pattern of SV-1).
func TestR251_SR3_ALoginDenialLineDoesNotHoldTheLogins(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	refreshLogFiles(dir)
	if serverGetLogState(denialsLogName) == nil {
		t.Fatal("turbo.denials isn't open")
	}
	const blocked = "198.51.100.9"
	for range loginMaxFailures - 1 {
		attempt, wait := startLoginAttempt(blocked)
		if wait != 0 {
			t.Fatalf("a login of %s before its limit: wait %d", blocked, wait)
		}
		finishLoginAttempt(attempt, true)
	}
	last, wait := startLoginAttempt(blocked)
	if wait != 0 {
		t.Fatalf("the last login of %s before its limit: wait %d", blocked, wait)
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
	finished := make(chan struct{})
	go func() { finishLoginAttempt(last, true); close(finished) }() // Blocks the client: its line waits for the log
	time.Sleep(200 * time.Millisecond)
	other := make(chan int64, 1)
	go func() {
		attempt, wait := startLoginAttempt("203.0.113.60") // Another client
		if wait == 0 {
			finishLoginAttempt(attempt, false)
		}
		other <- wait
	}()
	select {
	case wait := <-other:
		if wait != 0 {
			t.Errorf("another client: wait %d; expected none", wait)
		}
	case <-time.After(2 * time.Second):
		t.Error("the login of another client waited for the line of turbo.denials of the one blocked")
		release()
		<-other
	}
	release()
	<-finished
	if _, wait := startLoginAttempt(blocked); wait == 0 {
		t.Errorf("%s after %d failures: not blocked", blocked, loginMaxFailures)
	}
	serverSetLogState(denialsLogName, nil)
	if data, _ := os.ReadFile(dir + "turbo.denials"); strings.Count(string(data), " login denial ") != 1 || !strings.HasPrefix(string(data), blocked+" ") {
		t.Errorf("turbo.denials: %q; expected one line of the login denial of %s", data, blocked)
	}
}
