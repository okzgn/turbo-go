package main

// T34 (N41, I6, I7): a log rotated by renaming is opened again, fields with
// spaces don't break the lines, and a missing preprocessor doesn't fill the
// log.

import (
	"os"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

func TestN41_LogRotationDetected(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false)
	base := startServer(t)
	get(base, "/before", nil)
	serverSetLogState(visitsLogName, nil) // Windows can't rename an open file: closed, as logrotate's copy would
	if err := os.Rename(dir+"turbo.visits", dir+"turbo.visits.1"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(dir+"turbo.visits", nil, 0644) // logrotate's "create"
	updateSettings(true)
	get(base, "/after", nil)
	serverSetLogState(visitsLogName, nil)
	current, _ := os.ReadFile(dir + "turbo.visits")
	if !strings.Contains(string(current), "/after") {
		t.Errorf("after the rotation, turbo.visits does not get the new lines:\n%s", current)
	}
}

// N41: with the file open, a rename (on Unix) is detected in the next check
// and the new file is opened.
func TestN41_RenamedWhileOpen(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false)
	opened := serverGetLogState(visitsLogName)
	if opened == nil {
		t.Fatal("turbo.visits was not opened")
	}
	if err := os.Rename(dir+"turbo.visits", dir+"turbo.visits.1"); err != nil {
		t.Skipf("this system does not rename an open file: %v", err)
	}
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(true)
	if serverGetLogState(visitsLogName) == opened {
		t.Error("the renamed file is still being written to")
	}
}

// I6: a field with spaces or control characters goes in quotes.
func TestI06_LogFieldsQuoted(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	updateSettings(false)
	req, _ := customNetHttp.NewRequest("GET", "http://localhost/", nil)
	req.RequestURI = "/a b\tc"
	req.Host = "local host"
	req.RemoteAddr = "192.0.2.1:4000"
	serverWriteLogs(visitsLogName, req, 1, "Visit")
	serverSetLogState(visitsLogName, nil)
	data, _ := os.ReadFile(dir + "turbo.visits")
	line := strings.TrimSpace(string(data))
	if !strings.Contains(line, `"/a b\tc"`) || !strings.Contains(line, `"local host"`) {
		t.Errorf("log line: %q; expected the fields in quotes", line)
	}
}

// I7: 100 requests to an extension whose preprocessor does not exist leave a
// single line in the log.
func TestI07_MissingPreprocessorLoggedOnce(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.php", []byte("<?php"), 0644)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"?":{"php":"`+dir+`missing.exe"}}}}`)
	base := startServer(t)
	before := strings.Count(logs.String(), "Preprocessor unavailable")
	for i := 0; i < 100; i++ {
		if code, _, _ := get(base, "/x.php", nil); code != 500 {
			t.Fatalf("request %d: %d; expected 500", i, code)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := strings.Count(logs.String(), "Preprocessor unavailable") - before; n != 1 {
		t.Errorf("%d lines of \"Preprocessor unavailable\"; expected 1", n)
	}
}

// N110: a log that is there but can't be opened (another owner after a rotation, permissions, a folder with its
// name) is warned about, once while the error is the same, instead of failing without a word; once it can be
// opened, it is used.
func TestN110_LogThatCannotBeOpenedIsWarned(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	if err := os.Mkdir(dir+"turbo.visits", 0755); err != nil { // There, but not a file it can open
		t.Fatal(err)
	}
	refreshLogFiles(dir)
	refreshLogFiles(dir)
	if n := strings.Count(logs.String(), "Can't open the log"); n != 1 {
		t.Errorf("warnings about a log that can't be opened: %d; expected 1\n%s", n, logs.String())
	}
	os.Remove(dir + "turbo.visits")
	os.WriteFile(dir+"turbo.visits", nil, 0600)
	refreshLogFiles(dir)
	if serverGetLogState(visitsLogName) == nil {
		t.Error("the log that can be opened now is not used")
	}
}
