package main

// V20 (production review of 775a809): the grouped log of the errors of the connections and of the CGIs.
// - What was counted after the shutdown wrote the lines counted was lost: once closed, each line is written at once.
// - All the panics of the handlers were one kind, and within a minute only the last one's stack was written: each
//   distinct panic (its value up to its first digit, and the function in which it panicked) is a kind of its own.

import (
	"strings"
	"testing"
)

func TestRP3_V20_LinesAfterCloseWritten(t *testing.T) {
	logs := captureLog(t)
	errorLog := &aggregatedLog{}
	defer errorLog.reopen()                                                // Its timer, if any
	errorLog.Write([]byte("TLS handshake error from 192.0.2.1:1: first"))  // The first of its kind: at once
	errorLog.Write([]byte("TLS handshake error from 192.0.2.2:2: second")) // Counted
	errorLog.close()                                                       // The shutdown: what was counted
	errorLog.Write([]byte("TLS handshake error from 192.0.2.3:3: third"))  // After it: at once
	for _, expected := range []string{"first", "count=1", "second", "third"} {
		if !strings.Contains(logs.String(), expected) {
			t.Errorf("%q isn't in the log:\n%s", expected, logs.String())
		}
	}
}

// panicLine is how the server logs a handler's panic, with its stack.
func panicLine(value string, function string) []byte {
	return []byte("http: panic serving 192.0.2.9:40000: " + value + "\ngoroutine 7 [running]:\nnet/http.(*conn).serve.func1()\n" +
		"\t/go/src/net/http/server.go:1898 +0xbe\npanic({0x6e1a40?, 0xc000114030?})\n\t/go/src/runtime/panic.go:770 +0x132\n" +
		function + "(...)\n\t/x/main.go:12 +0x1d\n")
}

func TestRP3_V20_EachPanicItsOwnKind(t *testing.T) {
	logs := captureLog(t)
	errorLog := &aggregatedLog{}
	defer errorLog.reopen()
	errorLog.Write(panicLine("index out of range [3] with length 3", "main.first"))
	errorLog.Write(panicLine("nil map", "main.second"))
	errorLog.Write(panicLine("index out of range [5] with length 3", "main.first")) // The same panic again: counted
	if count := strings.Count(logs.String(), "main.first("); count != 1 {
		t.Errorf("the panic of main.first written %d times; expected once, its repeat counted:\n%s", count, logs.String())
	}
	if !strings.Contains(logs.String(), "main.second(") {
		t.Errorf("another panic, within the same minute, wasn't written with its stack:\n%s", logs.String())
	}
	if kind := aggregatedLogKind(string(panicLine("nil map", "main.second"))); kind != "http: panic serving nil map in main.second" {
		t.Errorf("kind of a panic: %q", kind)
	}
}
