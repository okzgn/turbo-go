package customNetHttp

import (
	"strconv"
	"strings"
	"testing"
)

// The error answers written before any handler (turboConnError) have their Date and the length of their body, as every
// other answer: only the closing of the connection said where the body ended. And a template without a detail ends
// with its own line break, without an empty line more. (External review of v2.5.2, GGCH H-15.g.)
func TestTurboConnErrorIsFramed(t *testing.T) {
	previous := TurboErrorTemplates.Load()
	TurboErrorTemplates.Store(&map[int]string{0: `OKZGN Turbo\n{TURBO_RESPONSE_CODE}`})
	t.Cleanup(func() { TurboErrorTemplates.Store(previous) })
	for _, c := range []struct {
		detail, body string
	}{{"", "OKZGN Turbo\n400\n"}, {"Unsupported transfer encoding", "OKZGN Turbo\n400\nUnsupported transfer encoding\n"}} {
		var written strings.Builder
		turboConnError(&written, c.detail, StatusBadRequest)
		head, body, found := strings.Cut(written.String(), "\r\n\r\n")
		if !found || body != c.body {
			t.Errorf("detail %q: body %q; expected %q", c.detail, body, c.body)
		}
		if !strings.Contains(head, "\r\nContent-Length: "+strconv.Itoa(len(c.body))+"\r\n") {
			t.Errorf("detail %q: no Content-Length of %d in %q", c.detail, len(c.body), head)
		}
		if !strings.Contains(head, "\r\nDate: ") || !strings.Contains(head, "\r\nConnection: close") {
			t.Errorf("detail %q: no Date, or no Connection: close, in %q", c.detail, head)
		}
	}
}
