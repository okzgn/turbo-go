/*
Turbo - A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.
Copyright (C) 2026 OKZGN

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please visit one of the following:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact
*/

package customNetHttp

// Functions that Turbo's patches over Go's code use (see PATCHES.md). They
// live here, and not in the regenerated files, so that the patches only have
// to call them.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"strconv"
	"strings"
	"time"
)

type turboFormLimitsKey struct{}

type turboFormLimitValues struct {
	parts   int
	headers int64
}

// TurboWithFormLimits returns r with its own maximums of parts and of
// headers for ParseMultipartForm, instead of TurboMaxFormParts and
// TurboMaxFormHeaders: for an already authenticated upload of many files.
// turbo:P10
func TurboWithFormLimits(r *Request, parts int, headers int64) *Request {
	return r.WithContext(context.WithValue(r.Context(), turboFormLimitsKey{}, turboFormLimitValues{parts, headers}))
}

// turboFormLimits returns the maximums set by TurboWithFormLimits, or 0, 0.
// turbo:P10
func turboFormLimits(r *Request) (parts int, headers int64) {
	limits, _ := r.Context().Value(turboFormLimitsKey{}).(turboFormLimitValues)
	return limits.parts, limits.headers
}

// turboIdleTimeout is how long an idle connection may stay open: IT, or RT
// if IT is 0, as Go does with IdleTimeout and ReadTimeout. turbo:P6
func turboIdleTimeout() time.Duration {
	t := TurboTimeLimits.Load()
	if t.IT != 0 {
		return t.IT
	}
	return t.RT
}

// turboErrorTemplate returns the Content-Type and the body of an error
// response with Turbo's template for the code (Y; the 0 one if it has none of
// its own): {TURBO_RESPONSE_CODE} is replaced by the code, a template that
// starts with '<' is served as HTML, and in the text ones `\n` is a line
// break. The detail goes on the next line, escaped in the HTML ones (it may
// carry text from the client). turbo:P1 turbo:P9
func turboErrorTemplate(code int, detail string) (contentType, body string) {
	templates := *TurboErrorTemplates.Load()
	v, ok := templates[code]
	if !ok {
		v = templates[0]
	}
	kind := "plain"
	if strings.HasPrefix(v, "<") {
		kind = "html"
		detail = html.EscapeString(detail)
	} else {
		v = strings.ReplaceAll(v, `\n`, "\n")
	}
	return "text/" + kind + "; charset=utf-8", strings.ReplaceAll(v, "{TURBO_RESPONSE_CODE}", strconv.Itoa(code)) + "\n" + detail + "\n"
}

// turboWriteError responds with Turbo's error template. As Go's Error does,
// it sets the headers before WriteHeader and deletes Content-Length.
// turbo:P2 turbo:P9
func turboWriteError(w ResponseWriter, detail string, code int) {
	contentType, body := turboErrorTemplate(code, detail)
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	io.WriteString(w, body)
}

// turboErrorHandler returns a handler that responds with the error template
// of the code. turbo:P3
func turboErrorHandler(code int) HandlerFunc {
	return func(w ResponseWriter, r *Request) { turboWriteError(w, "", code) }
}

// errTurboURITooLong is the error of readRequest when the URI exceeds
// TurboMaxURILength (setting MUB); conn.serve responds 414. turbo:P3
var errTurboURITooLong = errors.New("http: request URI too large")

// turboMaxRSTStreamPerSecond is the maximum of RST_STREAM frames per second
// and HTTP/2 connection that cancel an open stream: four times the concurrent
// streams the connection accepts (200 with Turbo's 50), so cancelling all the
// open streams twice in a second doesn't reach it. Above it, the connection
// is closed with GOAWAY (ENHANCE_YOUR_CALM). It adds to Go's mitigation of
// the Rapid Reset attack (CVE-2023-44487), which limits the pending
// handlers. turbo:P11
func turboMaxRSTStreamPerSecond(maxStreams uint32) int {
	return 4 * int(max(maxStreams, 1))
}

// turboRSTLimiter counts the RST_STREAM frames of a connection in windows of
// one second. Only the connection's goroutine uses it. turbo:P11
type turboRSTLimiter struct {
	window   time.Time
	received int
}

func (l *turboRSTLimiter) exceeded(now time.Time, limit int) bool {
	if now.Sub(l.window) > time.Second {
		l.window = now
		l.received = 0
	}
	l.received++
	return l.received > limit
}

// turboConnError writes to the connection a whole HTTP/1.1 error response
// with Turbo's template and closes the connection, for the errors that
// happen before any handler is reached. turbo:P1
func turboConnError(w io.Writer, detail string, code int) {
	contentType, body := turboErrorTemplate(code, detail)
	io.WriteString(w, "HTTP/1.1 "+strconv.Itoa(code)+" "+StatusText(code)+"\r\nContent-Type: "+contentType+"\r\nX-Content-Type-Options: nosniff\r\nServer: "+TurboServerName+"\r\nConnection: close\r\n\r\n"+body)
}

// Limits of the headers a CGI writes: each line and the whole block.
// turbo:P12
const (
	turboCGIMaxHeaderLine  = 16 << 10
	turboCGIMaxHeaderBytes = 64 << 10
)

// turboCGIStatus reads the Status header of a CGI ("404" or "404 Not
// Found"): three digits from 200 to 599. A 1xx is not a final response, and
// anything else is not a code. turbo:P12
func turboCGIStatus(value string) (int, bool) {
	if len(value) < 3 || (len(value) > 3 && value[3] != ' ') {
		return 0, false
	}
	for _, c := range value[:3] {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	code, _ := strconv.Atoi(value[:3])
	return code, code >= 200 && code <= 599
}

// turboMaxHeaderStringLen is the maximum length of an HPACK field: the largest
// of 64 KiB, MHB and MUB. A field over MHB, or a :path over MUB, gets 431 or
// 414 on its stream with the template; only one larger than this cap is a
// connection error. turbo:P5
func turboMaxHeaderStringLen() int {
	return int(max(64<<10, TurboMaxHeaderBytes.Load(), TurboMaxURILength.Load()))
}

// turboHeadersInBuffer reports whether the header block of the request that
// starts in the buffer ends within its first limit bytes. With more bytes in
// the buffer than the limit, the request can only be read if it does.
// turbo:P4
func turboHeadersInBuffer(br *bufio.Reader, limit int64) bool {
	data, _ := br.Peek(br.Buffered())
	data = data[:min(int64(len(data)), limit)]
	return bytes.Contains(data, []byte("\r\n\r\n")) || bytes.Contains(data, []byte("\n\n"))
}
