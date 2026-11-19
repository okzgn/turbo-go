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

package server

// Expressions in the headers and the rewrites of a site: a value written with expressionMark before it is an
// expression of the package expr, computed for each request. What an expression may read of a request, and where
// each piece of what it gives may go, is expr's; here is what it reads (expressionRequest), the expressions already
// compiled, and what a site's headers do with them.

import (
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"turbo/customNetHttp"
	"turbo/internal/expr"
)

// expressionMark starts the value of a header, or the target of a rewrite, that is an expression: the panel adds it
// and takes it away, and what follows it is the expression. A header written as it is can't start with it.
const expressionMark = "="

// expressionSource returns the expression of a value, and whether it is one.
func expressionSource(value string) (string, bool) { return strings.CutPrefix(value, expressionMark) }

// normalizedExpression is value with the line breaks of an expression as "\n" (a text area sends "\r\n"); a value
// that isn't one, as it is. A lone "\r" is left, and the expression doesn't compile.
func normalizedExpression(value string) string {
	if _, isExpression := expressionSource(value); isExpression {
		return strings.ReplaceAll(value, "\r\n", "\n")
	}
	return value
}

// sentExpression reports whether a value that a panel action received is an expression once its character
// replacements are undone, as its validator will: one of them may stand for the mark.
func sentExpression(value string) bool {
	withReadLock(func() { value = replaceURIChars(value) }) // charReplacements
	_, isExpression := expressionSource(value)
	return isExpression
}

// expressionOptions are what the expressions of target are compiled with (for a header, the header named header):
// they can't read the credentials of the client nor those of the panel's sessions (the cookies, and the token of the
// "ok" header), which they could copy into a header or a redirection; and quoted is refused in the headers where it
// doesn't keep a text together.
func expressionOptions(target expr.Target, header string) expr.Options {
	return expr.Options{
		Target:            target,
		UnreadableHeaders: []string{"Cookie", "Authorization", "Proxy-Authorization", "ok"},
		UnreadableCookies: []string{sessionCookieName, sessionCookieNameTLS},
		NoQuoted:          target == expr.HeaderValue && quotedUnsafeHeaders[customNetHttp.CanonicalHeaderKey(header)],
	}
}

// quotedUnsafeHeaders are the headers whose grammar doesn't keep a quoted text together: a ";" or a space inside the
// quotes still ends the value there (an attribute of Set-Cookie, a directive or a source of a policy), and what
// quoted gives of the request could add one.
var quotedUnsafeHeaders = map[string]bool{"Set-Cookie": true, "Content-Security-Policy": true, "Content-Security-Policy-Report-Only": true}

// compiledExpressions are the expressions compiled, each once, by their target and their text, with the error of
// those that don't compile: the views of the sites take them from here each time they are made. Only what the
// configuration has, or had, is here: it is emptied whole when it reaches maxCompiledExpressions.
var compiledExpressions struct {
	mutex   sync.Mutex
	entries map[compiledExpressionKey]compiledExpression
}

type compiledExpressionKey struct {
	target   expr.Target
	noQuoted bool
	source   string
}

type compiledExpression struct {
	program *expr.Program
	err     error
}

const maxCompiledExpressions = 1024

// compileExpression returns the compiled expression of source for target (for a header, the one named header), or why
// it doesn't compile.
func compileExpression(target expr.Target, header string, source string) (*expr.Program, error) {
	options := expressionOptions(target, header)
	key := compiledExpressionKey{target, options.NoQuoted, source}
	compiledExpressions.mutex.Lock()
	compiled, found := compiledExpressions.entries[key]
	compiledExpressions.mutex.Unlock()
	if found {
		return compiled.program, compiled.err
	}
	compiled.program, compiled.err = expr.Compile(source, options)
	expressionCompiles.Add(1)
	compiledExpressions.mutex.Lock()
	defer compiledExpressions.mutex.Unlock()
	if compiledExpressions.entries == nil || len(compiledExpressions.entries) >= maxCompiledExpressions {
		compiledExpressions.entries = make(map[compiledExpressionKey]compiledExpression)
	}
	if kept, found := compiledExpressions.entries[key]; found { // Compiled meanwhile: everyone gets the same program
		return kept.program, kept.err
	}
	compiledExpressions.entries[key] = compiled
	return compiled.program, compiled.err
}

// expressionCompiles counts the expressions compiled (not found in compiledExpressions), for the tests.
var expressionCompiles atomic.Int64

// rewriteProgram returns the compiled expression of a rewrite's target (source), compiled once for each generation of
// the state (siteViews), as the views of the sites: each request looked it up in compiledExpressions, under its mutex,
// and beyond maxCompiledExpressions that cache was emptied whole and every request compiled its expression again. The
// sources are those of the rewrites of the state, never a request's: as many as the rewrites. Callers hold the global
// lock.
func rewriteProgram(source string) (*expr.Program, error) {
	kept := viewsKept()
	if kept == nil { // A writer, who may be changing the state: nothing is kept
		return compileExpression(expr.RewriteTarget, "", source)
	}
	if compiled, found := kept.rewriteExpressions.Load(source); found {
		return compiled.(compiledExpression).program, compiled.(compiledExpression).err
	}
	program, err := compileExpression(expr.RewriteTarget, "", source)
	kept.rewriteExpressions.Store(source, compiledExpression{program, err})
	return program, err
}

// expressionRequest is what an expression reads of a request: the values of the placeholders of the rewrites, as
// shortcutWordReplacers gives them, its headers, query and cookies, the client's IP and whether it came by TLS.
// requestPath is the decoded, clean path the request named, which rewriteMatch matched; servedPath, for a header, the
// file served (after the rewrite and the index), which DIR, FILE, EXT and PATH name there.
type expressionRequest struct {
	request      *customNetHttp.Request
	site         siteMatch
	rewriteMatch string
	requestPath  string
	servedPath   string
	overTLS      bool
}

func (r *expressionRequest) Variable(v expr.Variable) string {
	path := r.requestPath
	switch v {
	case expr.IP:
		return ipAddr(r.request.RemoteAddr)
	case expr.Path:
		return r.servedPath
	case expr.Method:
		return r.request.Method
	case expr.Dir, expr.File, expr.Ext:
		if r.servedPath != "" {
			path = r.servedPath
		}
	}
	if replacer, found := shortcutWordReplacers[v.Name()]; found {
		return replacer(r.request, r.site, r.rewriteMatch, path)
	}
	return ""
}

// Header is the values of the header name of the request, joined. Host is the request's host, as it chose the site:
// Go keeps it apart from the other headers (HTTP/2's :authority too), and HEADER('Host') gave nothing.
func (r *expressionRequest) Header(name string) string {
	if strings.EqualFold(name, "Host") {
		return r.request.Host
	}
	return strings.Join(r.request.Header.Values(name), ", ")
}

// Query is the first value of the parameter name of the request's query, decoded, as a CGI's library reads it ("&"
// and ";" separate them); "" if its value can't be decoded.
func (r *expressionRequest) Query(name string) string {
	_, query, _ := strings.Cut(r.request.RequestURI, "?")
	for _, parameter := range strings.FieldsFunc(query, func(c rune) bool { return c == '&' || c == ';' }) {
		key, value, _ := strings.Cut(parameter, "=")
		if decoded, err := url.QueryUnescape(key); err != nil || decoded != name {
			continue
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return ""
		}
		return decoded
	}
	return ""
}

func (r *expressionRequest) Cookie(name string) string {
	if cookie, err := r.request.Cookie(name); err == nil {
		return cookie.Value
	}
	return ""
}

func (r *expressionRequest) HTTPS() bool { return r.overTLS }

// headerExpression is a header of a site whose value is an expression.
type headerExpression struct {
	name    string
	program *expr.Program
}

// siteHeaderExpressions returns, of the headers of a site, those written as they are, the expressions (by name), the
// first that doesn't compile (with why) and what the response depends on because of them (Vary).
func siteHeaderExpressions(headers map[string]string) (fixed map[string]string, expressions []headerExpression, broken string, brokenWhy string, vary []string) {
	for _, name := range sortedKeys(headers) {
		source, isExpression := expressionSource(headers[name])
		if !isExpression {
			if fixed == nil {
				fixed = make(map[string]string, len(headers))
			}
			fixed[name] = headers[name]
			continue
		}
		program, err := compileExpression(expr.HeaderValue, name, source)
		if err != nil {
			if broken == "" {
				broken, brokenWhy = name, err.Error()
			}
			continue
		}
		expressions = append(expressions, headerExpression{name, program})
		vary = expressionVary(vary, program)
	}
	return fixed, expressions, broken, brokenWhy, vary
}

// expressionVary adds to vary the headers that program reads, and Cookie if it reads a cookie: a cache that keeps
// the response must keep one for each of their values.
func expressionVary(vary []string, program *expr.Program) []string {
	names := program.ReadsHeaders()
	if program.ReadsCookies() {
		names = append(names, "Cookie")
	}
	for _, name := range names {
		name = customNetHttp.CanonicalHeaderKey(name)
		if !headerListHas(vary, name) {
			vary = append(vary, name)
		}
	}
	return vary
}

// addVary adds to the Vary of a response the names it doesn't list yet: added, never in place of what is there.
func addVary(header customNetHttp.Header, names []string) {
	for _, name := range names {
		if !headerListHas(header.Values("Vary"), name) {
			header.Add("Vary", name)
		}
	}
}

// setSiteHeader sets a header of the site in a response. A Content-Security-Policy of the site goes next to the one
// already set (panelCSP, on the panel's own host served by a site), never in its place: browsers apply them all, so
// it can only restrict more. Set, it replaced panelCSP, and the session alone could add one that allowed scripts
// there.
func setSiteHeader(header customNetHttp.Header, name string, value string) {
	if customNetHttp.CanonicalHeaderKey(name) == "Content-Security-Policy" && header.Get(name) != "" {
		header.Add(name, value)
		return
	}
	header.Set(name, value)
}

// computedHeader is the value an expression gave to a header for a request.
type computedHeader struct {
	name  string
	value string
}

// computeHeaders evaluates the expressions of the headers of the plan's site for the file served (servedPath). An
// expression that fails, or doesn't compile, answers 500 (and it returns false): what it would have sent may be what
// keeps a page safe, and a client that made it fail would have the page without it. Those that give nothing send no
// header. The file of an ACME challenge is served without them: a broken expression doesn't stop the certificate.
func (plan *servePlan) computeHeaders(responseWriter customNetHttp.ResponseWriter, request *customNetHttp.Request, servedPath string) ([]computedHeader, bool) {
	if plan.acmeChallenge || len(plan.headerExpressions) == 0 && plan.brokenHeader == "" {
		return nil, true
	}
	if plan.brokenHeader != "" {
		if logDueOnceAMinute(plan.root + "|header|" + plan.brokenHeader) {
			slog.Error("Header whose expression doesn't compile: the site answers 500 (reported once a minute)", "site", plan.root, "header", plan.brokenHeader, "reason", plan.brokenWhy)
		}
		reqMsg(responseWriter, 500)
		return nil, false
	}
	read := &expressionRequest{request: request, site: plan.site, rewriteMatch: plan.rewriteMatch, requestPath: plan.requestPath, servedPath: servedPath, overTLS: plan.overTLS}
	computed := make([]computedHeader, 0, len(plan.headerExpressions))
	for _, header := range plan.headerExpressions {
		value, err := header.program.Header(read)
		if err != nil {
			if logDueOnceAMinute(plan.root + "|header|" + header.name) {
				slog.Error("Header expression failed: 500 (reported once a minute)", "site", plan.root, "header", header.name, "reason", err.Error())
			}
			reqMsg(responseWriter, 500)
			return nil, false
		}
		if value != "" {
			computed = append(computed, computedHeader{header.name, value})
		}
	}
	return computed, true
}

// joinedVary is base with the names of more it doesn't have, without changing base (a view's, which requests share).
func joinedVary(base []string, more []string) []string {
	var joined []string // A copy of base, made when the first name is added
	for _, name := range more {
		if headerListHas(base, name) || headerListHas(joined, name) {
			continue
		}
		if joined == nil {
			joined = append(make([]string, 0, len(base)+len(more)), base...)
		}
		joined = append(joined, name)
	}
	if joined == nil {
		return base
	}
	return joined
}

// maxExpressionTarget is the length of the target that the expression of a rewrite may give, once placed.
const maxExpressionTarget = 2048

// expressionTarget evaluates the expression of a rewrite (source) for a request, and places its parts as a target is
// written ("N/…", "H…" or "S…", as shortcutWords gives it), each with targetWriter: the texts of the expression as
// they are, and the rest encoded for where it goes. It returns "" when the expression gives nothing (the rewrite
// doesn't apply), and what the response depends on because of it (Vary). An expression that fails or doesn't
// compile, a target that would start with something else than a text of the expression, a part that the client
// chose in the host of a redirection, and a target too long answer 500 (and it returns true): Compile refuses the
// expressions that could do the last ones, which are checked again here.
func expressionTarget(responseWriter customNetHttp.ResponseWriter, read *expressionRequest, source string) (string, []string, bool) {
	logKey := joinedSite(read.site.siteSubdomain, read.site.siteDomain) + "|rewrite|" + read.rewriteMatch
	fail := func(message string, reason string) (string, []string, bool) {
		if logDueOnceAMinute(logKey) {
			slog.Error(message+" (reported once a minute)", "site", joinedSite(read.site.siteSubdomain, read.site.siteDomain), "source", read.rewriteMatch, "reason", reason)
		}
		reqMsg(responseWriter, 500)
		return "", nil, true
	}
	program, err := rewriteProgram(source)
	if err != nil {
		return fail("Rewrite whose expression doesn't compile: 500", err.Error())
	}
	vary := expressionVary(nil, program)
	parts, err := program.Rewrite(read)
	if err != nil {
		return fail("Rewrite expression failed: 500", err.Error())
	}
	if len(parts) == 0 {
		return "", vary, false
	}
	first := parts[0]
	lower := strings.ToLower(first.Text)
	var writer *targetWriter
	switch {
	case first.Class != expr.Const:
		return fail("Rewrite expression that doesn't start with a text of its own: 500", "the first part isn't a text of the expression")
	case strings.HasPrefix(lower, "https://"):
		writer = newTargetWriter(read.request, true)
		writer.text("S" + first.Text[len("https://"):])
	case strings.HasPrefix(lower, "http://"):
		writer = newTargetWriter(read.request, true)
		writer.text("H" + first.Text[len("http://"):])
	case strings.HasPrefix(first.Text, "/"):
		writer = newTargetWriter(read.request, false)
		writer.text("N" + first.Text)
	default:
		return fail("Rewrite expression that doesn't start with /, http:// or https://: 500", "the target starts with something else")
	}
	labels := 0 // In the host: 1 right after labels that the client may choose (SUBDOMAIN), 2 after them and a "."
	for _, part := range parts[1:] {
		if writer.position == targetInHost {
			ok := true
			switch part.Class {
			case expr.Labels:
				labels = 1
			case expr.Const:
				labels, ok = hostAfterLabels(labels, part.Text)
			case expr.Config, expr.Host:
				labels, ok = 0, labels != 1 // Right after the labels, they would start another name
			default:
				return fail("Rewrite expression that would place what the client chose in the host of a redirection: 500", "a part the client chose in the host")
			}
			if !ok {
				return fail("Rewrite expression whose host would end with labels that the client chose: 500", "SUBDOMAIN or FIRST_SUBDOMAIN at the end of the host")
			}
		}
		if part.Class == expr.Const {
			writer.text(part.Text)
			continue
		}
		writer.value(part.Name, part.Text)
	}
	target := writer.finish()
	if labels != 0 {
		return fail("Rewrite expression whose host would end with labels that the client chose: 500", "SUBDOMAIN or FIRST_SUBDOMAIN at the end of the host")
	}
	if mode := target[0]; (mode == 'H' || mode == 'S') && (len(target) == 1 || strings.IndexByte(redirectHostStarters, target[1]) != -1) {
		return fail("Rewrite expression that gives a redirection without a host: 500", "the host is empty, or starts with what a browser skips")
	}
	if len(target) > maxExpressionTarget {
		return fail("Rewrite expression with a target too long: 500", "longer than 2048 bytes once placed")
	}
	return target, vary, false
}

// hostAfterLabels is what is right before the next part once text, of the expression, is placed in the host of a
// redirection after labels that the client may choose (state 1, or 2 with a "." after them): 0 when the host goes on
// with what the expression or Turbo chose, 2 when a "." still waits for the rest of the host; and false when the
// labels would end the host, or start another name. As Compile checks it (expr), for each request again.
func hostAfterLabels(state int, text string) (int, bool) {
	if state == 0 || text == "" {
		return state, true
	}
	host := text // What of the text is still the host
	if end := strings.IndexAny(host, "/?#"); end != -1 {
		host = host[:end]
	}
	if state == 1 {
		if host == "" || host[0] != '.' {
			return 0, false
		}
		if host = host[1:]; host == "" {
			return 2, len(text) == 1 // A "." alone waits for the rest; "./x" ends the host with it
		}
	}
	return 0, host != "" && host[0] > ' ' && strings.IndexByte(`/\?#.:@`, host[0]) == -1
}

// The failures that each request would meet again (an expression that fails, a redirection without a host) are logged
// at most once a minute per site and entry: each request would add a line otherwise. Nothing of the request goes to
// the log.
var (
	onceAMinuteMutex  sync.Mutex
	onceAMinuteLogged = make(map[string]int64) // Site, kind and entry -> monotonic time of the last line
)

func logDueOnceAMinute(key string) bool {
	now := monotonicNow()
	onceAMinuteMutex.Lock()
	defer onceAMinuteMutex.Unlock()
	if last, found := onceAMinuteLogged[key]; found && now-last < int64(time.Minute) {
		return false
	}
	if len(onceAMinuteLogged) > 10000 { // Bounded: forgotten all at once, at worst one more line each
		clear(onceAMinuteLogged)
	}
	onceAMinuteLogged[key] = now
	return true
}
