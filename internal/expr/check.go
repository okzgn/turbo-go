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

package expr

// What Compile checks once the expression is read: the kind of each element (a text, a condition or a list), and
// then, by the classes of what reaches the result, the rules of its target.

import (
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// kind is what an element of an expression gives.
type kind uint8

const (
	kindText kind = iota + 1
	kindBool
	kindList
)

func (k kind) String() string {
	switch k {
	case kindText:
		return "text"
	case kindBool:
		return "condition"
	}
	return "list"
}

type checker struct {
	source      string
	options     Options
	headers     []string // What the expression reads, for Vary
	cookies     bool
	patternCost int // The instructions of the patterns of matches, in all
	labelsAt    int // Where the last Labels placed in the host of a redirection is, for the errors
	// The texts of the expression may leave a "." and one label alone after Labels, to the end of the host
	// ("SUBDOMAIN + '.com'", "SUBDOMAIN + '.' + 'com/'"): allowed, and worth a warning of the caller
	// (Program.LabelsBeforeOneLabel)
	labelsOneLabel bool
	// FIRST_DOMAIN or FIRST_SITE may come right after Labels and a ".": allowed, and worth a warning of the caller
	// (Program.LabelsBeforeAnAliasName)
	labelsAliasName bool
	// A value that may give nothing for a request may leave two texts together as "//" or "..": allowed, and worth a
	// warning of the caller (Program.ValueMayJoinTexts)
	valueJoinsTexts bool
}

func (c *checker) errorAt(pos int, message string) *Error { return errorAt(c.source, pos, message) }

// want checks that n gives a text or a condition, as expected.
func (c *checker) want(n *node, expected kind, what string) *Error {
	got, err := c.kindOf(n)
	if err != nil {
		return err
	}
	if got == kindList {
		return c.errorAt(n.pos, "a list can only follow in, or be the second argument of oneOf")
	}
	if got != expected {
		return c.errorAt(n.pos, what+" needs a "+expected.String()+", not a "+got.String())
	}
	return nil
}

// arity checks the number of arguments of a function or a method (with its receiver).
func (c *checker) arity(n *node, count int, usage string) *Error {
	if len(n.args) != count {
		return c.errorAt(n.pos, usage)
	}
	return nil
}

func (c *checker) kindOf(n *node) (kind, *Error) {
	switch n.op {
	case opText:
		return kindText, nil
	case opList:
		return kindList, nil
	case opHTTPS:
		return kindBool, nil
	case opVariable:
		if variables[n.variable].headerOnly && c.options.Target != HeaderValue {
			return 0, c.errorAt(n.pos, n.name+" is only for headers")
		}
		return kindText, nil
	case opNot:
		return kindBool, c.want(n.args[0], kindBool, "!")
	case opOr, opAnd:
		symbol := map[op]string{opOr: "||", opAnd: "&&"}[n.op]
		if err := c.want(n.args[0], kindBool, symbol); err != nil {
			return 0, err
		}
		return kindBool, c.want(n.args[1], kindBool, symbol)
	case opEqual, opNotEqual:
		left, err := c.kindOf(n.args[0])
		if err != nil {
			return 0, err
		}
		right, err := c.kindOf(n.args[1])
		if err != nil {
			return 0, err
		}
		if left != right || left == kindList {
			return 0, c.errorAt(n.pos, "== and != compare two texts or two conditions")
		}
		return kindBool, nil
	case opIn:
		if err := c.want(n.args[0], kindText, "in"); err != nil {
			return 0, err
		}
		if n.args[1].op != opList {
			return 0, c.errorAt(n.args[1].pos, "in needs a list written in the expression: ['…', '…']")
		}
		return kindBool, nil
	case opConcat:
		if err := c.want(n.args[0], kindText, "+"); err != nil {
			return 0, err
		}
		return kindText, c.want(n.args[1], kindText, "+")
	case opCondition:
		if err := c.want(n.args[0], kindBool, "The condition of ? :"); err != nil {
			return 0, err
		}
		whenTrue, err := c.kindOf(n.args[1])
		if err != nil {
			return 0, err
		}
		if whenTrue == kindList {
			return 0, c.errorAt(n.args[1].pos, "a list can only follow in, or be the second argument of oneOf")
		}
		return whenTrue, c.want(n.args[2], whenTrue, "The other branch of ? :")
	case opHeader, opQuery, opCookie:
		return kindText, c.readName(n)
	case opOneOf:
		if err := c.arity(n, 2, "oneOf takes a text and a list: oneOf(HEADER('Origin'), ['https://a.example', …])"); err != nil {
			return 0, err
		}
		if err := c.want(n.args[0], kindText, "oneOf"); err != nil {
			return 0, err
		}
		if n.args[1].op != opList {
			return 0, c.errorAt(n.args[1].pos, "the second argument of oneOf is a list written in the expression: ['…', '…']")
		}
		return kindText, nil
	case opToken, opQuoted, opURLEncode, opLower, opUpper:
		if err := c.arity(n, 1, n.name+" takes one text"); err != nil {
			return 0, err
		}
		return kindText, c.want(n.args[0], kindText, n.name)
	case opStartsWith, opEndsWith, opContains:
		if err := c.arity(n, 2, n.name+" takes one text: text."+n.name+"('…')"); err != nil {
			return 0, err
		}
		if err := c.want(n.args[0], kindText, n.name); err != nil {
			return 0, err
		}
		return kindBool, c.want(n.args[1], kindText, n.name)
	case opMatches:
		if err := c.arity(n, 2, "matches takes a pattern written in the expression: text.matches('^…$')"); err != nil {
			return 0, err
		}
		if err := c.want(n.args[0], kindText, "matches"); err != nil {
			return 0, err
		}
		pattern := n.args[1]
		if pattern.op != opText {
			return 0, c.errorAt(pattern.pos, "the pattern of matches is a text written in the expression")
		}
		if len(pattern.text) > maxPattern {
			return 0, c.errorAt(pattern.pos, "a pattern longer than "+strconv.Itoa(maxPattern)+" bytes")
		}
		compiled, err := regexp.Compile(pattern.text)
		if err != nil {
			return 0, c.errorAt(pattern.pos, "invalid pattern: "+strings.TrimPrefix(err.Error(), "error parsing regexp: "))
		}
		// What matching costs follows the instructions of the pattern, not its bytes (\pL{1000} has thousands): they
		// are counted, as regexp compiles them, for all the patterns of the expression.
		parsed, err := syntax.Parse(pattern.text, syntax.Perl)
		if err != nil {
			return 0, c.errorAt(pattern.pos, "invalid pattern")
		}
		program, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			return 0, c.errorAt(pattern.pos, "invalid pattern")
		}
		if c.patternCost += len(program.Inst); c.patternCost > maxPatternCost {
			return 0, c.errorAt(pattern.pos, "patterns too costly: their repetitions and classes make more than "+strconv.Itoa(maxPatternCost)+" steps in all")
		}
		n.pattern = compiled
		return kindBool, nil
	}
	return 0, c.errorAt(n.pos, "unknown element") // No node is made with another op
}

// readName checks the name that HEADER, QUERY or COOKIE reads: one text written in the expression, and neither a
// credential nor a name that can't be one.
func (c *checker) readName(n *node) *Error {
	if len(n.args) != 1 || n.args[0].op != opText {
		return c.errorAt(n.pos, n.name+" takes a name written between quotes: "+n.name+"('…')")
	}
	name, pos := n.args[0].text, n.args[0].pos
	if name == "" || len(name) > maxName {
		return c.errorAt(pos, "a name of 1 to "+strconv.Itoa(maxName)+" bytes")
	}
	switch n.op {
	case opHeader, opCookie:
		for i := 0; i < len(name); i++ {
			if !tokenByte(name[i]) {
				return c.errorAt(pos, "invalid "+strings.ToLower(n.name)+" name")
			}
		}
		unreadable := c.options.UnreadableHeaders
		if n.op == opCookie {
			unreadable = c.options.UnreadableCookies
		}
		for _, forbidden := range unreadable {
			if strings.EqualFold(name, forbidden) {
				return c.errorAt(pos, "the "+strings.ToLower(n.name)+" "+name+" can't be read: it carries credentials")
			}
		}
	}
	n.text = name
	switch n.op {
	case opHeader:
		for _, read := range c.headers {
			if strings.EqualFold(read, name) {
				return nil
			}
		}
		c.headers = append(c.headers, name)
	case opCookie:
		c.cookies = true
	}
	return nil
}

// tokenByte is a character of a header's or a cookie's name (a token of HTTP).
func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) != -1
}

// describe names an element that may reach the result, for the errors: its variable, or its call.
func describe(n *node) string {
	switch n.op {
	case opHeader, opQuery, opCookie:
		return n.name + "('" + n.text + "')"
	case opVariable:
		return n.name
	}
	return n.name + "(…)"
}

// headerParts checks the rules of a header: no text of the request as it came reaches the value (it could carry
// what the client wants into a header: a reflected origin, a parameter of its own), and with NoLabels, no labels
// that the client chose either (noLabelsIn). Only what reaches the result is looked at: a condition reads anything.
func (c *checker) headerParts(n *node) *Error {
	switch n.op {
	case opText, opOneOf:
		return nil
	case opToken, opURLEncode:
		return c.noLabelsIn(n.args[0])
	case opQuoted:
		if c.options.NoQuoted {
			return c.errorAt(n.pos, "quoted can't be used in this header: what reads it doesn't keep a quoted text as one value (a \";\" or a space inside still ends it, or the quotes are dropped); use token, urlencode or oneOf")
		}
		return c.noLabelsIn(n.args[0])
	case opConcat:
		if err := c.headerParts(n.args[0]); err != nil {
			return err
		}
		return c.headerParts(n.args[1])
	case opCondition:
		if err := c.headerParts(n.args[1]); err != nil {
			return err
		}
		return c.headerParts(n.args[2])
	case opLower, opUpper:
		return c.headerParts(n.args[0])
	case opVariable:
		if class := variables[n.variable].class; class == Labels {
			return c.noLabelsIn(n)
		} else if class != Raw {
			return nil
		}
	}
	return c.errorAt(n.pos, "a header can't carry "+describe(n)+", which the request sends as it wants: pass it through oneOf, token, quoted or urlencode")
}

// noLabelsIn checks, with NoLabels, that no SUBDOMAIN nor FIRST_SUBDOMAIN of n reaches the value of the header: by
// itself, through what changes a text (token, urlencode, quoted, lower, upper) or through either branch of ? :.
// oneOf gives a text of its list, and a condition no text.
func (c *checker) noLabelsIn(n *node) *Error {
	if !c.options.NoLabels {
		return nil
	}
	switch n.op {
	case opVariable:
		if variables[n.variable].class == Labels {
			return c.errorAt(n.pos, labelsInANavigationHeader)
		}
	case opConcat:
		if err := c.noLabelsIn(n.args[0]); err != nil {
			return err
		}
		return c.noLabelsIn(n.args[1])
	case opCondition:
		if err := c.noLabelsIn(n.args[1]); err != nil {
			return err
		}
		return c.noLabelsIn(n.args[2])
	case opToken, opURLEncode, opQuoted, opLower, opUpper:
		return c.noLabelsIn(n.args[0])
	}
	return nil
}

// labelsInANavigationHeader is why a header that a browser follows (NoLabels) can't carry the labels that the client
// chose.
const labelsInANavigationHeader = "SUBDOMAIN and FIRST_SUBDOMAIN can't be used in this header: a browser goes where its value says, and a wildcard subdomain lets the client choose them; redirect with a rewrite, whose host is checked"

// position is where the next part of a rewrite's target goes, as the caller places it: before anything (the start,
// which only a text of the expression can begin), in the host of a redirection, in the path, in the query or in the
// fragment. A set of them is a bit mask, with what may be right before it.
type position uint16

const (
	positionStart     position = 1 << iota
	positionHostStart          // Right after the scheme: nothing of the host is written yet
	positionHost
	positionPath
	positionQuery
	positionFragment // After a "#": the rest is the fragment, which nothing moves
	// What may be right before the next part, besides where it goes: a text of the expression that ends in "/" or "."
	// (a text that starts with one of them would make "//" or ".." with it), and labels that the client may choose at
	// the end of the host (Labels), alone or with a "." after them.
	afterSlash
	afterDot
	afterLabels
	afterLabelsDot
	// The same "/" or "." of a text, with values between that may give nothing for a request (mayBeEmpty): "'/' + EXT +
	// '/x'" gives "//x" for a request without an extension. Allowed, as the value is meant to be there, and worth a
	// warning of the caller.
	maybeAfterSlash
	maybeAfterDot
	// After labels that the client may choose and a ".", the host has one label so far, without or with a final "."
	// (afterOneLabelDot): if the host ends there, the visitor chooses the whole domain (labelsOneLabel).
	afterOneLabel
	afterOneLabelDot
)

// positions are the bits of where the next part goes.
const positions = positionStart | positionHostStart | positionHost | positionPath | positionQuery | positionFragment

// rewriteParts checks the rules of a rewrite's target (flow), and what only its end tells: a redirection without a
// host whatever it gives, or a host that may end with labels that the client chose.
func (c *checker) rewriteParts(root *node) *Error {
	out, err := c.flow(root, positionStart)
	switch {
	case err != nil:
		return err
	case out&positions&^positionStart == positionHostStart: // Each target it gives (none for positionStart) is a scheme alone
		return &Error{Message: "the target needs a host"} // Of the whole expression
	case out&(afterLabels|afterLabelsDot) != 0:
		return c.errorAt(c.labelsAt, labelsAtTheEnd)
	}
	if out&(afterOneLabel|afterOneLabelDot) != 0 { // The host may end with the expression, after one label
		c.labelsOneLabel = true
	}
	return nil
}

// labelsAtTheEnd is why the host of a redirection can't end with SUBDOMAIN or FIRST_SUBDOMAIN: under a wildcard the
// client chooses them ("evil.example" of "evil.example.mysite.com"), and would choose where its visitors go.
const labelsAtTheEnd = "SUBDOMAIN and FIRST_SUBDOMAIN, which a wildcard lets the client choose, can't end the host of a redirection: write a \".\" and the rest of the host after them"

// rewriteInTheHost is why REWRITE, the key of the rewrite, can't be in the host of a redirection: it always starts
// with "/", and encoded there it gave no URL ("https://new.example.com%2Fblog%2F/blog/a").
const rewriteInTheHost = `REWRITE starts with "/": it can't be in the host of a redirection; write the host alone (the path asked for is added) or the path after it`

// labelStart is a character that can start a label of a host after the "." that follows Labels.
func labelStart(c byte) bool {
	return c > ' ' && strings.IndexByte(`/\?#.:@`, c) == -1
}

// hostStarters are what a host can't start with: a browser skips "/" and "\" after the scheme, and takes what follows
// for the host; "?" and "#" leave it empty. Compile refuses a text that would surely start the host with one of them;
// where an earlier part may have written the host or not (oneOf, ? :), the caller refuses it as it places the parts.
const hostStarters = `/\?#`

// flow checks the rules of a rewrite's target, from the positions where n may start (in), and returns those where
// it may end. Its texts move the position as the caller does when it places them ("/" from the host to the path,
// "?" to the query); the other parts are encoded there, and don't move it. The target starts with a text of the
// expression ("/", "http://" or "https://"), and the host of a redirection only gets texts of the expression, of the
// configuration or hosts that Turbo serves.
func (c *checker) flow(n *node, in position) (position, *Error) {
	switch n.op {
	case opText:
		return c.advance(n, in, n.text)
	case opOneOf: // Its result is one of the texts of its list, or nothing
		out := in
		for _, item := range n.args[1].list {
			next, err := c.advance(n.args[1], in, item)
			if err != nil {
				return 0, err
			}
			out |= next
		}
		return out, nil
	case opConcat:
		middle, err := c.flow(n.args[0], in)
		if err != nil {
			return 0, err
		}
		return c.flow(n.args[1], middle)
	case opCondition:
		whenTrue, err := c.flow(n.args[1], in)
		if err != nil {
			return 0, err
		}
		whenFalse, err := c.flow(n.args[2], in)
		return whenTrue | whenFalse, err
	case opLower, opUpper: // Each part as it was, in other capitals: neither "/" nor "?" changes
		return c.flow(n.args[0], in)
	}
	class := Clean // token, quoted and urlencode
	switch n.op {
	case opVariable:
		class = variables[n.variable].class
	case opHeader, opQuery, opCookie:
		class = Raw
	}
	if in&positionStart != 0 {
		return 0, c.errorAt(n.pos, "a target starts with a text written in the expression (/, http:// or https://), and "+describe(n)+" may come first")
	}
	inHost := in&(positionHostStart|positionHost) != 0
	if inHost && n.op == opVariable && n.variable == Rewrite {
		return 0, c.errorAt(n.pos, rewriteInTheHost)
	}
	if inHost && class != Config && class != Host && class != Labels {
		return 0, c.errorAt(n.pos, "the host of a redirection can only be written in the expression, chosen with oneOf, or one that Turbo serves; "+describe(n)+" may fall in it")
	}
	if inHost && in&afterLabels != 0 && class != Labels { // "SUBDOMAIN + DOMAIN": the client's labels would start another name
		return 0, c.errorAt(n.pos, labelsAtTheEnd)
	}
	if inHost && in&afterLabelsDot != 0 && n.op == opVariable && (n.variable == FirstDomain || n.variable == FirstSite) {
		c.labelsAliasName = true // Nothing without an alias: the caller answers 500 then
	}
	// A value: what follows has no text of the expression right before it, unless the value gives nothing for the
	// request, which the evaluation drops. Not refused (the value is meant to be there): kept, for the warnings.
	out := in &^ (afterSlash | afterDot | afterLabels | afterLabelsDot | maybeAfterSlash | maybeAfterDot | afterOneLabel | afterOneLabelDot)
	if mayBeEmpty(n) {
		out |= in & (maybeAfterSlash | maybeAfterDot | afterOneLabel | afterOneLabelDot)
		if in&afterSlash != 0 {
			out |= maybeAfterSlash
		}
		if in&afterDot != 0 {
			out |= maybeAfterDot
		}
	}
	if out&positionHostStart != 0 { // A host that Turbo serves, or of the configuration, encoded: never one of hostStarters
		out = out&^positionHostStart | positionHost
	}
	if inHost && class == Labels {
		out |= afterLabels
		c.labelsAt = n.pos
	}
	return out, nil
}

// advance moves the positions in by a text of the expression, which the caller places as it is, and checks it with
// what may be right before it: a text that ends in "/" or ".", or labels at the end of the host.
func (c *checker) advance(n *node, in position, text string) (position, *Error) {
	if text == "" {
		return in, nil // Nothing placed: what was before is before what follows
	}
	var out position
	for _, from := range [...]position{positionStart, positionHostStart, positionHost, positionPath, positionQuery, positionFragment} {
		if in&from == 0 {
			continue
		}
		rest, at := text, from
		if from == positionStart && text != "" {
			lower := strings.ToLower(text)
			switch {
			case strings.HasPrefix(lower, "https://"):
				rest, at = text[8:], positionHostStart
			case strings.HasPrefix(lower, "http://"):
				rest, at = text[7:], positionHostStart
			case text[0] == '/': // Kept: "//" at its start would be refused as well
				rest, at = text, positionPath
			default:
				return 0, c.errorAt(n.pos, "a target starts with /, http:// or https://")
			}
		}
		if at == positionHostStart && rest != "" {
			if strings.IndexByte(hostStarters, rest[0]) != -1 && (from == positionStart || in&positions == positionHostStart) {
				return 0, c.errorAt(n.pos, "the target needs a host")
			}
			at = positionHost
		}
		if at == positionHost && strings.IndexByte(hostOf(rest), '\\') != -1 {
			// A browser ends the host there, and what was after it, the rest of the host for the rule of the labels,
			// was the path: "SUBDOMAIN + '.com\\.example.com'" went to the client's labels and ".com"
			return 0, c.errorAt(n.pos, `the host of a redirection can't have a \`)
		}
		if strings.Contains(rest, "..") || strings.Contains(rest, "//") {
			return 0, c.errorAt(n.pos, "a target can't have '..' or '//'")
		}
		out |= advancePosition(at, rest)
		if rest != "" { // Not after a scheme alone: its "//" is the scheme's
			switch rest[len(rest)-1] {
			case '/':
				out |= afterSlash
			case '.':
				out |= afterDot
			}
		}
	}
	if in&afterSlash != 0 && text[0] == '/' || in&afterDot != 0 && text[0] == '.' { // Joined to a text before it
		return 0, c.errorAt(n.pos, "a target can't have '..' or '//'")
	}
	if in&maybeAfterSlash != 0 && text[0] == '/' || in&maybeAfterDot != 0 && text[0] == '.' { // Where a value gives nothing
		c.valueJoinsTexts = true
	}
	if in&(afterLabels|afterLabelsDot|afterOneLabel|afterOneLabelDot) != 0 {
		host := hostOf(text)           // What of the text is still the host
		ended := len(host) < len(text) // A "/", "?" or "#" after it: the host ends in this text
		switch {
		case in&afterLabels != 0 && (host == "" || host[0] != '.'):
			return 0, c.errorAt(n.pos, labelsAtTheEnd)
		case in&afterLabels != 0 && host == ".":
			if len(text) > 1 { // "./x": the host ends with the labels and a "."
				return 0, c.errorAt(n.pos, labelsAtTheEnd)
			}
			out |= afterLabelsDot
		case in&afterLabels != 0 && !labelStart(host[1]), in&afterLabelsDot != 0 && (host == "" || !labelStart(host[0])):
			return 0, c.errorAt(n.pos, labelsAtTheEnd)
		}
		// One label after the labels and their "." may end the host, however its texts are written: "SUBDOMAIN + '.com'",
		// "SUBDOMAIN + '.' + 'com/'", "SUBDOMAIN + '.' + oneOf(EXT, ['com', 'org'])". Followed to where the host ends:
		// "SUBDOMAIN + '.app.' + DOMAIN" is a domain of the site's.
		if in&afterLabels != 0 && host != "." {
			out |= c.oneLabel(host[1:], ended)
		}
		if in&afterLabelsDot != 0 {
			out |= c.oneLabel(host, ended)
		}
		if in&afterOneLabel != 0 && (host == "" || host == "." || host[0] != '.') { // The same label goes on, or the host ends
			out |= c.oneLabel(host, ended)
		}
		if in&afterOneLabelDot != 0 && (host == "" || host[0] == ':') { // After its final ".", the host ends, or its port
			out |= c.oneLabel(host, ended)
		}
	}
	return out, nil
}

// oneLabel follows the host of a redirection after the labels that the client may choose and their ".": name is what
// of a text is still the host from there on, and ended whether the host ends in that text. With one label only where
// the host ends (without its port, nor the "." that may end a host, which is no label more), the visitor chooses the
// whole domain: it marks the warning. Where the host may go on in the next part, it returns what that part starts
// after.
func (c *checker) oneLabel(name string, ended bool) position {
	name, _, hasPort := strings.Cut(name, ":")
	if strings.IndexByte(strings.TrimSuffix(name, "."), '.') != -1 {
		return 0 // Another label: the rest of the host is written in the expression
	}
	if ended || hasPort {
		c.labelsOneLabel = true
		return 0
	}
	if strings.HasSuffix(name, ".") {
		return afterOneLabelDot
	}
	return afterOneLabel
}

// mayBeEmpty reports whether a value placed in a target (a variable, a header, a parameter or a cookie of the request,
// or what token, quoted and urlencode give) may give nothing for a request, which the evaluation drops: the texts
// around it then meet. DOMAIN, SITE, WILDCARD_DOMAIN, WILDCARD_SITE, REWRITE, FIRST_REQUEST, IP and METHOD always give
// something.
func mayBeEmpty(n *node) bool {
	if n.op != opVariable {
		return true
	}
	switch n.variable {
	case Domain, Site, WildcardDomain, WildcardSite, Rewrite, FirstRequest, IP, Method, Path:
		return false
	}
	return true
}

// hostOf is what of a text placed in the host of a redirection is still the host: up to a "/", "?" or "#".
func hostOf(text string) string {
	if end := strings.IndexAny(text, "/?#"); end != -1 {
		return text[:end]
	}
	return text
}

// advancePosition is where a text placed as it is from at leaves the next part: a "/" goes from the host to the
// path, a "?" from either to the query, and a "#" from any of them to the fragment, which nothing leaves. The caller
// places texts the same way.
func advancePosition(at position, text string) position {
	for i := 0; i < len(text) && at != positionFragment; i++ {
		switch text[i] {
		case '/':
			if at == positionHost {
				at = positionPath
			}
		case '?':
			at = positionQuery
		case '#':
			at = positionFragment
		}
	}
	return at
}
