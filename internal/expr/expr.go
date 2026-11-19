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

// Package expr is the language of the expressions that compute, for each request, the value of a site's header or
// the target of a rewrite: a subset of CEL (Common Expression Language) without loops, variables or functions of its
// own, so that every expression ends and its cost follows its size. It knows nothing of HTTP or of Turbo's state: it
// reads a request only through Request, and it has no access to the disk, the network or the clock.
//
// Every text an expression computes is a list of parts, each with the class of where it comes from (Class). What a
// part may become depends on its class: a header never carries a part of the request as it came, and the host of a
// redirection is never one the client chose. Compile refuses what could break those rules, and the evaluation checks
// them again.
package expr

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Target is what an expression computes.
type Target uint8

const (
	HeaderValue   Target = iota + 1 // The value of a response header: "" sends none
	RewriteTarget                   // The target of a rewrite ("/…", "http://…" or "https://…"): "" is no rewrite
)

// Class is where a text comes from, which decides where it may go.
type Class uint8

const (
	Const  Class = iota // Written in the expression: its texts, the one oneOf chooses among those, lower and upper of them
	Config              // From the configuration: the wildcards of the site, and the key of the rewrite that matched
	Host                // A host name that Turbo validated, or an IP address
	Labels              // The labels of such a host before its domain, which a wildcard subdomain lets the client choose
	Clean               // Made safe for a header: the client's IP, and what token, quoted and urlencode give
	Raw                 // As the request sent it
)

// Part is a piece of the text an expression gives, with its class. Name is the variable it is, or that lower or upper
// changed, as it came: a rewrite places some by their names (REWRITE_COMPLEMENT); "" otherwise. Encoded says that
// urlencode made it (also once lower or upper changed it): it has only the characters that a URL never encodes and
// %XX, and a rewrite places it in a path or a query as it is.
type Part struct {
	Text    string
	Class   Class
	Name    string
	Encoded bool
}

// Variable is a value of the request that an expression reads by its name.
type Variable uint8

const (
	WildcardDomain Variable = iota + 1
	WildcardSubdomain
	WildcardSite
	Rewrite
	Domain
	Subdomain
	Site
	FirstDomain
	FirstSubdomain
	FirstSite
	IP
	FirstRequest
	FirstQuery
	Dir
	File
	Ext
	RewriteComplement
	Path
	Method
)

// variableInfo is a variable's name in the expressions, its class and whether only headers have it.
type variableInfo struct {
	name       string
	class      Class
	headerOnly bool
}

var variables = [...]variableInfo{
	WildcardDomain:    {"WILDCARD_DOMAIN", Config, false},
	WildcardSubdomain: {"WILDCARD_SUBDOMAIN", Config, false},
	WildcardSite:      {"WILDCARD_SITE", Config, false},
	Rewrite:           {"REWRITE", Config, false},
	Domain:            {"DOMAIN", Host, false},
	Subdomain:         {"SUBDOMAIN", Labels, false},
	Site:              {"SITE", Host, false},
	FirstDomain:       {"FIRST_DOMAIN", Host, false},
	FirstSubdomain:    {"FIRST_SUBDOMAIN", Labels, false},
	FirstSite:         {"FIRST_SITE", Host, false},
	IP:                {"IP", Clean, false},
	FirstRequest:      {"FIRST_REQUEST", Raw, false},
	FirstQuery:        {"FIRST_QUERY", Raw, false},
	Dir:               {"DIR", Raw, false},
	File:              {"FILE", Raw, false},
	Ext:               {"EXT", Raw, false},
	RewriteComplement: {"REWRITE_COMPLEMENT", Raw, false},
	Path:              {"PATH", Raw, true},
	Method:            {"METHOD", Raw, false},
}

// variablesByName finds a variable by its name in the expressions.
var variablesByName = func() map[string]Variable {
	byName := make(map[string]Variable, len(variables))
	for v, info := range variables {
		if info.name != "" {
			byName[info.name] = Variable(v)
		}
	}
	return byName
}()

// Name is the name of a variable in the expressions ("DOMAIN"), or "" for none.
func (v Variable) Name() string {
	if int(v) < len(variables) {
		return variables[v].name
	}
	return ""
}

// ClassOf is the class of the variable named name ("DOMAIN"), and whether there is one: the targets of the rewrites
// written as a text place their keywords, which have the same names, by the same rules.
func ClassOf(name string) (Class, bool) {
	v, found := variablesByName[name]
	if !found {
		return 0, false
	}
	return variables[v].class, true
}

// Request is what an expression reads of a request. Each method returns "" (or false) for what isn't there.
type Request interface {
	Variable(v Variable) string
	Header(name string) string // The values of the header name (any case), joined with ", "
	Query(name string) string  // The first value of the parameter name of the query, decoded
	Cookie(name string) string // The value of the first cookie name
	HTTPS() bool
}

// Options are what an expression is compiled for.
type Options struct {
	Target Target
	// UnreadableHeaders and UnreadableCookies can't be read, in any case: the credentials of the client and those of
	// Turbo's panel, which an expression could otherwise copy into a header or a redirection.
	UnreadableHeaders []string
	UnreadableCookies []string
	// NoQuoted refuses quoted in the value of a header whose grammar doesn't keep a quoted text together, where a ";"
	// or a space inside the quotes would still end the value (Set-Cookie, Content-Security-Policy).
	NoQuoted bool
	// NoLabels refuses, in the value of a header whose URL a browser follows (Refresh, Location, Content-Location),
	// the variables of the class Labels (SUBDOMAIN, FIRST_SUBDOMAIN), which a wildcard subdomain lets the client
	// choose: also through token, urlencode, quoted, lower and upper, and in either branch of ? :. oneOf still takes
	// them (it gives a text of its list), and so does a condition. The host of a redirection has its rule only in
	// the targets of the rewrites; in such a header the client chose where its visitors went.
	NoLabels bool
}

// The limits of an expression.
const (
	MaxSource      = 2048    // Bytes of an expression
	MaxText        = 8 << 10 // Bytes of a text while it is computed
	MaxHeaderValue = 512     // Bytes of the value of a header, as for a header written as it is
	maxDepth       = 32      // Levels of nesting: parentheses, arguments, "!" and "? :"
	maxNodes       = 512     // Elements: texts, names, operators and calls
	maxListItems   = 64      // Texts of a list
	maxListItem    = 512     // Bytes of each
	maxPattern     = 256     // Bytes of the pattern of matches
	maxPatternCost = 1000    // Instructions of the patterns of an expression, in all, as regexp compiles them
	maxName        = 128     // Bytes of the name that HEADER, QUERY or COOKIE read
)

// Error is why an expression can't be compiled: its message and where it was found (in characters, from 1), or 0
// for the whole expression.
type Error struct {
	Position int
	Message  string
}

func (e *Error) Error() string {
	if e.Position > 0 {
		return "Expression: " + e.Message + " (position " + strconv.Itoa(e.Position) + ")"
	}
	return "Expression: " + e.Message
}

// The errors of an evaluation: the request is answered with an error, never with the text of the expression.
var (
	ErrTooLong     = errors.New("expression: a text longer than 8 KiB")
	ErrHeaderValue = errors.New("expression: a value longer than 512 bytes, or with control characters, can't be a header's")
	ErrFailed      = errors.New("expression: the evaluation failed")
	ErrTarget      = errors.New("expression: evaluated for another target than the one it was compiled for")
)

// Program is a compiled expression. Nothing changes it once it is made: requests can share it. It is only data (no
// functions inside), so that two compilations of the same expression are equal.
type Program struct {
	source  string
	target  Target
	root    *node
	headers []string
	cookies bool
	// The host of a redirection may be SUBDOMAIN or FIRST_SUBDOMAIN, a "." and one label of a text of the expression
	labelsOneLabel bool
	// The host of a redirection may be SUBDOMAIN or FIRST_SUBDOMAIN, a "." and FIRST_DOMAIN or FIRST_SITE
	labelsAliasName bool
}

// LabelsBeforeOneLabel reports whether the target of a rewrite may have, as the host of a redirection, SUBDOMAIN or
// FIRST_SUBDOMAIN and then a text with a "." and one label only ("SUBDOMAIN + '.com'"): under a wildcard subdomain the
// visitor chooses that label's domain whole (evil.yoursite.net to evil.com). It compiles, as a site may want it with
// a suffix of its own; the caller may warn of it.
func (p *Program) LabelsBeforeOneLabel() bool { return p.labelsOneLabel }

// LabelsBeforeAnAliasName reports whether the target of a rewrite may have, as the host of a redirection, SUBDOMAIN
// or FIRST_SUBDOMAIN, a "." and FIRST_DOMAIN or FIRST_SITE, which give nothing for a request that comes through no
// alias and no wildcard domain: such a request answers 500, as the client's labels and a "." would be the host. It
// compiles, as through an alias it is what is meant; the caller may warn of it, as for a target written as a text.
func (p *Program) LabelsBeforeAnAliasName() bool { return p.labelsAliasName }

// Source is the expression as it was written.
func (p *Program) Source() string { return p.source }

// Target is what the expression was compiled for.
func (p *Program) Target() Target { return p.target }

// ReadsHeaders are the headers of the request that the expression reads, as written in it, each once (in any
// case): a response that depends on them says so in Vary.
func (p *Program) ReadsHeaders() []string { return append([]string(nil), p.headers...) }

// ReadsCookies reports whether the expression reads a cookie (Vary: Cookie).
func (p *Program) ReadsCookies() bool { return p.cookies }

// Compile reads an expression for options.Target. What could break the rules of its target is refused here, with the
// position of the part that would: an expression that compiles can only fail when evaluated by a text too long or,
// for a header, a value too long.
func Compile(source string, options Options) (*Program, error) {
	if options.Target != HeaderValue && options.Target != RewriteTarget {
		return nil, ErrTarget
	}
	if len(source) > MaxSource {
		return nil, &Error{Message: "longer than " + strconv.Itoa(MaxSource) + " bytes"}
	}
	if !utf8.ValidString(source) {
		return nil, &Error{Message: "invalid UTF-8"}
	}
	root, err := parse(source)
	if err != nil {
		return nil, err
	}
	c := &checker{source: source, options: options}
	result, err := c.kindOf(root)
	if err != nil {
		return nil, err
	}
	if result != kindText {
		return nil, c.errorAt(root.pos, "the expression must give a text, not a "+result.String())
	}
	if options.Target == HeaderValue {
		err = c.headerParts(root)
	} else {
		err = c.rewriteParts(root)
	}
	if err != nil {
		return nil, err
	}
	return &Program{source: source, target: options.Target, root: root, headers: c.headers, cookies: c.cookies, labelsOneLabel: c.labelsOneLabel, labelsAliasName: c.labelsAliasName}, nil
}

// Header evaluates a header expression for r: the value of the header, without the spaces and tabs at its ends, or
// "" not to send it.
func (p *Program) Header(r Request) (value string, err error) {
	if p.target != HeaderValue {
		return "", ErrTarget
	}
	parts, err := p.evaluate(r)
	if err != nil {
		return "", err
	}
	var text strings.Builder
	for _, part := range parts {
		if part.Class == Raw { // Compile refuses it: never sent, whatever happened
			return "", ErrFailed
		}
		text.WriteString(part.Text)
	}
	value = strings.Trim(text.String(), " \t")
	if len(value) > MaxHeaderValue {
		return "", ErrHeaderValue
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return "", ErrHeaderValue
		}
	}
	return value, nil
}

// Rewrite evaluates a rewrite expression for r: the parts of its target, without the empty ones. None means that
// the rewrite doesn't apply to r. Where each part goes, and how it is encoded there, is the caller's: Compile has
// checked that the first part is a text of the expression that starts the target, and that no part the client
// chose can fall in the host of a redirection, which the caller checks again as it places them.
func (p *Program) Rewrite(r Request) ([]Part, error) {
	if p.target != RewriteTarget {
		return nil, ErrTarget
	}
	return p.evaluate(r)
}

// evaluate computes the text of the expression. A panic (which no expression should cause) is an error of the
// evaluation: a request is answered while Turbo holds its lock.
func (p *Program) evaluate(r Request) (parts []Part, err error) {
	defer func() {
		if recover() != nil {
			parts, err = nil, ErrFailed
		}
	}()
	return evaluateText(p.root, r)
}
