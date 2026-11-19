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

// The grammar, from the lowest precedence to the highest:
//
//	expression  = or [ "?" expression ":" expression ]
//	or          = and { "||" and }
//	and         = comparison { "&&" comparison }
//	comparison  = sum [ ( "==" | "!=" | "in" ) sum ]
//	sum         = unary { "+" unary }
//	unary       = "!" unary | postfix
//	postfix     = primary { "." NAME "(" [ arguments ] ")" }
//	primary     = TEXT | NAME | NAME "(" [ arguments ] ")" | list | "(" expression ")"
//	list        = "[" [ TEXT { "," TEXT } ] "]"
//	arguments   = expression { "," expression }
//
// A TEXT is written between double or single quotes, with \\, \" and \' as its only escapes and no control
// characters. Spaces, tabs and line breaks separate the rest, and mean nothing.

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// op is what a node of an expression does.
type op uint8

const (
	opText op = iota + 1 // A text written in the expression
	opList               // A list of texts written in the expression
	opVariable
	opHTTPS
	opCondition // condition ? whenTrue : whenFalse
	opOr
	opAnd
	opNot
	opEqual
	opNotEqual
	opIn
	opConcat
	opHeader
	opQuery
	opCookie
	opOneOf
	opToken
	opQuoted
	opURLEncode
	opLower
	opUpper
	opStartsWith
	opEndsWith
	opContains
	opMatches
)

// functions are the functions an expression can call, by name.
var functions = map[string]op{
	"HEADER": opHeader, "QUERY": opQuery, "COOKIE": opCookie, "oneOf": opOneOf, "token": opToken,
	"quoted": opQuoted, "urlencode": opURLEncode, "lower": opLower, "upper": opUpper,
}

// methods are the methods of a text, by name: text.startsWith("…").
var methods = map[string]op{"startsWith": opStartsWith, "endsWith": opEndsWith, "contains": opContains, "matches": opMatches}

// node is an element of a compiled expression. Only data: two compilations of the same expression are equal.
type node struct {
	op       op
	pos      int            // Byte offset in the expression, for the errors
	name     string         // The name written: of the variable, the function or the method
	text     string         // opText; the name read by opHeader, opQuery and opCookie (set when checked)
	variable Variable       // opVariable
	list     []string       // opList
	pattern  *regexp.Regexp // opMatches: its pattern, compiled when checked
	args     []*node        // The operands, the arguments, or the receiver and the arguments of a method
}

// token is a piece of an expression: a text without its quotes and escapes, a name, or a symbol ("(", "||"…). The
// end of the expression is the symbol "".
type token struct {
	kind tokenKind
	text string
	pos  int // Byte offset in the expression
}

type tokenKind uint8

const (
	tokenSymbol tokenKind = iota
	tokenText
	tokenName
)

// The symbols of two characters, tried before those of one.
var twoCharSymbols = [...]string{"||", "&&", "==", "!="}

const oneCharSymbols = "()[],.?:!+"

// lexer cuts an expression into tokens.
type lexer struct {
	source string
	offset int
}

// errorAt is an error at a byte offset of the expression, given in characters from 1.
func errorAt(source string, offset int, message string) *Error {
	return &Error{Position: utf8.RuneCountInString(source[:min(offset, len(source))]) + 1, Message: message}
}

func (l *lexer) next() (token, *Error) {
	for l.offset < len(l.source) {
		if c := l.source[l.offset]; c != ' ' && c != '\t' && c != '\n' {
			break
		}
		l.offset++
	}
	start := l.offset
	if start == len(l.source) {
		return token{kind: tokenSymbol, pos: start}, nil
	}
	c := l.source[start]
	switch {
	case c == '\'' || c == '"':
		return l.text(c)
	case nameStart(c):
		end := start + 1
		for end < len(l.source) && (nameStart(l.source[end]) || l.source[end] >= '0' && l.source[end] <= '9') {
			end++
		}
		l.offset = end
		return token{kind: tokenName, text: l.source[start:end], pos: start}, nil
	}
	for _, symbol := range twoCharSymbols {
		if strings.HasPrefix(l.source[start:], symbol) {
			l.offset += len(symbol)
			return token{kind: tokenSymbol, text: symbol, pos: start}, nil
		}
	}
	if strings.IndexByte(oneCharSymbols, c) != -1 {
		l.offset++
		return token{kind: tokenSymbol, text: l.source[start : start+1], pos: start}, nil
	}
	if c < 0x20 || c == 0x7f {
		return token{}, errorAt(l.source, start, "the only control characters allowed are spaces: tab and line break")
	}
	r, _ := utf8.DecodeRuneInString(l.source[start:])
	message := "unexpected character " + strconv.QuoteRune(r)
	switch c {
	case '=':
		message += " (== compares)"
	case '|', '&':
		message += " (|| and && join conditions)"
	}
	return token{}, errorAt(l.source, start, message)
}

// text reads a text between quotes, which starts at the offset.
func (l *lexer) text(quote byte) (token, *Error) {
	start := l.offset
	var text strings.Builder
	for i := start + 1; i < len(l.source); {
		switch c := l.source[i]; {
		case c == quote:
			l.offset = i + 1
			return token{kind: tokenText, text: text.String(), pos: start}, nil
		case c == '\\':
			if i+1 < len(l.source) && strings.IndexByte(`\"'`, l.source[i+1]) != -1 {
				text.WriteByte(l.source[i+1])
				i += 2
				continue
			}
			return token{}, errorAt(l.source, i, `the only escapes in a text are \\, \" and \'`)
		case c < 0x20 || c == 0x7f:
			return token{}, errorAt(l.source, i, "a text can't have control characters, a line break included")
		default:
			text.WriteByte(c)
			i++
		}
	}
	return token{}, errorAt(l.source, start, "a text without its closing quote")
}

func nameStart(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }

// parser reads the grammar above into nodes, within the limits of nesting and elements.
type parser struct {
	lexer
	token token
	depth int
	nodes int
}

func parse(source string) (*node, *Error) {
	p := &parser{lexer: lexer{source: source}}
	if err := p.advance(); err != nil {
		return nil, err
	}
	root, err := p.expression()
	if err != nil {
		return nil, err
	}
	if !p.atEnd() {
		return nil, p.unexpected("expected the end")
	}
	return root, nil
}

func (p *parser) advance() *Error {
	t, err := p.lexer.next()
	if err != nil {
		return err
	}
	p.token = t
	return nil
}

func (p *parser) at(symbol string) bool {
	return p.token.kind == tokenSymbol && p.token.text == symbol && symbol != ""
}

func (p *parser) atEnd() bool { return p.token.kind == tokenSymbol && p.token.text == "" }

func (p *parser) expect(symbol string) *Error {
	if !p.at(symbol) {
		return p.unexpected("expected " + symbol)
	}
	return p.advance()
}

// unexpected is the error of a token that isn't what the grammar expects there.
func (p *parser) unexpected(expected string) *Error {
	found := p.token.text
	switch {
	case p.atEnd():
		found = "the end"
	case p.token.kind == tokenText:
		found = "a text"
	case p.token.kind == tokenSymbol:
		found = strconv.Quote(found)
	}
	return errorAt(p.source, p.token.pos, expected+", not "+found)
}

func (p *parser) node(operation op, pos int, args ...*node) (*node, *Error) {
	if p.nodes++; p.nodes > maxNodes {
		return nil, errorAt(p.source, pos, "more than "+strconv.Itoa(maxNodes)+" elements")
	}
	return &node{op: operation, pos: pos, args: args}, nil
}

// enter counts a level of nesting, which leave undoes.
func (p *parser) enter() *Error {
	if p.depth++; p.depth > maxDepth {
		return errorAt(p.source, p.token.pos, "more than "+strconv.Itoa(maxDepth)+" levels of nesting")
	}
	return nil
}

func (p *parser) leave() { p.depth-- }

func (p *parser) expression() (*node, *Error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	condition, err := p.or()
	if err != nil || !p.at("?") {
		return condition, err
	}
	pos := p.token.pos
	if err := p.advance(); err != nil {
		return nil, err
	}
	whenTrue, err := p.expression()
	if err != nil {
		return nil, err
	}
	if err := p.expect(":"); err != nil {
		return nil, err
	}
	whenFalse, err := p.expression()
	if err != nil {
		return nil, err
	}
	return p.node(opCondition, pos, condition, whenTrue, whenFalse)
}

// binary reads operands of next joined by symbol, from the left.
func (p *parser) binary(symbol string, operation op, next func() (*node, *Error)) (*node, *Error) {
	left, err := next()
	for err == nil && p.at(symbol) {
		pos := p.token.pos
		if err = p.advance(); err != nil {
			return nil, err
		}
		var right *node
		if right, err = next(); err != nil {
			return nil, err
		}
		left, err = p.node(operation, pos, left, right)
	}
	return left, err
}

func (p *parser) or() (*node, *Error)  { return p.binary("||", opOr, p.and) }
func (p *parser) and() (*node, *Error) { return p.binary("&&", opAnd, p.comparison) }
func (p *parser) sum() (*node, *Error) { return p.binary("+", opConcat, p.unary) }

func (p *parser) comparison() (*node, *Error) {
	left, err := p.sum()
	if err != nil {
		return nil, err
	}
	var operation op
	switch {
	case p.at("=="):
		operation = opEqual
	case p.at("!="):
		operation = opNotEqual
	case p.token.kind == tokenName && p.token.text == "in":
		operation = opIn
	default:
		return left, nil
	}
	pos := p.token.pos
	if err := p.advance(); err != nil {
		return nil, err
	}
	right, err := p.sum()
	if err != nil {
		return nil, err
	}
	return p.node(operation, pos, left, right)
}

func (p *parser) unary() (*node, *Error) {
	if !p.at("!") {
		return p.postfix()
	}
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	pos := p.token.pos
	if err := p.advance(); err != nil {
		return nil, err
	}
	operand, err := p.unary()
	if err != nil {
		return nil, err
	}
	return p.node(opNot, pos, operand)
}

func (p *parser) postfix() (*node, *Error) {
	receiver, err := p.primary()
	for err == nil && p.at(".") {
		if err = p.advance(); err != nil {
			return nil, err
		}
		if p.token.kind != tokenName {
			return nil, p.unexpected("expected the name of a method")
		}
		name, pos := p.token.text, p.token.pos
		operation, known := methods[name]
		if !known {
			return nil, errorAt(p.source, pos, "unknown method "+name+" (startsWith, endsWith, contains or matches)")
		}
		if err = p.advance(); err != nil {
			return nil, err
		}
		var args []*node
		if args, err = p.arguments(); err != nil {
			return nil, err
		}
		if receiver, err = p.node(operation, pos, append([]*node{receiver}, args...)...); err == nil {
			receiver.name = name
		}
	}
	return receiver, err
}

func (p *parser) primary() (*node, *Error) {
	t := p.token
	switch {
	case t.kind == tokenText:
		if err := p.advance(); err != nil {
			return nil, err
		}
		n, err := p.node(opText, t.pos)
		if err == nil {
			n.text = t.text
		}
		return n, err
	case t.kind == tokenName:
		if err := p.advance(); err != nil {
			return nil, err
		}
		if p.at("(") {
			operation, known := functions[t.text]
			if !known {
				return nil, errorAt(p.source, t.pos, "unknown function "+t.text)
			}
			args, err := p.arguments()
			if err != nil {
				return nil, err
			}
			n, err := p.node(operation, t.pos, args...)
			if err == nil {
				n.name = t.text
			}
			return n, err
		}
		if t.text == "HTTPS" {
			n, err := p.node(opHTTPS, t.pos)
			if err == nil {
				n.name = t.text
			}
			return n, err
		}
		if variable, known := variablesByName[t.text]; known {
			n, err := p.node(opVariable, t.pos)
			if err == nil {
				n.name, n.variable = t.text, variable
			}
			return n, err
		}
		if _, isFunction := functions[t.text]; isFunction {
			return nil, errorAt(p.source, t.pos, t.text+" is a function: "+t.text+"(…)")
		}
		return nil, errorAt(p.source, t.pos, "unknown name "+t.text)
	case p.at("["):
		return p.list()
	case p.at("("):
		if err := p.advance(); err != nil {
			return nil, err
		}
		inner, err := p.expression()
		if err != nil {
			return nil, err
		}
		return inner, p.expect(")")
	}
	return nil, p.unexpected("expected a text, a name, a list or (")
}

// arguments reads "(" [ arguments ] ")".
func (p *parser) arguments() ([]*node, *Error) {
	if err := p.expect("("); err != nil {
		return nil, err
	}
	var args []*node
	if p.at(")") {
		return args, p.advance()
	}
	for {
		arg, err := p.expression()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if !p.at(",") {
			break
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
	}
	return args, p.expect(")")
}

// list reads "[" [ TEXT { "," TEXT } ] "]".
func (p *parser) list() (*node, *Error) {
	pos := p.token.pos
	if err := p.advance(); err != nil {
		return nil, err
	}
	var items []string
	for !p.at("]") {
		if p.token.kind != tokenText {
			return nil, p.unexpected("expected a text written between quotes (a list has only those)")
		}
		if len(p.token.text) > maxListItem {
			return nil, errorAt(p.source, p.token.pos, "a text of a list longer than "+strconv.Itoa(maxListItem)+" bytes")
		}
		if len(items) == maxListItems {
			return nil, errorAt(p.source, p.token.pos, "more than "+strconv.Itoa(maxListItems)+" texts in a list")
		}
		items = append(items, p.token.text)
		if err := p.advance(); err != nil {
			return nil, err
		}
		if !p.at(",") {
			break
		}
		if err := p.advance(); err != nil {
			return nil, err
		}
	}
	if err := p.expect("]"); err != nil {
		return nil, err
	}
	n, err := p.node(opList, pos)
	if err == nil {
		n.list = items
	}
	return n, err
}
