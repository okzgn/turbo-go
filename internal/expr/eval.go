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

// The evaluation of a compiled expression for a request. Each element is evaluated at most once, and ? : only the
// branch it takes: the work follows the size of the expression and of the texts, each of them within MaxText.

import "strings"

// evaluateText evaluates an element that gives a text, as its parts, without the empty ones.
func evaluateText(n *node, r Request) ([]Part, error) {
	switch n.op {
	case opText:
		return single(n.text, Const, "")
	case opVariable:
		return single(r.Variable(n.variable), variables[n.variable].class, n.name)
	case opHeader:
		return single(r.Header(n.text), Raw, "")
	case opQuery:
		return single(r.Query(n.text), Raw, "")
	case opCookie:
		return single(r.Cookie(n.text), Raw, "")
	case opConcat:
		left, err := evaluateText(n.args[0], r)
		if err != nil {
			return nil, err
		}
		right, err := evaluateText(n.args[1], r)
		if err != nil {
			return nil, err
		}
		if length(left)+length(right) > MaxText {
			return nil, ErrTooLong
		}
		return append(left[:len(left):len(left)], right...), nil
	case opCondition:
		condition, err := evaluateBool(n.args[0], r)
		if err != nil {
			return nil, err
		}
		if condition {
			return evaluateText(n.args[1], r)
		}
		return evaluateText(n.args[2], r)
	case opOneOf:
		value, err := evaluateJoined(n.args[0], r)
		if err != nil {
			return nil, err
		}
		for _, item := range n.args[1].list {
			if item == value {
				return single(item, Const, "")
			}
		}
		return nil, nil
	case opToken:
		value, err := evaluateJoined(n.args[0], r)
		if err != nil || !isToken(value) {
			return nil, err
		}
		return single(value, Clean, "")
	case opQuoted:
		value, err := evaluateJoined(n.args[0], r)
		if err != nil {
			return nil, err
		}
		quoted, ok := quote(value)
		if !ok {
			return nil, nil
		}
		return single(quoted, Clean, "")
	case opURLEncode:
		value, err := evaluateJoined(n.args[0], r)
		if err != nil {
			return nil, err
		}
		parts, err := single(urlEncode(value), Clean, "")
		for i := range parts {
			parts[i].Encoded = true // Placed as it is in a target: encoded again, "%20" was "%2520"
		}
		return parts, err
	case opLower, opUpper:
		parts, err := evaluateText(n.args[0], r)
		if err != nil {
			return nil, err
		}
		changed := make([]Part, len(parts))
		for i, part := range parts {
			if n.op == opLower {
				part.Text = asciiLower(part.Text)
			} else {
				part.Text = asciiUpper(part.Text)
			}
			changed[i] = part // With its name and whether urlencode made it: a rewrite places them by those, in any capitals
		}
		return changed, nil
	}
	return nil, ErrFailed // Compile made no other element that gives a text
}

// single is a text as its parts: none for an empty one.
func single(text string, class Class, name string) ([]Part, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > MaxText {
		return nil, ErrTooLong
	}
	return []Part{{Text: text, Class: class, Name: name}}, nil
}

func length(parts []Part) int {
	total := 0
	for _, part := range parts {
		total += len(part.Text)
	}
	return total
}

// evaluateJoined evaluates an element that gives a text, as one text.
func evaluateJoined(n *node, r Request) (string, error) {
	parts, err := evaluateText(n, r)
	if err != nil {
		return "", err
	}
	if len(parts) == 1 {
		return parts[0].Text, nil
	}
	var text strings.Builder
	for _, part := range parts {
		text.WriteString(part.Text)
	}
	return text.String(), nil
}

// evaluateBool evaluates a condition. || and && only evaluate their right side when it decides.
func evaluateBool(n *node, r Request) (bool, error) {
	switch n.op {
	case opHTTPS:
		return r.HTTPS(), nil
	case opNot:
		value, err := evaluateBool(n.args[0], r)
		return !value, err
	case opOr, opAnd:
		left, err := evaluateBool(n.args[0], r)
		if err != nil || left == (n.op == opOr) {
			return left, err
		}
		return evaluateBool(n.args[1], r)
	case opCondition:
		condition, err := evaluateBool(n.args[0], r)
		if err != nil {
			return false, err
		}
		if condition {
			return evaluateBool(n.args[1], r)
		}
		return evaluateBool(n.args[2], r)
	case opEqual, opNotEqual:
		equal, err := evaluateEqual(n.args[0], n.args[1], r)
		return equal == (n.op == opEqual), err
	case opIn:
		value, err := evaluateJoined(n.args[0], r)
		if err != nil {
			return false, err
		}
		for _, item := range n.args[1].list {
			if item == value {
				return true, nil
			}
		}
		return false, nil
	case opStartsWith, opEndsWith, opContains:
		value, err := evaluateJoined(n.args[0], r)
		if err != nil {
			return false, err
		}
		other, err := evaluateJoined(n.args[1], r)
		if err != nil {
			return false, err
		}
		switch n.op {
		case opStartsWith:
			return strings.HasPrefix(value, other), nil
		case opEndsWith:
			return strings.HasSuffix(value, other), nil
		}
		return strings.Contains(value, other), nil
	case opMatches:
		value, err := evaluateJoined(n.args[0], r)
		if err != nil {
			return false, err
		}
		return n.pattern.MatchString(value), nil // RE2: linear in the text, which is within MaxText
	}
	return false, ErrFailed // Compile made no other element that gives a condition
}

// evaluateEqual compares two texts, or two conditions, as Compile checked they are.
func evaluateEqual(a *node, b *node, r Request) (bool, error) {
	if givesBool(a) {
		left, err := evaluateBool(a, r)
		if err != nil {
			return false, err
		}
		right, err := evaluateBool(b, r)
		return left == right, err
	}
	left, err := evaluateJoined(a, r)
	if err != nil {
		return false, err
	}
	right, err := evaluateJoined(b, r)
	return left == right, err
}

// givesBool reports whether a checked element gives a condition.
func givesBool(n *node) bool {
	switch n.op {
	case opHTTPS, opNot, opOr, opAnd, opEqual, opNotEqual, opIn, opStartsWith, opEndsWith, opContains, opMatches:
		return true
	case opCondition:
		return givesBool(n.args[1])
	}
	return false
}

// isToken reports whether value is a token for token(): 1 to 128 characters of [A-Za-z0-9._~-].
func isToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !unreserved(value[i]) {
			return false
		}
	}
	return true
}

// unreserved is a character that a URL never needs to encode.
func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '~' || c == '-'
}

// quote is value between double quotes, with its \ and " escaped, as a header's quoted-string; false if it has
// control characters, which no header can carry.
func quote(value string) (string, bool) {
	var quoted strings.Builder
	quoted.Grow(len(value) + 2)
	quoted.WriteByte('"')
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x20 || c == 0x7f {
			return "", false
		}
		if c == '\\' || c == '"' {
			quoted.WriteByte('\\')
		}
		quoted.WriteByte(c)
	}
	quoted.WriteByte('"')
	return quoted.String(), true
}

// urlEncode encodes every character of value but those of unreserved, as %XX.
func urlEncode(value string) string {
	const hex = "0123456789ABCDEF"
	var encoded strings.Builder
	encoded.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if c := value[i]; unreserved(c) {
			encoded.WriteByte(c)
		} else {
			encoded.WriteByte('%')
			encoded.WriteByte(hex[c>>4])
			encoded.WriteByte(hex[c&15])
		}
	}
	return encoded.String()
}

// asciiLower and asciiUpper change only the letters of ASCII, byte by byte: every other byte stays, also where the
// text isn't UTF-8 (strings.Map would turn those into U+FFFD).
func asciiLower(value string) string { return asciiCase(value, 'A', 'a') }

func asciiUpper(value string) string { return asciiCase(value, 'a', 'A') }

func asciiCase(value string, from byte, to byte) string {
	changed := []byte(nil)
	for i := 0; i < len(value); i++ {
		if c := value[i]; c >= from && c <= from+25 {
			if changed == nil {
				changed = []byte(value)
			}
			changed[i] = c - from + to
		}
	}
	if changed == nil {
		return value
	}
	return string(changed)
}
