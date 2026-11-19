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

// What the second review of v2.5 found in the language: each case failed before its fix.

import (
	"errors"
	"strings"
	"testing"
)

// The rules of a target that only the texts joined, or the end of the expression, break: a redirection without a
// host whatever it gives, "//" or ".." made of two texts, and a host that ends with the labels a wildcard lets the
// client choose ("https://" + SUBDOMAIN, with SUBDOMAIN "evil.example" of the host evil.example.mysite.com).
func TestTargetsJoinedTextsAndHostsEnd(t *testing.T) {
	const host, joined, labels = "the target needs a host", "a target can't have '..' or '//'", "can't end the host of a redirection"
	for _, c := range []struct {
		source   string
		message  string
		position int
	}{
		{"'https://'", host, 0},
		{"'HTTP://'", host, 0},
		{"'http://' + oneOf(QUERY('h'), [])", host, 0},
		{"'https://' + (HTTPS ? '' : '')", host, 0},
		{"HTTPS ? 'https://' : ''", host, 0},
		{"'/' + '/evil.example'", joined, 7},
		{"'/.' + './x'", joined, 8},
		{"'/a/' + (HTTPS ? '/b' : '')", joined, 18},
		{"'https://a.example/.' + './b'", joined, 25},
		{"'/' + oneOf(QUERY('x'), ['/evil'])", joined, 25},
		{"'/x' + oneOf(QUERY('x'), ['/', '']) + '/y'", joined, 39},
		{"'https://' + SUBDOMAIN + '/x'", labels, 26},
		{"'https://' + SUBDOMAIN", labels, 14},
		{"'https://' + FIRST_SUBDOMAIN + '.'", labels, 14},
		{"'https://' + SUBDOMAIN + '.' + '/x'", labels, 32},
		{"'https://' + SUBDOMAIN + './x'", labels, 26},
		{"'https://' + SUBDOMAIN + DOMAIN", labels, 26},
		{"'https://' + SUBDOMAIN + 'm'", labels, 26},
		{"'https://' + SUBDOMAIN + '.:8080'", labels, 26},
		{"'https://' + SUBDOMAIN + oneOf(QUERY('x'), ['.a.example'])", labels, 14},
		{"'https://' + lower(SUBDOMAIN) + '?x=1'", labels, 33},
	} {
		_, err := Compile(c.source, rewriteOptions)
		var compileErr *Error
		if !errors.As(err, &compileErr) || !strings.Contains(compileErr.Message, c.message) || compileErr.Position != c.position {
			t.Errorf("%s: %v; expected %q at %d", c.source, err, c.message, c.position)
		}
	}
	for _, source := range []string{
		"'https://' + SUBDOMAIN + '.new.example/' + REWRITE_COMPLEMENT",
		"'https://' + SUBDOMAIN + '.' + DOMAIN + '/x'",
		"'https://' + FIRST_SUBDOMAIN + '.' + FIRST_SUBDOMAIN + '.example'",
		"'https://' + oneOf(QUERY('to'), ['a.example', 'b.example']) + '/x'",
		"'/a/' + SUBDOMAIN + '/b'",
		"'/' + FILE + '/x'",
		"'/a.' + 'b'",
		"HTTPS ? '' : '/x'",
	} {
		if _, err := Compile(source, rewriteOptions); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
	// What a host made of labels and a "." gives, part by part: the caller checks it again as it places them
	got, err := mustCompile(t, "'https://' + SUBDOMAIN + '.' + DOMAIN", rewriteOptions).Rewrite(&fakeRequest{vars: map[Variable]string{Subdomain: "a.b", Domain: "example.com"}})
	if err != nil || len(got) != 4 || got[1].Class != Labels || got[3].Class != Host {
		t.Errorf("labels, a dot and a host: %+v, %v", got, err)
	}
}

// quoted keeps a text together only where the header's grammar has quoted texts: in Set-Cookie a ";" inside the
// quotes still starts an attribute ("lang=\"x; Domain=example.com\""), and Content-Security-Policy has no quoted texts
// at all. Compiled for such a header (NoQuoted), it is refused where it reaches the value.
func TestQuotedOnlyWhereQuotesHold(t *testing.T) {
	noQuoted := headerOptions
	noQuoted.NoQuoted = true
	source := "'lang=' + quoted(QUERY('l'))"
	if _, err := Compile(source, headerOptions); err != nil {
		t.Errorf("quoted in a header that keeps it together: %v", err)
	}
	_, err := Compile(source, noQuoted)
	var compileErr *Error
	if !errors.As(err, &compileErr) || !strings.Contains(compileErr.Message, "quoted can't be used in this header") || compileErr.Position != 11 {
		t.Errorf("quoted in a Set-Cookie: %v", err)
	}
	if _, err := Compile(`quoted(FILE) == '"a"' ? 'x' : token(QUERY('l'))`, noQuoted); err != nil {
		t.Errorf("quoted in a condition, and token in the value: %v", err)
	}
}
