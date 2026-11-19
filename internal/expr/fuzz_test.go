package expr

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// sameRequest answers every variable and every parameter with a, and every header and cookie with b.
type sameRequest struct {
	a, b  string
	https bool
}

func (r sameRequest) Variable(Variable) string { return r.a }
func (r sameRequest) Header(string) string     { return r.b }
func (r sameRequest) Query(string) string      { return r.a }
func (r sameRequest) Cookie(string) string     { return r.b }
func (r sameRequest) HTTPS() bool              { return r.https }

var fuzzSeeds = []string{
	`'no-cache'`,
	`EXT in ['js', 'css'] ? 'public, max-age=31536000' : 'no-cache'`,
	`oneOf(HEADER('Origin'), ['https://a.example', 'https://b.example'])`,
	`DIR == '/d' ? 'attachment; filename=' + quoted(FILE) : ''`,
	`token(QUERY('v')) + urlencode(HEADER('X')) + lower(DOMAIN) + upper(IP)`,
	`METHOD.matches('^(GET|HEAD)$') && !HTTPS || COOKIE('a').startsWith('b') ? 'x' : 'y'`,
	`'/es' + FIRST_REQUEST`,
	`'https://' + oneOf(QUERY('to'), ['a.example', 'b.example/x?']) + '/' + FILE`,
	`'https://' + DOMAIN + '?q=' + HEADER('Referer')`,
	`HEADER('Accept-Language').contains('es') ? '/es' + REWRITE_COMPLEMENT : ''`,
	`(((('a'))))`,
	`'a' +`,
	`"\'" + '\"'`,
}

// FuzzCompile: whatever the text, Compile ends without panicking, its errors give a position inside the text, and
// what it compiles is the same each time.
func FuzzCompile(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source string) {
		for _, options := range []Options{headerOptions, rewriteOptions} {
			program, err := Compile(source, options)
			if err != nil {
				var compileErr *Error
				if !errors.As(err, &compileErr) {
					t.Fatalf("%q: %v is not an *Error", source, err)
				}
				if compileErr.Position < 0 || compileErr.Position > utf8.RuneCountInString(source)+1 {
					t.Fatalf("%q: position %d outside the text", source, compileErr.Position)
				}
				continue
			}
			if program.Source() != source {
				t.Fatalf("Source %q of %q", program.Source(), source)
			}
			if again, err := Compile(source, options); err != nil || !reflect.DeepEqual(program, again) {
				t.Fatalf("%q compiles differently the second time: %v", source, err)
			}
		}
	})
}

// FuzzEvaluate: what Compile accepts keeps the rules of its target when evaluated, whatever the request sends. A
// header's value has no control characters (a tab aside), no spaces at its ends and 512 bytes at most; a rewrite's
// target starts with a text of the expression that is "/", "http://" or "https://", and no part the client chose
// falls in the host of a redirection.
func FuzzEvaluate(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed, "/a/b.js", "https://a.example", true)
		f.Add(seed, "x\r\nInjected: 1", "evil.example/x?", false)
	}
	f.Fuzz(func(t *testing.T, source string, a string, b string, https bool) {
		request := sameRequest{a: a, b: b, https: https}
		if program, err := Compile(source, headerOptions); err == nil {
			value, err := program.Header(request)
			switch {
			case err != nil && !errors.Is(err, ErrTooLong) && !errors.Is(err, ErrHeaderValue):
				t.Fatalf("%q: %v", source, err)
			case err != nil:
			case len(value) > MaxHeaderValue || value != strings.Trim(value, " \t"):
				t.Fatalf("%q gave %q", source, value)
			default:
				for i := 0; i < len(value); i++ {
					if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
						t.Fatalf("%q gave a control character: %q", source, value)
					}
				}
			}
		}
		program, err := Compile(source, rewriteOptions)
		if err != nil {
			return
		}
		parts, err := program.Rewrite(request)
		if err != nil {
			if !errors.Is(err, ErrTooLong) {
				t.Fatalf("%q: %v", source, err)
			}
			return
		}
		at := positionStart
		for i, part := range parts {
			if part.Text == "" {
				t.Fatalf("%q gave an empty part: %+v", source, parts)
			}
			if part.Class != Const {
				if at == positionStart || at == positionHost && part.Class != Config && part.Class != Host {
					t.Fatalf("%q placed part %d (%+v) where it can't go: %+v", source, i, part, parts)
				}
				continue
			}
			text := part.Text
			if at == positionStart {
				lower := strings.ToLower(text)
				switch {
				case strings.HasPrefix(lower, "https://"):
					text, at = text[8:], positionHost
				case strings.HasPrefix(lower, "http://"):
					text, at = text[7:], positionHost
				case text[0] == '/':
					text, at = text[1:], positionPath
				default:
					t.Fatalf("%q starts with %q", source, part.Text)
				}
			}
			at = advancePosition(at, text)
		}
	})
}
