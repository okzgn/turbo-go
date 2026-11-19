package server

// The tests of the findings about the rewrites and the expressions of the review of v2.5.0: each failed before its fix.

import (
	"os"
	"strings"
	"testing"

	"turbo/customNetHttp"
	"turbo/internal/expr"
)

// V2.5.0 review EX-1: the host of a redirection written as a text keeps the rule of the labels that the client may
// choose with the values of each request, as an expression does. "https://{SUBDOMAIN}.{FIRST_DOMAIN}/home" passes the
// check of what is written, but {FIRST_DOMAIN} and {FIRST_SITE} give nothing for a request that comes through no alias
// and no wildcard domain, and the host was the client's labels and a dot ("evil.test."): now it answers 500. Through
// an alias, where the keyword gives a domain, it redirects as before.
func TestR250_EX1_ATextTargetIsCheckedWithItsValues(t *testing.T) {
	dir := initForTest(t)
	logs := captureLog(t)
	for _, folder := range []string{"example.com/@", "example.com/#/@"} {
		if err := os.MkdirAll(dir+folder, 0755); err != nil {
			t.Fatal(err)
		}
	}
	loadConfig(t, dir, `{"^":{"v":"2"},"example.com":{"":{"&":{"alias.test":""}},"*":{"=":{`+
		`"/a":"https://{SUBDOMAIN}.{FIRST_DOMAIN}/home","/b":"https://{SUBDOMAIN}.{FIRST_SITE}","/c":"https://{SUBDOMAIN}.{FIRST_DOMAIN}:8443/x","/ok":"https://{SUBDOMAIN}.{DOMAIN}/home"}}}}`)
	if !strings.Contains(logs.String(), "these give nothing for a request that comes through no alias") {
		t.Errorf("no warning when the rewrite is read: %s", logs.String())
	}
	base := startServer(t)
	for _, path := range []string{"/a", "/b", "/c"} {
		for _, host := range []string{"evil.test.example.com", "evil.example.com"} {
			response, _, err := rawGet(base, host, path)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 500 || response.Header.Get("Location") != "" {
				t.Errorf("%s with Host %s: %d, Location %q; expected 500 without a redirection", path, host, response.StatusCode, response.Header.Get("Location"))
			}
		}
	}
	// The same labels with a domain of the site after them: the redirection that was meant
	if response, _, err := rawGet(base, "shop.example.com", "/ok"); err != nil || response.StatusCode != 302 || response.Header.Get("Location") != "https://shop.example.com/home" {
		t.Errorf("/ok: %v, %+v", err, response)
	}
	if !strings.Contains(logs.String(), "Rewrite whose host would end with labels that the client chose") {
		t.Errorf("no line in the log for the 500: %s", logs.String())
	}
	if strings.Contains(logs.String(), "evil.test") {
		t.Errorf("the client's host is in the log: %s", logs.String())
	}
}

// The values of each request decide: with what an alias or a wildcard domain gives after the labels, the host is
// kept; with nothing after them, it isn't.
func TestR250_EX1_TheHostOfATextTargetByItsValues(t *testing.T) {
	request := &customNetHttp.Request{RequestURI: "/a", Header: customNetHttp.Header{}}
	direct := siteMatch{siteDomain: "example.com", siteSubdomain: "*", domain: "example.com", subdomain: "evil.test"}
	alias := siteMatch{siteDomain: "example.com", siteSubdomain: "*", domain: "example.com", subdomain: "shop", firstDomain: "alias.test", firstSubdomain: "shop"}
	for _, c := range []struct {
		target string
		site   siteMatch
		want   string
		kept   bool
	}{
		{"S{SUBDOMAIN}.{FIRST_DOMAIN}/home", direct, "", false},
		{"S{SUBDOMAIN}.{FIRST_SITE}", direct, "", false},
		{"S{SUBDOMAIN}.{FIRST_DOMAIN}/home", alias, "Sshop.alias.test/home", true},
		{"S{SUBDOMAIN}.{DOMAIN}/home", direct, "Sevil.test.example.com/home", true},
		{"S{SUBDOMAIN}.shop.example.org/x", direct, "Sevil.test.shop.example.org/x", true},
		{"Swww.{DOMAIN}/x", direct, "Swww.example.com/x", true},
		{"N/{SUBDOMAIN}/x", direct, "N/evil.test/x", true}, // Not a host: nothing to keep
	} {
		got, kept := shortcutWordsChecked(request, c.target, c.site, "/a", "/a")
		if kept != c.kept || kept && got != c.want {
			t.Errorf("%s: %q, kept %v; expected %q, kept %v", c.target, got, kept, c.want, c.kept)
		}
	}
}

// V2.5.0 review EX-2: quoted isn't for Refresh either: a browser takes the URL of "0; url=\"…\"" without its quotes,
// so quoted left there the URL as the client sent it, and the page went where the client said.
func TestR250_EX2_QuotedIsNotForRefresh(t *testing.T) {
	for _, header := range []string{"Refresh", "refresh", "REFRESH"} {
		if _, err := expr.Compile(`'0; url=' + quoted(QUERY('next'))`, expressionOptions(expr.HeaderValue, header)); err == nil || !strings.Contains(err.Error(), "quoted can't be used in this header") {
			t.Errorf("%s: %v; expected quoted refused", header, err)
		}
	}
	for _, source := range []string{`'0; url=/' + urlencode(QUERY('next'))`, `'0; url=' + oneOf(QUERY('next'), ['/a', '/b'])`, `'5'`} {
		if _, err := expr.Compile(source, expressionOptions(expr.HeaderValue, "Refresh")); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
	if _, err := expr.Compile(`'attachment; filename=' + quoted(FILE)`, expressionOptions(expr.HeaderValue, "Content-Disposition")); err != nil {
		t.Errorf("quoted in Content-Disposition: %v", err)
	}
}

// V2.5.0 review EX-4: an expression whose host is SUBDOMAIN and one label gets the warning that the same target
// written as a text gets (decision D6 of the review of v2.5).
func TestR250_EX4_AnExpressionWithLabelsAndOneLabelIsWarnedOf(t *testing.T) {
	for source, want := range map[string]bool{
		`'https://' + SUBDOMAIN + '.com'`:                 true,
		`'https://' + SUBDOMAIN + '.com/x'`:               true,
		`'https://' + FIRST_SUBDOMAIN + '.net'`:           true,
		`'https://' + SUBDOMAIN + '.example.org'`:         false,
		`'https://' + SUBDOMAIN + '.' + DOMAIN + '/home'`: false,
		`'https://www.example.org/' + FILE`:               false,
	} {
		program, err := expr.Compile(source, expressionOptions(expr.RewriteTarget, ""))
		if err != nil {
			t.Errorf("%s: %v", source, err)
			continue
		}
		if program.LabelsBeforeOneLabel() != want {
			t.Errorf("%s: LabelsBeforeOneLabel %v; expected %v", source, program.LabelsBeforeOneLabel(), want)
		}
	}
	dir := initForTest(t)
	logs := captureLog(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"=":{"/a":"='https://' + SUBDOMAIN + '.com'"}}}}`)
	if !strings.Contains(logs.String(), "Rewrite whose host is SUBDOMAIN and one label") {
		t.Errorf("no warning for the expression: %s", logs.String())
	}
}
