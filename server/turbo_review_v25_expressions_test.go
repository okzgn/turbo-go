package server

// The tests of the findings about the expressions of the review of v2.5 (_revision/INFORME_REVISION_4cb626c.md,
// block 5).

import (
	"strconv"
	"strings"
	"testing"
)

// V2.5 review R-1: the expression of a rewrite is compiled once for each generation of the state, also with more of
// them than the cache of compileExpression keeps (1024): beyond, that cache was emptied whole, and every request
// compiled its expression again, under a mutex that every request took.
func TestV25R_R1_RewriteExpressionsCompiledOncePerGeneration(t *testing.T) {
	initForTest(t)
	const count = maxCompiledExpressions + 100
	rewrites := make(map[string]string, count)
	for i := 0; i < count; i++ {
		rewrites["/r"+strconv.Itoa(i)+"/"] = "='/t" + strconv.Itoa(i) + "/' + REWRITE_COMPLEMENT"
	}
	addSiteRewrites(t, rewrites)
	serverRequestLimits.CII.Store(1 << 40) // Not the limiter of requests per client
	base := startServer(t)
	request := func(i int) {
		if code, _, err := get(base, "/r"+strconv.Itoa(i)+"/x", nil); err != nil || code != 404 {
			t.Fatalf("/r%d/x: %d %v; expected the 404 of its target", i, code, err)
		}
	}
	for i := 0; i < count; i++ { // The first request of each, after the last change of the state
		request(i)
	}
	before := expressionCompiles.Load()
	for i := 0; i < count; i++ {
		request(i)
	}
	if compiled := expressionCompiles.Load() - before; compiled != 0 {
		t.Errorf("%d expressions compiled again for the second request of each of %d rewrites; expected none", compiled, count)
	}
}

// V2.5 review R-3 (decision D6): a redirection whose host is {SUBDOMAIN} or {FIRST_SUBDOMAIN} and one label only is
// accepted, with a warning: under a wildcard subdomain, the visitor chooses the whole domain.
func TestV25R_R3_SubdomainBeforeOneLabelIsWarnedOf(t *testing.T) {
	for target, warned := range map[string]bool{
		"S{SUBDOMAIN}.com/":            true,
		"H{FIRST_SUBDOMAIN}.net":       true,
		"S{SUBDOMAIN}.example.com/":    false,
		"S{SUBDOMAIN}.{DOMAIN}/":       false,
		"Sexample.com/{SUBDOMAIN}.com": false, // In the path
		"N/{SUBDOMAIN}.com":            false,
		"S{SUBDOMAIN}.com:8443/":       true, // With a port
		"S{SUBDOMAIN}.co.uk/":          false,
		"S{SUBDOMAIN}.com./":           true, // A final dot is no label more
	} {
		if labelsBeforeOneLabel(target) != warned {
			t.Errorf("labelsBeforeOneLabel(%q) = %v; expected %v", target, !warned, warned)
		}
	}
	initForTest(t)
	logs := captureLog(t)
	addSiteRewrites(t, map[string]string{"/away": "https://{SUBDOMAIN}.com/"})
	if !strings.Contains(logs.String(), "{SUBDOMAIN} and one label") {
		t.Errorf("no warning for a redirection to {SUBDOMAIN}.com:\n%s", logs.String())
	}
}
