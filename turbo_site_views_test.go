package main

// Review of 6046dbe (R6), O-2: what a site serves its requests with (its MIME types, preprocessors, headers and
// indexes) is copied once after each change of the shared state, not for each request.

import (
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// viewSite leaves view.test with a MIME type, a header, a preprocessor and two indexes, and bare.test with nothing,
// and returns how a request for view.test is resolved.
func viewSite(t *testing.T) func() *servePlan {
	t.Helper()
	initForTest(t)
	withGlobalLock(func() {
		constructSiteWithoutIndex("view.test", "")
		constructSiteWithoutIndex("bare.test", "") // Without settings
		for kind, entry := range map[string][2]string{"$": {"css", "text/x-view"}, ".": {"X-View", "first"}, "?": {"cgi", toolPath("cgiecho")}, "-": {"index.html", "1"}} {
			if ok, msg := subdomainContentCheckers[kind](true, map[string]interface{}{entry[0]: entry[1]}, true, "view.test", ""); !ok {
				t.Fatalf("%s: %s", kind, msg)
			}
		}
		addIndex("view.test", "start.html")
	})
	return func() *servePlan {
		var plan *servePlan
		request := benchRequest("view.test", "/a.css", "203.0.113.9:40000")
		recorder := &responseRecorder{}
		held := newHeldResponse(recorder)
		withReadLock(func() { plan = resolveRequest(false, held, request, &acmeLookup{}) })
		if plan == nil {
			t.Fatalf("no plan for view.test: %d", held.status)
		}
		return plan
	}
}

// samePlanMaps says whether two plans have the very same maps and indexes, not copies.
func samePlanMaps(a, b *servePlan) bool {
	same := func(x, y map[string]string) bool { return reflect.ValueOf(x).Pointer() == reflect.ValueOf(y).Pointer() }
	return same(a.mimeTypes, b.mimeTypes) && same(a.headers, b.headers) && same(a.preprocessors, b.preprocessors) && &a.indexes[0] == &b.indexes[0]
}

// R6 O-2: the requests of a site between two changes of the state share what the site serves with; a change, of that
// site or of anything else, makes the next request copy it again, with what the state says then.
func TestR6_O2_SiteViewKeptBetweenWriteLocks(t *testing.T) {
	resolve := viewSite(t)
	first, second := resolve(), resolve()
	if first.mimeTypes["css"] != "text/x-view" || first.headers["X-View"] != "first" || first.preprocessors["cgi"] == "" || !reflect.DeepEqual(first.indexes, []string{"index.html", "start.html"}) {
		t.Fatalf("the plan of view.test: %+v", first)
	}
	if !samePlanMaps(first, second) {
		t.Error("two requests of a site, with nothing changed between them, got a copy each of what it serves with")
	}

	if ok, msg := lockedCheck(func() (bool, string) {
		return subdomainContentCheckers["."](true, map[string]interface{}{"X-View": "second"}, false, "view.test", "")
	}); !ok {
		t.Fatal(msg)
	}
	third := resolve()
	if third.headers["X-View"] != "second" {
		t.Errorf("after changing the header: %q; expected the new value", third.headers["X-View"])
	}
	if first.headers["X-View"] != "first" {
		t.Errorf("the plan of a request made before the change now has %q: it is served with what it was resolved with", first.headers["X-View"])
	}
	withGlobalLock(func() { delete(indexFiles["view.test"], "start.html") })
	if fourth := resolve(); !reflect.DeepEqual(fourth.indexes, []string{"index.html"}) || samePlanMaps(third, fourth) {
		t.Errorf("after removing an index: %v; expected it gone, in a new copy", fourth.indexes)
	}
	withGlobalLock(func() {}) // Nothing changed: copied again all the same, as nothing says what a write lock did
	if a, b := resolve(), resolve(); !samePlanMaps(a, b) || !reflect.DeepEqual(a.indexes, []string{"index.html"}) {
		t.Errorf("after a write lock that changed nothing: %v, shared %v", a.indexes, samePlanMaps(a, b))
	}

	// A site without settings has no maps to share, as before
	localhost := benchRequest("localhost", "/", "203.0.113.9:40000")
	var plan *servePlan
	withReadLock(func() { plan = resolveRequest(false, newHeldResponse(&responseRecorder{}), localhost, &acmeLookup{}) })
	if plan == nil || plan.mimeTypes != nil || plan.headers != nil || plan.preprocessors != nil || !reflect.DeepEqual(plan.indexes, []string{"index.html"}) {
		t.Errorf("the plan of localhost: %+v", plan)
	}
}

// R6 O-2: who has the write lock gets what the state says at that moment, and leaves nothing kept for the others.
func TestR6_O2_SiteViewUnderTheWriteLock(t *testing.T) {
	resolve := viewSite(t)
	before := resolve()
	withGlobalLock(func() {
		customHeaders["view.test"]["X-View"] = "while locked"
		if view := siteViewOf("view.test"); view.headers["X-View"] != "while locked" {
			t.Errorf("under the write lock, after a change: %q", view.headers["X-View"])
		}
		customHeaders["view.test"]["X-View"] = "at the end"
		if view := siteViewOf("view.test"); view.headers["X-View"] != "at the end" {
			t.Errorf("under the write lock, after another change: %q", view.headers["X-View"])
		}
	})
	if after := resolve(); after.headers["X-View"] != "at the end" || before.headers["X-View"] != "first" {
		t.Errorf("after the write lock: %q (and the plan of before, %q)", after.headers["X-View"], before.headers["X-View"])
	}
}

// R6 O-2: the tests would notice a site changed without the write lock, which no request would see: the check that
// every test runs with (checkKeptView) counts the view kept that the state no longer gives.
func TestR6_O2_AChangeWithoutTheWriteLockIsNoticed(t *testing.T) {
	if keptViewCheck == nil {
		t.Skip("the views aren't checked in this run")
	}
	resolve := viewSite(t)
	resolve()
	customHeaders["view.test"]["X-View"] = "without the lock" // Only here: nothing else is running
	stale := resolve()
	counted := staleSiteViews.Swap(0)
	if stale.headers["X-View"] != "first" || counted != 1 {
		t.Errorf("a header changed without the write lock: served %q, and %d views counted as stale; expected the one kept, counted once", stale.headers["X-View"], counted)
	}
	withGlobalLock(func() {})
	if fresh := resolve(); fresh.headers["X-View"] != "without the lock" || staleSiteViews.Load() != 0 {
		t.Errorf("after a write lock: %q, %d stale", fresh.headers["X-View"], staleSiteViews.Load())
	}
}

// R6 O-2: with requests in parallel, each change that the panel makes to a site is in the next request that starts
// after it, and no request gets a mix that the site never had.
func TestR6_O2_SiteViewsWhileThePanelChangesTheSite(t *testing.T) {
	resolve := viewSite(t)
	const changes = 300
	var stop atomic.Bool
	var readers sync.WaitGroup
	for reader := 0; reader < 6; reader++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				plan := resolve()
				// Each change sets the header and the MIME type to the same number: one without the other is a mix
				if header, mime := plan.headers["X-View"], plan.mimeTypes["css"]; header != "first" && "text/x-"+header != mime {
					t.Errorf("a request got the header %q with the MIME type %q", header, mime)
					return
				}
			}
		}()
	}
	for change := 1; change <= changes; change++ {
		number := strconv.Itoa(change)
		if ok, msg := lockedCheck(func() (bool, string) {
			if ok, msg := subdomainContentCheckers["$"](true, map[string]interface{}{"css": "text/x-" + number}, false, "view.test", ""); !ok {
				return false, msg
			}
			return subdomainContentCheckers["."](true, map[string]interface{}{"X-View": number}, false, "view.test", "")
		}); !ok {
			t.Fatal(msg)
		}
		if plan := resolve(); plan.headers["X-View"] != number || plan.mimeTypes["css"] != "text/x-"+number {
			t.Fatalf("after change %s: header %q, MIME type %q", number, plan.headers["X-View"], plan.mimeTypes["css"])
		}
	}
	stop.Store(true)
	readers.Wait()
}

// R6 O-2: resolving a request of a site with settings no longer copies them: it costs what resolving one of a site
// without settings does.
func TestR6_O2_ResolvingDoesNotCopyTheSettings(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates on its own")
	}
	resolve := viewSite(t)
	check := keptViewCheck
	keptViewCheck = nil // It makes each view again
	defer func() { keptViewCheck = check }()
	resolve()
	request := benchRequest("bare.test", "/a.css", "203.0.113.9:40000")
	plain := testing.AllocsPerRun(200, func() {
		withReadLock(func() { resolveRequest(false, newHeldResponse(&responseRecorder{}), request, &acmeLookup{}) })
	})
	request = benchRequest("view.test", "/a.css", "203.0.113.9:40000")
	withSettings := testing.AllocsPerRun(200, func() {
		withReadLock(func() { resolveRequest(false, newHeldResponse(&responseRecorder{}), request, &acmeLookup{}) })
	})
	if withSettings > plain {
		t.Errorf("resolving a request of a site with settings: %.0f allocations, and %.0f for one without; expected the same", withSettings, plain)
	}
}
