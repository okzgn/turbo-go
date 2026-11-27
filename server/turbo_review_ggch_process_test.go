package server

// The tests of the findings about the processes, the certificates and the limiter of the external review of v2.5.2
// (GGCH): each failed before its fix.

import (
	"os"
	"strings"
	"testing"
	"time"
)

// GGCH H-11: stop waits, within its time, for the start of a worker that its request gave up on, and that worker
// ends: only the idle workers were ended, and Turbo could stop with one still starting, in a group of its own.
func TestGGCH_H11_StopWaitsForAStartInFlight(t *testing.T) {
	_, base := setupDX(t, dxVariant(t, "slowgreet-stop"))
	if ok, message := setting("WT", "200ms"); !ok {
		t.Fatal(message)
	}
	if code, _ := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 504 {
		t.Fatalf("the request that started a slow worker: %d; expected 504", code)
	}
	began := time.Now()
	dxWorkers.stop(10 * time.Second)
	elapsed := time.Since(began)
	dxWorkers.mutex.Lock()
	starting, pools := dxWorkers.starting, len(dxWorkers.pools)
	dxWorkers.mutex.Unlock()
	if starting != 0 || pools != 0 || elapsed < time.Second {
		t.Errorf("after stop: %d starts in flight, %d programs, after %v; expected stop to wait for the start (it greets 2.5 s after it began)", starting, pools, elapsed)
	}
}

// Review of v2.5.3 (B-2): a start that its request gave up on, still going when the wait of stop is over, is killed
// then: a worker slower to greet than that wait (or that doesn't end when its input closes) went on after Turbo.
func TestGGCH_H11_StopKillsAStartLeftAtItsEnd(t *testing.T) {
	_, base := setupDX(t, dxVariant(t, "slowgreet-stubborn-stop"))
	if ok, message := setting("WT", "200ms"); !ok {
		t.Fatal(message)
	}
	if code, _ := dxRequest(t, "GET", base, "/x.dx", nil, nil); code != 504 {
		t.Fatalf("the request that started a slow worker: %d; expected 504", code)
	}
	var starting *dxWorker
	for wait := time.Now().Add(2 * time.Second); starting == nil && time.Now().Before(wait); time.Sleep(10 * time.Millisecond) {
		dxWorkers.mutex.Lock()
		for worker := range dxWorkers.unsettled {
			starting = worker
		}
		dxWorkers.mutex.Unlock()
	}
	if starting == nil {
		t.Fatal("no start in flight")
	}
	began := time.Now()
	dxWorkers.stop(500 * time.Millisecond) // It greets 2.5 s after it began, and goes on 60 s after its input closes
	if elapsed := time.Since(began); elapsed > 2*time.Second {
		t.Errorf("stop took %v", elapsed)
	}
	select {
	case <-starting.process.Exited():
	case <-time.After(2 * time.Second):
		t.Error("the worker still starting when stop ended goes on")
		starting.kill()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		dxWorkers.mutex.Lock()
		count, unsettled := dxWorkers.starting, len(dxWorkers.unsettled)
		dxWorkers.mutex.Unlock()
		if count == 0 && unsettled == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after stop: %d starts in flight, %d unsettled", count, unsettled)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// sameSiteInNewDirectory does what setM does to the sites (resetSitesLocked), and makes localhost again with an e-mail,
// as the site of the same name of another sites directory. Callers hold the global lock.
func sameSiteInNewDirectory() {
	resetSitesLocked()
	constructSiteLocked("localhost", "")
	siteSSLConfig["localhost"].email = "admin@new-directory.test"
}

// GGCH H-10: a retry of Certbot waiting when the sites directory changes (setM) doesn't run: it had the folders of the
// directory left, and ran for a site of the same name of the new one, whose certificate went to the old folders.
func TestGGCH_H10_ARetryOfTheSitesDirectoryLeftIsDropped(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	initForTest(t)
	globalMutex.Lock()
	currentCertDomain = "other.test" // Another issuance in progress
	siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@localhost.test", "")
	sameSiteInNewDirectory()
	globalMutex.Unlock()
	time.Sleep(300 * time.Millisecond)
	withGlobalLock(func() { currentCertDomain = "" })
	time.Sleep(500 * time.Millisecond)
	waitIdle()
	if data, _ := os.ReadFile(logf); strings.Contains(string(data), `"-d" "localhost"`) {
		t.Errorf("Certbot ran for the sites directory left:\n%s", data)
	}
}

// GGCH H-10: an attempt of Certbot that ends after the sites directory changed isn't put in use there: its files went
// to the folders of the directory left.
func TestGGCH_H10_AnAttemptOfTheSitesDirectoryLeftIsNotApplied(t *testing.T) {
	useFakeCertbot(t, "ok")
	t.Setenv("FAKE_CERTBOT_DELAY", "800")
	initForTest(t)
	globalMutex.Lock()
	siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@localhost.test", "")
	globalMutex.Unlock()
	time.Sleep(200 * time.Millisecond) // Certbot works
	withGlobalLock(sameSiteInNewDirectory)
	waitIdle()
	globalMutex.RLock()
	state := siteSSLConfig["localhost"].asSection()["C"]
	globalMutex.RUnlock()
	if state == true {
		t.Errorf("the certificate of the directory left was put in the state of the site of the new one: C = %v", state)
	}
}

// Review of v2.5.3 (B-8): an attempt of Certbot of the sites directory left (setM) isn't that of the site of the same
// name of the new one: "Create SSL" answered "being processed" and queued nothing (the result of that attempt isn't
// applied), and "Delete SSL" was refused.
func TestGGCH_H10_AnAttemptOfTheDirectoryLeftIsNotTheSites(t *testing.T) {
	useFakeCertbot(t, "ok")
	initForTest(t)
	globalMutex.Lock()
	currentCertDomain, currentCertEpoch = "localhost", certSitesEpoch // An attempt for localhost...
	sameSiteInNewDirectory()                                          // ...of the sites directory left
	_, deleted := siteSSLSettingCheckers["C"](false, "0", "localhost", "", "", "")
	_, created := siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@localhost.test", "")
	queued := certPending["localhost"]
	globalMutex.Unlock()
	t.Cleanup(func() { withGlobalLock(func() { currentCertDomain = "" }) })
	if deleted == certificateBeingIssued {
		t.Errorf("Delete SSL: %q", deleted)
	}
	if !queued || !strings.Contains(created, "busy on localhost") {
		t.Errorf("Create SSL: %q, queued %v; expected a retry queued", created, queued)
	}
}

// GGCH H-10: when Turbo stops, the attempt of Certbot in progress is cancelled and waited for, and none starts any
// more: one could start during the wait of the requests, and Turbo could stop in the middle of putting a certificate in
// place.
func TestGGCH_H10_StoppingCancelsAndWaitsForCertbot(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	t.Setenv("FAKE_CERTBOT_DELAY", "20000")
	initForTest(t)
	globalMutex.Lock()
	siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@localhost.test", "")
	globalMutex.Unlock()
	time.Sleep(300 * time.Millisecond) // Certbot works
	began := time.Now()
	stopCertbot()
	waitCertbot(15 * time.Second)
	if elapsed := time.Since(began); elapsed > 12*time.Second {
		t.Errorf("waiting for the Certbot cancelled took %v", elapsed)
	}
	// Straight to startCertbot (review of v2.5.3, B-9): "C" doesn't reach it after the attempt cancelled, which left
	// certificate.failed, and found nothing started without certbotStopping too
	globalMutex.Lock()
	busy := currentCertDomain
	startCertbot("localhost", func() (certbotJob, bool) { return certbotJob{}, false }, func(interface{}) {})
	started := currentCertDomain
	globalMutex.Unlock()
	if attempts := certbotAttempts.Load(); busy != "" || started != "" || attempts != 0 {
		t.Errorf("after stopping: in progress %q, started %q, %d attempts; expected none", busy, started, attempts)
	}
	data, _ := os.ReadFile(logf)
	if n := strings.Count(string(data), `"certonly"`); n != 1 {
		t.Errorf("Certbot ran %d times; expected the one cancelled", n)
	}
}

// Review of v2.5.3 (B-1): stopping Certbot and waiting for it don't take the global lock, which a slow disk may hold
// (the renames of hardUpload, a certificate read): shutdown waited for it, and a second signal had nothing to end.
func TestGGCH_H10_StoppingCertbotTakesNoGlobalLock(t *testing.T) {
	initForTest(t)
	done := make(chan struct{})
	globalMutex.Lock()
	go func() {
		stopCertbot()
		waitCertbot(time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("stopping Certbot waits for the global lock")
	}
	globalMutex.Unlock()
	<-done
}

// GGCH H-10: a subdomain whose certificate Turbo issued in the folder of its domain (v2.3, before each site had its own)
// gets a folder of its own before an attempt of the domain empties that folder, and is renewed after it: the attempt
// took its lineage, and the subdomain was renewed no more. It got its folder at the pass of the renewals (review of
// v2.5.3), and an issuance of the domain by hand before the pass (after the start, or after setM) still took it.
func TestGGCH_H10_ALineageInTheFolderOfTheDomainMovesOn(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	if err := os.MkdirAll(dir+"localhost/www/@", 0755); err != nil {
		t.Fatal(err)
	}
	updateSettings(true)
	lineage := dir + "turbo.certificates/localhost/archive/www.localhost"
	if err := os.MkdirAll(lineage, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestCertificate(t, dir+"localhost/www/", 10*24*time.Hour, "www.localhost") // Due for its renewal
	withGlobalLock(func() { siteSSLConfig["www.localhost"].email = "admin@localhost.test" })
	globalMutex.Lock()
	siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@localhost.test", "") // No pass of the renewals before
	globalMutex.Unlock()
	waitIdle()
	if dirExists(lineage) {
		t.Fatal("the attempt of localhost didn't empty its folder: the test proves nothing")
	}
	if !dirExists(dir + "turbo.certificates/www.localhost") {
		t.Error("www.localhost has no folder of its own after the attempt of localhost took its lineage")
	}
	os.WriteFile(logf, nil, 0644)
	renewCertificates()
	waitIdle()
	if calls, _ := os.ReadFile(logf); !strings.Contains(string(calls), `"-d" "www.localhost"`) {
		t.Errorf("www.localhost wasn't renewed after the attempt of localhost:\n%s", calls)
	}
}

// GGCH H-12: an entry of the limiter that cleanIPReferences forgets is marked gone, holding its mutex, and a request
// that had taken it counts in a new one: the count, or the block of 5 s it set, went to an entry no longer in the map.
func TestGGCH_H12_AForgottenEntryIsNotCountedIn(t *testing.T) {
	initForTest(t)
	r250KeepLimits(t)
	client := clientOf("198.51.100.77:1234")
	perIPRejected(client, true)
	old := limiterReference(client.key)
	old.mutex.Lock()
	old.windowStart = monotonicNow() - 2*serverRequestLimits.CIL.Load()
	before := old.requestCount
	old.mutex.Unlock()
	cleanIPReferences()
	old.mutex.Lock()
	gone := old.gone
	old.mutex.Unlock()
	if !gone {
		t.Fatal("the entry forgotten isn't marked gone")
	}
	perIPRejected(client, true)
	fresh := limiterReference(client.key)
	old.mutex.Lock()
	after := old.requestCount
	old.mutex.Unlock()
	if fresh == old || after != before {
		t.Errorf("a request after the cleanup counted in the entry forgotten (%d -> %d), the same entry %v", before, after, fresh == old)
	}
}

// GGCH H-12: the line of turbo.denials of a block of an entry that a client shares with its network names the
// network: it named the client that happened to reach the limit.
func TestGGCH_H12_ASharedBlockNamesItsNetwork(t *testing.T) {
	dir := initForTest(t)
	r250KeepLimits(t)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	updateSettings(false) // The periodic reload opens the log
	previousLimit := ipReferenceLimit
	ipReferenceLimit = 1
	t.Cleanup(func() { ipReferenceLimit = previousLimit })
	serverRequestLimits.CIL.Store(int64(10 * time.Second))
	serverRequestLimits.CIS.Store(int64(time.Second))
	serverRequestLimits.CII.Store(1)
	handler := serverHandlerFn(false)
	serveFrom(handler, "198.51.100.1") // Its own entry: the level of the clients is full
	serveFrom(handler, "198.51.100.2") // Shares that of 198.51.100.0/24
	if rec := serveFrom(handler, "198.51.100.2"); rec.code != 429 {
		t.Fatalf("the request that blocks the shared entry: %d", rec.code)
	}
	serverSetLogState(denialsLogName, nil) // Flushes and closes it
	data, _ := os.ReadFile(dir + "turbo.denials")
	if !strings.HasPrefix(string(data), "198.51.100.0/24 ") || !strings.Contains(string(data), " conn denial") {
		t.Errorf("the line of the shared block: %q; expected the network 198.51.100.0/24", data)
	}
}
