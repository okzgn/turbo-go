package main

// Concurrency (#3, #4, #14, #26). TestR_RealisticRace is the smoke test for
// go test -race on Linux.

import (
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// #3: cleanOldValues against writes under the lock must not abort the process
// with "concurrent map writes".
func TestP03_CleanupRace(t *testing.T) {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			globalMutex.Lock()
			signedInTokens["ip"+strconv.Itoa(i%1000)] = time.Now().Unix() - 1
			globalMutex.Unlock()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cleanOldValues(&signedInTokens)
	}
	close(stop)
	wg.Wait()
}

// #26: reading the published timeouts (as the fork does on each connection,
// without the lock) against the panel's writes (under the lock).
func TestP26_TimeoutMapRace(t *testing.T) {
	withGlobalLock(func() { setTimeLimits(func(t *customNetHttp.Timeouts) { t.RT = 5 * time.Second }) })
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			withGlobalLock(func() {
				setTimeLimits(func(t *customNetHttp.Timeouts) { t.RT = time.Duration(i%1000+100) * time.Millisecond })
			})
		}
	}()
	var d time.Duration
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d = customNetHttp.TurboTimeLimits.Load().RT // Read without the lock, as in customNetHttp
	}
	close(stop)
	wg.Wait()
	t.Logf("last value read: %v", d)
}

// Realistic load for the race detector: HTTP traffic, the panel and periodic
// tasks at the same time. With -race there must be no warnings.
func TestR_RealisticRace(t *testing.T) {
	dir := initForTest(t)
	// Visitors and the administrator share the IP 127.0.0.1: the limiter must not
	// block it. CII can't exceed CIS in ms, nor CIS 66 times CII, so they are
	// raised in steps; and not even the maximum is enough on Linux, where the
	// loopback and a dozen CPUs exceed 50 000 requests in a few seconds and the
	// IP block (connections closed on arrival) cut the administrator off: as in
	// the performance tests, the limit is removed altogether. What is tested is
	// the races, not the limiter.
	for _, step := range [][2]string{{"CIS", "6600"}, {"CII", "6600"}, {"CIS", "50000"}, {"CII", "50000"}} {
		if ok, msg := defaultSettingValidators["."][step[0]](step[1], "Admin"); !ok {
			t.Fatalf("%s=%s: %s", step[0], step[1], msg)
		}
	}
	serverRequestLimits.CII.Store(1 << 40)
	// setP computes two PBKDF2; with -race and the CPU busy with the rest of this
	// test they can take longer than the 10 s of WT, which would cut the response
	// (EOF) even though the change is applied. The test looks for races, not timings.
	setTimeLimits(func(limits *customNetHttp.Timeouts) { limits.WT = time.Minute })
	base := startServer(t)
	tok := login(t, base)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	// A6: sites, subdomains and replacements added and deleted
	// The administrator below changes the password and sets RT itself
	results := panelLoops(base, tok, "", stop, &wg)
	for i := 0; i < 8; i++ { // Visitors
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					get(base, "/", nil)
					get(base, "/missing", nil) // Error template
				}
			}
		}()
	}
	var credentialsWritten, credentialsRejected atomic.Int64
	wg.Add(1)
	go func() { // Administrator
		defer wg.Done()
		user, password := "Turbo", "Admin"
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			post(base, "/admin:inside:setRT?b="+password+"&a="+strconv.Itoa(5+i%3)+"s", tok)
			post(base, "/admin:inside:addHeader?s=localhost&d=&a=X-T&c=Admin&b=v"+strconv.Itoa(i), tok)
			post(base, "/admin:inside:sites", tok)
			// Settings that change the credentials, the directory and the error
			// templates while the server reads them (Server header, Error, ErrorD).
			// The credentials alternate between two values so that each set* really
			// writes (with the same value they would answer 400 and change nothing).
			newUser, newPassword := "Turbo2", "AdminPassword2"
			if user == newUser {
				newUser = "Turbo"
			}
			if password == newPassword {
				newPassword = "AdminPassword1"
			}
			for _, change := range []struct {
				path    string
				current *string
				value   string
			}{
				{"/admin:inside:setU?a=" + newUser + "&b=" + password, &user, newUser},
				{"/admin:inside:setP?a=" + newPassword + "&b=" + password, &password, newPassword},
			} {
				if code, body, renewed, err := postSession(base, change.path, tok); err == nil && code == 200 {
					*change.current = change.value
					tok = renewed // setU and setP renew the session
					credentialsWritten.Add(1)
				} else {
					if credentialsRejected.Add(1) == 1 {
						t.Logf("first rejection: %s -> %d %q %v", change.path, code, body, err)
					}
				}
			}
			post(base, "/admin:inside:setM?b="+password+"&a="+url.QueryEscape(dir), tok)
			post(base, "/admin:inside:addHttpCodeResponse?s=404&d=Not+found+"+strconv.Itoa(i)+"&b="+password, tok)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Add(1)
	go func() { // The periodic tasks of main(), sped up
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				updateSettings(true)
				cleanOldValues(&signedInTokens)
			}
		}
	}()
	time.Sleep(6 * time.Second)
	close(stop)
	wg.Wait()
	t.Logf("setU and setP: %d writes", credentialsWritten.Load())
	if accepted, other := results.accepted.Load(), results.other.Load(); accepted == 0 || other != 0 {
		t.Errorf("panel actions: %d accepted and %d with a code other than 200, 400, 429 or 503", accepted, other)
	}
	if credentialsWritten.Load() == 0 || credentialsRejected.Load() != 0 {
		t.Errorf("setU and setP: %d writes and %d rejected; they must always write", credentialsWritten.Load(), credentialsRejected.Load())
	}
}
