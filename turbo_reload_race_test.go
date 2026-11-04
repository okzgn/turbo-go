package main

// A6 (H10): the panel actions don't read shared state without the lock, not
// even while the periodic reload adds sites found on disk.

import (
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// loopResults counts what the panel answers to panelLoops: accepted (200), refused (400: "already exists" or
// "not found" when the periodic reload gets ahead of an addition or a deletion), limited (429 or 503, by the
// limit of attempts and that of PBKDF2 under load), other (none should happen: a 500 is a panic in the API) and
// failed, with no answer (transport errors: with thousands of connections in seconds, Windows runs out of ports).
type loopResults struct{ accepted, refused, limited, other, failed atomic.Int64 }

// panelLoops runs, until stop is closed, panel actions that read and write
// the shared maps: adding and deleting sites, subdomains and character
// replacements and, if the password is given, a setting (setRT) whose
// parameters go through the replacements. Without a password there is no
// setting: a wrong current password counts as a failed login and would block
// the IP.
func panelLoops(base, tok, password string, stop chan struct{}, wg *sync.WaitGroup) *loopResults {
	results := &loopResults{}
	do := func(path string) {
		switch code, _, err := post(base, path, tok); {
		case err != nil:
			results.failed.Add(1)
		case code == 200:
			results.accepted.Add(1)
		case code == 400:
			results.refused.Add(1)
		case code == 429 || code == 503:
			results.limited.Add(1)
		default:
			results.other.Add(1)
		}
	}
	// delSite asks for the current password (T28); without one, the internal one, which is always valid
	deletePassword := password
	if deletePassword == "" {
		deletePassword = internalAuth
	}
	loops := []func(i int){
		func(i int) {
			site := "a6-" + strconv.Itoa(i%4) + ".test"
			do("/admin:inside:addSite?s=" + site)
			do("/admin:inside:delSite?s=" + site + "&d=&b=" + deletePassword)
		},
		func(i int) {
			sub := "s" + strconv.Itoa(i%4)
			do("/admin:inside:addSubdomain?s=localhost&d=" + sub)
			do("/admin:inside:delSite?s=localhost&d=" + sub + "&b=" + deletePassword)
		},
		func(i int) {
			do("/admin:inside:addCharsReplace?" + url.Values{"s": {"!"}, "d": {"zz" + strconv.Itoa(i%9)}}.Encode())
			do("/admin:inside:delCharsReplace?s=!")
		},
	}
	if password != "" {
		loops = append(loops, func(i int) {
			do("/admin:inside:setRT?b=" + password + "&a=" + strconv.Itoa(5+i%2) + "s")
		})
	}
	for _, loop := range loops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
					loop(i)
				}
			}
		}()
	}
	return results
}

// H10: four panel clients add and delete sites, subdomains and replacements
// while the periodic reload runs in a loop: without -race it must not abort
// ("concurrent map read and map write"), and with -race it must not warn.
func TestA6_PanelActionsDuringReload(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	results := panelLoops(base, tok, "Admin", stop, &wg)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		updateSettings(true)
	}
	close(stop)
	wg.Wait()
	if accepted, other := results.accepted.Load(), results.other.Load(); accepted == 0 || other != 0 {
		t.Errorf("panel actions during the reload: %d accepted and %d with a code that is not 200, 400, 429 or 503", accepted, other)
	}
}
