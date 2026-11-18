package main

// Review of 6046dbe (R6), 7.6: the periodic work of main() (the renewal of certificates, the reload, the cleanup) is
// a function that takes its ticks, so that a test can give them. It was a loop inside main(), which no test could
// run: what each tick did was tested, and that the tick did it was not.

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// R6 7.6: each tick does its work, one after another, and a signal stops the servers and ends the loop.
func TestR6_M76_MaintenanceDoesTheWorkOfEachTick(t *testing.T) {
	certbotLog := useFakeCertbot(t, "ok")
	dir := initForTest(t)
	// A site whose certificate ends in 10 days, issued by Turbo (with an e-mail and its Certbot folder): due
	os.MkdirAll(dir+"soon.test/@", 0755)
	writeTestCertificate(t, dir+"soon.test/", 10*24*time.Hour, "soon.test")
	updateSettings(false)
	withGlobalLock(func() {
		siteSSLSettingCheckers["E"](false, "admin@soon.test", "soon.test", "")
		os.MkdirAll(dir+"turbo.certificates/soon.test", 0700)
		if ok, msg := siteSSLSettingCheckers["S"](false, "1", "soon.test", ""); !ok {
			t.Fatalf("cfgS: %q", msg)
		}
		// A session that ended a minute ago, and a denial that ended too
		signedInTokens["203.0.113.9|ended"] = time.Now().Unix() - 60
		sessionDeadlines["203.0.113.9|ended"] = time.Now().Unix() - 60
		setDeniedIPs(func(list map[string]int64) { list["203.0.113.10"] = time.Now().Unix() - 60 })
	})
	os.WriteFile(certbotLog, nil, 0644)

	stop := make(chan os.Signal, 1)
	renew, config, cleanup := make(chan time.Time), make(chan time.Time), make(chan time.Time)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		runMaintenance(stop, renew, config, cleanup)
	}()
	// The channels have no buffer and the loop does one thing at a time: a tick is taken when the work of the one
	// before it is done.
	tick := func(channel chan time.Time) {
		t.Helper()
		select {
		case channel <- time.Now():
		case <-time.After(30 * time.Second):
			t.Fatal("the loop didn't take a tick in 30 s")
		}
	}

	tick(cleanup)
	os.MkdirAll(dir+"ticked.test/@", 0755) // A site that appears on disk: the reload activates it
	tick(config)
	withReadLock(func() {
		if _, kept := signedInTokens["203.0.113.9|ended"]; kept {
			t.Error("after the tick of the cleanup, the session that had ended is still there")
		}
		if _, kept := sessionDeadlines["203.0.113.9|ended"]; kept {
			t.Error("after the tick of the cleanup, the deadline of the session that had ended is still there")
		}
	})
	if _, denied := deniedIPsInUse()["203.0.113.10"]; denied {
		t.Error("after the tick of the cleanup, the denial that had ended is still there")
	}
	tick(renew)
	withReadLock(func() {
		if !siteExists("ticked.test", "") {
			t.Error("after the tick of the reload, the site that appeared on disk isn't active")
		}
	})
	tick(cleanup) // The renewal has been started when this one is taken
	deadline := time.Now().Add(20 * time.Second)
	for {
		calls, _ := os.ReadFile(certbotLog)
		if strings.Contains(string(calls), `"-d" "soon.test"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the tick of the renewal, Certbot wasn't run for soon.test:\n%s", calls)
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitIdle()

	stop <- syscall.SIGTERM
	select {
	case <-ended:
	case <-time.After(shutdownGrace + 10*time.Second):
		t.Fatal("the loop didn't end after the signal")
	}
	select {
	case config <- time.Now():
		t.Error("the loop took a tick after it was stopped")
	case <-time.After(100 * time.Millisecond):
	}
}

// R6 7.6: a variable of Turbo that a test changes and doesn't put back is noticed, by its name, and put back: a
// function replaced, and a wait moved. The ones changed before the call that looks aren't that call's to judge.
func TestR6_M76_AHookLeftChangedIsNoticed(t *testing.T) {
	if left := restoreTestHooks(nil); len(left) != 0 {
		t.Fatalf("changed before this test: %v", left)
	}
	rename, grace := renameFile, shutdownGrace
	renameFile = func(from, to string) error { return os.Rename(from, to) }
	shutdownGrace = time.Millisecond
	if left := restoreTestHooks(map[string]bool{"renameFile": true}); len(left) != 1 || left[0] != "shutdownGrace" || shutdownGrace != grace {
		t.Errorf("with renameFile set aside: noticed %v, shutdownGrace %v; expected shutdownGrace alone, put back", left, shutdownGrace)
	}
	if left := restoreTestHooks(nil); len(left) != 1 || left[0] != "renameFile" {
		t.Errorf("noticed %v; expected renameFile", left)
	}
	if left := restoreTestHooks(nil); len(left) != 0 {
		t.Errorf("after putting them back: %v", left)
	}
	if err := renameFile(t.TempDir()+"/a", t.TempDir()+"/b"); err == nil || rename == nil {
		t.Error("renameFile isn't the one of the start")
	}
}
