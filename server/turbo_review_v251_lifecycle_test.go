package server

// The tests of the findings about turbo.config, the certificates and the life cycle of the review of v2.5.1: each
// failed before its fix (CO-2's and CO-6's, which test a new argument and a new function, didn't build).

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// V2.5.1 review CO-1: the probe of whether the sites directory takes a name in other capitals for the same file looks
// through siteDirStat, and only "not found" for the name in capitals says that it doesn't: another error (an I/O
// error of a share, a loop of links) is a probe that couldn't look, and the reload keeps what it knew. It was taken as
// a sure "doesn't fold", and the protections of the systems that ignore case were left off.
func TestR251_CO1_AnErrorOfTheProbeKeepsWhatWasKnown(t *testing.T) {
	dir := initForTest(t)
	var askedInCapitals atomic.Int64
	upperError := error(&fs.PathError{Op: "stat", Path: "LOCALHOST", Err: errors.New("input/output error")})
	previousStat := siteDirStat
	siteDirStat = func(name string) (os.FileInfo, error) {
		if strings.HasSuffix(name, "LOCALHOST") {
			askedInCapitals.Add(1)
			return nil, upperError
		}
		return previousStat(name)
	}
	t.Cleanup(func() { siteDirStat = previousStat })

	if folds, known := probeNameFoldingKnown(dir, []diskSite{{"localhost", ""}}); known || folds {
		t.Errorf("an I/O error on the name in capitals: folds %v, known %v; expected a probe that couldn't look", folds, known)
	}
	if askedInCapitals.Load() == 0 {
		t.Fatal("the probe didn't look through siteDirStat")
	}
	previousFolds := sitesDirFolds.Load()
	t.Cleanup(func() { sitesDirFolds.Store(previousFolds) })
	for _, before := range []bool{true, false} {
		sitesDirFolds.Store(before)
		if err := updateSettings(true); err != nil {
			t.Fatal(err)
		}
		if sitesDirFolds.Load() != before {
			t.Errorf("a reload whose probe got an I/O error: sitesDirFolds %v; expected %v, as it was", sitesDirFolds.Load(), before)
		}
	}

	upperError = &fs.PathError{Op: "stat", Path: "LOCALHOST", Err: fs.ErrNotExist}
	if folds, known := probeNameFoldingKnown(dir, []diskSite{{"localhost", ""}}); !known || folds {
		t.Errorf("the name in capitals not found: folds %v, known %v; expected a sure \"doesn't fold\"", folds, known)
	}
	// An error on one site, and another that can be looked at: the answer is that one's
	os.MkdirAll(dir+"other.test/@", 0755)
	upperError = &fs.PathError{Op: "stat", Path: "LOCALHOST", Err: errors.New("input/output error")}
	folds, known := probeNameFoldingKnown(dir, []diskSite{{"localhost", ""}, {"other.test", ""}})
	if expected := namesIgnoreCaseIn(t, dir); !known || folds != expected {
		t.Errorf("an error on one site and another to look at: folds %v, known %v; expected %v, known", folds, known, expected)
	}
}

// V2.5.1 review CO-2: the first renewal of the certificates, at start, runs first in the goroutine of the periodic
// work (atStart): with a disk that doesn't answer right at the start, a signal still stops Turbo. It ran before
// runMaintenance, once the signal was caught and with no one to read it, and Turbo didn't stop until it came back.
func TestR251_CO2_TheRenewalAtStartDoesNotHoldTheSignal(t *testing.T) {
	initForTest(t)
	entered, release := make(chan struct{}), make(chan struct{})
	stop := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		runMaintenance(stop, func() { close(entered); <-release }, nil, nil, nil)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the work at start didn't run")
	}
	stop <- os.Interrupt
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("3 s after the signal, Turbo still hasn't stopped: the signal waits for the renewal at start that hangs")
	}
	close(release)
	<-done
}

// V2.5.1 review CO-3: a certificate kept after turbo.config is applied, while its files can't be loaded, is warned
// about once, by what keeps it. The validator S said that HTTPS waited for it ("tried again every 30 s"), which
// wasn't so, and the look that followed warned again.
func TestR251_CO3_AKeptCertificateIsWarnedOnce(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	config := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"!":{"S":"1"}}}}`
	if err := os.WriteFile(dir+"turbo.config", []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	var inUse any
	withReadLock(func() { inUse = siteCertificates["localhost"] })
	if inUse == nil {
		t.Fatal("the certificate of localhost isn't in use")
	}
	scratch := t.TempDir() + "/"
	loadTestCertificate(t, scratch, time.Hour, "localhost") // Another chain, whose key isn't the one in the folder
	data, _ := os.ReadFile(scratch + certFileName)
	if err := os.WriteFile(dir+"localhost/"+certFileName, data, 0600); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	edited := strings.TrimSuffix(config, "}") + `,".":{"RT":"6s"}}`
	if err := os.WriteFile(dir+"turbo.config", []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := updateSettings(true); err != nil {
			t.Fatal(err)
		}
		refreshSiteCertificates()
	}
	var kept any
	withReadLock(func() { kept = siteCertificates["localhost"] })
	if kept != inUse {
		t.Errorf("the certificate in use wasn't kept")
	}
	out := logs.String()
	if count := strings.Count(out, "can't be loaded"); count != 1 || !strings.Contains(out, "can't be loaded: the certificate in use stays") || strings.Contains(out, "tried again every 30 s") {
		t.Errorf("the pair that can't be loaded, in 3 reloads and looks: %d warnings; expected one, that the certificate in use stays:\n%s", count, out)
	}

	// A site whose certificate isn't in use still says that HTTPS waits for it
	os.MkdirAll(dir+"other.test/@", 0755)
	os.WriteFile(dir+"other.test/"+certFileName, data, 0600) // A chain without its key
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	logs = captureLog(t)
	withGlobalLock(func() {
		if ok, message := siteSSLSettingCheckers["S"](true, "1", "other.test", ""); !ok {
			t.Errorf("S from turbo.config, for a pair that can't be loaded: refused, %q", message)
		}
	})
	if !strings.Contains(logs.String(), "tried again every 30 s") {
		t.Errorf("a site without a certificate in use whose pair can't be loaded: %q; expected the warning that it is tried again", logs.String())
	}
}

// V2.5.1 review CO-6: TURBO_HTTP_ADDR and TURBO_HTTPS_ADDR can't take the same port on a same interface: the HTTPS
// address failed to open, and was tried again every 30 s for good. The addresses are as listenAddress returns them.
func TestR251_CO6_SameListenAddress(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{":80", ":443", false},
		{":8080", ":8080", true},
		{":8080", "127.0.0.1:8080", true},
		{"0.0.0.0:8080", "127.0.0.1:8080", true},
		{"[::]:8080", "127.0.0.1:8080", true},
		{"127.0.0.1:8080", "[::]:8080", true},
		{"127.0.0.1:8080", "127.0.0.1:8080", true},
		{"127.0.0.1:8080", "127.0.0.2:8080", false},
		{"127.0.0.1:8080", "127.0.0.1:8443", false},
		{"[::1]:8080", "[0:0:0:0:0:0:0:1]:8080", true},
		{"localhost:8080", "LOCALHOST:8080", true},
		{"localhost:8080", "example.test:8080", false},
		{"[::1]:8080", "127.0.0.1:8080", false},
	} {
		if same := sameListenAddress(c.a, c.b); same != c.same {
			t.Errorf("sameListenAddress(%q, %q) = %v; expected %v", c.a, c.b, same, c.same)
		}
	}
}
