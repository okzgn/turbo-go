package server

// The tests of the findings about the certificates and the life of the server of the review of v2.5.0: each failed
// before its fix, and its comment says what happened then.

import (
	"os"
	"strings"
	"testing"
	"time"
)

// V2.5.0 review CT-3 (as it was): an expired certificate of the panel wins over the valid ones of the sites for the names it covers.
func TestR250_CT3_ExpiredPanelCertificateWins(t *testing.T) {
	initForTest(t)
	scratch := t.TempDir() + "/"
	expiredPanel := loadTestCertificate(t, scratch+"p/", -time.Minute, "admin.example.test", "example.test", "*.example.test")
	own := loadTestCertificate(t, scratch+"s/", time.Hour, "example.test")
	wild := loadTestCertificate(t, scratch+"w/", time.Hour, "*.example.test")
	withGlobalLock(func() {
		panelCertificate = expiredPanel
		setSiteCertificate("example.test", own)
		setSiteCertificate("*.example.test", wild)
	})
	t.Cleanup(func() { withGlobalLock(func() { panelCertificate = nil; publishCertificates() }) })
	if got := certificateFor("example.test"); got != own {
		t.Errorf("example.test: got %v (expired panel=%v); expected the site's own valid one", certificateNames(got), got == expiredPanel)
	}
	if got := certificateFor("shop.example.test"); got != wild {
		t.Errorf("shop.example.test: got %v (expired panel=%v); expected the valid wildcard of the site *.example.test", certificateNames(got), got == expiredPanel)
	}
	var timer bool
	withReadLock(func() { timer = certificatesPublishTimer != nil })
	t.Logf("republish timer armed: %v", timer)
}

// V2.5.0 review CT-1 (as it was): a turbo.config read again while a site's pair can't be loaded leaves the site without the certificate in use.
func TestR250_CT1_ReloadDropsTheCertificateInUse(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	config := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"!":{"S":"1"}}}}`
	if err := os.WriteFile(dir+"turbo.config", []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	first := certificateFor("localhost")
	if first == nil {
		t.Fatal("no certificate in use after reading turbo.config")
	}
	// A renewal outside Turbo: the new chain first, its key later
	scratch := t.TempDir() + "/"
	loadTestCertificate(t, scratch, time.Hour, "localhost")
	data, _ := os.ReadFile(scratch + certFileName)
	if err := os.WriteFile(dir+"localhost/"+certFileName, data, 0600); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	if err := updateSettings(true); err != nil { // The periodic look: the one in use stays, as promised
		t.Fatal(err)
	}
	if certificateFor("localhost") != first {
		t.Fatal("the periodic look replaced the certificate in use")
	}
	// Meanwhile turbo.config changes (a hand edit)
	edited := strings.TrimSuffix(config, "}") + `,".":{"RT":"6s"}}`
	if err := os.WriteFile(dir+"turbo.config", []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	if got := certificateFor("localhost"); got != first {
		t.Errorf("after reading turbo.config again: certificate in use %v (nil=%v); expected the one in use to stay\n%s", certificateNames(got), got == nil, logs.String())
	}
}

// V2.5.0 review CT-7 (as it was): cfgPC saves the e-mail and then refuses the adapter: the answer is an error and the e-mail changed.
func TestR250_CT7_PanelEmailSavedWithAnInvalidAdapter(t *testing.T) {
	initForTest(t)
	var ok bool
	var msg, email string
	withGlobalLock(func() {
		panelCertEmail = "old@example.test"
		ok, msg = panelCertificateAction("1", "new@example.test", "dns-", true)
		email = panelCertEmail
		panelCertEmail = ""
	})
	if ok {
		t.Fatalf("accepted: %s", msg)
	}
	if email != "old@example.test" {
		t.Errorf("answer %q, and the e-mail is now %q", msg, email)
	}
}

// V2.5.0 review CT-5 (as it was): a reload that hangs (a disk that doesn't answer) keeps Turbo from stopping: the signal waits for it.
func TestR250_CT5_StopWaitsForAReloadThatHangs(t *testing.T) {
	initForTest(t)
	release := make(chan struct{})
	entered := make(chan struct{})
	previous := beforeSitesScan
	beforeSitesScan = func() {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
	}
	t.Cleanup(func() { beforeSitesScan = previous })
	stop := make(chan os.Signal, 1)
	config := make(chan time.Time, 1)
	done := make(chan struct{})
	go func() { runMaintenance(stop, nil, config, nil); close(done) }()
	config <- time.Now()
	<-entered
	stop <- os.Interrupt
	select {
	case <-done:
		t.Log("stopped while the reload hung")
	case <-time.After(3 * time.Second):
		t.Error("3 s after the signal, Turbo still hasn't stopped: the signal waits for the reload that hangs")
	}
	close(release)
	<-done
}

// V2.5.0 review CT-6 (as it was): a panic while a turbo.config is applied (a bug of a validator) is recovered, but leaves the configuration half
// applied, the file taken as read and certificatePublishPaused set.
func TestR250_CT6_PanicDuringAReload(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"localhost/@/x.php", []byte("<?php echo 'secret'; ?>"), 0644)
	cfg := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"?":{"php":"` + toolPath("cgiecho") + `"},"!":{"S":"0"}}}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	base := startServer(t)
	if _, body, err := rawGet(base, "localhost", "/x.php"); err != nil || strings.Contains(body, "secret") {
		t.Fatalf("before: %v %q", err, body)
	}
	original := subdomainContentCheckers["!"]
	subdomainContentCheckers["!"] = func(bool, interface{}, bool, ...string) (bool, string) { panic("a bug of a validator") }
	os.WriteFile(dir+"turbo.config", []byte(strings.Replace(cfg, `"S":"0"`, `"S":"0","Z":"0"`, 1)), 0600)
	runRecovering("updateSettings", func() { logConfigError(updateSettings(true)) })
	subdomainContentCheckers["!"] = original
	runRecovering("updateSettings", func() { logConfigError(updateSettings(true)) }) // The next periodic reload
	var paused bool
	withReadLock(func() { paused = certificatePublishPaused })
	t.Cleanup(func() { withGlobalLock(func() { certificatePublishPaused = false }) })
	if _, body, err := rawGet(base, "localhost", "/x.php"); err != nil || strings.Contains(body, "secret") {
		t.Errorf("after the panic and the next reload, the script is served as text: %v %q", err, body)
	}
	if paused {
		t.Error("certificatePublishPaused stays set: no certificate is published until turbo.config changes")
	}
}

// V2.5.0 review CT-4 (as it was): the probe of name folding, inconclusive in a reload (no site with letters found), turns it off.
func TestR250_CT4_FoldingProbeTurnsOffWhenItCantLook(t *testing.T) {
	dir := initForTest(t)
	t.Cleanup(func() { sitesDirFolds.Store(false) })
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	before := sitesDirFolds.Load()
	os.Rename(dir+"localhost/@", dir+"localhost/@x") // Its @ can't be read for a moment
	updateSettings(false)                            // checkSites aside: as with an error that says nothing of the site
	os.Rename(dir+"localhost/@x", dir+"localhost/@")
	after := sitesDirFolds.Load()
	var active bool
	withReadLock(func() { active = siteExists("localhost", "") })
	t.Logf("sitesDirFolds before %v, after %v; site still active: %v", before, after, active)
	if before && !after {
		t.Error("an inconclusive probe turned off the folding of names that the sites directory has")
	}
}

// V2.5.0 review CT-1 (as it was): "Delete SSL" without x=1 leaves the certificate in use "until another one is installed or Turbo restarts";
// a turbo.config edited by hand meanwhile takes it out of use.
func TestR250_CT1_DeleteSSLThenAnEditedConfig(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	config := `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"!":{"S":"1"}}}}`
	os.WriteFile(dir+"turbo.config", []byte(config), 0600)
	if err := updateSettings(true); err != nil {
		t.Fatal(err)
	}
	first := certificateFor("localhost")
	if first == nil {
		t.Fatal("no certificate in use")
	}
	look := newDiskLook()
	look.siteFiles(dir+"localhost/", false)
	var ok bool
	var msg string
	withDiskLook(look, func() { ok, msg = siteSSLSettingCheckers["C"](false, "0", "localhost", "", "", "", "0") })
	if !ok || fileExists(dir+"localhost/"+certFileName) {
		t.Fatalf("Delete SSL: %v %q", ok, msg)
	}
	updateSettings(true)
	if certificateFor("localhost") != first {
		t.Fatal("the periodic look took it out of use")
	}
	os.WriteFile(dir+"turbo.config", []byte(strings.TrimSuffix(config, "}")+`,".":{"RT":"6s"}}`), 0600)
	updateSettings(true)
	if certificateFor("localhost") != first {
		t.Errorf("after turbo.config was edited, the certificate that \"Delete SSL\" left in use is gone (nil=%v)", certificateFor("localhost") == nil)
	}
}

// V2.5.0 review CT-2 (as it was): a chain fixed on disk with the same leaf (an intermediate added to fullchain.pem) is taken as read and never
// put in use: refreshSiteCertificates compares only the first certificate.
func TestR250_CT2_ChainFixedWithTheSameLeaf(t *testing.T) {
	dir := initForTest(t)
	writeTestCertificate(t, dir+"localhost/", time.Hour, "localhost")
	withGlobalLock(func() { siteSSLSettingCheckers["S"](false, "1", "localhost", "") })
	first := certificateFor("localhost")
	if first == nil || len(first.Certificate) != 1 {
		t.Fatal("no certificate of one element in use")
	}
	refreshSiteCertificates() // The first look after the load
	// The administrator appends the intermediate that was missing (here, another certificate as a stand-in)
	scratch := t.TempDir() + "/"
	loadTestCertificate(t, scratch, time.Hour, "intermediate.test")
	chain, _ := os.ReadFile(dir + "localhost/" + certFileName)
	intermediate, _ := os.ReadFile(scratch + certFileName)
	os.WriteFile(dir+"localhost/"+certFileName, append(chain, intermediate...), 0600)
	future := time.Now().Add(2 * time.Second)
	os.Chtimes(dir+"localhost/"+certFileName, future, future)
	refreshSiteCertificates()
	if got := certificateFor("localhost"); len(got.Certificate) != 2 {
		t.Errorf("the chain in use has %d certificates after fullchain.pem got its intermediate; expected 2", len(got.Certificate))
	}
	refreshSiteCertificates()
	if got := certificateFor("localhost"); len(got.Certificate) != 2 {
		t.Errorf("and at the next look, still %d", len(got.Certificate))
	}
}
