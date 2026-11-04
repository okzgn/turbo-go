package main

// C2 (H25): with another issuance in progress, several "Create SSL" of the same
// site leave a single pending issuance, and Certbot runs once.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestC2_OnePendingIssuancePerSite(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	initForTest(t)
	globalMutex.Lock()
	currentCertDomain = "other.test" // Another issuance in progress
	for i := 0; i < 3; i++ {
		siteSSLSettingCheckers["C"](false, "1", "localhost", "", "admin@localhost.test", "")
	}
	globalMutex.Unlock()
	time.Sleep(250 * time.Millisecond)
	withGlobalLock(func() { currentCertDomain = "" })

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !fileExists(sitesDir.Get()+"localhost/fullchain.pem") {
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond) // Room for any other pending retry to run
	waitIdle()
	data, _ := os.ReadFile(logf)
	if n := strings.Count(string(data), `"certonly" "-d" "localhost"`); n != 1 {
		t.Errorf("Certbot ran %d times for localhost; expected 1:\n%s", n, data)
	}
	if certRetryDelay != 100*time.Millisecond {
		t.Errorf("the delay between attempts changed to %v", certRetryDelay)
	}
}

// Review of 57cbb3c, S13: an attempt removes the certificate of the previous one, but not the ACME account that
// Certbot keeps in accounts/: with a new account on each attempt, Let's Encrypt (10 new accounts per IP every 3
// hours) refused the next sites issued in a row.
func TestRL_S13_CertbotKeepsTheACMEAccount(t *testing.T) {
	useFakeCertbot(t, "ok")
	dir := initForTest(t)
	certDir := dir + "turbo.certificates/localhost"
	job := certbotJob{names: []string{"localhost"}, email: "admin@localhost.test", webroot: dir + "localhost/@", certDir: certDir, destDir: dir + "localhost/"}
	if status := runCertbot(context.Background(), job); status != true {
		t.Fatalf("first attempt: %v", status)
	}
	account := certDir + "/accounts/acme.test/directory/account/regr.json"
	if err := os.MkdirAll(filepath.Dir(account), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(account, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if status := runCertbot(context.Background(), job); status != true {
		t.Fatalf("second attempt: %v", status)
	}
	if !fileExists(account) {
		t.Error("the second attempt deleted the ACME account")
	}
	if !fileExists(dir + "localhost/fullchain.pem") {
		t.Error("the second attempt left no certificate")
	}
}
