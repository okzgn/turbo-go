package main

// C2 (H25): con otra emisión en curso, varios "Crear SSL" del mismo sitio
// dejan una sola emisión pendiente, y Certbot se lanza una vez.

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestC2_OnePendingIssuancePerSite(t *testing.T) {
	logf := useFakeCertbot(t, "ok")
	initForTest(t)
	globalMutex.Lock()
	currentCertDomain = "otro.test" // Another issuance in progress
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
		t.Errorf("Certbot se lanzó %d veces para localhost; se esperaba 1:\n%s", n, data)
	}
	if certRetryDelay != 100*time.Millisecond {
		t.Errorf("el retardo entre intentos cambió a %v", certRetryDelay)
	}
}
