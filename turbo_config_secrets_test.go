package main

// R5-09 (production reviews of 2026-11-04): the credentials of turbo.config and the secrets around them.
// - A plain "P" was hashed again, with PBKDF2 under the global lock, each time the file was read, and the new hash
//   closed every session. It is hashed before the lock now, and the password in use keeps its hash.
// - The message of an invalid turbo.config showed a "P" or "PH" that wasn't a string (a number, an array…).
// - Certbot, and its hooks, got all of Turbo's environment, TURBO_PASSWORD included.
// - An "E" with "+" (admin+certs@example.com) written in turbo.config was read as a space, and dropped.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRP3_R509_PlainPasswordHashedOutsideTheLock(t *testing.T) {
	dir := initForTest(t)
	var underLock int
	previous := derivePasswordKey
	t.Cleanup(func() { derivePasswordKey = previous })
	derivePasswordKey = func(password string, salt []byte, iterations int, keyLength int) ([]byte, error) {
		if lookedDisk != nil { // Within the reload's withDiskLook: every request waits meanwhile
			underLock++
		}
		return previous(password, salt, iterations, keyLength)
	}
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"U":"Operator","P":"plain-password-1"}}`)
	if underLock != 0 {
		t.Errorf("%d PBKDF2 under the global lock while reading a plain P; expected none", underLock)
	}
	if panelUser.Get() != "Operator" || !passwordMatches("plain-password-1") {
		t.Error("the credentials of the file aren't in use")
	}
}

func TestRP3_R509_ReReadingPlainPasswordKeepsSessions(t *testing.T) {
	dir := initForTest(t)
	config := `{"^":{"v":"2"},".":{"U":"Operator","P":"plain-password-1"}}`
	loadConfig(t, dir, config)
	var hash string
	withReadLock(func() { hash = panelPasswordHash.Get() })
	rec := loginFrom(serverHandlerFn(""), "192.0.2.60", "Operator", "plain-password-1")
	if rec.code != 200 {
		t.Fatalf("login with the password of the file: %d %q", rec.code, rec.body.String())
	}
	token := strings.TrimPrefix(rec.body.String(), "ok")
	loadConfig(t, dir, config+"\n") // The same password, in a file that changed
	var again string
	withReadLock(func() { again = panelPasswordHash.Get() })
	if again != hash {
		t.Error("reading the same plain P again changed the hash in use")
	}
	if _, alive := sessionExpiry("192.0.2.60", token); !alive {
		t.Error("reading the same plain P again closed the session")
	}
	loadConfig(t, dir, `{"^":{"v":"2"},".":{"U":"Operator","P":"plain-password-2"}}`) // Another password
	withReadLock(func() { again = panelPasswordHash.Get() })
	if again == hash || !passwordMatches("plain-password-2") {
		t.Error("another plain P isn't in use")
	}
	if _, alive := sessionExpiry("192.0.2.60", token); alive {
		t.Error("the session is still alive after the password changed")
	}
}

func TestRP3_R509_SecretsNeverShown(t *testing.T) {
	dir := t.TempDir()
	for _, value := range []string{
		`12345678901`,
		`["secret-in-a-list"]`,
		`{"secret-key":"secret-in-an-object"}`,
		`"secret-cut-short`, // Unterminated: the rest of the file is the value
		`secret-not-json`,
	} {
		for _, key := range []string{"P", "PH", `P`} {
			config := "{\n\"^\":{\"v\":\"2\"},\n\".\":{\"" + key + "\":" + value + "}\n}\n"
			path := filepath.Join(dir, configFileName)
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := parseSiteConfig(path)
			if err == nil {
				t.Errorf("%s: %s accepted", key, value)
				continue
			}
			message := configErrorMessage(err, true)
			for _, secret := range []string{"12345678901", "secret"} {
				if strings.Contains(message, secret) {
					t.Errorf("the message for %s: %s shows it:\n%s", key, value, message)
				}
			}
		}
	}
}

func TestRP3_R509_CertbotWithoutTurboVariables(t *testing.T) {
	useFakeCertbot(t, "ok")
	dir := initForTest(t)
	environment := filepath.Join(t.TempDir(), "environment")
	t.Setenv("FAKE_CERTBOT_ENV_LOG", environment)
	t.Setenv("TURBO_TEST_SECRET", "secret-of-turbo")
	t.Setenv("turbo_test_lower", "secret-of-turbo") // The same variable as TURBO_TEST_LOWER on Windows
	job := certbotJob{names: []string{"localhost"}, email: "admin@localhost.test", webroot: dir + "localhost/@", certDir: dir + "turbo.certificates/localhost", destDir: dir + "localhost/"}
	if status := runCertbot(context.Background(), job); status != true {
		t.Fatalf("issuing with the fake Certbot: %v", status)
	}
	data, err := os.ReadFile(environment)
	if err != nil {
		t.Fatal(err)
	}
	seen := string(data)
	if strings.Contains(strings.ToUpper(seen), "\nTURBO_") || strings.HasPrefix(strings.ToUpper(seen), "TURBO_") || strings.Contains(seen, "secret-of-turbo") {
		t.Errorf("Certbot got Turbo's variables:\n%s", seen)
	}
	if !strings.Contains(seen, "FAKE_CERTBOT_MODE=ok") {
		t.Errorf("Certbot didn't get the rest of the environment:\n%s", seen)
	}
}

func TestRP3_R509_EmailWithPlus(t *testing.T) {
	dir := initForTest(t)
	loadConfig(t, dir, `{"^":{"v":"2"},"localhost":{"":{"-":{"index.html":"1"},"!":{"E":"admin+certs@example.com"}}}}`)
	email := func() interface{} {
		globalMutex.RLock()
		defer globalMutex.RUnlock()
		return siteSSLConfig["localhost"]["E"]
	}
	if got := email(); got != "admin+certs@example.com" {
		t.Errorf("E written with +: %q; expected admin+certs@example.com", got)
	}
	saveDefaultConfig() // Saved encoded, and read back the same
	saved, err := os.ReadFile(dir + configFileName)
	if err != nil {
		t.Fatal(err)
	}
	loadConfig(t, dir, string(saved))
	if got := email(); got != "admin+certs@example.com" {
		t.Errorf("E saved and read again: %q; expected admin+certs@example.com", got)
	}
}
