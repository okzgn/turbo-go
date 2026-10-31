package main

// A8 (H7, D2): límite de intentos de login por IP, tope de espera en la cola
// de PBKDF2 y aviso al arrancar con las credenciales por defecto.

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// countPasswordKeys cuenta las derivaciones PBKDF2 hasta el final de la prueba.
func countPasswordKeys(t testing.TB) *atomic.Int64 {
	var calls atomic.Int64
	previous := derivePasswordKey
	derivePasswordKey = func(password string, salt []byte, iterations int, keyLength int) ([]byte, error) {
		calls.Add(1)
		return previous(password, salt, iterations, keyLength)
	}
	t.Cleanup(func() { derivePasswordKey = previous })
	return &calls
}

// loginFrom envía un login (cuerpo urlencoded) desde la IP dada, sin red.
func loginFrom(handler func(customNetHttp.ResponseWriter, *customNetHttp.Request), ip, user, password string) *responseRecorder {
	body := url.Values{"u": {user}, "p": {password}}.Encode()
	req, _ := customNetHttp.NewRequest("POST", "http://localhost/admin:", strings.NewReader(body))
	req.RequestURI = "/admin:"
	req.RemoteAddr = ip + ":40000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := &responseRecorder{}
	handler(rec, req)
	return rec
}

// H7: tras 5 fallos desde una IP, el sexto intento recibe 429 sin calcular
// PBKDF2, también con la contraseña correcta; al terminar el bloqueo, el login
// correcto entra, y un segundo bloqueo dura más que el primero.
func TestA8_FailedLoginsLimited(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	calls := countPasswordKeys(t)
	for i := 1; i <= 5; i++ {
		if rec := loginFrom(handler, "198.51.100.7", "Turbo", "mal"+strconv.Itoa(i)); rec.code != 403 {
			t.Fatalf("fallo %d: %d; se esperaba 403", i, rec.code)
		}
	}
	before := calls.Load()
	for _, password := range []string{"mal6", "Admin"} {
		rec := loginFrom(handler, "198.51.100.7", "Turbo", password)
		retry, _ := strconv.Atoi(rec.Header().Get("Retry-After"))
		if rec.code != 429 || retry < 1 || retry > 60 {
			t.Errorf("intento con %q tras 5 fallos: %d, Retry-After %q; se esperaba 429 con hasta 60 s", password, rec.code, rec.Header().Get("Retry-After"))
		}
	}
	if n := calls.Load() - before; n != 0 {
		t.Errorf("los intentos bloqueados calcularon %d PBKDF2", n)
	}
	if rec := loginFrom(handler, "198.51.100.8", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("otra IP: %d; se esperaba 200", rec.code)
	}

	expireLoginBlock(t, "198.51.100.7")
	if rec := loginFrom(handler, "198.51.100.7", "Turbo", "Admin"); rec.code != 200 || !strings.HasPrefix(rec.body.String(), "ok") {
		t.Fatalf("login correcto tras el bloqueo: %d %q", rec.code, rec.body.String())
	}

	// A correct login clears the failures; a second block, before they are forgotten, lasts longer.
	for i := 0; i < 5; i++ {
		loginFrom(handler, "198.51.100.7", "Turbo", "mal")
	}
	expireLoginBlock(t, "198.51.100.7")
	for i := 0; i < 5; i++ {
		loginFrom(handler, "198.51.100.7", "Turbo", "mal")
	}
	rec := loginFrom(handler, "198.51.100.7", "Turbo", "Admin")
	if retry, _ := strconv.Atoi(rec.Header().Get("Retry-After")); rec.code != 429 || retry <= 60 || retry > 120 {
		t.Errorf("segundo bloqueo: %d, Retry-After %q; se esperaban 2 minutos", rec.code, rec.Header().Get("Retry-After"))
	}
}

// H57: los intentos simultáneos desde una IP cuentan para el límite mientras
// se comprueban, así que una ráfaga no calcula más de 5 contraseñas.
func TestH57_ConcurrentLoginsLimited(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	calls := countPasswordKeys(t)
	t.Cleanup(func() {
		loginFailuresMutex.Lock()
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
	})
	var wg sync.WaitGroup
	var forbidden, limited atomic.Int64
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch loginFrom(handler, "198.51.100.20", "Turbo", "mal"+strconv.Itoa(i)).code {
			case 403:
				forbidden.Add(1)
			case 429:
				limited.Add(1)
			}
		}()
	}
	wg.Wait()
	if calls.Load() > loginMaxFailures || forbidden.Load() > loginMaxFailures {
		t.Errorf("60 logins simultáneos: %d contraseñas calculadas, %d respuestas 403, %d 429; se esperaban como mucho %d cálculos",
			calls.Load(), forbidden.Load(), limited.Load(), loginMaxFailures)
	}
	if rec := loginFrom(handler, "198.51.100.20", "Turbo", "Admin"); rec.code != 429 {
		t.Errorf("tras la ráfaga: %d; se esperaba 429", rec.code)
	}
	if rec := loginFrom(handler, "198.51.100.21", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("otra IP tras la ráfaga: %d; se esperaba 200", rec.code)
	}
}

// expireLoginBlock da por terminado el bloqueo de login de una IP.
func expireLoginBlock(t *testing.T, ip string) {
	t.Helper()
	loginFailuresMutex.Lock()
	defer loginFailuresMutex.Unlock()
	failures, found := loginFailuresByIP[ip]
	if !found {
		t.Fatalf("%s no tiene fallos de login registrados", ip)
	}
	failures.blockedUntil = time.Now().Add(-time.Second)
}

// H7: si la cola de PBKDF2 está llena más de 2 s, el login recibe 503 con
// Retry-After: 2 en lugar de esperar sin límite.
func TestA8_HashQueueBounded(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	verifiedPassword.Store(nil) // A password already checked doesn't need a slot
	for i := 0; i < cap(passwordHashSlots); i++ {
		passwordHashSlots <- struct{}{}
	}
	start := time.Now()
	rec := loginFrom(handler, "198.51.100.9", "Turbo", "Admin")
	elapsed := time.Since(start)
	for i := 0; i < cap(passwordHashSlots); i++ {
		<-passwordHashSlots
	}
	if rec.code != 503 || rec.Header().Get("Retry-After") != "2" || elapsed > 3*time.Second {
		t.Fatalf("con la cola llena: %d, Retry-After %q, %v; se esperaba 503 con Retry-After: 2 en unos 2 s", rec.code, rec.Header().Get("Retry-After"), elapsed)
	}
	if rec := loginFrom(handler, "198.51.100.9", "Turbo", "Admin"); rec.code != 200 {
		t.Errorf("con la cola libre: %d", rec.code)
	}
}

// H7: con 50 logins fallidos simultáneos desde IPs distintas, el
// administrador entra en menos de 3 s, o recibe 503 y entra al reintentar.
func TestA8_AdminEntersDuringAttack(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	verifiedPassword.Store(nil) // The administrator's login also computes a PBKDF2
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			loginFrom(handler, "203.0.113."+strconv.Itoa(i+1), "Turbo", "mal")
		}()
	}
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	rec := loginFrom(handler, "192.0.2.1", "Turbo", "Admin")
	if rec.code == 503 {
		time.Sleep(2 * time.Second)
		rec = loginFrom(handler, "192.0.2.1", "Turbo", "Admin")
	} else if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("el administrador tardó %v en entrar", elapsed)
	}
	wg.Wait()
	if rec.code != 200 {
		t.Errorf("login del administrador durante el ataque: %d", rec.code)
	}
}

// D2: al arrancar con Turbo/Admin, un aviso en el log; con otra contraseña, no.
func TestA8_DefaultCredentialsWarning(t *testing.T) {
	initForTest(t)
	logs := captureLog(t)
	warnDefaultCredentials()
	if !strings.Contains(logs.String(), "Se usan las credenciales por defecto") {
		t.Errorf("sin aviso con Turbo/Admin:\n%s", logs.String())
	}
	setPanelPassword("Otra")
	before := len(logs.String())
	warnDefaultCredentials()
	if strings.Contains(logs.String()[before:], "credenciales por defecto") {
		t.Error("aviso con una contraseña cambiada")
	}
}

// §11.2: ninguna entrada inicia sesión sin las credenciales.
func FuzzLogin(f *testing.F) {
	for _, body := range []string{"u=Turbo&p=Admin", "u=Turbo&p=admin", "u=turbo&p=Admin", "u=Turbo&u=x&p=Admin", "p=Admin", "u=Turbo&p=Admin%00", "u=%54urbo&p=Admin", ""} {
		f.Add(body, false)
		f.Add(body, true)
	}
	initFuzz(f)
	// A hash of few iterations, so that each attempt is fast.
	salt := []byte("0123456789abcdef")
	key, _ := derivePasswordKey("Admin", salt, 1, 32)
	panelPasswordHash.Set("pbkdf2-sha256$1$MDEyMzQ1Njc4OWFiY2RlZg==$" + base64.StdEncoding.EncodeToString(key))
	verifiedPassword.Store(nil)
	handler := serverHandlerFn("")
	f.Fuzz(func(t *testing.T, body string, multipartBody bool) {
		loginFailuresMutex.Lock()
		clear(loginFailuresByIP)
		loginFailuresMutex.Unlock()
		values, err := url.ParseQuery(body)
		contentType := "application/x-www-form-urlencoded"
		if multipartBody {
			if err != nil {
				return
			}
			var buf strings.Builder
			buf.WriteString("--X\r\n")
			for name, list := range values {
				for _, value := range list {
					buf.WriteString("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n--X\r\n")
				}
			}
			body, contentType = strings.TrimSuffix(buf.String(), "\r\n")+"--\r\n", "multipart/form-data; boundary=X"
		}
		req, _ := customNetHttp.NewRequest("POST", "http://localhost/admin:", strings.NewReader(body))
		req.RequestURI = "/admin:"
		req.RemoteAddr = "198.51.100.200:40000"
		req.Header.Set("Content-Type", contentType)
		rec := &responseRecorder{}
		handler(rec, req)
		valid := err == nil && len(values["u"]) > 0 && values["u"][0] == "Turbo" && len(values["p"]) > 0 && values["p"][0] == "Admin"
		if signedIn := strings.HasPrefix(rec.body.String(), "ok"); signedIn && !valid {
			t.Fatalf("sesión iniciada con %q (multipart %v)", body, multipartBody)
		}
	})
}
