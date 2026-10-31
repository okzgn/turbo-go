package main

// B3 (H12), B5 (H16): el lock global no se mantiene mientras se escribe una respuesta
// del panel ni mientras se calcula PBKDF2.

import (
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// blockingWriter es un ResponseWriter cuyo Write se detiene (como con un
// cliente que no lee) hasta que se cierre release.
type blockingWriter struct {
	responseRecorder
	writing chan struct{}
	release chan struct{}
}

func (w *blockingWriter) Write(b []byte) (int, error) {
	close(w.writing)
	<-w.release
	return w.responseRecorder.Write(b)
}

// H12: "sites", "subdomains" y "subdomainData" no tienen el lock global
// mientras escriben la respuesta: un cliente que no lee no deja al resto del
// servidor esperando detrás de un Lock pendiente.
func TestB3_PanelWritesWithoutLock(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	token := strings.TrimPrefix(loginFrom(handler, "192.0.2.10", "Turbo", "Admin").body.String(), "ok")
	for _, path := range []string{"/admin:inside:sites", "/admin:inside:subdomains?s=localhost", "/admin:inside:subdomainData?s=localhost&d="} {
		req := newPanelRequest(path, "192.0.2.10:40000")
		req.Header.Set("ok", token)
		w := &blockingWriter{writing: make(chan struct{}), release: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			handler(w, req)
			close(done)
		}()
		select {
		case <-w.writing:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no llegó a escribir la respuesta", path)
		}
		if globalMutex.TryLock() {
			globalMutex.Unlock()
		} else {
			t.Errorf("%s escribe la respuesta con el lock global tomado", path)
		}
		close(w.release)
		<-done
		if !strings.HasPrefix(w.body.String(), "{") {
			t.Errorf("%s: respuesta %q", path, w.body.String())
		}
	}
}

// newPanelRequest prepara un POST al panel desde remoteAddr, sin red y, como
// los del servidor, con cuerpo (vacío).
func newPanelRequest(path, remoteAddr string) *customNetHttp.Request {
	req, _ := customNetHttp.NewRequest("POST", "http://localhost"+path, customNetHttp.NoBody) // As the server gives it: never a nil body
	req.RequestURI = path
	req.RemoteAddr = remoteAddr
	return req
}

// maxLatency pide GET / varias veces durante d y devuelve la mayor espera.
func maxLatency(t *testing.T, base string, d time.Duration) time.Duration {
	t.Helper()
	get(base, "/", nil) // The first request also opens the connection
	var worst time.Duration
	for end := time.Now().Add(d); time.Now().Before(end); {
		start := time.Now()
		if code, _, err := get(base, "/", nil); err != nil || code != 200 {
			t.Fatalf("GET /: %d %v", code, err)
		}
		worst = max(worst, time.Since(start))
		time.Sleep(5 * time.Millisecond)
	}
	return worst
}

// latencyLimit es la espera máxima admitida para GET / (más con -race).
func latencyLimit() time.Duration {
	if raceEnabled {
		return 500 * time.Millisecond
	}
	return 60 * time.Millisecond
}

// H16: setP calcula PBKDF2 sin el lock global: durante un cambio de
// contraseña, GET / responde en milisegundos.
func TestB5_SetPasswordDoesNotBlock(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	tok := login(t, base)
	verifiedPassword.Store(nil) // The current password is also checked with PBKDF2
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		post(base, "/admin:inside:setP?a=Nueva&b=Admin", tok)
		done <- time.Since(start)
	}()
	time.Sleep(10 * time.Millisecond)
	worst := maxLatency(t, base, 150*time.Millisecond)
	took := <-done
	if worst > latencyLimit() {
		t.Errorf("GET / tardó %v durante setP (que tardó %v)", worst, took)
	}
	if !passwordMatches("Nueva") {
		t.Error("setP no cambió la contraseña")
	}
}
