package main

// Concurrencia (#3, #4, #14, #26). TestR_RealisticRace es la prueba de humo
// para go test -race en Linux.

import (
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// #3: cleanOldValues frente a escrituras con lock no debe abortar el proceso
// con "concurrent map writes".
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

// #26: lectura de los timeouts publicados (como hace el fork en cada
// conexión, sin lock) frente a la escritura del panel (con lock).
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
		d = customNetHttp.TurboTimeLimits.Load().RT // lectura sin lock, como en customNetHttp
	}
	close(stop)
	wg.Wait()
	t.Logf("último valor leído: %v", d)
}

// Carga realista para el detector de carreras: tráfico HTTP, panel y tareas
// periódicas a la vez. Con -race no debe haber avisos.
func TestR_RealisticRace(t *testing.T) {
	dir := initForTest(t)
	// Visitantes y administrador comparten la IP 127.0.0.1: el limitador no debe
	// bloquearla (CII no puede pasar de CIS en ms, así que primero se sube CIS).
	for _, ajuste := range [][2]string{{"CIS", "50000"}, {"CII", "50000"}} {
		if ok, msg := defaultSettingValidators["."][ajuste[0]](ajuste[1], "Admin"); !ok {
			t.Fatalf("%s=%s: %s", ajuste[0], ajuste[1], msg)
		}
	}
	base := startServer(t)
	tok := login(t, base)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // visitantes
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					get(base, "/", nil)
					get(base, "/no-existe", nil) // plantilla de error
				}
			}
		}()
	}
	var credencialesEscritas, credencialesRechazadas atomic.Int64
	wg.Add(1)
	go func() { // administrador
		defer wg.Done()
		usuario, clave := "Turbo", "Admin"
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			post(base, "/admin:inside:setRT?b="+clave+"&a="+strconv.Itoa(5+i%3)+"s", tok)
			post(base, "/admin:inside:addHeader?s=localhost&d=&a=X-T&b=v"+strconv.Itoa(i), tok)
			post(base, "/admin:inside:sites", tok)
			// Ajustes que cambian credenciales, directorio y plantillas de error
			// mientras el servidor los lee (cabecera Server, Error, ErrorD). Las
			// credenciales alternan entre dos valores para que cada set* escriba
			// de verdad (con el mismo valor responderían 400 sin cambiar nada).
			nuevoUsuario, nuevaClave := "Turbo2", "Admin2"
			if usuario == nuevoUsuario {
				nuevoUsuario = "Turbo"
			}
			if clave == nuevaClave {
				nuevaClave = "Admin"
			}
			for _, cambio := range []struct {
				ruta  string
				nuevo *string
				valor string
			}{
				{"/admin:inside:setU?a=" + nuevoUsuario + "&b=" + clave, &usuario, nuevoUsuario},
				{"/admin:inside:setP?a=" + nuevaClave + "&b=" + clave, &clave, nuevaClave},
			} {
				if code, body, err := post(base, cambio.ruta, tok); err == nil && code == 200 {
					*cambio.nuevo = cambio.valor
					credencialesEscritas.Add(1)
				} else {
					if credencialesRechazadas.Add(1) == 1 {
						t.Logf("primer rechazo: %s -> %d %q %v", cambio.ruta, code, body, err)
					}
				}
			}
			post(base, "/admin:inside:setM?b="+clave+"&a="+url.QueryEscape(dir), tok)
			post(base, "/admin:inside:addHttpCodeResponse?s=404&d=No+existe+"+strconv.Itoa(i), tok)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Add(1)
	go func() { // tareas periódicas de main(), aceleradas
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				updateSettings(true)
				cleanOldValues(&signedInTokens)
				cleanOldValues(&persistentIPs)
			}
		}
	}()
	time.Sleep(6 * time.Second)
	close(stop)
	wg.Wait()
	t.Logf("setU y setP: %d escrituras", credencialesEscritas.Load())
	if credencialesEscritas.Load() == 0 || credencialesRechazadas.Load() != 0 {
		t.Errorf("setU y setP: %d escrituras y %d rechazadas; deben escribir siempre", credencialesEscritas.Load(), credencialesRechazadas.Load())
	}
}
