package main

// Límites de tamaño, limitador de frecuencia e IPs denegadas (#7, #8, #9, #25,
// #36, #37, #42).

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// #25: MUB y MHB cambiados desde el validador deben llegar al servidor.
func TestP25_LimitsValueCopy(t *testing.T) {
	initForTest(t)
	ok1, m1 := defaultSettingValidators["."]["MUB"]("40", "Admin")
	ok2, m2 := defaultSettingValidators["."]["MHB"]("600", "Admin")
	ok3, m3 := defaultSettingValidators["."]["MBB"]("10", "Admin")
	t.Logf("validadores: MUB %v %q | MHB %v %q | MBB %v %q", ok1, m1, ok2, m2, ok3, m3)
	t.Logf("fork: MUB=%d MHB=%d MBB=%d", customNetHttp.TurboMaxURILength.Load(), customNetHttp.TurboMaxHeaderBytes.Load(), customNetHttp.TurboMaxBodySize.Load())
	base := startServer(t)
	if code, _, err := get(base, "/"+strings.Repeat("a", 100), nil); code != 414 {
		t.Errorf("URI de 101 bytes con MUB=40: code=%d err=%v; se esperaba 414", code, err)
	}
	if code, _, err := get(base, "/index.html", map[string]string{"X-Test": strings.Repeat("a", 3000)}); code != 431 {
		t.Errorf("cabecera de 3000 bytes con MHB=600: code=%d err=%v; se esperaba 431", code, err)
	}
}

// #9: CIL y CIS en milisegundos reales.
func TestP09_CILUnits(t *testing.T) {
	initForTest(t)
	defaultSettingValidators["."]["CIL"]("1000", "Admin")
	defaultSettingValidators["."]["CIS"]("100", "Admin")
	if d := time.Duration(serverRequestLimits[0]); d != time.Second {
		t.Errorf("CIL=1000 -> %v; se esperaba 1s", d)
	}
	if d := time.Duration(serverRequestLimits[1]); d != 100*time.Millisecond {
		t.Errorf("CIS=100 -> %v; se esperaba 100ms", d)
	}
}

// #8, #36: con los valores por defecto (CII=100), el rechazo llega cerca de la
// petición 100 y es un 429.
func TestP08_RateLimitCount(t *testing.T) {
	initForTest(t)
	base := startServer(t)
	for i := 1; i <= 300; i++ {
		code, _, err := get(base, "/", nil) // /index.html redirige a ./ (#39): contaría dos peticiones
		if err != nil || code == 429 {
			t.Logf("primer rechazo en la petición %d (code=%d err=%v)", i, code, err)
			if err != nil || code != 429 {
				t.Fatalf("rechazo sin 429: code=%d err=%v", code, err)
			}
			if i < 90 || i > 110 {
				t.Fatalf("rechazo en la petición %d; se esperaba cerca de 100", i)
			}
			// Misma conexión (el transporte la reutiliza): una nueva se cerraría.
			res, _, err := rawGet(base, "localhost", "/")
			if err != nil || res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
				t.Fatalf("petición bloqueada: err=%v res=%v; se esperaba 429 con Retry-After", err, res)
			}
			t.Logf("Retry-After: %s", res.Header.Get("Retry-After"))
			return
		}
	}
	t.Fatal("sin rechazo en 300 peticiones")
}

// #37: la primera denegación debe quedar en turbo.denials.
func TestP08b_RateLimitDetail(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	updateSettings(false) // la recarga periódica abre el log
	base := startServer(t)
	fails := 0
	for i := 1; i <= 200; i++ {
		code, _, err := get(base, "/", nil)
		if err != nil || code != 200 {
			t.Logf("petición %d: code=%d err=%v", i, code, err)
			fails++
			if fails > 6 {
				break
			}
		}
	}
	if fails == 0 {
		t.Fatal("el limitador no rechazó ninguna petición")
	}
	serverSetLogState(denialsLogName, nil) // vacía y cierra el log
	b, _ := os.ReadFile(dir + "turbo.denials")
	t.Logf("denials:\n%s", b)
	if !strings.Contains(string(b), "127.0.0.1") {
		t.Fatal("turbo.denials no contiene la denegación")
	}
}

// #42: una IP denegada a mano queda bloqueada desde la primera llamada y se
// desbloquea al borrarla.
func TestW_ManualDeniedIP(t *testing.T) {
	initForTest(t)
	ip := "203.0.113.7"
	globalMutex.Lock()
	ok, msg := adminAddHandlers["@"](ip, "9999999999")
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("alta: %q", msg)
	}
	if !perIpNotAvailable(ip, true) {
		t.Fatal("la IP denegada no está bloqueada en la primera llamada")
	}
	globalMutex.Lock()
	ok, msg = adminDeleteHandlers["@"](ip)
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("baja: %q", msg)
	}
	if perIpNotAvailable(ip, true) {
		t.Fatal("la IP sigue bloqueada tras borrarla")
	}
}

// #7: ipReferences no debe crecer sin límite: la limpieza periódica olvida las
// IPs inactivas más de CIL.
func TestPend_IPRefMemory(t *testing.T) {
	initForTest(t)
	if ok, msg := defaultSettingValidators["."]["CIL"]("1000", "Admin"); !ok {
		t.Fatal(msg)
	}
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	n := 1_000_000
	for i := 0; i < n; i++ {
		perIpNotAvailable(fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff), true)
	}
	time.Sleep(1100 * time.Millisecond)
	cleanIPReferences()
	runtime.GC()
	runtime.ReadMemStats(&m1)
	count := 0
	ipReferences.Range(func(_, _ any) bool { count++; return true })
	t.Logf("%d IPs distintas -> %d entradas retenidas tras la limpieza, %+.1f MiB de heap tras GC", n, count, (float64(m1.HeapAlloc)-float64(m0.HeapAlloc))/(1<<20))
	if count > n/100 {
		t.Fatalf("%d entradas retenidas; se esperaban cerca de cero", count)
	}
}

// #42, §5.2: las entradas de "@" de un turbo.config anterior se cargan como
// denegaciones manuales (las caducadas se descartan) y al guardar solo se
// escriben esas, no las marcas temporales del limitador global.
func TestC_DeniedIPsFromConfig(t *testing.T) {
	dir := initForTest(t)
	cfg := `{"localhost":{"":{}},"@":{"203.0.113.8":"9999999999","203.0.113.9":"1000"}}`
	os.WriteFile(dir+"turbo.config", []byte(cfg), 0600)
	configFileModTime = 0
	updateSettings(false)
	if !perIpNotAvailable("203.0.113.8", true) {
		t.Error("la IP activa de turbo.config no está bloqueada")
	}
	if perIpNotAvailable("203.0.113.9", true) {
		t.Error("la IP caducada de turbo.config está bloqueada")
	}
	if !saveDefaultConfig() {
		t.Fatal("no se pudo guardar")
	}
	b, _ := os.ReadFile(dir + "turbo.config")
	s := string(b)
	if !strings.Contains(s, "203.0.113.8") || strings.Contains(s, "203.0.113.9") {
		t.Errorf("\"@\" guardado: %s", s)
	}
}

// Una IP de menos de 3 caracteres ("::" es una IPv6 válida) no debe entrar en
// panic al darla de alta, ni desde el panel ni al cargar turbo.config (allí
// tumbaría el arranque).
func TestW_DeniedIPShortAddress(t *testing.T) {
	dir := initForTest(t)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic al denegar \"::\": %v", r)
			}
		}()
		globalMutex.Lock()
		defer globalMutex.Unlock()
		if ok, msg := adminAddHandlers["@"]("::", "9999999999"); ok {
			t.Errorf("\"::\" aceptada: %q", msg)
		}
		if ok, msg := adminAddHandlers["@"]("::1", "9999999999"); ok {
			t.Errorf("\"::1\" (localhost) aceptada: %q", msg)
		}
	}()
	os.WriteFile(dir+"turbo.config", []byte(`{"localhost":{"":{}},"@":{"::":"9999999999"}}`), 0600)
	configFileModTime = 0
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic al cargar turbo.config con \"::\" en \"@\": %v", r)
		}
	}()
	updateSettings(false)
}
