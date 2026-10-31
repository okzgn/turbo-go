package main

// A5 (H6): el limitador global tiene su propio ajuste (CGL, peticiones por
// segundo en total), desactivado por defecto, y no marca a ninguna IP.

import (
	"bytes"
	"strconv"
	"sync"
	"testing"
	"time"

	"turbo/customNetHttp"
)

// responseRecorder es un ResponseWriter en memoria para llamar al manejador
// sin red, con la IP de cliente que se quiera.
type responseRecorder struct {
	header customNetHttp.Header
	code   int
	body   bytes.Buffer
}

func (r *responseRecorder) Header() customNetHttp.Header {
	if r.header == nil {
		r.header = make(customNetHttp.Header)
	}
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = 200
	}
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
}

// serveFrom pide GET / a localhost desde la IP dada, sin red.
func serveFrom(handler func(customNetHttp.ResponseWriter, *customNetHttp.Request), ip string) *responseRecorder {
	req, _ := customNetHttp.NewRequest("GET", "http://localhost/", nil)
	req.RequestURI = "/"
	req.RemoteAddr = ip + ":40000"
	rec := &responseRecorder{}
	handler(rec, req)
	return rec
}

// waitNextSecond espera al comienzo del siguiente segundo, para que una ráfaga
// quede en una sola ventana del limitador global.
func waitNextSecond() {
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 10*time.Millisecond)))
}

// H6: con los valores por defecto, 300 peticiones de 300 IPs en menos de un
// segundo se sirven todas: no hay límite global.
func TestA5_NoGlobalLimitByDefault(t *testing.T) {
	initForTest(t)
	handler := serverHandlerFn("")
	waitNextSecond()
	for i := 0; i < 300; i++ {
		if rec := serveFrom(handler, "10.1."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250+1)); rec.code != 200 {
			t.Fatalf("petición %d de una IP distinta: %d; se esperaba 200", i+1, rec.code)
		}
	}
}

// H6, D4: con CGL=50, las peticiones por encima de 50 en un segundo reciben
// 503 con Retry-After: 1, sin 429; al segundo siguiente nadie queda bloqueado.
func TestA5_GlobalLimitCGL(t *testing.T) {
	initForTest(t)
	validator, exists := defaultSettingValidators["."]["CGL"]
	if !exists {
		t.Fatal("no existe el ajuste CGL")
	}
	globalMutex.Lock()
	ok, msg := validator("50", internalAuth)
	globalMutex.Unlock()
	if !ok {
		t.Fatalf("setCGL 50: %q", msg)
	}
	handler := serverHandlerFn("")
	waitNextSecond()
	served, limited := 0, 0
	for i := 0; i < 120; i++ {
		rec := serveFrom(handler, "10.2.0."+strconv.Itoa(i+1))
		switch {
		case rec.code == 200:
			served++
		case rec.code == 503 && rec.Header().Get("Retry-After") == "1":
			limited++
		default:
			t.Fatalf("petición %d: %d (Retry-After %q); se esperaba 200 o 503 con Retry-After: 1", i+1, rec.code, rec.Header().Get("Retry-After"))
		}
	}
	if served != 50 || limited != 70 {
		t.Errorf("servidas %d y limitadas %d; se esperaban 50 y 70", served, limited)
	}
	waitNextSecond()
	for _, ip := range []string{"10.2.0.120", "10.2.0.1", "10.3.0.1"} {
		if rec := serveFrom(handler, ip); rec.code != 200 {
			t.Errorf("%s al segundo siguiente: %d; se esperaba 200", ip, rec.code)
		}
	}
}

// D4: CGL admite 0 (desactivado) o de 10 a 1 000 000, se guarda en
// turbo.config y se vuelve a leer.
func TestA5_CGLSetting(t *testing.T) {
	dir := initForTest(t)
	validator, exists := defaultSettingValidators["."]["CGL"]
	if !exists {
		t.Fatal("no existe el ajuste CGL")
	}
	globalMutex.Lock()
	defer globalMutex.Unlock()
	for _, c := range []struct {
		value string
		want  bool
	}{{"5", false}, {"9", false}, {"-1", false}, {"x", false}, {"1000001", false}, {"10", true}, {"1000000", true}, {"0", true}, {"250", true}} {
		if ok, msg := validator(c.value, internalAuth); ok != c.want {
			t.Errorf("CGL %q: %v %q; se esperaba %v", c.value, ok, msg, c.want)
		}
	}
	if !saveDefaultConfig() {
		t.Fatal("no se pudo guardar")
	}
	if raw := savedConfig(t, dir); raw["."]["CGL"] != "250" {
		t.Fatalf("CGL guardado: %v", raw["."]["CGL"])
	}
	globalRequestLimit.Store(0)
	configFileModTime = 0
	globalMutex.Unlock()
	updateSettings(false)
	globalMutex.Lock()
	if globalRequestLimit.Load() != 250 {
		t.Errorf("CGL tras recargar: %d", globalRequestLimit.Load())
	}
}

// H59: el contador global no vuelve a un segundo anterior: una petición que
// leyó la hora justo antes del cambio de segundo cuenta en el segundo nuevo,
// sin reiniciarlo, y ninguna petición simultánea se pierde del recuento.
func TestH59_GlobalWindowOnlyMovesForward(t *testing.T) {
	initForTest(t)
	globalRequestLimit.Store(3)
	t.Cleanup(func() { globalRequestLimit.Store(0) })
	for i := 1; i <= 3; i++ {
		if globalRateExceededAt(1001) {
			t.Fatalf("petición %d en el segundo 1001 con CGL = 3: rechazada", i)
		}
	}
	if !globalRateExceededAt(1000) {
		t.Error("petición con la hora del segundo 1000 tras 3 en el 1001: aceptada; reinició el recuento")
	}
	if !globalRateExceededAt(1001) {
		t.Error("quinta petición del segundo 1001: aceptada")
	}
	if globalRateExceededAt(1002) {
		t.Error("primera petición del segundo 1002: rechazada")
	}

	globalRequestLimit.Store(1000000)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				globalRateExceededAt(2000 + int64(i)/250)
			}
		}()
	}
	wg.Wait()
	// The last second (2003) counted at least its 2000 requests (some late ones of 2002 count there too).
	globalRequestLimit.Store(2000)
	if !globalRateExceededAt(2003) {
		t.Error("el recuento del segundo 2003 perdió peticiones simultáneas: la 2001 no supera un límite de 2000")
	}
}
