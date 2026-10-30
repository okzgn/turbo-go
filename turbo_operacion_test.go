package main

// Operación: arranque sin puerto, cierre de los logs y direcciones de escucha
// configurables (#31, #53, #19).

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// #53: si no puede abrir el puerto 80, Turbo termina con un código distinto de
// cero en lugar de seguir en ejecución sin servir.
func TestW_ExitWithoutPort80(t *testing.T) {
	if testing.Short() {
		t.Skip("compila el binario")
	}
	bin := filepath.Join(t.TempDir(), "turbo")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	// Ocupa el puerto si se puede; si no (sin privilegios u ocupado por otro
	// proceso), Turbo tampoco podrá abrirlo.
	if l, err := net.Listen("tcp", ":80"); err == nil {
		defer l.Close()
	}
	dir := t.TempDir()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Turbo terminó con código 0; se esperaba un error")
		}
		t.Logf("Turbo terminó: %v", err)
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("Turbo sigue en ejecución sin el puerto 80")
	}
}

// #31: resetSettings cierra los logs abiertos, no solo olvida sus punteros.
func TestW_ResetSettingsClosesLogs(t *testing.T) {
	dir := initForTest(t)
	os.WriteFile(dir+"turbo.visits", nil, 0644)
	os.WriteFile(dir+"turbo.denials", nil, 0644)
	updateSettings(false) // la recarga periódica abre los logs
	visits, denials := serverGetLogState(visitsLogName), serverGetLogState(denialsLogName)
	if visits == nil || denials == nil {
		t.Fatal("los logs no se abrieron")
	}
	resetSettings()
	for name, f := range map[string]*os.File{"turbo.visits": visits, "turbo.denials": denials} {
		if _, err := f.WriteString("x"); err == nil {
			t.Errorf("%s sigue abierto tras resetSettings", name)
		}
	}
}

// T2.5 (#19): TURBO_HTTP_ADDR y TURBO_HTTPS_ADDR cambian dónde escucha Turbo.
func TestT25_ListenAddress(t *testing.T) {
	casos := []struct{ valor, esperado string }{
		{"", ":80"},
		{"8080", ":8080"},
		{":8080", ":8080"},
		{"127.0.0.1:8080", "127.0.0.1:8080"},
		{"[::1]:8443", "[::1]:8443"},
		{"localhost:0", ""},
		{"puerto", ""},
		{"1.2.3.4:70000", ""},
	}
	for _, c := range casos {
		t.Setenv("TURBO_PRUEBA_ADDR", c.valor)
		got, err := listenAddress("TURBO_PRUEBA_ADDR", ":80")
		if c.esperado == "" {
			if err == nil {
				t.Errorf("%q: %q sin error; se esperaba un error", c.valor, got)
			}
			continue
		}
		if err != nil || got != c.esperado {
			t.Errorf("%q: %q, %v; se esperaba %q", c.valor, got, err, c.esperado)
		}
	}
}

func TestT25_ServeOnConfiguredAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("compila el binario")
	}
	bin := filepath.Join(t.TempDir(), "turbo")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	dir := t.TempDir()
	cmd := exec.Command(bin)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TURBO_DIR="+dir, "TURBO_HTTP_ADDR="+addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	for inicio := time.Now(); time.Since(inicio) < 15*time.Second; time.Sleep(100 * time.Millisecond) {
		res, err := http.Get("http://" + addr + "/")
		if err != nil {
			continue
		}
		res.Body.Close()
		if res.Header.Get("Server") != serverName {
			t.Fatalf("responde sin la cabecera Server de Turbo: %v", res.Header)
		}
		return
	}
	t.Fatalf("Turbo no responde en %s", addr)
}
