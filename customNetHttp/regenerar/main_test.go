package main

// B8 (H14): -comprobar verifica también los archivos propios (0.*.go) y las
// fuentes de Go de las que se regenera, y un fragmento de parche que coincide
// en más de un sitio no se aplica.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copiaDelFork copia customNetHttp (sin regenerar/) a un directorio temporal.
func copiaDelFork(t *testing.T) string {
	t.Helper()
	destino := t.TempDir()
	err := filepath.WalkDir("..", func(ruta string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relativa, _ := filepath.Rel("..", ruta)
		if d.IsDir() {
			if d.Name() == "regenerar" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(destino, relativa), 0o755)
		}
		contenido, err := os.ReadFile(ruta)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(destino, relativa), contenido, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(destino, "regenerar"), 0o755)
	return destino
}

func comprobarEn(dir string) error {
	return ejecutar(dir, "", -1, true, false, func(string, ...any) {})
}

func TestB8_ComprobarArchivosPropios(t *testing.T) {
	if testing.Short() {
		t.Skip("regenera el fork")
	}
	dir := copiaDelFork(t)
	if err := comprobarEn(dir); err != nil {
		t.Fatalf("la copia del fork no pasa -comprobar: %v", err)
	}

	os.WriteFile(filepath.Join(dir, "0.zz.go"), []byte("package customNetHttp\n\nfunc init() {}\n"), 0o644)
	if err := comprobarEn(dir); err == nil {
		t.Error("-comprobar acepta un 0.zz.go añadido")
	}
	os.Remove(filepath.Join(dir, "0.zz.go"))

	propio := filepath.Join(dir, "0.turbo.parches.go")
	original, _ := os.ReadFile(propio)
	os.WriteFile(propio, append(original, []byte("\nfunc turboAñadida() {}\n")...), 0o644)
	if err := comprobarEn(dir); err == nil {
		t.Error("-comprobar acepta un 0.turbo.parches.go modificado")
	}
}

// Una fuente de Go distinta de la del manifiesto se detecta.
func TestB8_FuentesDeGo(t *testing.T) {
	fuentes := map[string][]byte{"net/http/a.go": []byte("package http\n"), "mime/multipart/b.go": []byte("package multipart\n")}
	manifiesto := manifiestoDe(fuentes)
	if err := compararManifiesto(manifiesto, fuentes); err != nil {
		t.Fatalf("las mismas fuentes no coinciden: %v", err)
	}
	alteradas := map[string][]byte{"net/http/a.go": []byte("package http\nfunc init() {}\n"), "mime/multipart/b.go": fuentes["mime/multipart/b.go"]}
	if err := compararManifiesto(manifiesto, alteradas); err == nil || !strings.Contains(err.Error(), "net/http/a.go") {
		t.Errorf("una fuente alterada no se detecta: %v", err)
	}
	if err := compararManifiesto(manifiesto, map[string][]byte{"net/http/a.go": fuentes["net/http/a.go"]}); err == nil {
		t.Error("una fuente que falta no se detecta")
	}
}

// Un fragmento cuyo contexto aparece en dos sitios no se aplica en ninguno.
func TestB8_FragmentoAmbiguo(t *testing.T) {
	archivos := map[string]string{"x.go": "a\nb\nc\nx\na\nb\nc\n"}
	parche := "--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"
	if err := aplicarParche(archivos, parche); err == nil {
		t.Errorf("fragmento ambiguo aplicado: %q", archivos["x.go"])
	}
	archivos = map[string]string{"x.go": "a\nb\nc\nx\n"}
	if err := aplicarParche(archivos, parche); err != nil || archivos["x.go"] != "a\nB\nc\nx\n" {
		t.Errorf("fragmento único: %v %q", err, archivos["x.go"])
	}
}
