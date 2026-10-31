// Regenera customNetHttp a partir del código fuente de Go y le aplica los
// parches de Turbo (customNetHttp/patches/*.patch).
//
// Uso, desde la raíz del repositorio y con la versión de Go de
// customNetHttp/UPSTREAM (la herramienta lee el GOROOT con el que se ejecuta):
//
//	go run ./customNetHttp/regenerar              regenera customNetHttp
//	go run ./customNetHttp/regenerar -comprobar   comprueba que customNetHttp es
//	                                              exactamente lo que se regenera
//	go run ./customNetHttp/regenerar -parches N -salida DIR
//	                                              base con solo los N primeros
//	                                              parches, en otro directorio
//	go run ./customNetHttp/regenerar -actualizar  regenera desde otra versión de
//	                                              Go y la anota en UPSTREAM
//
// Los paquetes de origen (net/http y los que necesita de mime/multipart,
// net/http/cgi, x/net y x/text) se fusionan en el paquete único customNetHttp:
// se quitan los calificadores entre ellos y, si dos paquetes declaran el mismo
// nombre, el de net/http lo conserva y el del otro paquete pasa a
// <paquete>_<nombre>. internal/godebug no se puede importar fuera de Go: sus
// usos pasan a godebug_<nombre>, que define 0.turbo.godebug.go.
//
// Los archivos de customNetHttp que empiezan por "0." son propios de Turbo y la
// herramienta no los toca; el resto de *.go los genera ella. Sus SHA-256 están
// en PROPIOS.sha256, que la herramienta reescribe al regenerar en customNetHttp
// y -comprobar verifica: un 0.*.go nuevo o cambiado tiene que verse en ese
// archivo. FUENTES.sha256 tiene los SHA-256 de cada archivo de Go del que se
// regenera: -actualizar lo escribe y el resto de modos comprueba que el GOROOT
// coincide con él.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// origen describe un paquete de Go que se fusiona en customNetHttp.
type origen struct {
	dir      string   // directorio bajo GOROOT/src
	prefijo  string   // prefijo de los archivos generados
	archivos []string // si no está vacío, solo estos archivos
}

var origenes = []origen{
	{dir: "net/http", prefijo: "1.net.http."},
	{dir: "net/http/internal", prefijo: "1.net.http.internal."},
	{dir: "net/http/internal/ascii", prefijo: "1.net.http.internal.ascii."},
	{dir: "net/http/internal/httpcommon", prefijo: "1.net.http.internal.httpcommon."},
	{dir: "net/http/cgi", prefijo: "a.server.cgi.", archivos: []string{"host.go"}},
	{dir: "mime/multipart", prefijo: "c.mime."},
	{dir: "vendor/golang.org/x/net/http2/hpack", prefijo: "x.net.http2.hpack."},
	{dir: "vendor/golang.org/x/net/http/httpguts", prefijo: "z.x.net.http.httpguts."},
	{dir: "vendor/golang.org/x/net/http/httpproxy", prefijo: "z.x.net.http.httpproxy."},
	{dir: "vendor/golang.org/x/net/idna", prefijo: "z.x.net.idna."},
	{dir: "vendor/golang.org/x/text/secure/bidirule", prefijo: "y.x.text.secure.bidirule."},
	{dir: "vendor/golang.org/x/text/transform", prefijo: "y.x.text.transform."},
	{dir: "vendor/golang.org/x/text/unicode/bidi", prefijo: "y.x.text.unicode.bidi."},
	{dir: "vendor/golang.org/x/text/unicode/norm", prefijo: "y.x.text.unicode.norm."},
}

// principal es el paquete que conserva sus nombres en caso de conflicto.
const principal = "net/http"

// sustituidos son paquetes internos de Go que no se pueden importar desde
// fuera: sus usos pasan a <nombre>_<identificador>, definidos a mano en un
// archivo 0.turbo.*.go.
var sustituidos = map[string]string{
	"internal/godebug": "godebug",
}

// nombresFijos fija el nombre de un identificador en conflicto en lugar de
// <paquete>_<nombre>: son los que usa Turbo.
var nombresFijos = map[string]map[string]string{
	"net/http/cgi": {"Handler": "CgiHandler"},
}

// contextos en los que se comprueba que la selección de archivos no depende
// del sistema operativo ni de la arquitectura.
var contextos = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"darwin", "arm64"}, {"freebsd", "amd64"},
}

const paquete = "customNetHttp"

func main() {
	log := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	dir := flag.String("dir", "customNetHttp", "directorio de customNetHttp (con UPSTREAM y patches/)")
	salida := flag.String("salida", "", "escribir el resultado en este directorio en lugar de en -dir")
	nParches := flag.Int("parches", -1, "aplicar solo los N primeros parches (-1: todos)")
	comprobar := flag.Bool("comprobar", false, "no escribe: comprueba que -dir coincide con lo regenerado")
	actualizar := flag.Bool("actualizar", false, "regenerar con la versión de Go en uso aunque UPSTREAM diga otra y anotarla")
	flag.Parse()

	if err := ejecutar(*dir, *salida, *nParches, *comprobar, *actualizar, log); err != nil {
		log("regenerar: %v", err)
		os.Exit(1)
	}
}

func ejecutar(dir, salida string, nParches int, comprobar, actualizar bool, log func(string, ...any)) error {
	version := runtime.Version()
	upstream, err := os.ReadFile(filepath.Join(dir, "UPSTREAM"))
	if err != nil && !actualizar {
		return err
	}
	esperada := strings.TrimSpace(strings.SplitN(normalizar(string(upstream)), "\n", 2)[0])
	if esperada != version && !actualizar {
		return fmt.Errorf("UPSTREAM pide %s y se está ejecutando %s: ejecútalo con esa versión de Go o usa -actualizar", esperada, version)
	}
	if comprobar && (actualizar || salida != "" || nParches >= 0) {
		return errors.New("-comprobar no admite -actualizar, -salida ni -parches")
	}

	// El código se lee del GOROOT, que la variable de entorno GOROOT puede
	// cambiar: debe ser el de la versión que se ejecuta.
	goroot := build.Default.GOROOT
	versionGoroot, err := os.ReadFile(filepath.Join(goroot, "VERSION"))
	if err != nil {
		return fmt.Errorf("no se puede leer la versión de %s: %v", goroot, err)
	}
	if v := strings.TrimSpace(strings.SplitN(normalizar(string(versionGoroot)), "\n", 2)[0]); v != version {
		return fmt.Errorf("el GOROOT %s es %s y se está ejecutando %s: quita la variable GOROOT o ejecútalo con esa versión", goroot, v, version)
	}

	fuentes := map[string][]byte{}
	generados, err := generar(goroot, dir, version, fuentes)
	if err != nil {
		return err
	}
	manifiestoFuentes := filepath.Join(dir, "FUENTES.sha256")
	if !actualizar { // The Go sources must be the ones recorded for UPSTREAM (H14)
		guardado, err := os.ReadFile(manifiestoFuentes)
		if err != nil {
			return fmt.Errorf("falta FUENTES.sha256 (regenera con -actualizar): %v", err)
		}
		if err := compararManifiesto(normalizar(string(guardado)), fuentes); err != nil {
			return fmt.Errorf("las fuentes de Go de %s no son las de FUENTES.sha256: %v", goroot, err)
		}
	}
	parches, err := filepath.Glob(filepath.Join(dir, "patches", "*.patch"))
	if err != nil {
		return err
	}
	sort.Strings(parches)
	if nParches >= 0 && nParches < len(parches) {
		parches = parches[:nParches]
	}
	for _, p := range parches {
		texto, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := aplicarParche(generados, normalizar(string(texto))); err != nil {
			return fmt.Errorf("%s no aplica limpio: %v", filepath.Base(p), err)
		}
	}
	for nombre, contenido := range generados {
		formateado, err := format.Source([]byte(contenido))
		if err != nil {
			return fmt.Errorf("%s no es Go válido tras los parches: %v", nombre, err)
		}
		if string(formateado) != contenido {
			return fmt.Errorf("%s no queda con el formato de gofmt tras los parches", nombre)
		}
	}

	if comprobar {
		if err := comprobarPropios(dir); err != nil {
			return err
		}
		return compararCon(dir, generados, log)
	}
	destino := dir
	if salida != "" {
		destino = salida
		if err := os.MkdirAll(destino, 0o755); err != nil {
			return err
		}
	}
	if err := escribir(destino, generados); err != nil {
		return err
	}
	if destino == dir {
		propios, err := leerPropios(dir)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "PROPIOS.sha256"), []byte(manifiestoDe(propios)), 0o644); err != nil {
			return err
		}
	}
	if actualizar {
		if err := os.WriteFile(filepath.Join(dir, "UPSTREAM"), []byte(version+"\n"), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(manifiestoFuentes, []byte(manifiestoDe(fuentes)), 0o644); err != nil {
			return err
		}
	}
	log("regenerar: %d archivos desde %s con %d parches en %s", len(generados), version, len(parches), destino)
	return nil
}

// normalizar quita los retornos de carro (copias de Windows con autocrlf).
func normalizar(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// esGenerado indica si un archivo de customNetHttp lo produce esta herramienta.
func esGenerado(nombre string) bool {
	return strings.HasSuffix(nombre, ".go") && !strings.HasPrefix(nombre, "0.")
}

// esperado indica si una entrada de customNetHttp es de las que puede haber:
// archivos .go (generados o 0.*.go), los textos de licencia y del fork, y las
// carpetas patches y regenerar. Cualquier otra (un .s o un .syso, que también
// se compilarían con el paquete) es un error.
func esperado(e os.DirEntry) bool {
	if e.IsDir() {
		return e.Name() == "patches" || e.Name() == "regenerar"
	}
	switch e.Name() {
	case "LICENCE", "NOTICE", "PATENTS", "UPSTREAM", "PATCHES.md", "PROPIOS.sha256", "FUENTES.sha256":
		return true
	}
	return strings.HasSuffix(e.Name(), ".go")
}

func compararCon(dir string, generados map[string]string, log func(string, ...any)) error {
	entradas, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var diferencias []string
	vistos := map[string]bool{}
	for _, e := range entradas {
		if !esperado(e) {
			diferencias = append(diferencias, e.Name()+": inesperado (solo se admiten los archivos generados, 0.*.go y los de PATCHES.md)")
			continue
		}
		if e.IsDir() || !esGenerado(e.Name()) {
			continue
		}
		vistos[e.Name()] = true
		esperado, ok := generados[e.Name()]
		if !ok {
			diferencias = append(diferencias, e.Name()+": sobra")
			continue
		}
		actual, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if normalizar(string(actual)) != esperado {
			diferencias = append(diferencias, e.Name()+": distinto")
		}
	}
	for nombre := range generados {
		if !vistos[nombre] {
			diferencias = append(diferencias, nombre+": falta")
		}
	}
	sort.Strings(diferencias)
	if len(diferencias) > 0 {
		for _, d := range diferencias {
			log("  %s", d)
		}
		return fmt.Errorf("%d archivos no coinciden con Go %s más los parches", len(diferencias), runtime.Version())
	}
	log("regenerar: customNetHttp coincide con Go %s más los parches (%d archivos)", runtime.Version(), len(generados))
	return nil
}

func escribir(destino string, generados map[string]string) error {
	entradas, err := os.ReadDir(destino)
	if err != nil {
		return err
	}
	for _, e := range entradas {
		if !e.IsDir() && esGenerado(e.Name()) {
			if _, ok := generados[e.Name()]; !ok {
				if err := os.Remove(filepath.Join(destino, e.Name())); err != nil {
					return err
				}
			}
		}
	}
	for nombre, contenido := range generados {
		if err := os.WriteFile(filepath.Join(destino, nombre), []byte(contenido), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// canonica quita el prefijo vendor/ de una ruta de importación.
func canonica(ruta string) string { return strings.TrimPrefix(ruta, "vendor/") }

type paqueteOrigen struct {
	origen
	ruta     string // ruta de importación canónica
	nombre   string
	archivos []*ast.File
	fuentes  map[*ast.File][]byte
	nombres  map[*ast.File]string
	info     *types.Info
	tipos    *types.Package
}

// generar fusiona los paquetes de Go en customNetHttp y devuelve los archivos generados. En fuentes deja cada
// archivo de Go leído, por su ruta bajo GOROOT/src.
func generar(goroot, dir, version string, fuentes map[string][]byte) (map[string]string, error) {
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil)
	var paquetes []*paqueteOrigen
	fusionados := map[string]*paqueteOrigen{}

	for _, o := range origenes {
		p := &paqueteOrigen{origen: o, ruta: canonica(o.dir), fuentes: map[*ast.File][]byte{}, nombres: map[*ast.File]string{}}
		lista, err := seleccionar(filepath.Join(goroot, "src", filepath.FromSlash(o.dir)), o.archivos)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", o.dir, err)
		}
		for _, ruta := range lista {
			fuente, err := os.ReadFile(ruta)
			if err != nil {
				return nil, err
			}
			f, err := parser.ParseFile(fset, ruta, fuente, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			p.archivos = append(p.archivos, f)
			p.fuentes[f] = fuente
			fuentes[o.dir+"/"+filepath.Base(ruta)] = fuente
			p.nombres[f] = filepath.Base(ruta)
		}
		p.nombre = p.archivos[0].Name.Name
		p.info = &types.Info{
			Defs:      map[*ast.Ident]types.Object{},
			Uses:      map[*ast.Ident]types.Object{},
			Implicits: map[ast.Node]types.Object{},
		}
		conf := types.Config{Importer: imp}
		p.tipos, err = conf.Check(o.dir, fset, p.archivos, p.info)
		if err != nil {
			return nil, fmt.Errorf("comprobación de tipos de %s: %v", o.dir, err)
		}
		paquetes = append(paquetes, p)
		fusionados[p.ruta] = p
	}

	propios, err := nombresPropios(dir)
	if err != nil {
		return nil, err
	}
	renombres, err := calcularRenombres(paquetes, propios)
	if err != nil {
		return nil, err
	}

	destino := func(rutaPaquete, nombre string) (string, bool) {
		rutaPaquete = canonica(rutaPaquete)
		if s, ok := sustituidos[rutaPaquete]; ok {
			return s + "_" + nombre, true
		}
		if _, ok := fusionados[rutaPaquete]; !ok {
			return "", false
		}
		if n, ok := renombres[rutaPaquete][nombre]; ok {
			return n, true
		}
		return nombre, true
	}

	generados := map[string]string{}
	for _, p := range paquetes {
		for _, f := range p.archivos {
			texto, err := reescribir(fset, p, f, destino)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %v", p.dir, p.nombres[f], err)
			}
			cabecera := fmt.Sprintf("// Origen: %s, src/%s/%s. Regenerado con customNetHttp/regenerar; parches en customNetHttp/PATCHES.md.\n\n", version, p.dir, p.nombres[f])
			nombre := p.prefijo + p.nombres[f]
			if _, ok := generados[nombre]; ok {
				return nil, fmt.Errorf("nombre de archivo repetido: %s", nombre)
			}
			generados[nombre] = cabecera + texto
		}
	}
	return generados, nil
}

// seleccionar devuelve los archivos que se compilan para el sistema actual y
// comprueba que son los mismos en todos los contextos de referencia.
func seleccionar(dir string, solo []string) ([]string, error) {
	entradas, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var referencia []string
	for i, c := range contextos {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = c[0], c[1], false
		var lista []string
		for _, e := range entradas {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			if len(solo) > 0 && !contiene(solo, n) {
				continue
			}
			ok, err := ctx.MatchFile(dir, n)
			if err != nil {
				return nil, err
			}
			if ok {
				lista = append(lista, filepath.Join(dir, n))
			}
		}
		if i == 0 {
			referencia = lista
		} else if strings.Join(lista, "|") != strings.Join(referencia, "|") {
			return nil, fmt.Errorf("los archivos cambian con %s/%s: %v frente a %v", c[0], c[1], lista, referencia)
		}
	}
	if len(referencia) == 0 {
		return nil, errors.New("ningún archivo")
	}
	return referencia, nil
}

func contiene(lista []string, s string) bool {
	for _, x := range lista {
		if x == s {
			return true
		}
	}
	return false
}

// nombresPropios devuelve los nombres de nivel de paquete de los archivos
// 0.*.go de Turbo.
func nombresPropios(dir string) (map[string]bool, error) {
	nombres := map[string]bool{}
	archivos, err := filepath.Glob(filepath.Join(dir, "0.*.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	for _, a := range archivos {
		f, err := parser.ParseFile(fset, a, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					nombres[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						nombres[s.Name.Name] = true
					case *ast.ValueSpec:
						for _, n := range s.Names {
							nombres[n.Name] = true
						}
					}
				}
			}
		}
	}
	return nombres, nil
}

// calcularRenombres decide qué nombres de nivel de paquete cambian al fusionar.
func calcularRenombres(paquetes []*paqueteOrigen, propios map[string]bool) (map[string]map[string]string, error) {
	declarados := map[string][]string{} // nombre -> paquetes que lo declaran
	importados := map[string]bool{}     // nombres de paquetes importados que siguen en el código
	usados := map[string]bool{}         // cualquier identificador que aparezca
	for _, p := range paquetes {
		for _, n := range p.tipos.Scope().Names() {
			declarados[n] = append(declarados[n], p.ruta)
		}
		for _, f := range p.archivos {
			for _, is := range f.Imports {
				ruta, _ := strconv.Unquote(is.Path.Value)
				if _, ok := sustituidos[canonica(ruta)]; ok || esFusionado(paquetes, ruta) {
					continue
				}
				var obj types.Object
				if is.Name != nil {
					obj = p.info.Defs[is.Name]
				} else {
					obj = p.info.Implicits[is]
				}
				if obj != nil {
					importados[obj.Name()] = true
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok {
					usados[id.Name] = true
				}
				return true
			})
		}
	}

	renombres := map[string]map[string]string{}
	nuevos := map[string]string{}
	for _, p := range paquetes {
		for _, n := range p.tipos.Scope().Names() {
			conflicto := len(declarados[n]) > 1 || propios[n] || importados[n] || types.Universe.Lookup(n) != nil
			if !conflicto {
				continue
			}
			if p.ruta == principal {
				if propios[n] || importados[n] || types.Universe.Lookup(n) != nil {
					return nil, fmt.Errorf("%s declara %s, que choca con un nombre propio, importado o predeclarado", p.ruta, n)
				}
				continue
			}
			nuevo := p.nombre + "_" + n
			if fijo, ok := nombresFijos[p.ruta][n]; ok {
				nuevo = fijo
			}
			if usados[nuevo] || propios[nuevo] || len(declarados[nuevo]) > 0 {
				return nil, fmt.Errorf("no se puede renombrar %s.%s a %s: el nombre ya existe", p.ruta, n, nuevo)
			}
			if otro, ok := nuevos[nuevo]; ok {
				return nil, fmt.Errorf("%s.%s y %s pasarían a llamarse %s", p.ruta, n, otro, nuevo)
			}
			nuevos[nuevo] = p.ruta + "." + n
			if renombres[p.ruta] == nil {
				renombres[p.ruta] = map[string]string{}
			}
			renombres[p.ruta][n] = nuevo
		}
	}
	return renombres, nil
}

func esFusionado(paquetes []*paqueteOrigen, ruta string) bool {
	for _, p := range paquetes {
		if p.ruta == canonica(ruta) {
			return true
		}
	}
	return false
}

type edicion struct {
	desde, hasta int
	texto        string
}

// reescribir aplica a un archivo los cambios de la fusión: cláusula package,
// importaciones de paquetes fusionados, calificadores y renombres.
func reescribir(fset *token.FileSet, p *paqueteOrigen, f *ast.File, destino func(string, string) (string, bool)) (string, error) {
	fuente := p.fuentes[f]
	tf := fset.File(f.Pos())
	off := func(pos token.Pos) int { return tf.Offset(pos) }
	var ediciones []edicion

	ediciones = append(ediciones, edicion{off(f.Name.Pos()), off(f.Name.End()), paquete})

	// Importaciones de paquetes fusionados o sustituidos.
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		quedan := 0
		var quitar []ast.Spec
		for _, s := range gd.Specs {
			is := s.(*ast.ImportSpec)
			ruta, _ := strconv.Unquote(is.Path.Value)
			if _, ok := destino(ruta, "x"); ok {
				quitar = append(quitar, s)
			} else {
				quedan++
			}
		}
		if quedan == 0 && len(quitar) > 0 {
			desde, hasta := lineaCompleta(fuente, off(gd.Pos()), off(gd.End()))
			ediciones = append(ediciones, edicion{desde, hasta, ""})
			continue
		}
		for _, s := range quitar {
			desde, hasta := lineaCompleta(fuente, off(s.Pos()), off(s.End()))
			ediciones = append(ediciones, edicion{desde, hasta, ""})
		}
	}

	var fallo error
	ast.Inspect(f, func(n ast.Node) bool {
		if fallo != nil {
			return false
		}
		switch n := n.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.SelectorExpr:
			x, ok := n.X.(*ast.Ident)
			if !ok {
				return true
			}
			pn, ok := p.info.Uses[x].(*types.PkgName)
			if !ok {
				return true
			}
			if nuevo, ok := destino(pn.Imported().Path(), n.Sel.Name); ok {
				ediciones = append(ediciones, edicion{off(n.Pos()), off(n.End()), nuevo})
			}
			return false
		case *ast.Ident:
			// Uses va primero: en un campo incrustado, Defs da el campo y
			// Uses el tipo, que es lo que se renombra.
			obj := p.info.Uses[n]
			if obj == nil {
				obj = p.info.Defs[n]
			}
			// Un campo incrustado se llama como su tipo: si el tipo cambia de
			// nombre, también cambian los accesos al campo (x.options).
			if v, ok := obj.(*types.Var); ok && v.IsField() && v.Embedded() {
				t := v.Type()
				if ptr, ok := t.(*types.Pointer); ok {
					t = ptr.Elem()
				}
				if named, ok := t.(*types.Named); ok {
					obj = named.Obj()
				}
			}
			if obj == nil || obj.Pkg() == nil || obj.Parent() != obj.Pkg().Scope() {
				return true
			}
			if _, ok := obj.(*types.PkgName); ok {
				return true
			}
			if nuevo, ok := destino(obj.Pkg().Path(), n.Name); ok && nuevo != n.Name {
				ediciones = append(ediciones, edicion{off(n.Pos()), off(n.End()), nuevo})
			}
		}
		return true
	})
	if fallo != nil {
		return "", fallo
	}

	// Directivas //go:linkname que nombran un identificador renombrado.
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname ") {
				campos := strings.Fields(c.Text)
				if len(campos) >= 2 {
					if nuevo, ok := destino(p.dir, campos[1]); ok && nuevo != campos[1] {
						return "", fmt.Errorf("//go:linkname de un nombre renombrado (%s)", campos[1])
					}
				}
			}
		}
	}

	sort.Slice(ediciones, func(i, j int) bool { return ediciones[i].desde > ediciones[j].desde })
	salida := append([]byte(nil), fuente...)
	limite := len(salida) + 1
	for _, e := range ediciones {
		if e.hasta > limite {
			return "", fmt.Errorf("ediciones solapadas en el byte %d", e.desde)
		}
		salida = append(salida[:e.desde], append([]byte(e.texto), salida[e.hasta:]...)...)
		limite = e.desde
	}
	formateado, err := format.Source(salida)
	if err != nil {
		return "", fmt.Errorf("gofmt: %v", err)
	}
	return string(formateado), nil
}

// lineaCompleta amplía [desde, hasta) a las líneas completas si no hay nada más
// en ellas, para no dejar líneas vacías al quitar una importación.
func lineaCompleta(fuente []byte, desde, hasta int) (int, int) {
	i := desde
	for i > 0 && (fuente[i-1] == ' ' || fuente[i-1] == '\t') {
		i--
	}
	if i > 0 && fuente[i-1] != '\n' {
		return desde, hasta
	}
	j := hasta
	for j < len(fuente) && fuente[j] != '\n' {
		j++
	}
	resto := bytes.TrimSpace(fuente[hasta:j])
	if len(resto) > 0 && !bytes.HasPrefix(resto, []byte("//")) {
		return desde, hasta
	}
	if j < len(fuente) {
		j++
	}
	return i, j
}

// aplicarParche aplica un diff unificado a los archivos generados. Cada
// fragmento debe coincidir exactamente; solo se admite un desplazamiento de
// líneas, como hace patch, nunca contexto aproximado.
func aplicarParche(archivos map[string]string, texto string) error {
	lineas := strings.Split(texto, "\n")
	for i := 0; i < len(lineas); {
		if !strings.HasPrefix(lineas[i], "--- ") || i+1 >= len(lineas) || !strings.HasPrefix(lineas[i+1], "+++ ") {
			i++
			continue
		}
		viejo := rutaDiff(lineas[i][4:])
		nuevo := rutaDiff(lineas[i+1][4:])
		i += 2
		nombre := nuevo
		var contenido []string
		var finSinSalto bool
		switch {
		case viejo == "":
			// archivo nuevo
		default:
			nombre = viejo
			actual, ok := archivos[viejo]
			if !ok {
				return fmt.Errorf("%s no existe", viejo)
			}
			finSinSalto = !strings.HasSuffix(actual, "\n")
			contenido = strings.Split(strings.TrimSuffix(actual, "\n"), "\n")
		}
		desplazamiento := 0
		for i < len(lineas) && strings.HasPrefix(lineas[i], "@@ ") {
			cab := lineas[i]
			var inicioViejo int
			if _, err := fmt.Sscanf(strings.TrimPrefix(cab, "@@ -"), "%d", &inicioViejo); err != nil {
				return fmt.Errorf("%s: cabecera %q", nombre, cab)
			}
			i++
			var antes, despues []string
			for i < len(lineas) {
				l := lineas[i]
				if l == `\ No newline at end of file` {
					i++
					continue
				}
				if strings.HasPrefix(l, "@@ ") || strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "diff ") || (l == "" && i == len(lineas)-1) {
					break
				}
				switch {
				case l == "" || l[0] == ' ':
					c := ""
					if l != "" {
						c = l[1:]
					}
					antes, despues = append(antes, c), append(despues, c)
				case l[0] == '-':
					antes = append(antes, l[1:])
				case l[0] == '+':
					despues = append(despues, l[1:])
				default:
					return fmt.Errorf("%s: línea inesperada %q", nombre, l)
				}
				i++
			}
			esperado := inicioViejo - 1 + desplazamiento
			if len(antes) == 0 {
				esperado = inicioViejo + desplazamiento
			}
			pos := buscar(contenido, antes, esperado)
			if pos < 0 {
				return fmt.Errorf("%s: el fragmento %s no coincide", nombre, cab)
			}
			if len(antes) > 0 && coincidencias(contenido, antes) > 1 { // Never a guess between two places (H14)
				return fmt.Errorf("%s: el fragmento %s coincide en más de un sitio", nombre, cab)
			}
			contenido = append(contenido[:pos], append(append([]string(nil), despues...), contenido[pos+len(antes):]...)...)
			desplazamiento = pos - (inicioViejo - 1) + len(despues) - len(antes)
		}
		if nuevo == "" {
			delete(archivos, nombre)
			continue
		}
		resultado := strings.Join(contenido, "\n")
		if !finSinSalto {
			resultado += "\n"
		}
		archivos[nuevo] = resultado
	}
	return nil
}

// buscar localiza un bloque de líneas empezando por la posición esperada y
// alejándose de ella.
func buscar(contenido, bloque []string, esperado int) int {
	coincide := func(p int) bool {
		if p < 0 || p+len(bloque) > len(contenido) {
			return false
		}
		for k, l := range bloque {
			if contenido[p+k] != l {
				return false
			}
		}
		return true
	}
	for d := 0; d <= len(contenido); d++ {
		if coincide(esperado - d) {
			return esperado - d
		}
		if coincide(esperado + d) {
			return esperado + d
		}
	}
	return -1
}

// coincidencias cuenta en cuántas posiciones aparece el bloque de líneas.
func coincidencias(contenido, bloque []string) int {
	total := 0
	for p := 0; p+len(bloque) <= len(contenido); p++ {
		iguales := true
		for k, l := range bloque {
			if contenido[p+k] != l {
				iguales = false
				break
			}
		}
		if iguales {
			total++
		}
	}
	return total
}

// manifiestoDe devuelve las líneas "<sha256>  <nombre>" de los archivos, ordenadas por nombre, como sha256sum.
// Los finales de línea se normalizan a LF antes de calcular el hash.
func manifiestoDe(archivos map[string][]byte) string {
	nombres := make([]string, 0, len(archivos))
	for nombre := range archivos {
		nombres = append(nombres, nombre)
	}
	sort.Strings(nombres)
	var b strings.Builder
	for _, nombre := range nombres {
		suma := sha256.Sum256([]byte(normalizar(string(archivos[nombre]))))
		b.WriteString(hex.EncodeToString(suma[:]) + "  " + nombre + "\n")
	}
	return b.String()
}

// compararManifiesto comprueba que los archivos son exactamente los del manifiesto, con los mismos hashes.
func compararManifiesto(manifiesto string, archivos map[string][]byte) error {
	if actual := manifiestoDe(archivos); actual != manifiesto {
		esperados := map[string]bool{}
		for _, l := range strings.Split(strings.TrimSpace(manifiesto), "\n") {
			esperados[l] = true
		}
		var diferencias []string
		for _, l := range strings.Split(strings.TrimSpace(actual), "\n") {
			if !esperados[l] {
				diferencias = append(diferencias, strings.TrimSpace(l[min(len(l), 64):])+" (distinto o de más)")
			}
			delete(esperados, l)
		}
		for l := range esperados {
			diferencias = append(diferencias, strings.TrimSpace(l[min(len(l), 64):])+" (distinto o falta)")
		}
		sort.Strings(diferencias)
		return errors.New(strings.Join(diferencias, ", "))
	}
	return nil
}

// leerPropios lee los archivos propios de Turbo (0.*.go) de customNetHttp.
func leerPropios(dir string) (map[string][]byte, error) {
	rutas, err := filepath.Glob(filepath.Join(dir, "0.*.go"))
	if err != nil {
		return nil, err
	}
	propios := map[string][]byte{}
	for _, ruta := range rutas {
		if propios[filepath.Base(ruta)], err = os.ReadFile(ruta); err != nil {
			return nil, err
		}
	}
	return propios, nil
}

// comprobarPropios verifica los 0.*.go contra PROPIOS.sha256: ni uno de más ni uno cambiado (H14).
func comprobarPropios(dir string) error {
	guardado, err := os.ReadFile(filepath.Join(dir, "PROPIOS.sha256"))
	if err != nil {
		return fmt.Errorf("falta PROPIOS.sha256 (regenera sin -comprobar para crearlo): %v", err)
	}
	propios, err := leerPropios(dir)
	if err != nil {
		return err
	}
	if err := compararManifiesto(normalizar(string(guardado)), propios); err != nil {
		return fmt.Errorf("los archivos propios no son los de PROPIOS.sha256: %v", err)
	}
	return nil
}

// rutaDiff convierte "a/1.net.http.server.go" (o /dev/null) en el nombre del
// archivo dentro de customNetHttp.
func rutaDiff(s string) string {
	if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(s, "a/") || strings.HasPrefix(s, "b/") {
		s = s[2:]
	}
	return path.Base(s)
}
