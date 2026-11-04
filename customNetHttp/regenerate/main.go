// Regenerates customNetHttp from the Go source code and applies Turbo's patches
// (customNetHttp/patches/*.patch).
//
// Usage, from the repository root and with the Go version of
// customNetHttp/UPSTREAM (the tool reads the GOROOT it runs with):
//
//	go run ./customNetHttp/regenerate              regenerates customNetHttp
//	go run ./customNetHttp/regenerate -check       checks that customNetHttp is
//	                                               exactly what would be generated
//	go run ./customNetHttp/regenerate -patches N -output DIR
//	                                               a base with only the first N
//	                                               patches, in another directory
//	go run ./customNetHttp/regenerate -update      regenerates from another Go
//	                                               version and records it in
//	                                               UPSTREAM (it doesn't downgrade
//	                                               without -allow-downgrade)
//
// -output only writes to an empty directory or to one that was already an
// output of this tool (it marks it with .regenerate), and only deletes the
// files it generated then.
//
// The source packages (net/http and what it needs from mime/multipart,
// net/http/cgi, x/net and x/text) are merged into the single package
// customNetHttp: the qualifiers between them are removed and, if two packages
// declare the same name, net/http keeps it and the other package's becomes
// <package>_<name>. internal/godebug can't be imported outside Go: its uses
// become godebug_<name>, defined by 0.turbo.godebug.go.
//
// The files of customNetHttp that start with "0." are Turbo's own and the tool
// doesn't touch them; it generates every other *.go. Their SHA-256 sums are in
// OWN.sha256, which the tool rewrites when it regenerates in customNetHttp and
// -check verifies: a new or changed 0.*.go has to show in that file.
// SOURCES.sha256 has the SHA-256 of every Go file the package is regenerated
// from: -update writes it, and the other modes check that the GOROOT matches
// it.
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

// source describes a Go package that is merged into customNetHttp.
type source struct {
	dir    string   // directory under GOROOT/src
	prefix string   // prefix of the generated files
	files  []string // if not empty, only these files
}

var sources = []source{
	{dir: "net/http", prefix: "1.net.http."},
	{dir: "net/http/internal", prefix: "1.net.http.internal."},
	{dir: "net/http/internal/ascii", prefix: "1.net.http.internal.ascii."},
	{dir: "net/http/internal/httpcommon", prefix: "1.net.http.internal.httpcommon."},
	{dir: "net/http/cgi", prefix: "a.server.cgi.", files: []string{"host.go"}},
	{dir: "mime/multipart", prefix: "c.mime."},
	{dir: "vendor/golang.org/x/net/http2/hpack", prefix: "x.net.http2.hpack."},
	{dir: "vendor/golang.org/x/net/http/httpguts", prefix: "z.x.net.http.httpguts."},
	{dir: "vendor/golang.org/x/net/http/httpproxy", prefix: "z.x.net.http.httpproxy."},
	{dir: "vendor/golang.org/x/net/idna", prefix: "z.x.net.idna."},
	{dir: "vendor/golang.org/x/text/secure/bidirule", prefix: "y.x.text.secure.bidirule."},
	{dir: "vendor/golang.org/x/text/transform", prefix: "y.x.text.transform."},
	{dir: "vendor/golang.org/x/text/unicode/bidi", prefix: "y.x.text.unicode.bidi."},
	{dir: "vendor/golang.org/x/text/unicode/norm", prefix: "y.x.text.unicode.norm."},
}

// primary is the package that keeps its names when they clash.
const primary = "net/http"

// substituted are internal packages of Go that can't be imported from outside:
// their uses become <name>_<identifier>, defined by hand in a 0.turbo.*.go file.
var substituted = map[string]string{
	"internal/godebug": "godebug",
}

// fixedNames fixes the name of a clashing identifier instead of
// <package>_<name>: they are the ones Turbo uses.
var fixedNames = map[string]map[string]string{
	"net/http/cgi": {"Handler": "CgiHandler"},
}

// contexts in which the tool checks that the selection of files doesn't depend
// on the operating system or the architecture.
var contexts = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"darwin", "arm64"}, {"freebsd", "amd64"},
}

const packageName = "customNetHttp"

func main() {
	log := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }
	dir := flag.String("dir", "customNetHttp", "customNetHttp directory (with UPSTREAM and patches/)")
	output := flag.String("output", "", "write the result to this directory instead of -dir")
	nPatches := flag.Int("patches", -1, "apply only the first N patches (-1: all)")
	check := flag.Bool("check", false, "don't write: check that -dir matches what would be generated")
	update := flag.Bool("update", false, "regenerate with the Go version in use even if UPSTREAM says another, and record it")
	allowDowngrade := flag.Bool("allow-downgrade", false, "with -update, accept a Go version earlier than the one of UPSTREAM")
	flag.Parse()

	if err := run(*dir, *output, *nPatches, *check, *update, *allowDowngrade, log); err != nil {
		log("regenerate: %v", err)
		os.Exit(1)
	}
}

func run(dir, output string, nPatches int, check, update, allowDowngrade bool, log func(string, ...any)) error {
	// The options are checked before anything is read or written.
	switch {
	case check && (update || output != "" || nPatches >= 0):
		return errors.New("-check doesn't take -update, -output or -patches")
	case nPatches >= 0 && output == "":
		return errors.New("-patches needs -output: without it, customNetHttp would be overwritten with fewer patches")
	case update && (output != "" || nPatches >= 0):
		return errors.New("-update doesn't take -output or -patches: it updates the whole customNetHttp")
	case allowDowngrade && !update:
		return errors.New("-allow-downgrade only makes sense with -update")
	}
	version := runtime.Version()
	upstream, err := os.ReadFile(filepath.Join(dir, "UPSTREAM"))
	if err != nil && !update {
		return err
	}
	expected := strings.TrimSpace(strings.SplitN(normalize(string(upstream)), "\n", 2)[0])
	if expected != version && !update {
		return fmt.Errorf("UPSTREAM asks for %s and this is %s: run it with %s. Only to move customNetHttp to %s is -update used, after checking its sources against the official ones (PATCHES.md)", expected, version, expected, version)
	}
	if update && expected != "" && versionBefore(version, expected) && !allowDowngrade {
		return fmt.Errorf("-update would downgrade customNetHttp from %s to %s: run it with %s or later, or add -allow-downgrade if that is what you want", expected, version, expected)
	}

	// The code is read from the GOROOT, which the GOROOT environment variable
	// can change: it must be the one of the version that is running.
	goroot := build.Default.GOROOT
	gorootVersion, err := os.ReadFile(filepath.Join(goroot, "VERSION"))
	if err != nil {
		return fmt.Errorf("can't read the version of %s: %v", goroot, err)
	}
	if v := strings.TrimSpace(strings.SplitN(normalize(string(gorootVersion)), "\n", 2)[0]); v != version {
		return fmt.Errorf("GOROOT %s is %s and this is %s: unset GOROOT or run it with that version", goroot, v, version)
	}

	goSources := map[string][]byte{}
	generated, err := generate(goroot, dir, version, goSources)
	if err != nil {
		return err
	}
	sourcesManifest := filepath.Join(dir, "SOURCES.sha256")
	if !update { // The Go sources must be the ones recorded for UPSTREAM (H14)
		saved, err := os.ReadFile(sourcesManifest)
		if err != nil {
			return fmt.Errorf("SOURCES.sha256 is missing (regenerate with -update): %v", err)
		}
		if err := compareManifest(normalize(string(saved)), goSources); err != nil {
			return fmt.Errorf("the Go sources of %s are not those of SOURCES.sha256: %v", goroot, err)
		}
	}
	patches, err := listPatches(filepath.Join(dir, "patches"))
	if err != nil {
		return err
	}
	if len(patches) == 0 && nPatches != 0 { // Nothing would be checked: -check would pass on any fork
		return fmt.Errorf("no patches in %s", filepath.Join(dir, "patches"))
	}
	if nPatches >= 0 && nPatches < len(patches) {
		patches = patches[:nPatches]
	}
	for _, p := range patches {
		text, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := applyPatch(generated, normalize(string(text))); err != nil {
			return fmt.Errorf("%s doesn't apply cleanly: %v", filepath.Base(p), err)
		}
	}
	for name, content := range generated {
		formatted, err := format.Source([]byte(content))
		if err != nil {
			return fmt.Errorf("%s is not valid Go after the patches: %v", name, err)
		}
		if string(formatted) != content {
			return fmt.Errorf("%s doesn't keep the gofmt format after the patches", name)
		}
	}

	if check {
		if err := checkOwn(dir); err != nil {
			return err
		}
		return compareWith(dir, generated, log)
	}
	target := dir
	if output != "" {
		target = output
		if err := writeOutput(target, generated); err != nil {
			return err
		}
	} else if err := write(target, generated); err != nil {
		return err
	}
	if target == dir {
		own, err := readOwn(dir)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "OWN.sha256"), []byte(manifestOf(own)), 0o644); err != nil {
			return err
		}
	}
	if update {
		if err := os.WriteFile(filepath.Join(dir, "UPSTREAM"), []byte(version+"\n"), 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(sourcesManifest, []byte(manifestOf(goSources)), 0o644); err != nil {
			return err
		}
	}
	log("regenerate: %d files from %s with %d patches in %s", len(generated), version, len(patches), target)
	return nil
}

// normalize removes the carriage returns (Windows copies with autocrlf).
func normalize(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

// isGenerated reports whether a file of customNetHttp is produced by this tool.
func isGenerated(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasPrefix(name, "0.")
}

// expected reports whether an entry of customNetHttp is one of those that may
// be there: .go files (generated or 0.*.go), the license and fork texts, and
// the patches and regenerate folders. Anything else (a .s or a .syso, which
// would also be compiled with the package) is an error.
func expected(e os.DirEntry) bool {
	if e.IsDir() {
		return e.Name() == "patches" || e.Name() == "regenerate"
	}
	switch e.Name() {
	case "LICENCE", "NOTICE", "PATENTS", "UPSTREAM", "PATCHES.md", "OWN.sha256", "SOURCES.sha256":
		return true
	}
	return strings.HasSuffix(e.Name(), ".go")
}

func compareWith(dir string, generated map[string]string, log func(string, ...any)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var differences []string
	seen := map[string]bool{}
	for _, e := range entries {
		if !expected(e) {
			differences = append(differences, e.Name()+": unexpected (only the generated files, 0.*.go and those of PATCHES.md are allowed)")
			continue
		}
		if e.IsDir() || !isGenerated(e.Name()) {
			continue
		}
		seen[e.Name()] = true
		want, ok := generated[e.Name()]
		if !ok {
			differences = append(differences, e.Name()+": extra")
			continue
		}
		current, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if normalize(string(current)) != want {
			differences = append(differences, e.Name()+": different")
		}
	}
	for name := range generated {
		if !seen[name] {
			differences = append(differences, name+": missing")
		}
	}
	sort.Strings(differences)
	if len(differences) > 0 {
		for _, d := range differences {
			log("  %s", d)
		}
		return fmt.Errorf("%d files don't match Go %s plus the patches. Either customNetHttp or its patches have changed (review the diff), or this Go isn't the one of UPSTREAM; -update is the answer to neither", len(differences), runtime.Version())
	}
	log("regenerate: customNetHttp matches Go %s plus the patches (%d files)", runtime.Version(), len(generated))
	return nil
}

func write(target string, generated map[string]string) error {
	entries, err := os.ReadDir(target)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && isGenerated(e.Name()) {
			if _, ok := generated[e.Name()]; !ok {
				if err := os.Remove(filepath.Join(target, e.Name())); err != nil {
					return err
				}
			}
		}
	}
	for name, content := range generated {
		if err := os.WriteFile(filepath.Join(target, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// outputMarker is the file with which -output marks its directory: the list of
// the files it generated, the only ones a later output may delete.
const outputMarker = ".regenerate"

// writeOutput writes the generated files to target, which must be empty or an
// earlier output (with outputMarker). It only deletes the files of that earlier
// output that are no longer generated.
func writeOutput(target string, generated map[string]string) error {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return err
	}
	marker, err := os.ReadFile(filepath.Join(target, outputMarker))
	if err != nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty and is not an earlier output of regenerate (no %s): choose an empty directory", target, outputMarker)
	}
	for _, name := range strings.Fields(normalize(string(marker))) {
		if _, still := generated[name]; !still && isGenerated(name) && filepath.Base(name) == name {
			if err := os.Remove(filepath.Join(target, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	names := make([]string, 0, len(generated))
	for name, content := range generated {
		if err := os.WriteFile(filepath.Join(target, name), []byte(content), 0o644); err != nil {
			return err
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return os.WriteFile(filepath.Join(target, outputMarker), []byte(strings.Join(names, "\n")+"\n"), 0o644)
}

// listPatches returns the *.patch of dir in order (without taking the name as
// a pattern, as filepath.Glob would).
func listPatches(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var patches []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".patch") {
			patches = append(patches, filepath.Join(dir, e.Name()))
		}
	}
	return patches, nil
}

// versionBefore reports whether the Go version a ("go1.26.9") is earlier than b
// ("go1.26.10"), comparing their numbers.
func versionBefore(a, b string) bool {
	numbers := func(v string) []int {
		var n []int
		for _, part := range strings.Split(strings.TrimPrefix(v, "go"), ".") {
			digits := part
			for i, c := range part {
				if c < '0' || c > '9' {
					digits = part[:i]
					break
				}
			}
			x, _ := strconv.Atoi(digits)
			n = append(n, x)
		}
		return n
	}
	na, nb := numbers(a), numbers(b)
	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// canonical removes the vendor/ prefix of an import path.
func canonical(importPath string) string { return strings.TrimPrefix(importPath, "vendor/") }

type sourcePackage struct {
	source
	path  string // canonical import path
	name  string
	files []*ast.File
	texts map[*ast.File][]byte
	names map[*ast.File]string
	info  *types.Info
	pkg   *types.Package
}

// generate merges the Go packages into customNetHttp and returns the generated files. It leaves in goSources every
// Go file it read, by its path under GOROOT/src.
func generate(goroot, dir, version string, goSources map[string][]byte) (map[string]string, error) {
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "source", nil)
	var packages []*sourcePackage
	merged := map[string]*sourcePackage{}

	for _, s := range sources {
		p := &sourcePackage{source: s, path: canonical(s.dir), texts: map[*ast.File][]byte{}, names: map[*ast.File]string{}}
		list, err := selectFiles(filepath.Join(goroot, "src", filepath.FromSlash(s.dir)), s.files)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", s.dir, err)
		}
		for _, filePath := range list {
			text, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}
			f, err := parser.ParseFile(fset, filePath, text, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			p.files = append(p.files, f)
			p.texts[f] = text
			goSources[s.dir+"/"+filepath.Base(filePath)] = text
			p.names[f] = filepath.Base(filePath)
		}
		p.name = p.files[0].Name.Name
		p.info = &types.Info{
			Defs:      map[*ast.Ident]types.Object{},
			Uses:      map[*ast.Ident]types.Object{},
			Implicits: map[ast.Node]types.Object{},
		}
		conf := types.Config{Importer: imp}
		p.pkg, err = conf.Check(s.dir, fset, p.files, p.info)
		if err != nil {
			return nil, fmt.Errorf("type check of %s: %v", s.dir, err)
		}
		packages = append(packages, p)
		merged[p.path] = p
	}

	own, err := ownNames(dir)
	if err != nil {
		return nil, err
	}
	renames, err := computeRenames(packages, own)
	if err != nil {
		return nil, err
	}

	target := func(packagePath, name string) (string, bool) {
		packagePath = canonical(packagePath)
		if s, ok := substituted[packagePath]; ok {
			return s + "_" + name, true
		}
		if _, ok := merged[packagePath]; !ok {
			return "", false
		}
		if n, ok := renames[packagePath][name]; ok {
			return n, true
		}
		return name, true
	}

	generated := map[string]string{}
	for _, p := range packages {
		for _, f := range p.files {
			text, err := rewrite(fset, p, f, target)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %v", p.dir, p.names[f], err)
			}
			header := fmt.Sprintf("// Source: %s, src/%s/%s. Generated by customNetHttp/regenerate; patches in customNetHttp/PATCHES.md.\n\n", version, p.dir, p.names[f])
			name := p.prefix + p.names[f]
			if _, ok := generated[name]; ok {
				return nil, fmt.Errorf("duplicate file name: %s", name)
			}
			generated[name] = header + text
		}
	}
	return generated, nil
}

// selectFiles returns the files that are compiled for the current system and
// checks that they are the same in every reference context.
func selectFiles(dir string, only []string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var reference []string
	for i, c := range contexts {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = c[0], c[1], false
		var list []string
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			if len(only) > 0 && !contains(only, n) {
				continue
			}
			ok, err := ctx.MatchFile(dir, n)
			if err != nil {
				return nil, err
			}
			if ok {
				list = append(list, filepath.Join(dir, n))
			}
		}
		if i == 0 {
			reference = list
		} else if strings.Join(list, "|") != strings.Join(reference, "|") {
			return nil, fmt.Errorf("the files change with %s/%s: %v against %v", c[0], c[1], list, reference)
		}
	}
	if len(reference) == 0 {
		return nil, errors.New("no files")
	}
	return reference, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ownNames returns the package-level names of Turbo's 0.*.go files.
func ownNames(dir string) (map[string]bool, error) {
	names := map[string]bool{}
	files, err := filepath.Glob(filepath.Join(dir, "0.*.go"))
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	for _, a := range files {
		f, err := parser.ParseFile(fset, a, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					names[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						names[s.Name.Name] = true
					case *ast.ValueSpec:
						for _, n := range s.Names {
							names[n.Name] = true
						}
					}
				}
			}
		}
	}
	return names, nil
}

// computeRenames decides which package-level names change when merging.
func computeRenames(packages []*sourcePackage, own map[string]bool) (map[string]map[string]string, error) {
	declared := map[string][]string{} // name -> packages that declare it
	imported := map[string]bool{}     // names of imported packages that stay in the code
	used := map[string]bool{}         // any identifier that appears
	for _, p := range packages {
		for _, n := range p.pkg.Scope().Names() {
			declared[n] = append(declared[n], p.path)
		}
		for _, f := range p.files {
			for _, is := range f.Imports {
				importPath, _ := strconv.Unquote(is.Path.Value)
				if _, ok := substituted[canonical(importPath)]; ok || isMerged(packages, importPath) {
					continue
				}
				var obj types.Object
				if is.Name != nil {
					obj = p.info.Defs[is.Name]
				} else {
					obj = p.info.Implicits[is]
				}
				if obj != nil {
					imported[obj.Name()] = true
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok {
					used[id.Name] = true
				}
				return true
			})
		}
	}

	renames := map[string]map[string]string{}
	taken := map[string]string{}
	for _, p := range packages {
		for _, n := range p.pkg.Scope().Names() {
			conflict := len(declared[n]) > 1 || own[n] || imported[n] || types.Universe.Lookup(n) != nil
			if !conflict {
				continue
			}
			if p.path == primary {
				if own[n] || imported[n] || types.Universe.Lookup(n) != nil {
					return nil, fmt.Errorf("%s declares %s, which clashes with an own, imported or predeclared name", p.path, n)
				}
				continue
			}
			newName := p.name + "_" + n
			if fixed, ok := fixedNames[p.path][n]; ok {
				newName = fixed
			}
			if used[newName] || own[newName] || len(declared[newName]) > 0 {
				return nil, fmt.Errorf("can't rename %s.%s to %s: the name already exists", p.path, n, newName)
			}
			if other, ok := taken[newName]; ok {
				return nil, fmt.Errorf("%s.%s and %s would both be called %s", p.path, n, other, newName)
			}
			taken[newName] = p.path + "." + n
			if renames[p.path] == nil {
				renames[p.path] = map[string]string{}
			}
			renames[p.path][n] = newName
		}
	}
	return renames, nil
}

func isMerged(packages []*sourcePackage, importPath string) bool {
	for _, p := range packages {
		if p.path == canonical(importPath) {
			return true
		}
	}
	return false
}

type edit struct {
	from, to int
	text     string
}

// rewrite applies the changes of the merge to a file: package clause, imports
// of merged packages, qualifiers and renames.
func rewrite(fset *token.FileSet, p *sourcePackage, f *ast.File, target func(string, string) (string, bool)) (string, error) {
	text := p.texts[f]
	tf := fset.File(f.Pos())
	off := func(pos token.Pos) int { return tf.Offset(pos) }
	var edits []edit

	edits = append(edits, edit{off(f.Name.Pos()), off(f.Name.End()), packageName})

	// Imports of merged or substituted packages.
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.IMPORT {
			continue
		}
		remaining := 0
		var remove []ast.Spec
		for _, s := range gd.Specs {
			is := s.(*ast.ImportSpec)
			importPath, _ := strconv.Unquote(is.Path.Value)
			if _, ok := target(importPath, "x"); ok {
				remove = append(remove, s)
			} else {
				remaining++
			}
		}
		if remaining == 0 && len(remove) > 0 {
			from, to := wholeLine(text, off(gd.Pos()), off(gd.End()))
			edits = append(edits, edit{from, to, ""})
			continue
		}
		for _, s := range remove {
			from, to := wholeLine(text, off(s.Pos()), off(s.End()))
			edits = append(edits, edit{from, to, ""})
		}
	}

	var failure error
	ast.Inspect(f, func(n ast.Node) bool {
		if failure != nil {
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
			if newName, ok := target(pn.Imported().Path(), n.Sel.Name); ok {
				edits = append(edits, edit{off(n.Pos()), off(n.End()), newName})
			}
			return false
		case *ast.Ident:
			// Uses goes first: in an embedded field, Defs gives the field and
			// Uses the type, which is what gets renamed.
			obj := p.info.Uses[n]
			if obj == nil {
				obj = p.info.Defs[n]
			}
			// An embedded field is called like its type: if the type changes
			// its name, so do the accesses to the field (x.options).
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
			if newName, ok := target(obj.Pkg().Path(), n.Name); ok && newName != n.Name {
				edits = append(edits, edit{off(n.Pos()), off(n.End()), newName})
			}
		}
		return true
	})
	if failure != nil {
		return "", failure
	}

	// //go:linkname directives that name a renamed identifier.
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname ") {
				fields := strings.Fields(c.Text)
				if len(fields) >= 2 {
					if newName, ok := target(p.dir, fields[1]); ok && newName != fields[1] {
						return "", fmt.Errorf("//go:linkname of a renamed name (%s)", fields[1])
					}
				}
			}
		}
	}

	sort.Slice(edits, func(i, j int) bool { return edits[i].from > edits[j].from })
	out := append([]byte(nil), text...)
	limit := len(out) + 1
	for _, e := range edits {
		if e.to > limit {
			return "", fmt.Errorf("overlapping edits at byte %d", e.from)
		}
		out = append(out[:e.from], append([]byte(e.text), out[e.to:]...)...)
		limit = e.from
	}
	formatted, err := format.Source(out)
	if err != nil {
		return "", fmt.Errorf("gofmt: %v", err)
	}
	return string(formatted), nil
}

// wholeLine widens [from, to) to whole lines if there is nothing else in them,
// so as not to leave empty lines when an import is removed.
func wholeLine(text []byte, from, to int) (int, int) {
	i := from
	for i > 0 && (text[i-1] == ' ' || text[i-1] == '\t') {
		i--
	}
	if i > 0 && text[i-1] != '\n' {
		return from, to
	}
	j := to
	for j < len(text) && text[j] != '\n' {
		j++
	}
	rest := bytes.TrimSpace(text[to:j])
	if len(rest) > 0 && !bytes.HasPrefix(rest, []byte("//")) {
		return from, to
	}
	if j < len(text) {
		j++
	}
	return i, j
}

// applyPatch applies a unified diff to the generated files. Every hunk must
// match exactly; only a shift of lines is accepted, as patch does, never fuzzy
// context.
func applyPatch(files map[string]string, text string) error {
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); {
		if !strings.HasPrefix(lines[i], "--- ") {
			// Outside a hunk, only git's headers of a file fit: an extra line (a hunk that counts fewer lines
			// than it has) is not skipped, nor are the hunks that follow it.
			if !isGitHeader(lines[i]) && !(lines[i] == "" && i == len(lines)-1) {
				return fmt.Errorf("line %d outside a hunk: %q", i+1, lines[i])
			}
			i++
			continue
		}
		if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "+++ ") {
			return fmt.Errorf("line %d: %q without its \"+++ \"", i+1, lines[i])
		}
		oldName := diffPath(lines[i][4:])
		newName := diffPath(lines[i+1][4:])
		i += 2
		// A patch changes the generated files in place: never one of Turbo's own files (0.*), which don't come
		// from the patches, and it doesn't rename them (it copied the file under another name and kept the old one).
		for _, n := range []string{oldName, newName} {
			if strings.HasPrefix(n, "0.") {
				return fmt.Errorf("%s: a patch doesn't change Turbo's own files (0.*)", n)
			}
		}
		if oldName != "" && newName != "" && oldName != newName {
			return fmt.Errorf("%s to %s: a patch doesn't rename files", oldName, newName)
		}
		name := newName
		var content []string
		var noFinalNewline bool
		switch {
		case oldName == "":
			// A new file: one that exists would be replaced whole without checking any line
			if _, exists := files[newName]; exists {
				return fmt.Errorf("%s: the patch creates it as new, but it already exists", newName)
			}
		default:
			name = oldName
			current, ok := files[oldName]
			if !ok {
				return fmt.Errorf("%s doesn't exist", oldName)
			}
			noFinalNewline = !strings.HasSuffix(current, "\n")
			content = strings.Split(strings.TrimSuffix(current, "\n"), "\n")
		}
		shift := 0
		for i < len(lines) && strings.HasPrefix(lines[i], "@@ ") {
			header := lines[i]
			oldStart, oldCount, newCount, err := hunkHeader(header)
			if err != nil {
				return fmt.Errorf("%s: %v", name, err)
			}
			i++
			// Exactly the lines the header counts: a removed line that starts with "-- " is content, not the
			// header of another file.
			var before, after []string
			context := 0
			for len(before) < oldCount || len(after) < newCount {
				if i >= len(lines) || (i == len(lines)-1 && lines[i] == "") {
					return fmt.Errorf("%s: hunk %s ends before its %d and %d lines", name, header, oldCount, newCount)
				}
				l := lines[i]
				i++
				switch {
				case l == `\ No newline at end of file`:
				case l == "" || l[0] == ' ':
					c := ""
					if l != "" {
						c = l[1:]
					}
					before, after = append(before, c), append(after, c)
					context++
				case l[0] == '-':
					before = append(before, l[1:])
				case l[0] == '+':
					after = append(after, l[1:])
				default:
					return fmt.Errorf("%s: unexpected line %q", name, l)
				}
			}
			if len(before) != oldCount || len(after) != newCount {
				return fmt.Errorf("%s: hunk %s doesn't have the lines its header says", name, header)
			}
			for i < len(lines) && lines[i] == `\ No newline at end of file` {
				i++
			}
			if context == 0 && len(content) > 0 { // Placed by line number alone, it would never be checked (-U0)
				return fmt.Errorf("%s: hunk %s has no context lines", name, header)
			}
			want := oldStart - 1 + shift
			if len(before) == 0 {
				want = oldStart + shift
			}
			pos := find(content, before, want)
			if pos < 0 {
				return fmt.Errorf("%s: hunk %s doesn't match", name, header)
			}
			if len(before) > 0 && occurrences(content, before) > 1 { // Never a guess between two places (H14)
				return fmt.Errorf("%s: hunk %s matches in more than one place", name, header)
			}
			content = append(content[:pos], append(append([]string(nil), after...), content[pos+len(before):]...)...)
			shift = pos - (oldStart - 1) + len(after) - len(before)
		}
		if newName == "" {
			delete(files, name)
			continue
		}
		result := strings.Join(content, "\n")
		if !noFinalNewline {
			result += "\n"
		}
		files[newName] = result
	}
	return nil
}

// isGitHeader reports whether a line is one of those git writes before the
// "--- " of a file.
func isGitHeader(l string) bool {
	for _, prefix := range []string{"diff --git ", "index ", "new file mode ", "deleted file mode ", "old mode ", "new mode "} { // Neither renames nor copies
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

// hunkHeader reads "@@ -start[,count] +start[,count] @@": the start line of the
// hunk in the original file and its line counts (1 if omitted).
func hunkHeader(header string) (oldStart, oldCount, newCount int, err error) {
	fields := strings.Fields(header)
	if len(fields) < 4 || fields[0] != "@@" || fields[3] != "@@" || !strings.HasPrefix(fields[1], "-") || !strings.HasPrefix(fields[2], "+") {
		return 0, 0, 0, fmt.Errorf("header %q", header)
	}
	parse := func(r string) (int, int, error) {
		start, count, hasCount := strings.Cut(r, ",")
		a, err := strconv.Atoi(start)
		if err != nil || a < 0 {
			return 0, 0, fmt.Errorf("header %q", header)
		}
		n := 1
		if hasCount {
			if n, err = strconv.Atoi(count); err != nil || n < 0 {
				return 0, 0, fmt.Errorf("header %q", header)
			}
		}
		return a, n, nil
	}
	if oldStart, oldCount, err = parse(fields[1][1:]); err != nil {
		return
	}
	_, newCount, err = parse(fields[2][1:])
	return
}

// find locates a block of lines, starting at the expected position and moving
// away from it.
func find(content, block []string, expected int) int {
	matches := func(p int) bool {
		if p < 0 || p+len(block) > len(content) {
			return false
		}
		for k, l := range block {
			if content[p+k] != l {
				return false
			}
		}
		return true
	}
	for d := 0; d <= len(content); d++ {
		if matches(expected - d) {
			return expected - d
		}
		if matches(expected + d) {
			return expected + d
		}
	}
	return -1
}

// occurrences counts in how many positions the block of lines appears.
func occurrences(content, block []string) int {
	total := 0
	for p := 0; p+len(block) <= len(content); p++ {
		equal := true
		for k, l := range block {
			if content[p+k] != l {
				equal = false
				break
			}
		}
		if equal {
			total++
		}
	}
	return total
}

// manifestOf returns the "<sha256>  <name>" lines of the files, sorted by name, as sha256sum does. Line endings
// are normalized to LF before hashing.
func manifestOf(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		sum := sha256.Sum256([]byte(normalize(string(files[name]))))
		b.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	return b.String()
}

// compareManifest checks that the files are exactly those of the manifest, with the same hashes.
func compareManifest(manifest string, files map[string][]byte) error {
	if current := manifestOf(files); current != manifest {
		expected := map[string]bool{}
		for _, l := range strings.Split(strings.TrimSpace(manifest), "\n") {
			expected[l] = true
		}
		var differences []string
		for _, l := range strings.Split(strings.TrimSpace(current), "\n") {
			if !expected[l] {
				differences = append(differences, strings.TrimSpace(l[min(len(l), 64):])+" (different or extra)")
			}
			delete(expected, l)
		}
		for l := range expected {
			differences = append(differences, strings.TrimSpace(l[min(len(l), 64):])+" (different or missing)")
		}
		sort.Strings(differences)
		return errors.New(strings.Join(differences, ", "))
	}
	return nil
}

// readOwn reads Turbo's own files (0.*.go) of customNetHttp.
func readOwn(dir string) (map[string][]byte, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "0.*.go"))
	if err != nil {
		return nil, err
	}
	own := map[string][]byte{}
	for _, p := range paths {
		if own[filepath.Base(p)], err = os.ReadFile(p); err != nil {
			return nil, err
		}
	}
	return own, nil
}

// checkOwn verifies the 0.*.go files against OWN.sha256: none extra, none changed (H14).
func checkOwn(dir string) error {
	saved, err := os.ReadFile(filepath.Join(dir, "OWN.sha256"))
	if err != nil {
		return fmt.Errorf("OWN.sha256 is missing (regenerate without -check to create it): %v", err)
	}
	own, err := readOwn(dir)
	if err != nil {
		return err
	}
	if err := compareManifest(normalize(string(saved)), own); err != nil {
		return fmt.Errorf("the own files are not those of OWN.sha256: %v", err)
	}
	return nil
}

// diffPath turns "a/1.net.http.server.go" (or /dev/null) into the name of the
// file inside customNetHttp.
func diffPath(s string) string {
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
