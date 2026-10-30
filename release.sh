#!/bin/bash
# Compila los binarios de una release de Turbo y sus SHA256SUMS en dist/<versión>/.
#
# Uso: ./release.sh v2.3.rc4
#
# - Usa el Go del PATH, que debe ser el último parche de la versión de go.mod.
# - Binarios estáticos (CGO_ENABLED=0), sin rutas locales (-trimpath) ni símbolos.
# - Exige un árbol limpio; si el tag ya existe, exige que apunte a HEAD, para
#   que los binarios publicados sean exactamente el código del tag.
# - Exige que customNetHttp sea el net/http de ese Go más los parches de Turbo.
# - Si govulncheck está instalado, revisa cada binario.
set -euo pipefail

VERSION="${1:?Uso: $0 <versión, por ejemplo v2.3.rc4>}"
cd "$(dirname "$0")"

if [ -n "$(git status --porcelain)" ]; then # también archivos sin seguimiento: Go marcaría vcs.modified
	echo "El árbol de trabajo tiene cambios o archivos sin commit." >&2
	exit 1
fi
if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
	if [ "$(git rev-parse "refs/tags/$VERSION^{commit}")" != "$(git rev-parse HEAD)" ]; then
		echo "El tag $VERSION no apunta a HEAD." >&2
		exit 1
	fi
else
	echo "Aviso: el tag $VERSION no existe todavía; etiquete HEAD ($(git rev-parse --short HEAD)) al publicar." >&2
fi

echo "Go: $(go env GOVERSION) (go.mod: $(go list -m -f '{{.GoVersion}}'))"

# La GUI se embebe tal cual (//go:embed): con CR, el binario cambiaría según
# dónde se compile. Una copia de Windows anterior a .gitattributes puede
# tenerlos: se arreglan con: rm -r turbo.dev && git checkout -- turbo.dev
if grep -rlq $'\r' --include='*.html' --include='*.css' turbo.dev; then
	echo "turbo.dev tiene finales de línea CRLF: rm -r turbo.dev && git checkout -- turbo.dev" >&2
	exit 1
fi

# customNetHttp debe ser el net/http de esta misma versión de Go más los parches
# de Turbo. Si Go es más nuevo que customNetHttp/UPSTREAM, hay que regenerarlo
# antes (customNetHttp/PATCHES.md, "Actualizar a otra versión de Go").
if ! go run ./customNetHttp/regenerar -comprobar; then
	echo "customNetHttp no corresponde a $(go env GOVERSION): ejecute go run ./customNetHttp/regenerar -actualizar y pruebe antes de publicar." >&2
	exit 1
fi
OUT="dist/$VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"

build() { # GOOS GOARCH nombre
	echo "Compilando $3"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -ldflags "-s -w" -o "$OUT/$3" .
}
build linux amd64 turbo-linux-amd64
build linux arm64 turbo-linux-arm64
build windows amd64 turbo-windows-x64.exe

(cd "$OUT" && sha256sum turbo-* > SHA256SUMS)
cat "$OUT/SHA256SUMS"

for b in "$OUT"/turbo-*; do
	go version -m "$b" | grep -E "^$b|	build	(CGO_ENABLED|vcs.revision|vcs.modified)" || true
	if command -v govulncheck >/dev/null; then
		govulncheck -mode=binary "$b"
	fi
done
