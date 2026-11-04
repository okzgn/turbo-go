#!/bin/bash
# Builds the binaries of a Turbo release and their SHA256SUMS in dist/<version>/.
#
# Usage: git tag v2.4 && ./release.sh v2.4
#
# - It uses the Go on the PATH, which must be the latest patch of the go.mod version.
# - Static binaries (CGO_ENABLED=0), without local paths (-trimpath) or symbols,
#   with the version embedded: Turbo writes it at startup, with the commit and the Go.
# - It requires the version's tag on HEAD and a clean tree (also without untracked
#   files, or files marked so that git doesn't see their changes), so that the
#   published binaries are exactly the code of the tag.
# - It requires that no file ignored by git goes into the build: those of
#   turbo.dev (they are embedded) and the .go, .s, .S, .sx or .syso files of the
#   folders Go builds (not those starting with _ or ., nor testdata), and go.work
#   or go.work.sum.
# - It builds with a fixed Go environment (without the go env file or the GOFLAGS,
#   GOEXPERIMENT or GOWORK of whoever runs it).
# - It requires customNetHttp to be the net/http of that Go plus Turbo's patches.
# - It checks each binary with govulncheck before writing SHA256SUMS: if it finds
#   a vulnerability, there is no SHA256SUMS. Without govulncheck, it warns.
set -euo pipefail

VERSION="${1:?Usage: $0 <version, for example v2.4>}"
cd "$(dirname "$0")"

# The version names dist/<version>, which is deleted before building: only
# vX.Y[.Z...] with an optional .rcN.
if ! [[ "$VERSION" =~ ^v[0-9]+(\.[0-9]+)+(\.rc[0-9]+)?$ ]]; then
	echo "Invalid version: $VERSION (expected, for example, v2.4, v2.4.1 or v2.5.rc1)." >&2
	exit 1
fi

# Also the untracked files that the configuration hides (status.showUntrackedFiles=no):
# Go would mark vcs.modified.
if [ -n "$(git status --porcelain --untracked-files=all --ignore-submodules=none)" ]; then
	echo "The working tree has changes or uncommitted files." >&2
	exit 1
fi
# A file marked skip-worktree or assume-unchanged can be changed without git status saying so.
HIDDEN="$(git ls-files -v | grep -E '^([a-z]|S) ' || true)"
if [ -n "$HIDDEN" ]; then
	echo "There are files marked so that git doesn't see their changes (skip-worktree or assume-unchanged):" >&2
	echo "$HIDDEN" >&2
	echo "Remove the mark (git update-index --no-skip-worktree --no-assume-unchanged <file>) and review the tree." >&2
	exit 1
fi
# //go:embed also takes the files git ignores (.gitignore, .git/info/exclude or the global one), which
# git status doesn't show, and go build compiles the ignored .go, .s and .syso files of the packages and
# reads go.work: the binary would carry something that is not in the repository. The folders Go doesn't
# look at (those starting with "_" or "." and testdata) don't count.
IGNORED="$(
	git ls-files --others --ignored --exclude-standard -- turbo.dev
	git ls-files --others --ignored --exclude-standard | grep -E '(\.(go|s|S|sx|syso)|(^|/)go\.work(\.sum)?)$' |
		grep -vE '(^|/)(_|\.)[^/]*/|(^|/)testdata/' || true
)"
if [ -n "$IGNORED" ]; then
	echo "There are files ignored by git that would go into the binary:" >&2
	echo "$IGNORED" | sort -u >&2
	exit 1
fi
# The tag is created before building, on HEAD: the binaries are exactly the code of the tag.
if ! git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
	echo "The tag $VERSION doesn't exist: tag HEAD ($(git rev-parse --short HEAD)) with git tag $VERSION and run it again." >&2
	exit 1
fi
if [ "$(git rev-parse "refs/tags/$VERSION^{commit}")" != "$(git rev-parse HEAD)" ]; then
	echo "The tag $VERSION doesn't point to HEAD." >&2
	exit 1
fi

# The Go environment, fixed: neither the go env file (GOENV=off) nor what whoever runs it has exported
# (GOFLAGS with -tags or -ldflags, GOEXPERIMENT, GOWORK, another GOAMD64 level...) changes the binaries.
export GOENV=off GOFLAGS= GOEXPERIMENT= GOWORK=off GOTOOLCHAIN=local GOAMD64=v1 GOARM64=v8.0
unset GODEBUG GOROOT_FINAL CGO_CFLAGS CGO_LDFLAGS 2>/dev/null || true

echo "Go: $(go env GOVERSION) (go.mod: $(go list -m -f '{{.GoVersion}}'))"

# The GUI is embedded as it is (//go:embed): with CR, the binary would depend on
# where it is built. A Windows copy older than .gitattributes may have them; they
# are fixed with: rm -r turbo.dev && git checkout -- turbo.dev
if grep -rlq $'\r' --include='*.html' --include='*.css' turbo.dev; then
	echo "turbo.dev has CRLF line endings: rm -r turbo.dev && git checkout -- turbo.dev" >&2
	exit 1
fi

# customNetHttp must be the net/http of this same Go version plus Turbo's patches.
# If Go is newer than customNetHttp/UPSTREAM, it has to be regenerated first
# (customNetHttp/PATCHES.md, "Updating to another Go version").
if ! go run ./customNetHttp/regenerate -check; then
	echo "customNetHttp is not the net/http of $(go env GOVERSION) plus the patches. There are two possible causes:" >&2
	echo "  - this Go is not the one of customNetHttp/UPSTREAM: build with that version;" >&2
	echo "  - customNetHttp or its patches have changed: review the diff first." >&2
	echo "Only to move to a new Go version is regenerate -update used, after checking its sources (PATCHES.md)." >&2
	exit 1
fi
OUT="dist/$VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"

build() { # GOOS GOARCH name
	echo "Building $3"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -ldflags "-s -w -X main.turboVersion=$VERSION" -o "$OUT/$3" .
}
build linux amd64 turbo-linux-amd64
build linux arm64 turbo-linux-arm64
build windows amd64 turbo-windows-x64.exe

for b in "$OUT"/turbo-*; do
	go version -m "$b" | grep -E "^$b|	build	(CGO_ENABLED|vcs.revision|vcs.modified)" || true
done
# Before SHA256SUMS: with a known vulnerability, the release isn't ready to publish.
if command -v govulncheck >/dev/null; then
	for b in "$OUT"/turbo-*; do
		govulncheck -mode=binary "$b"
	done
else
	echo "Warning: govulncheck is not installed; the binaries have not been checked (go install golang.org/x/vuln/cmd/govulncheck@latest)." >&2
fi

(cd "$OUT" && sha256sum turbo-* > SHA256SUMS)
cat "$OUT/SHA256SUMS"
