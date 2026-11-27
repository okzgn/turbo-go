#!/bin/bash
# Builds the binaries of a Turbo release and their SHA256SUMS in dist/<version>/.
#
# Usage: git tag v2.5.3 && bash release.sh v2.5.3
#
# - It uses the Go on the PATH, which must be the latest patch of the go.mod version: that Go itself, not an older
#   one that switches to it (inside the repository "go version" shows the one it switches to). If the Go of go.mod is
#   in the module cache: PATH="$(go env GOROOT)/bin:$PATH" bash release.sh v2.5.3
# - Static binaries (CGO_ENABLED=0), without local paths (-trimpath) or symbols, named with the version as the
#   releases up to v2.3.rc3 were (turbo-v2.5.2-linux-amd64, turbo-v2.5.2-windows-x64.exe),
#   with the version embedded: Turbo writes it at startup, with the commit and the Go.
# - It requires the version's tag on HEAD and a clean tree (also without untracked
#   files, or files marked so that git doesn't see their changes), so that the
#   published binaries are exactly the code of the tag.
# - It requires that no file ignored by git goes into the build: those of
#   server/turbo.dev (they are embedded) and the .go, .s, .S, .sx or .syso files of the
#   folders Go builds (not those starting with _ or ., nor testdata), and go.work
#   or go.work.sum.
# - It builds with a fixed Go environment (without the go env file or the GOFLAGS,
#   GOEXPERIMENT or GOWORK of whoever runs it).
# - It requires customNetHttp to be the net/http of that Go plus Turbo's patches.
# - It checks that each binary was built from HEAD, without changes and without cgo
#   (go version -m), and with govulncheck before writing SHA256SUMS: if it finds a
#   vulnerability, there is no SHA256SUMS. Without govulncheck it stops, unless
#   TURBO_RELEASE_WITHOUT_GOVULNCHECK=1 says so on purpose.
# - With TURBO_RELEASE_SIGNING_KEY (the file of the publisher's SSH private key), it signs SHA256SUMS with
#   ssh-keygen -Y sign: SHA256SUMS.sig, checked with the public key that SECURITY.md publishes. Without it, the
#   release goes unsigned, with a warning.
# - If anything fails, dist/<version> is removed: nothing half done is left to publish.
set -euo pipefail

VERSION="${1:?Usage: $0 <version, for example v2.5.1>}"
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
# The scripts are run as their usage lines say (./release.sh, deploy/real-ports-test.sh): a commit made by copying the
# files on Windows loses the bit, and a chmod afterwards leaves the tree with changes.
NOT_EXECUTABLE="$(git ls-files -s release.sh 'deploy/*.sh' | awk '$1 != "100755" {print $4}')"
if [ -n "$NOT_EXECUTABLE" ]; then
	echo "These scripts aren't executable in the repository (git update-index --chmod=+x <file>, and commit):" >&2
	echo "$NOT_EXECUTABLE" >&2
	exit 1
fi
# The Go of the PATH as it is (GOTOOLCHAIN=local, below): an older one that go.mod makes switch says so here, not in
# the middle of the build.
WANTED_GO="go$(sed -n 's/^go //p' go.mod | tr -d '\r')"
LOCAL_GO="$(cd / && GOTOOLCHAIN=local go env GOVERSION 2>/dev/null || true)" # Outside the module: go.mod doesn't speak there
if [ "$LOCAL_GO" != "$WANTED_GO" ]; then
	echo "The Go on the PATH is ${LOCAL_GO:-unknown}, and go.mod asks for $WANTED_GO: put that Go first in the PATH." >&2
	echo "If it is in the module cache: PATH=\"\$(go env GOROOT)/bin:\$PATH\" bash release.sh $VERSION" >&2
	exit 1
fi
# The Go environment, fixed before the first go command (the folders of the packages, below, are the ones of the
# build): neither the go env file (GOENV=off) nor what whoever runs it has exported (GOFLAGS with -tags or -ldflags,
# GOEXPERIMENT, GOWORK, another GOAMD64 level...) changes the binaries.
export GOENV=off GOFLAGS= GOEXPERIMENT= GOWORK=off GOTOOLCHAIN=local GOAMD64=v1 GOARM64=v8.0
unset GODEBUG GOROOT_FINAL CGO_CFLAGS CGO_LDFLAGS 2>/dev/null || true

# //go:embed also takes the files git ignores (.gitignore, .git/info/exclude or the global one), which
# git status doesn't show, and go build compiles the ignored .go, .s and .syso files of the folders of its
# packages and reads go.work: the binary would carry something that is not in the repository. Only the
# folders of the packages that go build compiles count (go list): what other builds leave elsewhere, such
# as the assembly files of LuaJIT that building dx/ leaves in dx/target, isn't Turbo's.
MODULE="$(go list -m)" # By their import paths, which say the same on every system (the folders of go list, on Windows, don't)
PACKAGE_DIRS="$(go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' . | sed "s|^$MODULE\$|.|; s|^$MODULE/||")"
# Without grep in the pipeline: with pipefail, a grep that finds nothing (a clean tree) would end the script. The
# names as they are (core.quotePath=false): git writes one with a character outside ASCII in quotes, with escapes,
# and neither its extension nor its folder was seen.
IGNORED="$(
	git -c core.quotePath=false ls-files --others --ignored --exclude-standard -- server/turbo.dev go.work go.work.sum
	git -c core.quotePath=false ls-files --others --ignored --exclude-standard | while IFS= read -r file; do
		case "$file" in
		*.go | *.s | *.S | *.sx | *.syso)
			if grep -qxF "$(dirname "$file")" <<<"$PACKAGE_DIRS"; then
				printf '%s\n' "$file"
			fi
			;;
		esac
	done
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

echo "Go: $(go env GOVERSION) (go.mod: $(go list -m -f '{{.GoVersion}}'))"

# The GUI is embedded as it is (//go:embed): with CR, the binary would depend on
# where it is built. A Windows copy older than .gitattributes may have them; they
# are fixed with: rm -r server/turbo.dev && git checkout -- server/turbo.dev
if grep -rlq $'\r' --include='*.html' --include='*.css' server/turbo.dev; then
	echo "server/turbo.dev has CRLF line endings: rm -r server/turbo.dev && git checkout -- server/turbo.dev" >&2
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
# A release that doesn't finish leaves nothing behind that could be published by mistake (binaries without
# SHA256SUMS, or with a vulnerability).
trap 'status=$?; if [ "$status" -ne 0 ]; then rm -rf "$OUT"; echo "The release didn'"'"'t finish: $OUT removed." >&2; fi' EXIT

build() { # GOOS GOARCH name
	echo "Building $3"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -ldflags "-s -w -X main.turboVersion=$VERSION" -o "$OUT/$3" .
}
build linux amd64 "turbo-$VERSION-linux-amd64"
build linux arm64 "turbo-$VERSION-linux-arm64"
build windows amd64 "turbo-$VERSION-windows-x64.exe"

# Each binary says what it was built from: HEAD, without changes (a file saved during the build would show here)
# and without cgo.
HEAD_COMMIT="$(git rev-parse HEAD)"
for b in "$OUT"/turbo-*; do
	info="$(go version -m "$b")"
	printf '%s\n' "$info" | grep -E "^$b|	build	(CGO_ENABLED|vcs.revision|vcs.modified)" || true
	for setting in "vcs.revision=$HEAD_COMMIT" "vcs.modified=false" "CGO_ENABLED=0"; do
		if ! printf '%s\n' "$info" | grep -qxF "	build	$setting"; then
			echo "$b doesn't say $setting: it isn't exactly the code of the tag." >&2
			exit 1
		fi
	done
done
# Before SHA256SUMS: with a known vulnerability, the release isn't ready to publish. govulncheck is the only check
# of the standard library outside customNetHttp (crypto/tls, net/url…) that the binaries carry.
if command -v govulncheck >/dev/null; then
	for b in "$OUT"/turbo-*; do
		govulncheck -mode=binary "$b"
	done
elif [ "${TURBO_RELEASE_WITHOUT_GOVULNCHECK:-}" = 1 ]; then
	echo "Warning: the binaries have not been checked with govulncheck (TURBO_RELEASE_WITHOUT_GOVULNCHECK=1)." >&2
else
	echo "govulncheck is not installed: go install golang.org/x/vuln/cmd/govulncheck@v1.9.0 (or, on purpose, TURBO_RELEASE_WITHOUT_GOVULNCHECK=1)." >&2
	exit 1
fi

# The licenses go with the binaries: Turbo's, those of the code of Go in customNetHttp (with its patents grant and
# its notice) and that of the panel's font.
cp LICENSE "$OUT/LICENSE"
cp LICENSE.Karla.txt "$OUT/LICENSE.Karla.txt"
cp customNetHttp/LICENCE "$OUT/LICENCE.customNetHttp"
cp customNetHttp/PATENTS "$OUT/PATENTS.customNetHttp"
cp customNetHttp/NOTICE "$OUT/NOTICE.customNetHttp"

(cd "$OUT" && sha256sum turbo-* > SHA256SUMS)
cat "$OUT/SHA256SUMS"
# The sums signed by the publisher: whoever could change the binaries where they are published could change their
# sums too, not this signature.
if [ -n "${TURBO_RELEASE_SIGNING_KEY:-}" ]; then
	ssh-keygen -Y sign -f "$TURBO_RELEASE_SIGNING_KEY" -n file "$OUT/SHA256SUMS"
	echo "Signed: $OUT/SHA256SUMS.sig"
else
	echo "Warning: SHA256SUMS is not signed (TURBO_RELEASE_SIGNING_KEY is not set)." >&2
fi
