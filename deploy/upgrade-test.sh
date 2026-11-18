#!/bin/bash
# Upgrade test of Turbo with real binaries, to run on Linux before each
# release: it configures a previous version from the panel, replaces it with
# the new one on the same sites directory and goes back as CHANGELOG.md says
# ("Upgrading from v2.3.rc3", point 3).
#
# Usage: deploy/upgrade-test.sh <previous binary> <new binary>
#
# It needs curl, openssl and ss, and being able to give the binaries
# CAP_NET_BIND_SERVICE with "sudo -n setcap" (without a password): v2.3.rc3
# only listens on ports 80 and 443, which must be free. Everything happens in a
# temporary folder that is deleted at the end. It exits with code 1 if a check
# fails.
#
# With the previous binary it creates a site with a subdomain and an alias, a
# rewrite, a header, a MIME type, an index, a preprocessor, a denied IP, a
# character replacement and an error template, and another site with a
# certificate (put there by hand and enabled with cfgS); it changes the
# password and saves. Then:
# - the new binary starts with that turbo.config, warns about the migration if
#   the file has schema 1, and serves the same;
# - the credentials are the saved ones (v2.3.rc3 didn't save the password in
#   turbo.config: it is Admin again, as point 4 of "Upgrading from v2.3.rc3"
#   in CHANGELOG.md says);
# - when saving with the new one, a schema 1 file is kept as
#   turbo.config.v1.bak with 0600 permissions, and the new one has
#   "^":{"v":"2"};
# - to go back, with a v1.bak copy it is restored as turbo.config and, without
#   it, the previous version starts with the new version's file; in both cases
#   it serves the same as at the beginning.
set -u

OLD_BIN="${1:-}"
NEW_BIN="${2:-}"
[ -x "$OLD_BIN" ] && [ -x "$NEW_BIN" ] || { echo "Usage: $0 <previous binary> <new binary>" >&2; exit 2; }
for tool in curl openssl ss; do
	command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
if ss -ltn | grep -qE ':(80|443) '; then
	echo "Ports 80 or 443 are in use" >&2
	exit 2
fi

# Not in /tmp: it is often mounted nosuid, and then CAP_NET_BIND_SERVICE has no effect.
mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}"
TMPD="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/turbo-upgrade.XXXXXX")"
RUN="$TMPD/sites"
PID=""
FAILURES=0
TOKEN=""
PASSWORD=Admin

stop_turbo() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
	PID=""
}
cleanup() {
	stop_turbo
	rm -rf "$TMPD"
}
trap cleanup EXIT

check() { # description, value got, value expected (regular expression)
	if [[ "$2" =~ ^$3$ ]]; then
		echo "  ok    $1: $2"
	else
		echo "  FAIL  $1: \"$2\"; expected \"$3\""
		FAILURES=$((FAILURES + 1))
	fi
}

start_turbo() { # binary, name of the log
	cp "$1" "$TMPD/turbo-$2"
	sudo -n setcap cap_net_bind_service=+ep "$TMPD/turbo-$2" || { echo "sudo -n setcap is not allowed" >&2; exit 2; }
	(cd "$RUN" && TURBO_DIR="$RUN/" exec "$TMPD/turbo-$2" >"$TMPD/$2.log" 2>&1) &
	PID=$!
	for _ in $(seq 100); do curl -s -o /dev/null http://localhost/ && return 0; sleep 0.1; done
	echo "  FAIL  $2 does not answer on port 80. Its output:"
	cat "$TMPD/$2.log"
	FAILURES=$((FAILURES + 1))
	return 1
}

sign_in() { # password; sets TOKEN and PASSWORD
	local response
	response="$(curl -s --data "u=Turbo&p=$1" http://localhost/admin:)"
	[ "${response#ok}" != "$response" ] || return 1
	TOKEN="${response#ok}"
	PASSWORD="$1"
}

panel() { # action, parameters (urlencoded): prints the response and the code, or "no session" for the login page
	local response
	response="$(curl -s -D "$TMPD/panel-headers" -H "ok: $TOKEN" -w ' %{http_code}' --data "$2" "http://localhost/admin:inside:$1")"
	if grep -qi '^x-turbo-login:' "$TMPD/panel-headers"; then # Without a valid session the answer is the login page, also with 200
		echo "no session"
	else
		echo "$response"
	fi
}

setup() { # action, parameters: a step of the preparation; an answer other than 200 is shown (some versions answer "unchanged")
	local response
	response="$(panel "$1" "$2")"
	[[ "$response" =~ \ 200$ ]] || echo "  note  $1 $2: $response"
}

# What is served, one line per request: code, the headers that matter and body.
served() {
	local request host path
	for request in "a.test /" "a.test /old" "a.test /x.dat" "a.test /x.cgi?q=1" "a.test /missing" \
		"sub.a.test /" "alias.test /"; do
		host="${request% *}"
		path="${request#* }"
		curl -s -o "$TMPD/body" -D "$TMPD/headers" -H "Host: $host" "http://localhost$path"
		printf '%s %s: %s %s %s | %s\n' "$host" "$path" \
			"$(head -1 "$TMPD/headers" | cut -d' ' -f2)" \
			"$(grep -i '^x-test:' "$TMPD/headers" | tr -d '\r')" \
			"$(grep -i '^content-type:' "$TMPD/headers" | tr -d '\r' | cut -d';' -f1)" \
			"$(tr '\n' ' ' <"$TMPD/body")"
	done
	printf 'https s.test: %s\n' "$(curl -sk --resolve s.test:443:127.0.0.1 https://s.test/)"
}

mkdir -p "$RUN"
# Only the first parameter: v2.3.rc3 added an empty "&" at the end of QUERY_STRING
printf '#!/bin/sh\nprintf "Content-Type: text/plain\\r\\n\\r\\ncgi-%%s\\n" "${QUERY_STRING%%%%&*}"\n' >"$TMPD/cgi.sh"
chmod +x "$TMPD/cgi.sh"

echo "== Previous version: configuration from the panel"
start_turbo "$OLD_BIN" old || exit 1
sign_in Admin || { echo "  FAIL  login with Turbo/Admin in the previous version"; exit 1; }
# The current password goes with the actions that need it in some version (a parameter that an earlier one ignores):
# addHeader, addMIME and addPreprocessor since v2.4.2, addCharsReplace and addHttpCodeResponse since v2.4.1, and
# addDenied since v2.4.3.
setup addSite "s=a.test"
setup addSite "s=s.test"
setup addSubdomain "s=a.test&d=sub"
setup addAlias "s=a.test&d=&a=alias.test"
setup addRewrite "s=a.test&d=&a=/old&b=/new.html"
setup addHeader "s=a.test&d=&a=X-Test&b=yes&c=Admin"
setup addMIME "s=a.test&d=&a=dat&b=text/x-dat&c=Admin"
setup addIndex "s=a.test&d=&a=start.html"
setup addPreprocessor "s=a.test&d=&a=cgi&b=$TMPD/cgi.sh&c=Admin"
setup addDenied "s=203.0.113.7&d=4102444800&b=Admin"
setup addCharsReplace "s=!&d=-x-&b=Admin"
setup addHttpCodeResponse "s=404&d=Not+here+{TURBO_RESPONSE_CODE}&b=Admin"
echo "start-a" >"$RUN/a.test/@/start.html"
echo "new-a" >"$RUN/a.test/@/new.html"
echo "data" >"$RUN/a.test/@/x.dat"
echo "x" >"$RUN/a.test/@/x.cgi"
echo "secure" >"$RUN/s.test/@/index.html"
setup addIndex "s=s.test&d=&a=index.html"
mkdir -p "$RUN/a.test/sub/@" && echo "sub-a" >"$RUN/a.test/sub/@/index.html"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=s.test -addext subjectAltName=DNS:s.test \
	-keyout "$RUN/s.test/privkey.pem" -out "$RUN/s.test/fullchain.pem" >/dev/null 2>&1
setup cfgS "s=s.test&d=&a=1"
# 14 bytes: since v2.4.1 a new password has 12 to 64
check "setP" "$(panel setP "a=Secret-pass-2x&b=Admin")" ".* 200"
sign_in Secret-pass-2x || echo "  (the new password doesn't work in the previous version)"
check "setC (save)" "$(panel setC "a=&b=$PASSWORD")" ".* 200"
served >"$TMPD/before.txt"
cat "$TMPD/before.txt"
cp "$RUN/turbo.config" "$TMPD/old-config"
check "character replacement saved by the previous version" "$(grep -c -- '-x-' "$RUN/turbo.config")" "[1-9][0-9]*"
check "error template saved by the previous version" "$(grep -c 'Not here' "$RUN/turbo.config")" "[1-9][0-9]*"
SCHEMA1=$(grep -q '"\^"' "$RUN/turbo.config" && echo no || echo yes)
SAVES_HASH=$(grep -q '"PH"' "$RUN/turbo.config" && echo yes || echo no)
echo "  turbo.config of the previous version: schema 1 = $SCHEMA1, password saved = $SAVES_HASH"
stop_turbo

echo "== New version with the same directory"
start_turbo "$NEW_BIN" new || exit 1
if [ "$SCHEMA1" = yes ]; then
	check "migration warning" "$(grep -c 'Configuration in schema 1' "$TMPD/new.log")" "[1-9][0-9]*"
fi
check "no errors when loading" "$(grep -c 'level=ERROR' "$TMPD/new.log")" "0"
check "nothing discarded when loading" "$(grep -ci 'discarded' "$TMPD/new.log")" "0"
grep -i 'discarded' "$TMPD/new.log" | cut -c1-240
served >"$TMPD/after.txt"
check "serves the same" "$(diff "$TMPD/before.txt" "$TMPD/after.txt" >"$TMPD/differences.txt" && echo same || echo different)" "same"
[ -s "$TMPD/differences.txt" ] && cat "$TMPD/differences.txt"
if [ "$SAVES_HASH" = yes ]; then
	sign_in Secret-pass-2x && r=yes || r=no # Outside $(...), which would lose the TOKEN
	check "login with the saved password" "$r" "yes"
else
	sign_in Admin && r=yes || r=no
	check "login with Admin (the previous version didn't save the password)" "$r" "yes"
fi
check "setCGP (new key)" "$(panel setCGP "a=8&b=$PASSWORD")" ".* 200"
check "setC (save)" "$(panel setC "a=&b=$PASSWORD")" ".* 200"
check "schema 2 when saving" "$(grep -o '"\^":{"v":"2"}' "$RUN/turbo.config")" '"\^":\{"v":"2"\}'
if [ "$SCHEMA1" = yes ]; then
	check "copy turbo.config.v1.bak" "$(cmp -s "$RUN/turbo.config.v1.bak" "$TMPD/old-config" && echo same || echo different)" "same"
	check "permissions of the copy" "$(stat -c %a "$RUN/turbo.config.v1.bak")" "600"
fi
stop_turbo

echo "== Back to the previous version"
if [ -e "$RUN/turbo.config.v1.bak" ]; then
	cp "$RUN/turbo.config.v1.bak" "$RUN/turbo.config"
	echo "  turbo.config.v1.bak restored as turbo.config"
fi
start_turbo "$OLD_BIN" back || exit 1
served >"$TMPD/back.txt"
check "serves the same as at the beginning" "$(diff "$TMPD/before.txt" "$TMPD/back.txt" >"$TMPD/differences.txt" && echo same || echo different)" "same"
[ -s "$TMPD/differences.txt" ] && cat "$TMPD/differences.txt"
stop_turbo

echo "== Result: $FAILURES failures"
[ "$FAILURES" = 0 ]
