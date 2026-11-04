#!/bin/bash
# Integration test of Turbo with the real ports 80 and 443, to run on Linux
# before each release.
#
# Usage: deploy/real-ports-test.sh [source folder]   (by default, this repository)
#        TURBO_BIN=<binary> deploy/real-ports-test.sh   (tests that binary, for example one from release.sh)
#
# It needs Go (except with TURBO_BIN), curl, openssl, ss and being able to give
# the binary CAP_NET_BIND_SERVICE with "sudo -n setcap" (without a password).
# Ports 80 and 443 must be free.
# It builds the code, starts it in a temporary directory with a site and a
# self-signed certificate, checks what is seen from outside and deletes it all
# at the end. It exits with code 1 if a check fails. The checks this system
# doesn't allow are marked SKIPPED, with the reason, and don't count as passed.
set -u

SRC="$(cd "${1:-$(dirname "$0")/..}" && pwd)"
# Not in /tmp: it is often mounted nosuid, and then CAP_NET_BIND_SERVICE has no effect.
mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}"
TMPD="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/turbo-test.XXXXXX")"
BIN="$TMPD/turbo"
RUN="$TMPD/sites"
PID=""
FAILURES=0
SKIPPED=0

cleanup() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
	rm -rf "$TMPD"
}
trap cleanup EXIT

check() { # description, value got, value expected (regular expression)
	if [[ "$2" =~ ^$3$ ]]; then
		echo "  ok      $1: $2"
	else
		echo "  FAIL    $1: \"$2\"; expected \"$3\""
		FAILURES=$((FAILURES + 1))
	fi
}

skip() { # description, reason
	echo "  SKIPPED $1: $2"
	SKIPPED=$((SKIPPED + 1))
}

for tool in $([ -z "${TURBO_BIN:-}" ] && echo go) curl openssl ss; do
	command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
if ss -ltn | grep -qE ':(80|443) '; then
	echo "Ports 80 or 443 are in use" >&2
	exit 2
fi

if [ -n "${TURBO_BIN:-}" ]; then
	echo "== Binary $TURBO_BIN"
	cp "$TURBO_BIN" "$BIN" || exit 2
else
	echo "== Building $SRC"
	(cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$BIN" .) || exit 2
fi
sudo -n setcap cap_net_bind_service=+ep "$BIN" || { echo "sudo -n setcap is not allowed" >&2; exit 2; }

mkdir -p "$RUN/localhost/@"
echo "hello-real" >"$RUN/localhost/@/index.html"
echo "outside-@" >"$RUN/localhost/outside.txt"
ln -s ../outside.txt "$RUN/localhost/@/link.txt"
echo "special-name" >"$RUN/localhost/@/dot."
echo "source-code" >"$RUN/localhost/@/test.CGI"
printf '#!/bin/sh\nprintf "Content-Type: text/plain\\r\\n\\r\\ncgi-ran\\n"\n' >"$TMPD/cgi.sh"
echo "slow" >"$RUN/localhost/@/wait.slow"
echo "child" >"$RUN/localhost/@/with.child"
printf '#!/bin/sh\nsleep 30 &\nprintf "Content-Type: text/plain\\r\\n\\r\\nwith-child\\n"\n' >"$TMPD/child.sh"
printf '#!/bin/sh\nsleep 6\nprintf "Content-Type: text/plain\\r\\n\\r\\nlate\\n"\n' >"$TMPD/slow.sh"
chmod +x "$TMPD/cgi.sh" "$TMPD/slow.sh" "$TMPD/child.sh"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
	-keyout "$RUN/localhost/privkey.pem" -out "$RUN/localhost/fullchain.pem" >/dev/null 2>&1
mkdir -p "$RUN/turbo.panel" # Certificate of the panel's own host
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=panel.test -addext subjectAltName=DNS:panel.test \
	-keyout "$RUN/turbo.panel/privkey.pem" -out "$RUN/turbo.panel/fullchain.pem" >/dev/null 2>&1
(cd "$RUN" && exec "$BIN" >"$TMPD/stdout.txt" 2>&1) &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null http://localhost/ && break; sleep 0.1; done
if ! curl -s -o /dev/null http://localhost/; then
	echo "Turbo does not answer on port 80. Its output:" >&2
	cat "$TMPD/stdout.txt" >&2
	exit 2
fi

echo "== HTTP"
check "GET http://localhost/" "$(curl -s -w ' %{http_code}' http://localhost/ | tr -d '\n')" "hello-real 200"
check "Server header" "$(curl -s -D - -o /dev/null http://localhost/ | tr -d '\r' | sed -n 's/^Server: //p')" "OKZGN Turbo"
check "GET /admin:" "$(curl -s -o /dev/null -w '%{http_code}' http://localhost/admin:)" "200"
check "1200-byte URI" "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost/$(head -c 1200 /dev/zero | tr '\0' a)")" "414"
check "Host in upper case" "$(curl -s -w ' %{http_code}' -H 'Host: LOCALHOST' http://localhost/ | tr -d '\n')" "hello-real 200"
check "Absolute-form request" "$(curl -s -w ' %{http_code}' --request-target 'http://localhost/' http://localhost/ | tr -d '\n')" "hello-real 200"
check "6000-byte header" "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Padding: $(head -c 6000 /dev/zero | tr '\0' r)" http://localhost/)" "431"

echo "== Panel: login"
check "Login by GET with the credentials in the URL" "$(curl -s 'http://localhost/admin:?u=Turbo&p=Admin' | head -c 2)" "([^o].|o[^k])"
check "Login by POST with the credentials in the URL" "$(curl -s -X POST 'http://localhost/admin:?u=Turbo&p=Admin' | head -c 2)" "(|[^o].|o[^k])"
big_body() { # code of the response to a 1 MB login; a connection cut without a response is not a 413
	local code
	code="$(head -c 1048576 /dev/zero | tr '\0' a | curl -s -o /dev/null -w '%{http_code}' --data-binary @- -H 'Content-Type: application/x-www-form-urlencoded' http://localhost/admin:)"
	[ "$code" = 000 ] && code="connection cut without a response"
	echo "$code"
}
check "Login with a 1 MB body" "$(big_body)" "413"
TOKEN="$(curl -s -F u=Turbo -F p=Admin http://localhost/admin: | sed 's/^ok//')"
check "Login" "${#TOKEN}" "64"

echo "== Paths outside @"
path_code() { curl -s --path-as-is -o /dev/null -w '%{http_code}' "http://localhost$1"; }
check "/../outside.txt" "$(path_code /../outside.txt)" "404"
check "/%2e%2e/outside.txt" "$(path_code /%2e%2e/outside.txt)" "404"
check "/..%2foutside.txt" "$(path_code /..%2foutside.txt)" "404"
check "/..%5coutside.txt" "$(path_code /..%5coutside.txt)" "404"
check "/../privkey.pem" "$(path_code /../privkey.pem)" "404"
check "/index.html%00" "$(path_code /index.html%00)" "404"
check "Symbolic link outside @" "$(path_code /link.txt)" "404"
check "Name ending in a dot" "$(path_code /dot.)" "404"

echo "== Preprocessor with the extension in upper case"
check "addPreprocessor cgi" "$(curl -s -X POST -H "ok: $TOKEN" --data-urlencode s=localhost --data-urlencode d= --data-urlencode a=cgi --data-urlencode c=Admin --data-urlencode "b=$TMPD/cgi.sh" 'http://localhost/admin:inside:addPreprocessor')" "Preprocessor.*"
check "GET /test.CGI runs it" "$(curl -s http://localhost/test.CGI)" "cgi-ran"

echo "== CGI that takes longer than WT"
check "addPreprocessor slow" "$(curl -s -X POST -H "ok: $TOKEN" --data-urlencode s=localhost --data-urlencode d= --data-urlencode a=slow --data-urlencode c=Admin --data-urlencode "b=$TMPD/slow.sh" 'http://localhost/admin:inside:addPreprocessor')" "Preprocessor.*"
check "setWT 2s" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "ok: $TOKEN" -d 'a=2s&b=Admin' 'http://localhost/admin:inside:setWT')" "200"
check "GET /wait.slow" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost/wait.slow)" "504"
check "addPreprocessor child" "$(curl -s -X POST -H "ok: $TOKEN" --data-urlencode s=localhost --data-urlencode d= --data-urlencode a=child --data-urlencode c=Admin --data-urlencode "b=$TMPD/child.sh" 'http://localhost/admin:inside:addPreprocessor')" "Preprocessor.*"
# The CGI leaves a process in the background with its output open: the response doesn't wait for it
check "CGI that leaves a child" "$(curl -s --max-time 5 -w ' %{http_code}' http://localhost/with.child | tr -d '\n')" "with-child 200"
check "setWT 10s" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "ok: $TOKEN" -d 'a=10s&b=Admin' 'http://localhost/admin:inside:setWT')" "200"

echo "== Panel: index and HTTPS"
check "addIndex" "$(curl -s -X POST -H "ok: $TOKEN" -d 'a=index.html&s=localhost&d=' 'http://localhost/admin:inside:addIndex')" "Index (assigned|unchanged)"
check "cfgS a=1" "$(curl -s -X POST -H "ok: $TOKEN" -d 'a=1&s=localhost&d=' 'http://localhost/admin:inside:cfgS')" "HTTPS redirect enabled"
for _ in $(seq 30); do ss -ltn | grep -q ':443 ' && break; sleep 0.1; done
check "Port 443 open" "$(ss -ltn | grep -c ':443 ')" "[1-9]"
check "HTTP -> HTTPS" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://localhost/x?y=1)" "301 https://localhost/x\?y=1"

echo "== HTTPS"
check "HTTP/1.1" "$(curl -sk --http1.1 -o /dev/null -w '%{http_version} %{http_code}' https://localhost/)" "1.1 200"
check "HTTP/2" "$(curl -sk --http2 -o /dev/null -w '%{http_version} %{http_code}' https://localhost/)" "2 200"
check "Server over HTTP/2" "$(curl -sk --http2 -D - -o /dev/null https://localhost/ | tr -d '\r' | sed -n 's/^server: //Ip')" "OKZGN Turbo"
check "1200-byte URI over HTTP/2" "$(curl -sk --http2 -o /dev/null -w '%{http_code}' "https://localhost/$(head -c 1200 /dev/zero | tr '\0' a)")" "414"
tls() { # version: prints the negotiated version or "refused"
	local output
	output="$(echo | timeout 5 openssl s_client -connect localhost:443 -servername localhost "-$1" -cipher 'DEFAULT:@SECLEVEL=0' 2>&1)"
	# s_client prints the attempted protocol even when it fails: what counts is the cipher suite.
	if echo "$output" | grep -q 'Cipher is (NONE)' || ! echo "$output" | grep -q 'Cipher is '; then
		echo refused
	else
		echo "$output" | grep -oE 'Protocol *: *TLSv[0-9.]+' | head -1 | sed 's/.*: *//'
	fi
}
tls_local() { # version: "yes" if this OpenSSL negotiates it with itself; otherwise "refused" would prove nothing
	local port=44330 server output
	openssl s_server -quiet -accept "127.0.0.1:$port" -cert "$RUN/localhost/fullchain.pem" -key "$RUN/localhost/privkey.pem" \
		"-$1" -cipher 'DEFAULT:@SECLEVEL=0' >/dev/null 2>&1 &
	server=$!
	sleep 0.5
	output="$(echo | timeout 5 openssl s_client -connect "127.0.0.1:$port" "-$1" -cipher 'DEFAULT:@SECLEVEL=0' 2>&1)"
	kill "$server" 2>/dev/null
	wait "$server" 2>/dev/null
	if echo "$output" | grep -q 'Cipher is ' && ! echo "$output" | grep -q 'Cipher is (NONE)'; then echo yes; else echo no; fi
}
tls_old() { # version, name
	if [ "$(tls_local "$1")" = yes ]; then
		check "$2" "$(tls "$1")" "refused"
	else
		skip "$2" "this OpenSSL doesn't negotiate $2 even with itself"
	fi
}
tls_old tls1 "TLS 1.0"
tls_old tls1_1 "TLS 1.1"
check "TLS 1.2" "$(tls tls1_2)" "TLSv1.2"
check "TLS 1.3" "$(tls tls1_3)" "TLSv1.3"
check "Without SNI (access by IP)" "$(echo | timeout 5 openssl s_client -connect 127.0.0.1:443 -noservername 2>&1 | grep -c 'BEGIN CERTIFICATE')" "0"
check "Unknown SNI" "$(echo | timeout 5 openssl s_client -connect localhost:443 -servername other.test 2>&1 | grep -c 'BEGIN CERTIFICATE')" "0"

echo "== Panel on a host of its own (PA)"
# Over HTTPS: with the certificate of localhost and HTTPS open, the panel over HTTP redirects to HTTPS.
check "setPA with the host of a site" "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "ok: $TOKEN" -d 'a=localhost&b=Admin' 'https://localhost/admin:inside:setPA')" "400"
# From panel.test: setPA refuses a value that leaves out the request itself.
check "setPA panel.test" "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H "ok: $TOKEN" -H 'Host: panel.test' -d 'a=panel.test&b=Admin' 'https://localhost/admin:inside:setPA')" "200"
# Through localhost, as the login: the session is tied to the client's IP (127.0.0.1 or ::1).
panel() { curl -sk --connect-to panel.test:443:localhost:443 "$@"; }
check "Panel on localhost" "$(curl -s -o /dev/null -w '%{http_code}' http://localhost/admin:)" "404"
check "Panel on panel.test over HTTP" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: panel.test' http://localhost/admin:)" "301 https://panel.test/admin:"
check "Panel on panel.test over HTTPS" "$(panel -o /dev/null -w '%{http_code}' https://panel.test/admin:)" "200"
check "HSTS on panel.test" "$(panel -D - -o /dev/null https://panel.test/admin: | tr -d '\r' | sed -n 's/^strict-transport-security: //Ip')" "max-age=31536000"
check "POST over HTTP to panel.test" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Host: panel.test' http://localhost/admin:inside:sites)" "308"
check "addSite panel.test" "$(panel -w ' %{http_code}' -X POST -H "ok: $TOKEN" -d 's=panel.test' 'https://panel.test/admin:inside:addSite')" "The site would serve the panel host.* 400"

echo "== Messages on stdout"
check "Start with level and time" "$(grep -c '^time=.* level=INFO msg=Starting' "$TMPD/stdout.txt")" "1"
check "HTTPS enabled" "$(grep -c 'msg="HTTPS enabled"' "$TMPD/stdout.txt")" "1"
check "Warning about the default credentials" "$(grep -c 'level=WARN msg="The default credentials' "$TMPD/stdout.txt")" "[1-9]"
check "Warning about a panel without a host of its own" "$(grep -c 'level=WARN msg="The panel answers on the same hosts' "$TMPD/stdout.txt")" "[1-9]"

echo "== Second instance with port 80 in use"
(cd "$RUN" && timeout 15 "$BIN" >"$TMPD/stdout2.txt" 2>&1)
check "Exits with an error" "$?" "1"
check "Explains it in the log" "$(grep -c "level=ERROR msg=\"Can't open the HTTP address\"" "$TMPD/stdout2.txt")" "1"

echo "== SIGTERM"
kill -TERM "$PID"
wait "$PID"
check "Exits with code 0" "$?" "0"
PID=""
check "Orderly shutdown in the log" "$(grep -cE 'msg=(Stopping|Stopped)( |$)' "$TMPD/stdout.txt")" "2"

echo
[ "$SKIPPED" -gt 0 ] && echo "$SKIPPED checks skipped (see the reason of each one)"
if [ "$FAILURES" -gt 0 ]; then
	echo "$FAILURES checks failed"
	exit 1
fi
echo "All the checks made passed"
