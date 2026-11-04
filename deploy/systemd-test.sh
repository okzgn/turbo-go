#!/bin/bash
# Test of the reference systemd unit (deploy/turbo.service) really installed,
# to run on Linux with systemd before each release.
#
# Usage, as root: deploy/systemd-test.sh <Turbo binary>
#
# It installs the unit as its comments say (the turbo user, the binary in
# /usr/local/bin/turbo, the sites in /home/server with turbo.dev owned by root
# and the credentials in /etc/turbo/credentials), starts it and checks: the
# ports, the user and the capabilities of Turbo, that the panel doesn't accept
# the default credentials, that a CGI inherits no capability and can't write
# the binary or turbo.dev, the private /tmp, stopping with systemctl stop (a
# CGI in progress ends and its response arrives whole), the restart after a
# crash and the journal. At the end it uninstalls everything and checks that
# nothing is left.
#
# It doesn't touch an existing installation: it refuses to start if the turbo
# user, /usr/local/bin/turbo, /home/server, /etc/turbo, a turbo.service unit
# or its drop-ins in any systemd folder already exist, or drop-ins for every
# service (service.d), which would change what is tested. It needs curl,
# openssl and ss. Ports 80 and 443 must be free.
#
# With CERTBOT_WRAPPER=<folder> and CERTBOT_DOMAIN=<domain>, it also requests
# from the panel a certificate for that domain with the certbot executable of
# that folder, which is copied whole (for example, a wrapper of the apt Certbot
# that points to a test CA, with its root certificate next to it): it checks
# that Certbot works with NoNewPrivileges.
set -u

SRC_BIN="${1:-}"
UNIT=/etc/systemd/system/turbo.service
SITES=/home/server
FAILURES=0
INSTALLED=0

check() { # description, value got, value expected (regular expression)
	if [[ "$2" =~ ^$3$ ]]; then
		echo "  ok    $1: $2"
	else
		echo "  FAIL  $1: \"$2\"; expected \"$3\""
		FAILURES=$((FAILURES + 1))
	fi
}

uninstall() {
	[ "$INSTALLED" = 1 ] || return
	echo "== Uninstalling"
	systemctl disable --now turbo >/dev/null 2>&1
	rm -f "$UNIT"
	rm -rf /etc/systemd/system/turbo.service.d
	systemctl daemon-reload
	systemctl reset-failed turbo >/dev/null 2>&1
	userdel turbo 2>/dev/null
	rm -f /usr/local/bin/turbo
	rm -rf /etc/turbo
	[ "$SITES" = /home/server ] && rm -rf /home/server
	check "credentials" "$([ -e /etc/turbo ] && echo exists || echo no)" "no"
	check "turbo user" "$(id turbo >/dev/null 2>&1 && echo exists || echo no)" "no"
	check "unit" "$([ -e "$UNIT" ] && echo exists || echo no)" "no"
	check "binary" "$([ -e /usr/local/bin/turbo ] && echo exists || echo no)" "no"
	check "sites" "$([ -e /home/server ] && echo exists || echo no)" "no"
	check "service loaded" "$(systemctl show -p LoadState --value turbo)" "not-found"
	echo "== Result: $FAILURES failures"
}
trap uninstall EXIT

[ "$(id -u)" = 0 ] || { echo "Run it as root" >&2; exit 2; }
[ -x "$SRC_BIN" ] || { echo "Usage: $0 <Turbo binary>" >&2; exit 2; }
[ "$(ps -p 1 -o comm=)" = systemd ] || { echo "systemd is not PID 1" >&2; exit 2; }
for tool in curl openssl ss useradd systemctl journalctl; do
	command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
if id turbo >/dev/null 2>&1 || [ -e /usr/local/bin/turbo ] || [ -e /home/server ] || [ -e /etc/turbo ] ||
	[ "$(systemctl show -p LoadState --value turbo)" != not-found ]; then
	echo "There is already a Turbo installation (turbo user, a turbo.service unit, /usr/local/bin/turbo, /home/server or /etc/turbo): it is not touched" >&2
	exit 2
fi
for dir in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
	for name in turbo.service turbo.service.d service.d; do
		if [ -e "$dir/$name" ]; then
			echo "$dir/$name exists: it would change the unit under test, or it belongs to another installation; it is not touched" >&2
			exit 2
		fi
	done
done
if ss -ltn | grep -qE ':(80|443) '; then
	echo "Ports 80 or 443 are in use" >&2
	exit 2
fi
SRC_UNIT="$(cd "$(dirname "$0")" && pwd)/turbo.service"

echo "== Installing as the comments of the unit say"
INSTALLED=1
useradd --system --home-dir /home/server --shell /usr/sbin/nologin turbo
install -o root -g root -m 0755 "$SRC_BIN" /usr/local/bin/turbo
mkdir -p /home/server/localhost/@ /home/server/cgi
echo "hello-systemd" >/home/server/localhost/@/index.html
echo "x" >/home/server/localhost/@/x.test
echo "x" >/home/server/localhost/@/x.slow
cat >/home/server/cgi/slow.sh <<'CGI'
#!/bin/sh
sleep 3
printf 'Content-Type: text/plain\r\n\r\nslow-complete\n'
CGI
chmod 0755 /home/server/cgi/slow.sh
cat >/home/server/cgi/test.sh <<'CGI'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
grep '^Cap' /proc/self/status
( : >>/usr/local/bin/turbo ) 2>/dev/null && echo "binary: written" || echo "binary: no"
( : >/home/server/turbo.dev/written ) 2>/dev/null && echo "turbo.dev: written" || echo "turbo.dev: no"
( : >/tmp/turbo-systemd-test ) 2>/dev/null && echo "tmp: written" || echo "tmp: no"
CGI
chmod 0755 /home/server/cgi/test.sh
printf '{"^":{"v":"2"},"localhost":{"":{"?":{"test":"/home/server/cgi/test.sh","slow":"/home/server/cgi/slow.sh"},"-":{"index.html":"1"},"!":{"S":"1"}}}}' >/home/server/turbo.config
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
	-keyout /home/server/localhost/privkey.pem -out /home/server/localhost/fullchain.pem >/dev/null 2>&1
if [ -n "${CERTBOT_WRAPPER:-}" ]; then
	[ -x "$CERTBOT_WRAPPER/certbot" ] || { echo "There is no certbot executable in $CERTBOT_WRAPPER" >&2; exit 2; }
	mkdir -p "/home/server/${CERTBOT_DOMAIN:?CERTBOT_DOMAIN is missing}/@"
	cp -r "$CERTBOT_WRAPPER" /home/server/certbot-bin
	echo "test-domain" >"/home/server/$CERTBOT_DOMAIN/@/index.html"
	mkdir -p /etc/systemd/system/turbo.service.d
	printf '[Service]\nEnvironment=PATH=/home/server/certbot-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' \
		>/etc/systemd/system/turbo.service.d/certbot-test.conf
fi
chown -R turbo:turbo /home/server
install -d -o root -g root -m 0755 /home/server/turbo.dev
install -d -o root -g root -m 0755 /etc/turbo
install -o root -g root -m 0600 /dev/null /etc/turbo/credentials
PANEL_USER=tester
PANEL_PASSWORD="$(openssl rand -hex 8)"
printf 'TURBO_USER=%s\nTURBO_PASSWORD=%s\n' "$PANEL_USER" "$PANEL_PASSWORD" >/etc/turbo/credentials
cp "$SRC_UNIT" "$UNIT"
systemctl daemon-reload && systemctl enable --now turbo >/dev/null 2>&1

for _ in $(seq 100); do curl -s -o /dev/null http://localhost/ && break; sleep 0.1; done
echo "== Service"
check "state" "$(systemctl is-active turbo)" "active"
PID="$(systemctl show -p MainPID --value turbo)"
check "user of the process" "$(ps -o user= -p "$PID" | tr -d ' ')" "turbo"
check "listens on 80 and 443" "$(ss -ltnpH | grep "pid=$PID," | grep -oE ':(80|443) ' | sort -u | tr -d ' \n')" ":443:80"
check "CapEff of Turbo (only CAP_NET_BIND_SERVICE)" "$(awk '/^CapEff/ {print $2}' /proc/"$PID"/status)" "0000000000000400"
check "HTTP redirects to HTTPS" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://localhost/)" "301 https://localhost/"
check "HTTPS" "$(curl -sk https://localhost/)" "hello-systemd"
check "turbo.dev owned by root" "$(stat -c %U /home/server/turbo.dev)" "root"
check "credentials 0600 owned by root" "$(stat -c '%a %U' /etc/turbo/credentials)" "600 root"
check "login with Turbo/Admin" "$(curl -sk -o /dev/null -w '%{http_code}' --data 'u=Turbo&p=Admin' https://localhost/admin:)" "403"
check "login with the credentials of the file" "$(curl -sk --data "u=$PANEL_USER&p=$PANEL_PASSWORD" https://localhost/admin: | cut -c1-2)" "ok"

echo "== CGI"
OUTPUT="$(curl -sk https://localhost/x.test)"
for cap in CapInh CapPrm CapEff CapAmb; do
	check "$cap of the CGI" "$(echo "$OUTPUT" | awk -v c="$cap:" '$1 == c {print $2}')" "0000000000000000"
done
check "the CGI writes the binary" "$(echo "$OUTPUT" | grep '^binary:')" "binary: no"
check "the CGI writes turbo.dev" "$(echo "$OUTPUT" | grep '^turbo.dev:')" "turbo.dev: no"
check "the CGI writes in its /tmp" "$(echo "$OUTPUT" | grep '^tmp:')" "tmp: written"
check "its /tmp is private" "$([ -e /tmp/turbo-systemd-test ] && echo "visible in /tmp" || echo private)" "private"

if [ -n "${CERTBOT_WRAPPER:-}" ]; then
	echo "== Certbot with NoNewPrivileges ($CERTBOT_DOMAIN)"
	# localhost has a certificate: the panel is used over HTTPS, with the credentials of /etc/turbo/credentials.
	TOKEN="$(curl -sk --data "u=$PANEL_USER&p=$PANEL_PASSWORD" https://localhost/admin: | sed 's/^ok//')"
	panel() { curl -sk -H "ok: $TOKEN" -o /dev/null -w '%{http_code}' --data "$1" "https://localhost/admin:inside:$2"; }
	panel "s=$CERTBOT_DOMAIN&d=&a=1&z=tests@example.org" cfgC >/dev/null
	STATUS=202
	for _ in $(seq 60); do
		STATUS="$(panel "s=$CERTBOT_DOMAIN&d=&a=1" cfgC)"
		[ "$STATUS" = 202 ] || break
		sleep 2
	done
	check "cfgC" "$STATUS" "200"
	check "certificate in the folder of the site" "$([ -s "/home/server/$CERTBOT_DOMAIN/fullchain.pem" ] && echo yes || echo no)" "yes"
fi

echo "== Journal"
check "messages with level and time" "$(journalctl -u turbo -o cat --no-pager | grep -c 'level=INFO' | awk '{print ($1 > 0) ? "yes" : "no"}')" "yes"

echo "== systemd-analyze security"
systemd-analyze security turbo --no-pager 2>/dev/null | tail -1

echo "== Restart after a crash"
kill -9 "$PID"
sleep 7 # RestartSec=5
NEW_PID="$(systemctl show -p MainPID --value turbo)"
check "state" "$(systemctl is-active turbo)" "active"
check "new process" "$([ "$NEW_PID" != "$PID" ] && [ "$NEW_PID" != 0 ] && echo yes || echo no)" "yes"
for _ in $(seq 50); do curl -sk -o /dev/null https://localhost/ && break; sleep 0.1; done
check "answers" "$(curl -sk https://localhost/)" "hello-systemd"

echo "== Stop"
# With a CGI in progress (it takes 3 s): systemd sends SIGTERM only to Turbo (KillMode=mixed), which lets it end.
SLOW_OUT="$(mktemp)"
curl -sk https://localhost/x.slow >"$SLOW_OUT" &
CURL_PID=$!
sleep 1
START=$(date +%s)
systemctl stop turbo
check "seconds until it stops" "$(($(date +%s) - START))" "[0-9]"
wait "$CURL_PID"
check "the CGI in progress at the stop answers whole" "$(cat "$SLOW_OUT")" "slow-complete"
rm -f "$SLOW_OUT"
check "exit code" "$(systemctl show -p ExecMainStatus --value turbo)" "0"
check "state" "$(systemctl is-active turbo)" "inactive"

trap - EXIT
uninstall
[ "$FAILURES" = 0 ]
