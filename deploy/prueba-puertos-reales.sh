#!/bin/bash
# Prueba de integración de Turbo con los puertos reales 80 y 443 (PLAN §10.8),
# para ejecutar en Linux antes de cada release.
#
# Uso: deploy/prueba-puertos-reales.sh [carpeta del código]   (por defecto, este repositorio)
#
# Necesita Go, curl, openssl, ss y poder dar al binario CAP_NET_BIND_SERVICE con
# "sudo -n setcap" (sin contraseña). Los puertos 80 y 443 deben estar libres.
# Compila el código, lo arranca en un directorio temporal con un sitio y un
# certificado autofirmado, comprueba lo que se ve desde fuera y lo borra todo al
# terminar. Sale con código 1 si alguna comprobación falla.
set -u

SRC="$(cd "${1:-$(dirname "$0")/..}" && pwd)"
# No en /tmp: suele montarse con nosuid y entonces CAP_NET_BIND_SERVICE no tiene efecto.
mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}"
TMPD="$(mktemp -d "${XDG_CACHE_HOME:-$HOME/.cache}/turbo-prueba.XXXXXX")"
BIN="$TMPD/turbo"
RUN="$TMPD/sitios"
PID=""
FALLOS=0

limpiar() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
	rm -rf "$TMPD"
}
trap limpiar EXIT

comprobar() { # descripción, valor obtenido, valor esperado (expresión regular)
	if [[ "$2" =~ ^$3$ ]]; then
		echo "  ok    $1: $2"
	else
		echo "  FALLA $1: «$2»; se esperaba «$3»"
		FALLOS=$((FALLOS + 1))
	fi
}

for herramienta in go curl openssl ss; do
	command -v "$herramienta" >/dev/null || { echo "Falta $herramienta" >&2; exit 2; }
done
if ss -ltn | grep -qE ':(80|443) '; then
	echo "Los puertos 80 o 443 están ocupados" >&2
	exit 2
fi

echo "== Compilando $SRC"
(cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$BIN" .) || exit 2
sudo -n setcap cap_net_bind_service=+ep "$BIN" || { echo "sudo -n setcap no está permitido" >&2; exit 2; }

mkdir -p "$RUN/localhost/@"
echo "hola-real" >"$RUN/localhost/@/index.html"
echo "fuera-de-@" >"$RUN/localhost/fuera.txt"
ln -s ../fuera.txt "$RUN/localhost/@/enlace.txt"
echo "nombre-especial" >"$RUN/localhost/@/punto."
echo "codigo-fuente" >"$RUN/localhost/@/prueba.CGI"
printf '#!/bin/sh\nprintf "Content-Type: text/plain\\r\\n\\r\\ncgi-ejecutado\\n"\n' >"$TMPD/cgi.sh"
chmod +x "$TMPD/cgi.sh"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
	-keyout "$RUN/localhost/privkey.pem" -out "$RUN/localhost/fullchain.pem" >/dev/null 2>&1
(cd "$RUN" && exec "$BIN" >"$TMPD/stdout.txt" 2>&1) &
PID=$!
for _ in $(seq 50); do curl -s -o /dev/null http://localhost/ && break; sleep 0.1; done
if ! curl -s -o /dev/null http://localhost/; then
	echo "Turbo no responde en el puerto 80. Su salida:" >&2
	cat "$TMPD/stdout.txt" >&2
	exit 2
fi

echo "== HTTP"
comprobar "GET http://localhost/" "$(curl -s -w ' %{http_code}' http://localhost/ | tr -d '
')" "hola-real 200"
comprobar "Cabecera Server" "$(curl -s -D - -o /dev/null http://localhost/ | tr -d '\r' | sed -n 's/^Server: //p')" "OKZGN Turbo"
comprobar "GET /admin:" "$(curl -s -o /dev/null -w '%{http_code}' http://localhost/admin:)" "200"
comprobar "URI de 1200 bytes" "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost/$(head -c 1200 /dev/zero | tr '\0' a)")" "414"
comprobar "Cabecera de 6000 bytes" "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Relleno: $(head -c 6000 /dev/zero | tr '\0' r)" http://localhost/)" "431"

echo "== Panel: login"
comprobar "Login por GET con credenciales en la URL" "$(curl -s 'http://localhost/admin:?u=Turbo&p=Admin' | head -c 2)" "([^o].|o[^k])"
comprobar "Login por POST con credenciales en la URL" "$(curl -s -X POST 'http://localhost/admin:?u=Turbo&p=Admin' | head -c 2)" "(|[^o].|o[^k])"
comprobar "Login con un cuerpo de 1 MB" "$(head -c 1048576 /dev/zero | tr '\0' a | curl -s -o /dev/null -w '%{http_code}' --data-binary @- -H 'Content-Type: application/x-www-form-urlencoded' http://localhost/admin:)" "413"
TOKEN="$(curl -s -F u=Turbo -F p=Admin http://localhost/admin: | sed 's/^ok//')"
comprobar "Login" "${#TOKEN}" "64"

echo "== Rutas fuera de @"
ruta() { curl -s --path-as-is -o /dev/null -w '%{http_code}' "http://localhost$1"; }
comprobar "/../fuera.txt" "$(ruta /../fuera.txt)" "404"
comprobar "/%2e%2e/fuera.txt" "$(ruta /%2e%2e/fuera.txt)" "404"
comprobar "/..%2ffuera.txt" "$(ruta /..%2ffuera.txt)" "404"
comprobar "/..%5cfuera.txt" "$(ruta /..%5cfuera.txt)" "404"
comprobar "/../privkey.pem" "$(ruta /../privkey.pem)" "404"
comprobar "/index.html%00" "$(ruta /index.html%00)" "404"
comprobar "Enlace simbólico fuera de @" "$(ruta /enlace.txt)" "404"
comprobar "Nombre acabado en punto" "$(ruta /punto.)" "404"

echo "== Preprocesador con la extensión en mayúsculas"
comprobar "addPreprocessor cgi" "$(curl -s -X POST -H "ok: $TOKEN" --data-urlencode s=localhost --data-urlencode d= --data-urlencode a=cgi --data-urlencode "b=$TMPD/cgi.sh" 'http://localhost/admin:inside:addPreprocessor')" "Preprocesador.*"
comprobar "GET /prueba.CGI se ejecuta" "$(curl -s http://localhost/prueba.CGI)" "cgi-ejecutado"

echo "== Panel: índice y HTTPS"
comprobar "addIndex" "$(curl -s -X POST -H "ok: $TOKEN" -d 'a=index.html&s=localhost&d=' 'http://localhost/admin:inside:addIndex')" "Índice (asignado|sin cambios)"
comprobar "cfgS a=1" "$(curl -s -X POST -H "ok: $TOKEN" -d 'a=1&s=localhost&d=' 'http://localhost/admin:inside:cfgS')" "Redirección a HTTPS activada"
for _ in $(seq 30); do ss -ltn | grep -q ':443 ' && break; sleep 0.1; done
comprobar "Puerto 443 abierto" "$(ss -ltn | grep -c ':443 ')" "[1-9]"
comprobar "HTTP -> HTTPS" "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://localhost/x?y=1)" "301 https://localhost/x\?y=1"

echo "== HTTPS"
comprobar "HTTP/1.1" "$(curl -sk --http1.1 -o /dev/null -w '%{http_version} %{http_code}' https://localhost/)" "1.1 200"
comprobar "HTTP/2" "$(curl -sk --http2 -o /dev/null -w '%{http_version} %{http_code}' https://localhost/)" "2 200"
comprobar "Server por HTTP/2" "$(curl -sk --http2 -D - -o /dev/null https://localhost/ | tr -d '\r' | sed -n 's/^server: //Ip')" "OKZGN Turbo"
comprobar "URI de 1200 bytes por HTTP/2" "$(curl -sk --http2 -o /dev/null -w '%{http_code}' "https://localhost/$(head -c 1200 /dev/zero | tr '\0' a)")" "414"
tls() { # versión: responde la versión negociada o "rechazada"
	local salida
	salida="$(echo | timeout 5 openssl s_client -connect localhost:443 -servername localhost "-$1" -cipher 'DEFAULT:@SECLEVEL=0' 2>&1)"
	# s_client imprime el protocolo intentado aunque falle: lo que cuenta es la suite.
	if echo "$salida" | grep -q 'Cipher is (NONE)' || ! echo "$salida" | grep -q 'Cipher is '; then
		echo rechazada
	else
		echo "$salida" | grep -oE 'Protocol *: *TLSv[0-9.]+' | head -1 | sed 's/.*: *//'
	fi
}
comprobar "TLS 1.0" "$(tls tls1)" "rechazada"
comprobar "TLS 1.1" "$(tls tls1_1)" "rechazada"
comprobar "TLS 1.2" "$(tls tls1_2)" "TLSv1.2"
comprobar "TLS 1.3" "$(tls tls1_3)" "TLSv1.3"
comprobar "Sin SNI (acceso por IP)" "$(echo | timeout 5 openssl s_client -connect 127.0.0.1:443 -noservername 2>&1 | grep -c 'BEGIN CERTIFICATE')" "0"
comprobar "SNI desconocido" "$(echo | timeout 5 openssl s_client -connect localhost:443 -servername otro.test 2>&1 | grep -c 'BEGIN CERTIFICATE')" "0"

echo "== Panel en un host propio (PA)"
comprobar "setPA con el host de un sitio" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "ok: $TOKEN" -d 'a=localhost&b=Admin' 'http://localhost/admin:inside:setPA')" "400"
comprobar "setPA panel.test" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "ok: $TOKEN" -d 'a=panel.test&b=Admin' 'http://localhost/admin:inside:setPA')" "200"
comprobar "Panel en localhost" "$(curl -s -o /dev/null -w '%{http_code}' http://localhost/admin:)" "404"
comprobar "Panel en panel.test" "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: panel.test' http://localhost/admin:)" "200"
# Por localhost, como el login: la sesión va ligada a la IP del cliente (127.0.0.1 o ::1).
comprobar "addSite panel.test" "$(curl -s -w ' %{http_code}' -X POST -H "ok: $TOKEN" -H 'Host: panel.test' -d 's=panel.test' 'http://localhost/admin:inside:addSite')" "El sitio serviría el host del panel.* 400"

echo "== Mensajes en stdout"
comprobar "Inicio con nivel y hora" "$(grep -c '^time=.* level=INFO msg=Inicio' "$TMPD/stdout.txt")" "1"
comprobar "HTTPS activado" "$(grep -c 'msg="HTTPS activado"' "$TMPD/stdout.txt")" "1"
comprobar "Aviso de credenciales por defecto" "$(grep -c 'level=WARN msg="Se usan las credenciales por defecto' "$TMPD/stdout.txt")" "[1-9]"
comprobar "Aviso de panel sin host propio" "$(grep -c 'level=WARN msg="El panel responde en los mismos hosts' "$TMPD/stdout.txt")" "[1-9]"

echo "== Segunda instancia con el puerto 80 ocupado"
(cd "$RUN" && timeout 15 "$BIN" >"$TMPD/stdout2.txt" 2>&1)
comprobar "Termina con error" "$?" "1"
comprobar "Lo explica en el log" "$(grep -c 'level=ERROR msg="No se puede abrir la dirección HTTP"' "$TMPD/stdout2.txt")" "1"

echo
if [ "$FALLOS" -gt 0 ]; then
	echo "$FALLOS comprobaciones fallidas"
	exit 1
fi
echo "Todas las comprobaciones correctas"
