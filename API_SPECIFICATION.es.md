# Turbo - API, Especificación Técnica

*In English: [API_SPECIFICATION.md](./API_SPECIFICATION.md).*

## 1. Arquitectura General y Protocolo de Comunicación

El backend de Turbo proporciona una API de estilo **RPC/REST sobre HTTP POST**. Toda la interacción entre la interfaz visual (GUI) o cualquier cliente externo y el servidor se realiza exclusivamente mediante peticiones `POST`.

### 1.1. Rutas de Acceso Principales (Base URLs)
* **Autenticación Pública / Login:** `/admin:`
* **Módulo Administrativo Autenticado:** `/admin:inside:`
* **Cierre de Sesión:** `/admin:signout:`

### 1.2. Cabeceras y Seguridad
* **Método HTTP:** Obligatoriamente `POST` para todas las acciones de la API.
* **Parámetros:** Los parámetros de las acciones (`s`, `d`, `a`, `b`…) pueden ir en la consulta de la URL o en un cuerpo `application/x-www-form-urlencoded`. La GUI los envía en el cuerpo, así que la contraseña actual (`b`) nunca aparece en la URL que registra `turbo.visits`; los clientes de la API deberían hacer lo mismo. La excepción es `hardUpload` (§9), cuyo sitio y subdominio (`s`, `d`, que no son sensibles) van en la URL, y su contraseña en el cuerpo multipart.
* **Manejo de Sesión:** Tras un login correcto, el servidor fija la cookie de sesión (`Path=/; HttpOnly; SameSite=Strict`), que el navegador envía por sí solo: `turbo_session` por HTTP, y `__Host-turbo_session` por HTTPS (con `Secure` y sin `Domain`, así que los navegadores solo la aceptan del host del panel y otro subdominio no puede poner una en su lugar). Los clientes de la API pueden enviar en su lugar el token en la cabecera `ok: <token>`. Se prueban todas las cookies de sesión de la petición (puede llegar antes una con el mismo nombre fijada por otro subdominio) y después la cabecera `ok`. El token **no** se acepta como parámetro en la URL. Las dos cookies se quitan de la cabecera `Cookie` que se pasa a los preprocesadores CGI.
* **Mismo Origen:** Un `POST` a `/admin:inside:` autenticado con la cookie debe venir del propio origen del panel: el navegador debe enviar `Sec-Fetch-Site: same-origin` (o `none`) o, sin `Sec-Fetch-Site`, una cabecera `Origin` igual a `<esquema>://<Host>`. Si no, el servidor responde `403`. Las peticiones autenticadas con la cabecera `ok` no lo necesitan.
* **Cabeceras de las Respuestas del Panel:** Las respuestas bajo `/admin:` llevan `X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` y una `Content-Security-Policy`: `frame-ancestors 'none'` en las páginas del panel, y en todo lo demás (respuestas de la API, errores con la plantilla de error) una sin scripts, marcos, formularios ni complementos (`default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`). Todo error que Turbo responde con la plantilla de error lleva también esa, en cualquier host, antes o después de leer la petición, así que una plantilla de error nunca ejecuta scripts: con `PA` vacío (lo predeterminado), los sitios comparten el origen del panel. En un host de `PA`, también la lleva toda respuesta fuera de las páginas del panel. Las respuestas JSON (`sites`, `subdomains`, `subdomainData`, el `WAIT` de `cfgC` y `cfgPC`) son `application/json; charset=utf-8`, y los mensajes de texto `text/plain; charset=utf-8`.
* **Sesión Ausente:** una petición a `/admin:inside:` sin una sesión válida recibe la misma redirección HTML de siempre (§3.2) y la cabecera `X-Turbo-Login: required`, que es lo que deben mirar los clientes: el contenido de una respuesta válida (una plantilla de error, una cabecera o una reescritura de un sitio) puede contener cualquier texto.
* **Dónde Responde el Panel:** El ajuste global `PA` (ver `setPA`, §5) puede limitar `/admin:` a una lista de hosts y/o redes CIDR: el `Host` de la petición tiene que ser uno de los hosts (si los hay) y la IP del cliente tiene que estar en una de las redes (si las hay). Si no, `/admin:` responde `404`. Vacío (por defecto) significa sin restricción, y entonces el panel comparte el origen de todos los sitios que sirve Turbo: la configuración recomendada es un host propio para el panel, que no sirva ningún sitio. Con redes y sin host, el panel solo responde cuando el `Host` es una dirección IP o `localhost`, nunca un nombre: una página cuyo nombre resuelve a Turbo (DNS rebinding) llegaría si no al panel desde el navegador de alguien de esas redes, en su propio origen. Se rechaza un host de `PA` que sirva un sitio (§5), y también un sitio, subdominio o alias nuevo que serviría un host de `PA` (`400` con el motivo).
* **Ciclo de Vida de la Sesión:** Los tokens son asignados a la IP del cliente y expiran tras **600 segundos (10 minutos)** de inactividad, y como mucho **12 horas** después del login, se usen como se usen. Cada petición a `/admin:inside:` del propio origen del panel (o sin `Sec-Fetch-Site`, como las envían los clientes de la API) renueva el temporizador, hasta ese límite; una de otro origen, como un recurso que carga otra página, no. Cambiar el usuario o la contraseña (`setU`, `setP`) cierra todas las sesiones, también la de la petición, y abre una nueva para su cliente: la respuesta fija la cookie nueva y lleva el token nuevo en su cabecera `ok`, que los clientes de la API deben enviar desde entonces (una copia del token viejo ya no vale nada). Lo mismo hacen `setM`, cuando el `turbo.config` del directorio nuevo trae otras credenciales, y `closeSessions` (§3.3); una recarga de `turbo.config` que las cambia cierra todas las sesiones. Sin una sesión válida, `/admin:inside:` devuelve la redirección HTML a `/admin:` (ver §3.2).
* **Lo que Basta con la Sesión:** leer el estado (`sites`, `subdomains`, `subdomainData`); añadir y borrar sitios y subdominios, reescrituras, tipos MIME, cabeceras, índices, alias e IPs denegadas (salvo `delSite`); y los `cfg<CLAVE>` que no borran un certificado (los de un sitio, y `cfgPC` con `a=1`). Toda otra acción pide además la contraseña actual: `set<CLAVE>`, `addPreprocessor` y `delPreprocessor`, `delSite`, `hardUpload`, `cfgC` y `cfgPC` con `a=0`, `addHttpCodeResponse` y `delHttpCodeResponse` (una plantilla es la página de error de todos los sitios), `addCharsReplace` y `delCharsReplace` (un reemplazo cambia lo que leen las acciones) y `closeSessions`.

---

## 2. Convenciones de Codificación de Datos y Reemplazo de Caracteres

Para evitar que caracteres especiales y delimitadores de URL interfieran o corrompan las peticiones HTTP (especialmente en reglas de reescritura o cabeceras), el backend exige que ciertos caracteres se codifiquen mediante una sustitución predefinida:

### 2.1. Sustituciones Inmutables (Fijas)
El servidor deshace los reemplazos de caracteres (los fijos de abajo y los añadidos con `addCharsReplace`, §7.3) solo en los parámetros de las acciones a las que basta la sesión (§1.2), y nunca en el sitio y el subdominio (`s` y `d`) de ninguna acción: en la práctica, `a` y `b` de `addRewrite`, `addMIME`, `addHeader`, `addIndex` y `addAlias`, y `a` de sus `del<TIPO>`. Las acciones que piden la contraseña actual, los `cfg<CLAVE>` y `hardUpload` toman todos sus parámetros exactamente como llegan: envíelos codificados para URL, como ya lo hace por sí solo un cuerpo `application/x-www-form-urlencoded`. Así, un reemplazo no puede cambiar lo que el administrador confirma con la contraseña (una extensión, el programa de un preprocesador, el sitio que se borra). Las siguientes sustituciones deben aplicarse en el lado del cliente antes de enviar los parámetros que el servidor decodifica, y no se pueden cambiar ni borrar:

| Carácter Original | Token de Transmisión Esperado |
|---|---|
| `;` (Punto y coma) | `-.-` |
| `#` (Almohadilla) | `-,-` |
| `&` (Ampersand) | `-_-` |

*Nota: Los administradores pueden añadir más reemplazos de caracteres con `addCharsReplace` (§7.3), que pide la contraseña actual. El servidor los deshace todos de una pasada, primero los tokens más largos, y los valores leídos de `turbo.config` no se vuelven a decodificar (se guardan decodificados).*

*Límite: un texto con un carácter reemplazado junto al principio o al final de un token no siempre se puede distinguir: `-,#` y `#,-` se envían los dos como `-,-,-`, y el servidor lee `#,-`. Un cliente puede comprobarlo antes de enviar: deshacer los reemplazos de lo que va a enviar y compararlo con el original. El panel no envía un texto así y lo avisa.*

### 2.2. Caracteres no admitidos
Ningún parámetro puede contener caracteres de control (bytes por debajo de `0x20` y `0x7f`) ni UTF-8 inválido: el servidor responde HTTP 400 `"Control characters not allowed"` o `"Invalid UTF-8 text"`. La única excepción es la plantilla de respuesta de `addHttpCodeResponse` (§7.2), que puede contener tabuladores y saltos de línea.

---

## 3. API de Autenticación y Control de Sesión

**HTTPS:** por HTTP, toda petición al panel (también el login y las acciones) en un host que cubre un certificado (el propio del panel, en `turbo.panel/`, o el de un sitio) se redirige a HTTPS mientras HTTPS está abierto: 301 en `GET` y `HEAD`, 308 en el resto, que conserva el método y el cuerpo. Por HTTPS, en un host de `PA`, el panel responde con `Strict-Transport-Security: max-age=31536000`.

### 3.1. Iniciar Sesión (Login)
Valida las credenciales del usuario y genera un token único enlazado a la dirección IP del cliente. *Nota: Puede ser frágil detrás de NAT/proxies compartidos, donde varios usuarios comparten una IP pública.*

* **Endpoint:** `POST /admin:` (solo esta ruta y este método; un `GET` sirve la página de login)
* **Formato del Cuerpo:** `multipart/form-data` o `application/x-www-form-urlencoded`, de 4 KiB como máximo (si es mayor: HTTP 413).
* **Parámetros Requeridos**, en el cuerpo (los de la URL se ignoran):
  * `u`: Nombre de usuario.
  * `p`: Contraseña.
* **Respuesta Exitosa (HTTP 200 OK):**
  El servidor genera un token opaco criptográficamente seguro (32 bytes aleatorios, 64 caracteres hexadecimales), distinto en cada login y asociado a la IP del cliente. Fija con él la cookie de sesión (`turbo_session`, o `__Host-turbo_session` por HTTPS), y el cuerpo contiene el token prefijado por la variable de éxito (por defecto `"ok"`), para los clientes que usan la cabecera `ok`.
  ```text
  ok<token>
  ```
* **Credenciales Incorrectas:** HTTP 403 con el cuerpo vacío.
* **Demasiados Logins Fallidos:** tras 5 fallos desde la misma IP (una dirección IPv4, o un /64 IPv6) en 10 minutos, todo login desde esa IP (también con las credenciales correctas) recibe HTTP 429 con `Retry-After` en segundos, sin comprobar la contraseña: 1 minuto la primera vez, después 2, 4, 8 y como máximo 15 minutos. Los /64 de un /48 IPv6 comparten además una cuenta de 20 fallos en 10 minutos, con los mismos bloqueos para todos ellos. Los logins que se están comprobando cuentan para los límites: los simultáneos que los superan reciben 429 con `Retry-After: 2`. Un login correcto pone a cero la cuenta de su IP (no la de su /48). Una contraseña actual errónea de un `set<CLAVE>` (§5) o de una acción que la pide (§1.2) cuenta como un login fallido, y mientras la IP está bloqueada, esas acciones reciben el mismo 429 sin comprobarla.
* **Servidor Ocupado:** si la contraseña no se puede comprobar en 2 segundos porque hay demasiadas comprobaciones en curso, HTTP 503 con `Retry-After: 2`. Una de las comprobaciones que corren a la vez se reserva para la contraseña actual de una petición con sesión y para los logins desde las redes de `PA`, así que una avalancha de logins desde otro sitio no deja fuera al administrador. El mismo 503 vale para la contraseña actual (`b`) de los `set<CLAVE>` (§5) y de las acciones que la piden.

### 3.2. Cerrar Sesión (Logout)
Invalida el token actual en la memoria RAM (las demás sesiones de la misma IP siguen activas) y caduca la cookie de sesión (`Max-Age=0`). Con la cookie, la petición debe venir del propio origen del panel, como las acciones (§1.2); si no, `403` y la sesión sigue abierta.

* **Endpoint:** `POST /admin:signout:` (un `GET` no cierra la sesión: sirve la página de login)
* **Autenticación:** La cookie de sesión o la cabecera `ok`.
* **Respuesta Exitosa (HTTP 200 OK):** 
  Devuelve un string HTML forzando la redirección del navegador.
  ```html
  <meta http-equiv='refresh' content='0; URL=/admin:'/>
  ```

### 3.3. Cerrar Todas las Sesiones
Cierra todas las sesiones del panel, también la de la petición (y cualquier copia de su token), y abre una nueva para su cliente, como al cambiar las credenciales. Es **Close every session** del panel.

* **Endpoint:** `POST /admin:inside:closeSessions`
* **Parámetros:** `b`, la contraseña actual, tal como se envía. Si falta: HTTP 400 `"Missing data: the current password (b)"`; si es errónea: HTTP 400 `"Wrong current password"`, que cuenta como un login fallido (§3.1).
* **Respuesta Exitosa (HTTP 200 OK):** `"Every session closed: this one goes on with a new token"`, con la cookie nueva y el token nuevo en la cabecera `ok` de la respuesta.

---

## 4. API de Consulta y Obtención de Estado (Data Retrieval)

Endpoints destinados a volcar el estado en memoria de la configuración hacia el cliente. Requieren una sesión autenticada (cookie o cabecera `ok: <token>`, §1.2).

### 4.1. Obtener Estado Global del Servidor
Devuelve la configuración general, mapas de sitios raíz, IPs denegadas, respuestas HTTP personalizadas y caracteres de reemplazo.

* **Endpoint:** `POST /admin:inside:sites`
* **Parámetros:** Ninguno.
* **Respuesta (JSON):**
  ```json
  {
    "site1.com": {
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "0",
        "E": "admin%40site1.com",
        "A": ""
      }
    },
    "~": {
      "old-site.com": ["", "www"]
    },
    "_": {
      ";": { "f": "-.-" },
      "#": { "f": "-,-" },
      "&": { "f": "-_-" }
    },
    "@": {
      "192.168.1.50": "1735689600"
    },
    "#": {
      "0": { "f": "OKZGN Turbo\\n{TURBO_RESPONSE_CODE}" },
      "404": "Página no encontrada: {TURBO_RESPONSE_CODE}"
    },
    ".": {
      "M": "/home/server/",
      "PA": "",
      "RT": "5s",
      "RHT": "1s",
      "WT": "10s",
      "IT": "2s",
      "MUB": "1000",
      "MHB": "5000",
      "MBB": "1048576",
      "CIL": "10000",
      "CIS": "1000",
      "CII": "100",
      "CGL": "0",
      "CGP": "0",
      "PCC": false
    }
  }
  ```
  *(Nota: Las entradas fijas, que no se pueden borrar, se devuelven como `{"f": <valor>}`. Los valores de texto del bloque `!` van codificados para URL, p. ej. `@` → `%40`. `~` lista los sitios cuya carpeta no está, con sus subdominios en la misma situación (`""` es el propio sitio): Turbo conserva sus ajustes, también en `turbo.config`, para cuando vuelva la carpeta, hasta que `delSite` los olvida, sin borrar ninguna carpeta).*

### 4.2. Obtener Lista de Subdominios de un Sitio
Devuelve un objeto JSON con todos los subdominios que pertenecen a un dominio raíz específico, incluyendo el alias (si aplica) y la configuración SSL/Redirecciones de cada uno.

* **Endpoint:** `POST /admin:inside:subdomains`
* **Parámetros de Formulario:**
  * `s`: Dominio principal (ej: `example.com`).
* **Respuesta Exitosa (JSON):**
  La respuesta incluye siempre el subdominio raíz, bajo la clave vacía `""`, y los demás subdominios anidados. El bloque `!` contiene el estado de la configuración (1 = Activado, 0 = Desactivado). `C`, el certificado, también puede contener el texto del error de Certbot si falló el último intento.
  ```json
  {
    "": {
      "&": {},
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "1",
        "E": "contact%40example.com",
        "A": ""
      }
    },
    "api": {
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "0",
        "E": "api-admin%40example.com",
        "A": "dns-route53"
      }
    },
    "*.dev": {
      "!": {
        "S": "0",
        "C": "0",
        "R": "0",
        "W": "0",
        "E": "",
        "A": ""
      }
    }
  }
  ```
  *(Nota: En este ejemplo, `*.dev` representa un subdominio wildcard que abarca cualquier petición dinámica de segundo nivel bajo `dev`, como `test.dev` o `admin.test.dev`. Un subdominio sin comodín, como `dev`, sirve solo su propio host: `test.dev` necesita `*.dev`, o el `*` del sitio).*

### 4.3. Obtener Datos Detallados de un Subdominio
Devuelve todas las reglas operativas (Reescrituras, Cabeceras, MIMEs, Índices, Preprocesadores y Alias) para un subdominio específico.

* **Endpoint:** `POST /admin:inside:subdomainData`
* **Parámetros de Formulario:**
  * `s`: Dominio principal.
  * `d`: Subdominio (enviar valor vacío `""` si se solicita el subdominio raíz).
* **Estructura de Respuesta (JSON):**
  ```json
  {
    "=": { "/old-path": "/new-path" },
    "$": { "png": "image/png" },
    ".": { "Cache-Control": "max-age=3600" },
    "?": { "php": "/usr/bin/php-cgi" },
    "-": { "index.html": "1", "index.php": "2" },
    "&": { "alias.com": "" },
    "!": { "S": "1", "C": "1" }
  }
  ```
  *(Nota: Cada índice de `-` lleva su posición, el orden en que se prueban los índices).*

---

## 5. API de Configuración General (`set<CLAVE>`)

Modifica los parámetros globales del servidor y sus límites operativos. Cambian la configuración en uso, en memoria: solo `setC` escribe `turbo.config` (**Save configuration** en el panel), y lo que no se guarda se pierde cuando Turbo se detiene o recarga el archivo. `setM` además lee el `turbo.config` del directorio nuevo, si lo tiene.

* **Ruta Base:** `POST /admin:inside:set<CLAVE>`
* **Parámetros Requeridos:** `a` (valor) y `b` (contraseña actual) en **todos** los `set<CLAVE>`. Si falta `b`, el servidor responde HTTP 400 `"Missing data"`; si es incorrecta, HTTP 400 `"Wrong current password"`, y cuenta como un login fallido de la IP: tras 5 fallos (logins y `b` juntos), HTTP 429 con `Retry-After` (§3.1). Un valor igual al actual también se responde con HTTP 400 (por ejemplo, `"User unchanged"` o `"Password unchanged"`).

| Endpoint | Parámetro `a` | Parámetro `b` | Descripción / Validación |
|---|---|---|---|
| `setU` | Nuevo Usuario | Contraseña Actual | Cambia el nombre de usuario (1-24 bytes en UTF-8: `ñ` o `é` cuentan 2). Todas las sesiones terminan, y la respuesta trae una nueva (§1.2). |
| `setP` | Nueva Contraseña | Contraseña Actual | Cambia la contraseña: de 12 a 64 bytes en UTF-8 (`ñ` o `é` cuentan 2); si no, 400 `"The password must have 12 to 64 bytes"`. Una contraseña más corta que ya está en uso (`Admin`, `TURBO_PASSWORD`, `turbo.config`) sigue valiendo. Todas las sesiones terminan, y la respuesta trae una nueva (§1.2). |
| `setM` | Ruta Directorio | Contraseña Actual | Cambia el directorio base de sitios (debe existir) y recarga la configuración. La ruta puede ser relativa al directorio de trabajo o usar `{TURBO_CURRENT_DIR}`, y se guarda tal como se escribe; el mismo directorio escrito de otra forma es "Sites directory unchanged". Si ese directorio tiene un `turbo.config` que no es JSON válido, responde 400 con dónde está el error. |
| `setC` | (Ignorado; `overwrite` para confirmar, ver abajo) | Contraseña Actual | Vuelca la configuración RAM actual al disco (`turbo.config`), incluidos el usuario y el hash de la contraseña (nunca la contraseña en claro). |
| `setPA` | Hosts / redes CIDR | Contraseña Actual | Dónde responde el panel: nombres de host y/o redes CIDR separados por comas (como máximo 32 entradas y 1 024 chars); con los dos tipos, una petición necesita los dos. Vacío o `*` = sin restricción (`*` solo como único valor). Un host que sirve un sitio (directamente, por un wildcard o como alias) se rechaza con 400 `"The panel host <host> serves the site <site>: …"`, y también los comodines de host (`*.example.com`, que nunca coinciden) y un valor que dejaría fuera a la propia petición que lo fija (su host o su IP), con el motivo. Una IP sin `/` es un host, que se compara con la cabecera `Host` (una IPv6 como `[::1]` o `::1`); para limitar la IP del cliente, use `/32` o `/128`. |
| `setMUB` | Valor entero | Contraseña Actual | Ajusta la longitud máxima de URI (40 - 10 240 bytes). |
| `setMHB` | Valor entero | Contraseña Actual | Ajusta la longitud máx. de cabeceras (600 - 20 480 bytes). |
| `setMBB` | Valor entero | Contraseña Actual | Ajusta tamaño máx. de cuerpo (1B - 100MB). |
| `setCIL` | Valor ms | Contraseña Actual | Reinicio de contador (1 000 - 800 000 ms). |
| `setCIS` | Valor ms | Contraseña Actual | Ventana de conteo (10 - 50 000 ms), como mínimo `CII` y como máximo 66 veces `CII`. |
| `setCII` | Valor entero | Contraseña Actual | Límite de peticiones por intervalo: de 1 hasta el valor de `CIS` en ms, y `CIS`/`CII` ≤ 66. |
| `setCGL` | Valor entero | Contraseña Actual | Peticiones por segundo para todo el servidor, entre todos los clientes (10 - 1 000 000; `0` = sin límite, el valor por defecto). Las que lo superan reciben `503` con `Retry-After: 1`; no se bloquea ninguna IP. |
| `setCGP` | Valor entero | Contraseña Actual | Procesos CGI (preprocesadores) que pueden ejecutarse a la vez (1 - 100 000; `0` = automático, el valor por defecto: 4 por CPU, al menos 16). Una petición a un CGI que no encuentra hueco en 2 s recibe `503` con `Retry-After: 2`. La salida de un CGI espera a su cliente en memoria y en un archivo temporal, así que el CGI libera su plaza al terminar; como mucho una cuarta parte de las plazas (la mitad para un /48 IPv6) puede esperar a las respuestas de un mismo cliente (una dirección IPv4 o un /64 IPv6), y una respuesta que tuviera que esperar más allá se corta. |
| `setRT` | Tiempo (`5s`, `0s`) | Contraseña Actual | Read Timeout total de petición (100 ms - 15 min; `0s` lo desactiva). Como mínimo el doble de `RHT`, salvo que `RHT` sea `0s`. |
| `setRHT` | Tiempo (`1s`, `0s`) | Contraseña Actual | Read Header Timeout (50 ms - 7.5 min y, si `RT` no es `0s`, como máximo la mitad de `RT`; `0s` usa `RT`). |
| `setWT` | Tiempo (`10s`, `0s`) | Contraseña Actual | Write Timeout para respuestas (100 ms - 30 min; `0s` lo desactiva). |
| `setIT` | Tiempo (`2s`, `0s`) | Contraseña Actual | Idle Timeout para *Keep-Alive* (100 ms - 5 min; `0s` usa `RT`). |

*Notas:*
* *`setPA`: Las entradas de host se comparan con la cabecera `Host` de la petición, que elige el cliente: dan al panel un origen propio, aparte de los sitios, pero no limitan quién puede acceder. Lo que limita el acceso son las redes CIDR, que se comparan con la IP del cliente. Un `turbo.config` cuyo host de `PA` sirve un sitio se carga igual, con un aviso en el log.*
* *Límite por IP (`CIL`, `CIS`, `CII`): "IP" es una dirección IPv4, o el /64 de una dirección IPv6 (el bloque que suele tener un cliente), también en el límite de logins fallidos. Cada IP puede hacer `CII` peticiones por ventana de `CIS` de media, contadas desde su primera petición e incluida la actual: pasados `t` ms, `CII` × (⌊`t`/`CIS`⌋ + 1) peticiones en total, así que lo que no usó en una ventana lo puede usar en otra posterior, hasta que la cuenta vuelve a empezar. La que pasa de ahí recibe 429 y bloquea la IP 5 s. La cuenta vuelve a empezar `CIL` ms después de comenzar. Los tiempos se miden con el reloj monotónico, así que cambiar la hora del sistema no bloquea a nadie. Turbo guarda hasta 200 000 IPs; por encima, las IPs nuevas comparten una sola cuenta (como un solo cliente) hasta que se olvidan las antiguas, y las IPs ya conocidas no se ven afectadas. `CGL` cuenta segundos fijos, así que una ráfaga entre dos de ellos puede llegar al doble de `CGL`; repartir el servidor entre los clientes es lo que hacen `CII`/`CIS`.*
* *`CIS`/`CII` y `RT`/`RHT`: sus condiciones se comprueban se cambie cuál se cambie (un cambio que las incumpliría recibe 400), y se comparan de forma exacta (66,5 es más que 66). En `turbo.config` se comprueban cuando ya se han leído todos los ajustes: si no se cumplen, `CII` (o `RHT`) toma su valor por defecto, con un aviso en el log; si el valor por defecto tampoco encaja, también `CIS` (o `RHT` pasa a `0s`, que usa `RT`).*
* *`setM`: los errores van en este orden: falta `b`, contraseña actual incorrecta (antes no se lee nada del nuevo directorio), un directorio que no existe (400 `"Sites directory not found"`), uno que no se puede listar (400 `"Sites directory can't be read"`), el mismo directorio escrito de otra forma (400 `"Sites directory unchanged"`) y un `turbo.config` allí que no se puede usar, o cuyo `M` lleva a un directorio que no existe o no se puede listar, a un `turbo.config` que no se puede usar, o de vuelta a un directorio del camino (400 con dónde está el error): todo ello se comprueba antes de cambiar nada. El `turbo.config` del nuevo directorio se lee siempre, también con la misma fecha que el que está en uso. Si no tiene, se conservan los ajustes globales, las credenciales y las listas en uso (`@`, `_`, `#`), que se escriben allí con el siguiente `setC`; la respuesta lo dice. Si tiene, se aplica entero, y la respuesta dice qué cambió de `PA` y de las credenciales. Al volver al directorio de arranque no se sigue el puntero que dejó `setC`.*
* *Recarga de `turbo.config`: cuando el archivo cambia (se comprueba cada 30 s), se aplica entero y sustituye lo que vino de él: lo que el archivo ya no tiene deja de aplicarse, y los cambios hechos con `set<CLAVE>`, `add<TIPO>` o `del<TIPO>` y no guardados con `setC` se pierden. Los reemplazos de caracteres y las respuestas fijos se mantienen siempre.*
* *`PA`, `U`, `PH` y `P` en `turbo.config`: si uno de ellos no se puede usar (otro tipo, un `PA` que `setPA` rechazaría, un usuario fuera de 1-24 bytes o una contraseña fuera de 1-64, un hash que no es de Turbo), el archivo es inválido: Turbo no arranca, y una recarga o un `setM` a ese directorio conservan la configuración en uso. También lo es un sitio, o una lista de un sitio (`!`, `=`, `$`, `.`, `?`, `-`, `&`), que no es un objeto JSON, y un `turbo.config` completo cuyo `M` nombra un directorio que no existe o no se puede listar: si se saltara, el sitio se serviría sin sus ajustes, sus scripts como texto.*
* *`setC`: Si `turbo.config` lo escribió una versión posterior de Turbo (un esquema posterior), guardar perdería sus ajustes nuevos, así que el servidor responde HTTP 400 con una explicación; para confirmar y sobrescribirlo, envíe `a=overwrite`. La primera vez que se guarda un archivo de un esquema anterior, el original se conserva como `turbo.config.v<esquema>.bak`, igual que un archivo de un esquema posterior sobrescrito con `a=overwrite`. Un `turbo.config` cambiado fuera de Turbo desde que Turbo lo leyó o lo guardó (una edición aún no recargada, o una que la recarga rechazó) se copia antes a `turbo.config.<fecha>.bak`. Si el directorio de sitios no es el directorio de arranque, en este se escribe además un `turbo.config` mínimo que apunta a aquel.*

---

## 6. API de Gestión de Recursos del Sitio (Añadir y Eliminar)

El backend maneja las creaciones de carpetas en disco y modificaciones en los mapas RAM. *Nota sobre comodines: Enviar los dominios con asteriscos (ej. `*.example.com`). El servidor los traducirá a `#` físicamente en el disco de manera transparente.*

### 6.1. Añadir/Actualizar Recursos (`add<Tipo>`)
* **Ruta Base:** `POST /admin:inside:add<TIPO>`

| Endpoint | `s` (Dominio) | `d` (Subdominio) | `a` (Clave/Identificador) | `b` (Valor/Ruta) |
|---|---|---|---|---|
| `addSite` | Dominio Web | - | - | - |
| `addSubdomain` | Dominio Web | Subdominio | - | - |
| `addRewrite` | Dominio Web | Subdominio | URI de origen (ej: `/old`) | Reescritura (`/new`, `http://...`, `https://...`), [palabras clave dinámicas disponibles](https://turbo-server.github.io/#so-2)|
| `addMIME` | Dominio Web | Subdominio | Extensión (ej: `png`) | Tipo MIME (ej: `image/png`), de 4 a 128 caracteres |
| `addHeader` | Dominio Web | Subdominio | Nombre Cabecera (de 1 a 48 bytes: letras, dígitos, `-` y `.`) | Valor Cabecera (de 1 a 512 bytes) |
| `addPreprocessor`| Dominio Web | Subdominio | Extensión (ej: `php`) | Ejecutable CGI (ej: `/usr/bin/php-cgi`). También pide la contraseña actual, en `c` |
| `addIndex` | Dominio Web | Subdominio | Archivo Índice (`index.html`)| - |
| `addAlias` | Dominio Web | Subdominio | Dominio Alias | - |

*Notas:*
* *`addHeader`: una cabecera que solo se diferencia en mayúsculas de una del sitio la sustituye ("Header changed"): saldrían las dos, cualquiera primero.*
* *`addSite` y `addSubdomain`: los nombres que Turbo usa para sus propias carpetas y archivos en el directorio de sitios (`turbo.dev`, `turbo.panel`, `turbo.certificates`, `turbo.config`, `turbo.visits`, `turbo.denials`) no pueden ser sitios, ni un nombre cuyos ajustes compartirían clave con otro sitio, ni el host de un alias (400 con el motivo), ni un sitio o subdominio que Turbo conserva sin su carpeta (`~` de `sites`), hasta que `delSite` lo olvide (400 "… is kept without its folder…").*
* *`addRewrite`: La reescritura debe empezar por `/` (ruta interna), `http://` o `https://`. Los destinos con `http://` o `https://` se responden con una redirección `302`: al destino exacto si tiene ruta o consulta, o al dominio de destino seguido del URI original si es solo un dominio. El origen (`a`) se compara con la ruta pedida ya decodificada (`/a b` coincide con `/a%20b`); un origen que acaba en `/` toma también la carpeta nombrada sin ella (`/privado/` toma `/privado`, que serviría su índice), y en Windows y macOS, cuyos sistemas de archivos no distinguen mayúsculas, una ruta en otras mayúsculas (`/PRIVADO/`), y un destino interno también es una ruta URL: se decodifica y tiene que quedar dentro del sitio (un destino con un segmento `..`, aunque quede dentro, o con `\`, una `/` o `\` codificada, `%00`, caracteres de control, UTF-8 inválido o un segmento que acaba en `.` o en espacio, se responde con 404).*
* *`addPreprocessor`: La ruta del ejecutable (como máximo 128 caracteres tal como se escribe, sin el prefijo `cgi>`; puede usar `{TURBO_CURRENT_DIR}`, que se guarda tal cual y se sustituye al ejecutarlo) debe existir; el prefijo `cgi>` es opcional y cualquier otro prefijo se rechaza. En `turbo.config`, una entrada que no se puede usar (no es una cadena, extensión incorrecta, ruta demasiado larga o vacía, otro prefijo, ejecutable inexistente) se conserva con un aviso en el log, y su extensión responde 500: los archivos nunca se sirven como texto. El CGI recibe la ruta URL del script (tras la reescritura) en `SCRIPT_NAME`, un `PATH_INFO` vacío, la URI original en `REQUEST_URI`, el archivo en disco en `SCRIPT_FILENAME` y la `@` del sitio en `DOCUMENT_ROOT`. `QUERY_STRING` lleva primero la consulta del cliente y después la de la reescritura, así que una aplicación que lee el último valor de un parámetro repetido (PHP lo hace) obtiene el de la reescritura. Una cabecera que fija el sitio (`addHeader`) gana a la del CGI con el mismo nombre. Las cabeceras sobre la conexión que escriba un CGI (`Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`…) se descartan, y también un `Content-Length` escrito dos veces y una cabecera cuyo valor tiene caracteres de control (salvo el tabulador): Turbo decide cómo se delimita la respuesta.*
* *`addRewrite`: el destino empieza por `/`, `http://` o `https://` (el esquema en mayúsculas o minúsculas; se guarda en minúsculas), y un destino `http(s)://` necesita host, escrito o dado por una palabra clave (si al responder la palabra no da nada, 500). Las palabras clave desconocidas (`{X}`) se rechazan. Las palabras se sustituyen por valores de la ruta decodificada de la petición (`{FIRST_REQUEST}`, `{DIR}`, `{FILE}`, `{EXT}`, `{REWRITE}`, `{REWRITE_COMPLEMENT}`) o de su consulta (`{FIRST_QUERY}`), codificados según dónde van: en la ruta, cada segmento, sin tocar `/`; en la consulta, como un valor; en el host, sin poder cambiar la URL. `{REWRITE_COMPLEMENT}` en la ruta toma el resto de la ruta, y la consulta de la petición se añade a la del destino: `/blog/` → `/new/{REWRITE_COMPLEMENT}` convierte `/blog/a/b?x=1` en `/new/a/b?x=1`.*
* *`addIndex`: El índice se añade al final del orden; los índices se prueban en el orden en que se añadieron. Los sitios y subdominios nuevos empiezan con `index.html`. El nombre sigue las reglas de la subida de archivos en todos los sistemas (§9): un solo segmento, sin `\`, `/`, `..`, `:`, un `.` o un espacio al final, un nombre de dispositivo de Windows, `~` seguido de un dígito ni los caracteres que Windows no admite (`<`, `>`, `"`, `|`, `?`, `*` y los de control); si no, HTTP 400 `"Invalid index file"`, y en `turbo.config` el índice se descarta con un aviso.*

### 6.2. Eliminar Recursos (`del<Tipo>`)
* **Ruta Base:** `POST /admin:inside:del<TIPO>`

| Endpoint | `s` (Dominio) | `d` (Subdominio) | `a` (Clave/Identificador a borrar) |
|---|---|---|---|
| `delSite` | Dominio Web | Subdominio (Vacío = Borrar Sitio) | - (la contraseña actual va en `b`) |
| `delRewrite` | Dominio Web | Subdominio | URI origen |
| `delMIME` | Dominio Web | Subdominio | Extensión |
| `delHeader` | Dominio Web | Subdominio | Nombre de Cabecera |
| `delPreprocessor`| Dominio Web | Subdominio | Extensión (la contraseña actual va en `b`: sin el preprocesador, los archivos de la extensión se servirían como texto, con su código fuente) |
| `delIndex` | Dominio Web | Subdominio | Archivo Índice |
| `delAlias` | Dominio Web | Subdominio | Dominio Alias |

*Los tres parámetros son obligatorios (salvo `a` en `delSite`): si falta alguno, la respuesta es `400` "Missing data".*

*`delSite` de un sitio o subdominio que se conserva sin su carpeta (listado en `~`) olvida los ajustes que Turbo guarda de él (y que `turbo.config` conserva), y no borra ninguna carpeta: la suya puede estar, y faltar solo su `@` o la de su sitio. Para un sitio, no los de sus subdominios, que se listan, y se olvidan, cada uno por su cuenta. Una carpeta con su nombre, después, es un sitio nuevo. Si no existe ni se conserva, la respuesta es `400` "Site not found" (o "Subdomain not found").*

---

## 7. API de Seguridad Global e Interfaz

### 7.1. Control de IPs Denegadas
Una IP denegada queda bloqueada hasta la fecha indicada: sus peticiones se responden con HTTP 429 y la cabecera `Retry-After` (segundos restantes), y sus conexiones nuevas se cierran.

* **`POST /admin:inside:addDenied`**
  * `s`: Dirección IP (IPv4 o IPv6). Una dirección IPv6 deniega su /64 entero, el cliente que cuentan los límites de peticiones (sus direcciones cambian solas). No se aceptan direcciones de loopback (`127.x.x.x`, `::1`) ni la dirección desde la que se hace la petición, o en IPv6 una de su /64 (`400` "Current IP": el panel se bloquearía a sí mismo).
  * `d`: Timestamp UNIX de expiración de bloqueo (`0` o una fecha pasada elimina un bloqueo existente).
* **`POST /admin:inside:delDenied`**
  * `s`: Dirección IP a desbloquear de la lista de IPs denegadas.

### 7.2. Respuestas a Códigos HTTP
Una plantilla es la página de error de todos los sitios, así que las dos acciones piden la contraseña actual en `b` (tal como se envía; si falta, es errónea o la IP está bloqueada, como en `set<CLAVE>`, §5), y todos los parámetros van tal como se envían (§2.1). Una página de error nunca ejecuta scripts: lleva una `Content-Security-Policy` sin ellos en cualquier host (§1.2).

* **`POST /admin:inside:addHttpCodeResponse`**
  * `s`: Código de estado HTTP (entre `400` y `599`, o `0` para fallback universal).
  * `d`: Plantilla de respuesta, de 1 a 2 048 caracteres. Se admiten saltos de línea y la macro `{TURBO_RESPONSE_CODE}`.
  * `b`: La contraseña actual.
* **`POST /admin:inside:delHttpCodeResponse`**
  * `s`: Código de estado HTTP a devolver a comportamiento por defecto del sistema.
  * `b`: La contraseña actual.

### 7.3. Reemplazo Global de Caracteres en URIs
Un reemplazo cambia lo que leen las acciones a las que basta la sesión (§2.1), así que las dos acciones piden la contraseña actual en `b` (tal como se envía; si falta, es errónea o la IP está bloqueada, como en `set<CLAVE>`, §5), y todos los parámetros van tal como se envían.

* **`POST /admin:inside:addCharsReplace`**
  * `s`: Secuencia de caracteres a reemplazar (ej: `;`), de 1 a 4 bytes, sin letras ni dígitos (`"Letters and digits are never replaced"`: con ellos, un token podría convertir un nombre en otro).
  * `d`: Cifra codificada objetivo (ej: `-.-`): de 2 a 16 caracteres, sin ningún carácter reemplazado (tampoco el suyo), sin contener otro token ni estar dentro de uno; y `s` no puede estar dentro de otro token. Si no, HTTP 400. Las sustituciones fijas de §2.1 no se pueden cambiar (`"Fixed replacement"`). En `turbo.config`, un reemplazo que incumple estas reglas se descarta con un aviso.
  * `b`: La contraseña actual.
* **`POST /admin:inside:delCharsReplace`**
  * `s`: Secuencia de caracteres que deja de reemplazarse (las sustituciones fijas de §2.1 no se pueden borrar).
  * `b`: La contraseña actual.

---

## 8. API de Certificados SSL y Redirecciones (`cfg<CLAVE>`)

Gestiona la habilitación de HTTPS, redirecciones en la capa de aplicación y la configuración/emisión de certificados mediante Certbot.

* **Ruta Base:** `POST /admin:inside:cfg<CLAVE>`

| Endpoint | Parámetro `a` (Acción) | Parámetro `s` (Dominio) | Parámetro `d` (Subdominio) | Parámetros Opcionales |
|---|---|---|---|---|
| **`cfgC`** | `"1"` = Ejecutar Certbot<br>`"0"` = Eliminar del disco (pide la contraseña actual en `b`) | Dominio Web | Subdominio o Vacío (`""`) | `z`: E-mail de registro.<br>`y`: Adaptador Certbot (`dns-<proveedor>`, ej: `dns-route53`). |
| **`cfgS`** | `"1"` = Activar HTTPS<br>`"0"` = Desactivar HTTPS | Dominio Web | Subdominio o Vacío (`""`) | - |
| **`cfgR`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Solo vacío (`""`): se configura en la raíz del sitio | Redirige `www.<sitio>` a `<sitio>` (301). Con un subdominio, HTTP 400. |
| **`cfgW`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Solo vacío (`""`): se configura en la raíz del sitio | Redirige `<sitio>` a `www.<sitio>` (301). Con un subdominio, HTTP 400. |
| **`cfgE`** | E-mail a registrar | Dominio Web | Subdominio o Vacío (`""`) | Modifica silenciosamente el E-mail para futuras renovaciones de Certbot. El valor se guarda tal como llega (un `+` enviado como `%2B` queda `+`). |
| **`cfgA`** | Nombre del Adaptador (`dns-<proveedor>`, o vacío para webroot) | Dominio Web | Subdominio o Vacío (`""`) | Modifica silenciosamente el flag del Adaptador para Certbot. |

### 8.1. Detalle Operativo: Emisión de Certificados (`cfgC`)
Certbot solo se ejecuta cuando se pide con `a="1"`, y requiere un e-mail (guardado con `cfgE` o enviado en `z`); sin él, la API responde HTTP 400 `"E-mail required to create the certificate"`. Si el sitio ya tiene un certificado de menos de 75 días, la API responde `"SSL certificate active"` sin ejecutar Certbot. Con `a="0"`, los archivos del certificado se borran tengan la antigüedad que tengan y la API responde `"SSL certificate deleted"`; sin certificado en disco, no se borra nada y la API responde HTTP 400 `"No certificate"`. El e-mail de `cfgE` y el de `z` se comprueban igual: de 5 a 40 bytes, una `@` con algo delante y un dominio con un punto detrás, y sin espacios, `#`, `--` ni un `-` al principio (HTTP 400 `"Invalid e-mail value"` o `"Invalid e-mail length"`).

La emisión o renovación de certificados no bloquea el servidor. Al enviar `a="1"`, la API delega el trabajo a una Goroutine separada que se encarga de:
1. Ejecutar el binario de Certbot en modo webroot o mediante el adaptador especificado, con su carpeta de trabajo en `turbo.certificates/<sitio>`.
2. Leer la carpeta temporal `archive`, localizar los archivos más recientes (`fullchain*.pem` y `privkey*.pem`) que tengan menos de 2,5 días (216 000 segundos) de creados.
3. Mover y renombrar físicamente estos archivos a la ruta raíz del sitio en Turbo.

**Renovación Automática:** Al arrancar y cada 24 horas, Turbo renueva los certificados que emitió él (sitios con e-mail y carpeta en `turbo.certificates`) cuando caducan en menos de 30 días, y los carga sin reiniciar. Los certificados puestos a mano no se renuevan.

**Flujo de Polling HTTP para el Frontend:**
Como la operación es asíncrona, el frontend debe realizar peticiones continuas (Polling) al endpoint `cfgC` evaluando la respuesta JSON. Mientras la emisión está en curso, la API responde **HTTP 202** con uno de estos cuerpos:
* `{"message":"Please wait, certificate in process","status":"WAIT"}`: La Goroutine acaba de iniciarse.
* `{"message":"Please wait, certificate being processed","status":"WAIT"}`: Certbot está trabajando.
* `{"message":"Please wait, certificate busy on <domain>","status":"WAIT"}`: Certbot está ocupado emitiendo un certificado para otro sitio. Turbo lo reintenta solo cada 30 segundos hasta que Certbot queda libre: el cliente solo tiene que seguir con el polling.
* **Respuesta Exitosa (200 OK):** `"SSL certificate active"` (El cliente debe detener el polling).
* **Respuesta de Error (400 Bad Request):** Devuelve la salida cruda de error de Certbot o del sistema de archivos.

La interfaz lo hace sola: tras un 202 vuelve a preguntar cada 5 segundos, como máximo durante 4 minutos, y muestra el resultado. Cancelar cualquier paso de su diálogo (e-mail, adaptador, confirmación) no envía nada, y vaciar un adaptador que estaba guardado pregunta si se vuelve a webroot (`cfgA` con el valor vacío).

### 8.2. El Certificado Propio del Panel (`cfgPC`)
`POST /admin:inside:cfgPC` emite o borra el certificado de los hosts propios del panel: los nombres de host de `PA` (las direcciones IP quedan fuera). No lleva `s` ni `d`.

* `a="1"`: ejecuta Certbot como `cfgC`, con un `-d` por cada host de `PA`, en modo webroot (`turbo.panel/webroot` dentro del directorio de sitios; Turbo responde a sus retos, `/.well-known/acme-challenge/<token>`, solo en los hosts de `PA`) o con el adaptador; Certbot trabaja en `turbo.certificates/turbo.panel`, y los archivos acaban en `turbo.panel/`. Las respuestas son las de `cfgC` (202 `WAIT` mientras corre, una emisión a la vez entre sitios y panel; 200 `"Panel certificate active"` cuando está en uso un certificado que cubre todos los hosts de `PA` y caduca en más de 30 días; 400 con el error del último intento, una vez). Sin e-mail: 400 `"E-mail required to create the certificate"`; sin un nombre de host en `PA`: 400.
* `a="0"`: borra `turbo.panel/fullchain.pem` y `privkey.pem` y deja de usar el certificado. Pide la contraseña actual en `b`, como `cfgC` con `a="0"`, y por HTTPS su respuesta envía `Strict-Transport-Security: max-age=0`, para que los navegadores puedan volver al panel por HTTP; sin los archivos, 400 `"No panel certificate"`.
* `z`: el e-mail, que se guarda como `PCE` en `.` de `turbo.config`. `y`: el adaptador DNS (`dns-<proveedor>`), que se guarda como `PCA`; un `y` vacío vuelve a webroot, y sin `y` se mantiene el guardado.

La renovación automática también renueva el certificado del panel cuando caduca en menos de 30 días, y `/admin:inside:sites` da su estado en `.` como `PCC` (con `PCE` y `PCA` si están fijados): `true` (en uso), `"WAIT"` (Certbot en marcha) o `false`. Un certificado colocado a mano en `turbo.panel/` también se usa, pero no se renueva.

### 8.3. Detalle Operativo: Activación SSL en Caliente (`cfgS`)
Turbo no requiere reinicios para aplicar certificados. Cuando se recibe la orden de activación (`a="1"`):
1. Go lee los archivos `fullchain.pem` y `privkey.pem` directamente del disco y los inyecta inmediatamente en la memoria RAM compartida del servidor.
2. Si el puerto `443` (o la dirección de `TURBO_HTTPS_ADDR`) estaba cerrado (porque el servidor arrancó sin certificados), **se inicia un nuevo socket Listener automáticamente**.
3. A partir de este momento, Turbo fuerza una redirección `301 Moved Permanently` a `https://`, en el mismo host, para el tráfico HTTP que ingrese a ese dominio/subdominio cuando un certificado cubre el host pedido. Un alias sin un certificado que cubra su nombre se sigue sirviendo por HTTP.

En el handshake TLS, cada nombre recibe el certificado que lo cubre (exactamente o con un wildcard). Los nombres que ningún certificado cubre y las conexiones sin SNI (acceso por IP) se rechazan.

*Nota: Desactivar HTTPS (`a="0"`) purga el certificado de la memoria RAM (impidiendo futuras conexiones TLS para ese host), pero **no elimina** los archivos `.pem` del disco ni cierra el puerto 443 a nivel de red.*

---

## 9. API de Gestión Física de Archivos (`hardUpload`)

Utilizado para sustituir masivamente todos los archivos públicos asociados a un subdominio/dominio. El servidor escribe los archivos nuevos en una carpeta propia junto a `@` (`@.upload-<aleatorio>`) y después la pone en lugar de `@` de una vez (la `@` anterior es `@.previous-<aleatorio>` un instante, y después se borra), así que el contenido existente (subcarpetas incluidas) se sustituye entero: hasta entonces, `@` queda como estaba, y si algo falla, no cambia nada.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Formato del Cuerpo:** `multipart/form-data`
* **Parámetros de Formulario:**
  * `s`: Dominio principal (ej: `example.com`).
  * `d`: Subdominio (vacío `""` si se trata del dominio raíz).
  * `f`: Array de archivos adjuntos (`File[]`).
  * `b`: la contraseña actual, solo en el cuerpo multipart (nunca en la URL, que `turbo.visits` registra).

  `s` y `d` se aceptan tanto en la URL como en el cuerpo *multipart*.
* **Manejo de Directorios Anidados:** 
  El backend analiza el parámetro `filename` dentro del encabezado HTTP `Content-Disposition` de cada bloque *multipart*. Se descarta el primer segmento de cada ruta (la carpeta elegida en el navegador), y `\` cuenta como separador. Si el resto del nombre contiene rutas relativas (ej: `sitio/assets/img/logo.png` → `assets/img/logo.png`), Turbo creará la estructura de carpetas. Un archivo y una carpeta no pueden tener el mismo nombre: de `a` y `a/b`, se descarta el segundo (sin distinguir mayúsculas en Windows y macOS). También los nombres que los sistemas de archivos no admiten: un nombre de archivo o carpeta de más de 255 bytes, o una ruta dentro de `@` de más de 1.024 bytes. Los nombres que saldrían de `@` (con `..`, absolutos o con `:`) se descartan, y también, en todos los sistemas, los que Windows trata de forma especial: acabados en `.` o en espacio, un nombre de dispositivo reservado (`CON`, `NUL`, `COM1`…), `~` seguido de un dígito (nombres cortos 8.3) o un carácter que Windows no admite (`<`, `>`, `"`, `|`, `?`, `*` y los de control).
* **Respuesta Exitosa (HTTP 200 OK):**
  Devuelve la cadena `"Data uploaded"`. Si se descartó algún archivo, la respuesta los enumera: `"Data uploaded. Discarded: <nombre>, <nombre>"`.
* **Manejo de Errores Específicos:**
  * Si el peso de la subida supera el límite global `MBB` (Max Body Bytes), o lleva más de 10 000 partes (los archivos y el campo `b`), la API corta la lectura y retorna HTTP 413 con el mensaje `"Maximum body size exceeded"`. Un cuerpo *multipart* mal formado recibe HTTP 400 `"Invalid parameters"`. (Los demás formularios multipart admiten como mucho 1 000 partes.) `MBB` acota la memoria que ocupa la subida, que se guarda en memoria: el contenido más unos 600 bytes por archivo (su nombre, cabeceras y entrada), así que un archivo de exactamente `MBB` bytes nunca cabe, y un sitio de muchos archivos pequeños necesita sitio para ellos. Como cada subida sustituye `@` entera, la salida de un 413 es un `MBB` mayor, no subir menos archivos; el panel lo dice.
  * Si se descartan todos los nombres, HTTP 400 `"No valid file; nothing was changed. Discarded: …"`, y `@` queda como estaba.
  * Si no se puede sustituir `@` (en Windows, por ejemplo, mientras un archivo suyo está abierto), HTTP 400 `"The public directory could not be replaced (open files?); nothing was changed"`; un archivo que no se puede escribir da HTTP 500. En los dos casos `@` queda como estaba.
  * Si el sitio se borra durante la subida, HTTP 400 `"Site not found"`, y el sitio no vuelve a aparecer.
  * Si no llega ningún archivo en `f`, HTTP 400 `"No data"`.

---

## 10. Estándar de Códigos de Respuesta HTTP de la API

| Código HTTP | Significado Funcional | Causa y Cuerpo de la Petición |
|---|---|---|
| **`200 OK`** | Operación Procesada | La orden se ejecutó en memoria y/o disco. Devuelve un texto plano de confirmación (ej: `"Subdomain added"`). |
| **`202 Accepted`** | En Proceso | Solo `cfgC` y `cfgPC` mientras se emite un certificado: un cuerpo JSON con `"status":"WAIT"` (§8.1). Siga consultando. |
| **`400 Bad Request`** | Fallo de Validación / Lógica | Parámetros nulos, formato inválido, recurso inexistente, contraseñas erróneas o restricciones de límites sobrepasadas. El Body contiene el string del error literal que debe mostrarse al usuario. |
| **`403 Forbidden`** | Bloqueo de Acceso | Login con credenciales incorrectas (Body vacío), o un `POST` autenticado con la cookie de sesión que no viene del mismo origen (§1.2). |
| **`404 Not Found`** | URL Incorrecta | Se ha consultado una URI (`RequestURI`) dentro del prefijo `/admin:` que no corresponde a ningún endpoint listado, o el panel no responde en ese host o red (`PA`). |
| **`413 Payload Too Large`** | Parámetros demasiado grandes | Los parámetros de una acción (o el cuerpo del login, §3.1) superan lo permitido: `MBB`, y como mucho 10 MiB en un cuerpo `application/x-www-form-urlencoded`. Una subida de archivos (§9) demasiado grande también recibe `413`. Los parámetros que no se pueden decodificar (por ejemplo, un escape `%` mal formado) reciben `400` `"Invalid parameters"`. |
| **`429 Too Many Requests`** | *Rate Limiter* Activado | La IP del cliente superó sus límites (CIL/CIS/CII), la IP está denegada (§7.1), o sus logins están bloqueados tras intentos fallidos, entre ellos las contraseñas actuales erróneas de `set<CLAVE>` y de las acciones que la piden (§3.1). Cada petición cuenta una vez. La respuesta lleva `Retry-After` con los segundos de espera, y las conexiones nuevas de una IP bloqueada se cierran. |
| **`503 Service Unavailable`** | Límite global alcanzado | El servidor en conjunto recibió más de `CGL` peticiones en el segundo actual (`Retry-After: 1`), la contraseña de un login o la contraseña actual de un `set<CLAVE>` o de una acción que la pide no se pudo comprobar en 2 segundos (`Retry-After: 2`, §3.1), o un CGI no encontró hueco en 2 segundos (`CGP`, `Retry-After: 2`). |
| **`500 Internal Server Error`** | Fallo Interno | Un error inesperado al procesar la acción. |

---

## Licencia

Turbo usa un modelo de doble licencia.

* **Código abierto (AGPL v3):**

    Este programa es software libre: puede redistribuirlo y/o modificarlo bajo los términos de la GNU Affero General Public License (AGPL v3) publicada por la Free Software Foundation. Si modifica este software y lo ofrece como servicio a través de una red, debe publicar sus modificaciones bajo la misma licencia. Véase: https://www.gnu.org/licenses/agpl-3.0.html

* **Licencia comercial:**

    Para quien quiera usar Turbo en un proyecto propietario, integrarlo en un producto de código cerrado o no acogerse a los requisitos de la AGPL v3, hay una licencia comercial de pago.

    Para consultas sobre la licencia comercial, visite uno de estos sitios:
    - https://okzgn.com/#contact
    - https://okzgn.github.io/#contact

* **Componentes de terceros:**

    El paquete `customNetHttp` contiene una versión modificada del `net/http` de la biblioteca estándar de Go (basada en Go 1.26.x; la versión exacta está en `customNetHttp/UPSTREAM` y los cambios en `customNetHttp/PATCHES.md`), distribuida bajo la **licencia BSD de 3 cláusulas**. Los archivos `customNetHttp/LICENCE`, `customNetHttp/PATENTS` y `customNetHttp/NOTICE` de esa carpeta tienen el texto completo y la atribución.

---

Copyright (C) 2026 [OKZGN](https://okzgn.com)
