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
* **Manejo de Sesión:** Tras un login correcto, el servidor fija la cookie de sesión (`Path=/; HttpOnly; SameSite=Strict`), que el navegador envía por sí solo: `turbo_session` por HTTP, y `__Host-turbo_session` por HTTPS (con `Secure` y sin `Domain`, así que los navegadores solo la aceptan del host del panel y otro subdominio no puede poner una en su lugar). La cookie de HTTP, que no lleva `Secure`, no es una sesión en una petición por HTTPS: una sesión abierta por HTTP vuelve a iniciar sesión cuando se llega al panel por HTTPS. Los clientes de la API pueden enviar en su lugar el token en la cabecera `ok: <token>`, que es una sesión por cualquiera de los dos. Se prueban todas las cookies de sesión de la petición (puede llegar antes una con el mismo nombre fijada por otro subdominio) y después la cabecera `ok`. El token **no** se acepta como parámetro en la URL. Las dos cookies se quitan de la cabecera `Cookie` que se pasa a los preprocesadores (un CGI, un worker del modo dx), y también la cabecera `ok`.
* **Mismo Origen:** Un `POST` a `/admin:inside:` autenticado con la cookie debe venir del propio origen del panel: el navegador debe enviar `Sec-Fetch-Site: same-origin` (o `none`) o, sin `Sec-Fetch-Site`, una cabecera `Origin` igual a `<esquema>://<Host>`. Si no, el servidor responde `403`. Las peticiones autenticadas con la cabecera `ok` no lo necesitan.
* **Cabeceras de las Respuestas del Panel:** Las respuestas bajo `/admin:` llevan `X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` y una `Content-Security-Policy`: en las páginas del panel incrustadas en el binario, una que solo les deja ejecutar su propio script y su propio estilo (por sus hashes) y cargar los archivos del propio panel; en una página propia de `turbo.dev/`, `frame-ancestors 'none'`; y en todo lo demás (respuestas de la API, errores con la plantilla de error) una sin scripts, marcos, formularios ni complementos (`default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`). Todo error que Turbo responde con la plantilla de error lleva también esa, en cualquier host, antes o después de leer la petición, así que una plantilla de error nunca ejecuta scripts: con `PA` vacío (lo predeterminado), los sitios comparten el origen del panel. En un host de `PA`, también la lleva toda respuesta fuera de las páginas del panel. Las respuestas JSON (`sites`, `subdomains`, `subdomainData`, el `WAIT` de `cfgC` y `cfgPC`) son `application/json; charset=utf-8`, y los mensajes de texto `text/plain; charset=utf-8`.
* **Sesión Ausente:** una petición a `/admin:inside:` sin una sesión válida recibe la misma redirección HTML de siempre (§3.2) y la cabecera `X-Turbo-Login: required`, que es lo que deben mirar los clientes: el contenido de una respuesta válida (una plantilla de error, una cabecera o una reescritura de un sitio) puede contener cualquier texto. Una acción se comprueba otra vez contra su sesión cuando ha llegado su cuerpo (o, en `hardUpload`, sus archivos): una cuya sesión se cerró entretanto (`closeSessions`, credenciales nuevas, su caducidad) no aplica nada y recibe la misma respuesta.
* **Dónde Responde el Panel:** El ajuste global `PA` (ver `setPA`, §5) puede limitar `/admin:` a una lista de hosts y/o redes CIDR: el `Host` de la petición tiene que ser uno de los hosts (si los hay) y la IP del cliente tiene que estar en una de las redes (si las hay). Si no, `/admin:` responde `404`. Vacío (por defecto) significa sin restricción, y entonces el panel comparte el origen de todos los sitios que sirve Turbo: la configuración recomendada es un host propio para el panel, que no sirva ningún sitio. Con redes y sin host, el panel solo responde cuando el `Host` es una dirección IP o `localhost`, nunca un nombre: una página cuyo nombre resuelve a Turbo (DNS rebinding) llegaría si no al panel desde el navegador de alguien de esas redes, en su propio origen. En ese modo los hosts del panel son las direcciones IP y `localhost`, y un sitio `*` (que sirve todas las direcciones IP), un sitio `localhost` o un alias `localhost` compartirían su origen: uno nuevo se rechaza (`400` con el motivo), y uno que tenga `turbo.config`, o que traiga una carpeta, se conserva, con un aviso en el log al leer `turbo.config`, al aparecer la carpeta de un sitio y al cambiar `PA`. Se rechaza un host de `PA` que sirva un sitio (§5), y también un sitio, subdominio o alias nuevo que serviría un host de `PA` (`400` con el motivo).
* **Ciclo de Vida de la Sesión:** Los tokens son asignados a la IP del cliente y expiran tras **600 segundos (10 minutos)** de inactividad, y como mucho **12 horas** después del login, se usen como se usen. Cada petición a `/admin:inside:` del propio origen del panel (o sin `Sec-Fetch-Site`, como las envían los clientes de la API) renueva el temporizador, hasta ese límite; una de otro origen, como un recurso que carga otra página, no. Una subida (`hardUpload`, §9) también lo renueva mientras llegan sus archivos: una que tarda más de esos diez minutos no se descarta al terminar. Cambiar el usuario o la contraseña (`setU`, `setP`) cierra todas las sesiones, también la de la petición, y abre una nueva para su cliente: la respuesta fija la cookie nueva y, para una petición cuya sesión llegó en la cabecera `ok` (un cliente de la API), lleva el token nuevo en su cabecera `ok`, que los clientes de la API deben enviar desde entonces; un navegador, cuya sesión llegó en la cookie, lo recibe solo ahí, donde los scripts de sus páginas no pueden leerlo (una copia del token viejo ya no vale nada). Lo mismo hacen `setM`, cuando el `turbo.config` del directorio nuevo trae otras credenciales, y `closeSessions` (§3.3); una recarga de `turbo.config` que las cambia cierra todas las sesiones. Sin una sesión válida, `/admin:inside:` devuelve la redirección HTML a `/admin:` (ver §3.2).
* **Lo que Basta con la Sesión:** leer el estado (`sites`, `subdomains`, `subdomainData`); añadir y borrar sitios y subdominios, reescrituras dentro del sitio, índices y alias (salvo `delSite`), y borrar IPs denegadas; y los `cfg<CLAVE>` que ni borran un certificado, ni quitan el HTTPS de un sitio, ni paran la renovación de un certificado (los de un sitio salvo `cfgC` y `cfgS` con `a=0`, `cfgE` que quita el e-mail, `cfgA` con otro adaptador y `cfgC` con otro adaptador en `y`; y `cfgPC` con `a=1` y el adaptador guardado, o sin `y`). Toda otra acción pide además la contraseña actual: `addRewrite` cuando su destino empieza por `http://` o `https://` o es una expresión (§6.3), `addDenied` y `cfgS` con `a=0` (envían a los visitantes de un sitio a otra dirección, dejan a un cliente sin ningún sitio y quitan el HTTPS de un sitio), lo que para la renovación de un certificado, que deja sin servicio a su sitio cuando caduca (`cfgE` con el valor vacío cuando el sitio tiene un e-mail, `cfgA` con otro adaptador, y `cfgC` o `cfgPC` con otro adaptador en `y`), `set<CLAVE>`, `addPreprocessor` y `delPreprocessor`, `addMIME` y `delMIME`, `addHeader` y `delHeader` (un tipo MIME o una cabecera pueden hacer que un archivo de un sitio se ejecute como página), `delSite`, `hardUpload`, `cfgC` y `cfgPC` con `a=0`, `addHttpCodeResponse` y `delHttpCodeResponse` (una plantilla es la página de error de todos los sitios), `addCharsReplace` y `delCharsReplace` (un reemplazo cambia lo que leen las acciones) y `closeSessions`.

---

## 2. Convenciones de Codificación de Datos y Reemplazo de Caracteres

Para evitar que caracteres especiales y delimitadores de URL interfieran o corrompan las peticiones HTTP (especialmente en reglas de reescritura o cabeceras), el backend exige que ciertos caracteres se codifiquen mediante una sustitución predefinida:

### 2.1. Sustituciones Inmutables (Fijas)
El servidor deshace los reemplazos de caracteres (los fijos de abajo y los añadidos con `addCharsReplace`, §7.3) en las rutas, los tipos y los valores que leen las acciones sobre los recursos de un sitio, y nunca en el sitio y el subdominio (`s` y `d`) de ninguna acción: en la práctica, `a` y `b` de `addRewrite`, `addMIME`, `addHeader`, `addIndex` y `addAlias`, y `a` de sus `del<TIPO>`; la contraseña actual de las que la piden (`c` de `addRewrite`, `addMIME` y `addHeader`, y `b` de `delMIME`, `delHeader` y `addDenied`) se toma tal como llega. Las demás acciones que piden la contraseña actual, los `cfg<CLAVE>` y `hardUpload` toman todos sus parámetros exactamente como llegan: envíelos codificados para URL, como ya lo hace por sí solo un cuerpo `application/x-www-form-urlencoded`. Así, un reemplazo no puede cambiar lo que el administrador confirma con la contraseña (una extensión, el programa de un preprocesador, el sitio que se borra). Las siguientes sustituciones deben aplicarse en el lado del cliente antes de enviar los parámetros que el servidor decodifica, y no se pueden cambiar ni borrar:

| Carácter Original | Token de Transmisión Esperado |
|---|---|
| `;` (Punto y coma) | `-.-` |
| `#` (Almohadilla) | `-,-` |
| `&` (Ampersand) | `-_-` |

*Nota: Los administradores pueden añadir más reemplazos de caracteres con `addCharsReplace` (§7.3), que pide la contraseña actual. El servidor los deshace todos de una pasada, primero los tokens más largos, y los valores leídos de `turbo.config` no se vuelven a decodificar (se guardan decodificados).*

*Límite: un texto con un carácter reemplazado junto al principio o al final de un token no siempre se puede distinguir: `-,#` y `#,-` se envían los dos como `-,-,-`, y el servidor lee `#,-`. Un cliente puede comprobarlo antes de enviar: deshacer los reemplazos de lo que va a enviar y compararlo con el original. El panel no envía un texto así y lo avisa.*

### 2.2. Caracteres no admitidos
Ningún parámetro puede contener caracteres de control (bytes por debajo de `0x20` y `0x7f`) ni UTF-8 inválido: el servidor responde HTTP 400 `"Control characters not allowed"` o `"Invalid UTF-8 text"`. Las únicas excepciones son la plantilla de respuesta de `addHttpCodeResponse` (§7.2) y una expresión (§6.3) de `addHeader` o `addRewrite`, que pueden contener tabuladores y saltos de línea.

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
  El servidor genera un token opaco criptográficamente seguro (32 bytes aleatorios, 64 caracteres hexadecimales), distinto en cada login y asociado a la IP del cliente. Fija con él la cookie de sesión (`turbo_session`, o `__Host-turbo_session` por HTTPS), y el cuerpo es `ok` seguido del token, para los clientes que usan la cabecera `ok`. Una petición de un navegador (una con `Sec-Fetch-Site` o, donde el navegador no la envía, como a un panel al que se llega por HTTP en otro host que `localhost`, con `Origin`), como la envía la página de login del panel, recibe `ok` a secas: su sesión está en la cookie, que sus scripts no pueden leer.
  ```text
  ok<token>
  ```
* **Credenciales Incorrectas:** HTTP 403 con el cuerpo vacío.
* **La Contraseña por Defecto:** la contraseña `Admin`, mientras es la del panel, solo abre sesión desde esta máquina: desde una dirección de loopback (`127.0.0.1`, `::1`), a un `Host` que es `localhost`, una dirección de loopback o un host de `PA` (una página de otro nombre que se resuelva a esta máquina no puede usarla), y sin una cabecera de las que envía un proxy delante (`Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, `Via`, `CF-Connecting-IP`, `True-Client-IP`). Desde otro sitio, HTTP 403 con `X-Turbo-Login: local-only` y un mensaje que lo dice, sin contar como fallo. Entre en la máquina (sirve un túnel SSH a su puerto 80) y cámbiela, o ponga `TURBO_PASSWORD`.
* **Otro Origen:** un login que el navegador dice que viene de otro origen (`Sec-Fetch-Site` distinto de `same-origin` o `none` o, sin él, un `Origin` distinto de `<esquema>://<Host>`) recibe HTTP 403 antes de leer su cuerpo, sin contar como fallo: si no, cualquier página podría hacer que el navegador del administrador entrara con credenciales erróneas y bloqueara su IP. Un cliente sin esas cabeceras (curl, un script) no se ve afectado.
* **Demasiados Logins Fallidos:** tras 5 fallos desde la misma IP (una dirección IPv4, o un /64 IPv6) en 10 minutos, todo login desde esa IP (también con las credenciales correctas) recibe HTTP 429 con `Retry-After` en segundos, sin comprobar la contraseña: 1 minuto la primera vez, después 2, 4, 8 y como máximo 15 minutos. Los /64 de un /48 IPv6 comparten además una cuenta de 20 fallos en 10 minutos, con los mismos bloqueos para todos ellos. Los logins que se están comprobando cuentan para los límites: los simultáneos que los superan reciben 429 con `Retry-After: 2`. Un login correcto pone a cero la cuenta de su IP y da confianza a su cliente (una dirección IPv4 o un /64 IPv6) durante 12 horas: sus logins no cuentan para su /48, aunque sí para su propia cuenta, y pueden usar la comprobación reservada a las sesiones (abajo). No pone a cero la de su /48. Las contraseñas actuales erróneas de un `set<CLAVE>` (§5) o de una acción que la pide (§1.2) cuentan por sesión, no para la IP, con las que aún se comprueban: la quinta en una sesión la cierra (HTTP 400 con `X-Turbo-Login: required`, como recibe una petición sin sesión), una más mientras se comprueban cinco recibe HTTP 429 con `Retry-After: 2`, y una correcta pone la cuenta a cero.
* **Servidor Ocupado:** si la contraseña no se puede comprobar en 2 segundos porque hay demasiadas comprobaciones en curso, HTTP 503 con `Retry-After: 2`. Una de las comprobaciones que corren a la vez se reserva para la contraseña actual de una petición con sesión y para los logins de los clientes de confianza (arriba), así que una avalancha de logins desde otro sitio no deja fuera al administrador. El mismo 503 vale para la contraseña actual (`b`) de los `set<CLAVE>` (§5) y de las acciones que la piden.

### 3.2. Cerrar Sesión (Logout)
Invalida el token actual en la memoria RAM (las demás sesiones de la misma IP siguen activas) y, cuando la petición trae la cookie de sesión, la caduca (`Max-Age=0`). Con la cookie, la petición debe venir del propio origen del panel, como las acciones (§1.2); si no, `403` y la sesión sigue abierta.

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
* **Parámetros:** `b`, la contraseña actual, tal como se envía. Si falta: HTTP 400 `"Missing data: the current password (b)"`; si es errónea: HTTP 400 `"Wrong current password"`, que cuenta para la sesión (§3.1).
* **Respuesta Exitosa (HTTP 200 OK):** `"Every session closed: this one goes on with a new token"`, con la cookie nueva y, para un cliente de la API, el token nuevo en la cabecera `ok` de la respuesta.

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
        "A": "",
        "Z": "0"
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
      "WFT": "0s",
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
  *(Nota: Las entradas fijas, que no se pueden borrar, se devuelven como `{"f": <valor>}`. Los valores de texto del bloque `!` van codificados para URL, p. ej. `@` → `%40`. `~` lista los sitios cuya carpeta no está, con sus subdominios en la misma situación (`""` es el propio sitio): Turbo conserva sus ajustes, también en `turbo.config`, para cuando vuelva la carpeta, hasta que su carpeta ya no está y `delSite` los olvida, sin borrar ninguna carpeta).*

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
        "A": "",
        "Z": "0"
      }
    },
    "api": {
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "0",
        "E": "api-admin%40example.com",
        "A": "dns-route53",
        "Z": "0"
      }
    },
    "*.dev": {
      "!": {
        "S": "0",
        "C": "0",
        "R": "0",
        "W": "0",
        "E": "",
        "A": "",
        "Z": "0"
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
* **Parámetros Requeridos:** `a` (valor) y `b` (contraseña actual) en **todos** los `set<CLAVE>`. Si falta `b`, el servidor responde HTTP 400 `"Missing data"`; si es incorrecta, HTTP 400 `"Wrong current password"`, que cuenta para la sesión: la quinta en una sesión la cierra (`X-Turbo-Login: required`, §3.1). Un valor igual al actual también se responde con HTTP 400 (por ejemplo, `"User unchanged"` o `"Password unchanged"`).

| Endpoint | Parámetro `a` | Parámetro `b` | Descripción / Validación |
|---|---|---|---|
| `setU` | Nuevo Usuario | Contraseña Actual | Cambia el nombre de usuario (1-24 bytes en UTF-8: `ñ` o `é` cuentan 2). Todas las sesiones terminan, y la respuesta trae una nueva (§1.2). Con `TURBO_USER` puesta, 400: se cambia ahí, y se reinicia Turbo. |
| `setP` | Nueva Contraseña | Contraseña Actual | Cambia la contraseña: de 12 a 64 bytes en UTF-8 (`ñ` o `é` cuentan 2); si no, 400 `"The password must have 12 to 64 bytes"`. Una contraseña más corta que ya está en uso (`Admin`, `TURBO_PASSWORD`, `turbo.config`) sigue valiendo. Todas las sesiones terminan, y la respuesta trae una nueva (§1.2). Con `TURBO_PASSWORD` puesta, 400: se cambia ahí, y se reinicia Turbo. |
| `setM` | Ruta Directorio | Contraseña Actual | Cambia el directorio base de sitios (debe existir) y recarga la configuración. La ruta puede ser relativa al directorio de trabajo o usar `{TURBO_CURRENT_DIR}`, y se guarda tal como se escribe; el mismo directorio escrito de otra forma es "Sites directory unchanged". Si ese directorio tiene un `turbo.config` que no es JSON válido, responde 400 con dónde está el error. |
| `setC` | (Ignorado; `overwrite` para confirmar, ver abajo) | Contraseña Actual | Vuelca la configuración RAM actual al disco (`turbo.config`), incluidos el usuario y el hash de la contraseña (nunca la contraseña en claro). |
| `setPA` | Hosts / redes CIDR | Contraseña Actual | Dónde responde el panel: nombres de host y/o redes CIDR separados por comas (como máximo 32 entradas y 1 024 bytes); con los dos tipos, una petición necesita los dos. Vacío o `*` = sin restricción (`*` solo como único valor). Un host que sirve un sitio (directamente, por un wildcard o como alias) se rechaza con 400 `"The panel host <host> serves the site <site>: …"`, y también los comodines de host (`*.example.com`, que nunca coinciden) y un valor que dejaría fuera a la propia petición que lo fija (su host o su IP), con el motivo. Una IP sin `/` es un host, que se compara con la cabecera `Host` (una IPv6 como `[::1]` o `::1`); para limitar la IP del cliente, use `/32` o `/128`. Solo con redes, un sitio `*` o `localhost`, o un alias `localhost`, comparte el origen del panel (§1.2): la respuesta es la misma, y el log lo avisa. |
| `setMUB` | Valor entero | Contraseña Actual | Ajusta la longitud máxima de URI (40 - 10 240 bytes). |
| `setMHB` | Valor entero | Contraseña Actual | Ajusta la longitud máx. de cabeceras (600 - 20 480 bytes). |
| `setMBB` | Valor entero | Contraseña Actual | Ajusta tamaño máx. de cuerpo (1B - 100MB). |
| `setCIL` | Valor ms | Contraseña Actual | Reinicio de contador (1 000 - 800 000 ms). |
| `setCIS` | Valor ms | Contraseña Actual | Ventana de conteo (10 - 50 000 ms), como mínimo `CII` y como máximo 66 veces `CII`. |
| `setCII` | Valor entero | Contraseña Actual | Límite de peticiones por intervalo: de 1 hasta el valor de `CIS` en ms, y `CIS`/`CII` ≤ 66. |
| `setCGL` | Valor entero | Contraseña Actual | Peticiones por segundo para todo el servidor, entre todos los clientes (10 - 1 000 000; `0` = sin límite, el valor por defecto). Las que lo superan reciben `503` con `Retry-After: 1`; no se bloquea ninguna IP. |
| `setCGP` | Valor entero | Contraseña Actual | Procesos CGI (preprocesadores) que pueden ejecutarse a la vez (1 - 100 000; `0` = automático, el valor por defecto: 4 por CPU, al menos 16). Una petición a un CGI que no encuentra hueco en 2 s recibe `503` con `Retry-After: 2`. La salida de un CGI espera a su cliente en memoria y en archivos temporales, así que el CGI libera su plaza al terminar; como mucho una cuarta parte de las plazas (al menos una; la mitad para un /48 IPv6) puede esperar a respuestas de un mismo cliente (una dirección IPv4 o un /64 IPv6) que pasan de sus límites o de su parte, y una respuesta que tuviera que esperar más allá se corta. Las peticiones que esperan plaza la reciben por orden de llegada, pero un cliente puede ocupar una cuarta parte de las plazas, y un /48 IPv6 la mitad (al menos una), mientras otros esperan: más allá, sus peticiones esperan detrás de las de ellos; mientras nadie más espera, una plaza libre es de cualquiera. Detrás de un proxy todos los clientes son el proxy (README, «Known Limitations»), y reciben plaza por orden de llegada. Una petición cuyo cliente se va mientras espera no toma plaza, y un `CGP` más alto da sus plazas en el momento a las que esperan. |
| `setRT` | Tiempo (`5s`, `0s`) | Contraseña Actual | Read Timeout total de petición (100 ms - 15 min; `0s` lo desactiva). Como mínimo el doble de `RHT`, salvo que `RHT` sea `0s`. |
| `setRHT` | Tiempo (`1s`, `0s`) | Contraseña Actual | Read Header Timeout (50 ms - 7.5 min y, si `RT` no es `0s`, como máximo la mitad de `RT`; `0s` usa `RT`). |
| `setWT` | Tiempo (`10s`, `0s`) | Contraseña Actual | Write Timeout para respuestas, y lo que puede durar un CGI (100 ms - 30 min; `0s` lo desactiva). Un archivo que un cliente tarda más en descargar se corta, salvo que `WFT` le dé más. |
| `setWFT` | Tiempo (`10m`, `0s`) | Contraseña Actual | Write Timeout para los archivos de los sitios, aparte de `WT` (100 ms - 24 h; `0s`, el valor por defecto, usa `WT`). |
| `setIT` | Tiempo (`2s`, `0s`) | Contraseña Actual | Idle Timeout para *Keep-Alive* (100 ms - 5 min; `0s` usa `RT`). |

*Notas:*
* *`setPA`: Las entradas de host se comparan con la cabecera `Host` de la petición, que elige el cliente: dan al panel un origen propio, aparte de los sitios, pero no limitan quién puede acceder. Lo que limita el acceso son las redes CIDR, que se comparan con la IP del cliente. Un `turbo.config` cuyo host de `PA` sirve un sitio se carga igual, con un aviso en el log.*
* *Límite por IP (`CIL`, `CIS`, `CII`): "IP" es una dirección IPv4, o el /64 de una dirección IPv6 (el bloque que suele tener un cliente), también en el límite de logins fallidos. Cada IP puede hacer `CII` peticiones por ventana de `CIS` de media, contadas desde su primera petición e incluida la actual: pasados `t` ms, `CII` × (⌊`t`/`CIS`⌋ + 1) peticiones en total, así que lo que no usó en una ventana lo puede usar en otra posterior, hasta que la cuenta vuelve a empezar. La que pasa de ahí recibe 429 y bloquea la IP 5 s. La cuenta vuelve a empezar `CIL` ms después de comenzar. Los tiempos se miden con el reloj monotónico, así que cambiar la hora del sistema no bloquea a nadie. Turbo guarda hasta 200 000 IPs; por encima, hasta que se olvidan las antiguas, una IP nueva comparte la cuenta de su red, un /24 IPv4 o un /48 IPv6 (hasta 25 000 de ellas), luego la de un /16 o un /32 (hasta 3125), y solo después una sola cuenta con todas las demás IPs nuevas. Una cuenta compartida responde 429, pero no cierra conexiones, y las IPs ya conocidas no se ven afectadas. `CGL` cuenta segundos fijos, así que una ráfaga entre dos de ellos puede llegar al doble de `CGL`; repartir el servidor entre los clientes es lo que hacen `CII`/`CIS`.*
* *`CIS`/`CII` y `RT`/`RHT`: sus condiciones se comprueban se cambie cuál se cambie (un cambio que las incumpliría recibe 400), y se comparan de forma exacta (66,5 es más que 66). En `turbo.config` se comprueban cuando ya se han leído todos los ajustes: si no se cumplen, `CII` (o `RHT`) toma su valor por defecto, con un aviso en el log; si el valor por defecto tampoco encaja, también `CIS` (o `RHT` pasa a `0s`, que usa `RT`).*
* *`setM`: los errores van en este orden: falta `b`, contraseña actual incorrecta (antes no se lee nada del nuevo directorio), un directorio que no existe (400 `"Sites directory not found"`), uno que no se puede listar (400 `"Sites directory can't be read"`), el mismo directorio escrito de otra forma (400 `"Sites directory unchanged"`) y un `turbo.config` allí que no se puede usar, o cuyo `M` lleva a un directorio que no existe o no se puede listar, a un `turbo.config` que no se puede usar, o de vuelta a un directorio del camino (400 con dónde está el error), y un `turbo.config` allí cuyo `M` lleva de vuelta al directorio de sitios en uso, una copia de él que todavía lo nombra (400 `"The sites directory is not changed. The turbo.config of <dir> leads back to the sites directory in use (its "M"): …"`): todo ello se comprueba antes de cambiar nada. El `turbo.config` del nuevo directorio se lee siempre, también con la misma fecha que el que está en uso. Si no tiene, se conservan los ajustes globales, las credenciales y las listas en uso (`@`, `_`, `#`), que se escriben allí con el siguiente `setC`; la respuesta lo dice. Si tiene, se aplica entero, y la respuesta dice qué cambió de `PA` y de las credenciales. Al volver al directorio de arranque no se sigue el puntero que dejó `setC`, ni el `M` de un `turbo.config` completo de ese directorio. El directorio nuevo se pone en uso junto con su configuración, de una vez: si eso falla (su `turbo.config` cambió después de las comprobaciones, por ejemplo), nada cambia y la respuesta es 400 con el motivo. Turbo sigue como mucho dos directorios contados desde el de arranque, para `setM` como al arrancar.*
* *Recarga de `turbo.config`: cuando el archivo cambia (se comprueba cada 30 s), se aplica entero y sustituye lo que vino de él: lo que el archivo ya no tiene deja de aplicarse, y los cambios hechos con `set<CLAVE>`, `add<TIPO>` o `del<TIPO>` y no guardados con `setC` se pierden. Los reemplazos de caracteres y las respuestas fijos se mantienen siempre.*
* *`PA`, `U`, `PH` y `P` en `turbo.config`: si uno de ellos no se puede usar (otro tipo, un `PA` que `setPA` rechazaría, un usuario fuera de 1-24 bytes o una contraseña fuera de 1-64, un hash que no es de Turbo), el archivo es inválido: Turbo no arranca, y una recarga o un `setM` a ese directorio conservan la configuración en uso. También lo es un sitio o un subdominio cuya clave no es el nombre de uno (`Example.com`, `example.com.`, con un espacio), como se llama su carpeta, un sitio, o una lista de un sitio (`!`, `=`, `$`, `.`, `?`, `-`, `&`), que no es un objeto JSON, y un `turbo.config` completo cuyo `M` nombra un directorio que no existe o no se puede listar: si se saltara, el sitio se serviría sin sus ajustes, sus scripts como texto.*
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
| `addRewrite` | Dominio Web | Subdominio | URI de origen (ej: `/old`) | Reescritura (`/new`, `http://...`, `https://...`), [palabras clave dinámicas disponibles](https://turbo-server.github.io/es/#so-2), o una expresión (`=…`, §6.3). Un destino que empieza por `http://` o `https://`, y una expresión, piden además la contraseña actual, en `c` |
| `addMIME` | Dominio Web | Subdominio | Extensión (ej: `png`), sin punto dentro | Tipo MIME (ej: `image/png`), de 4 a 128 caracteres. También pide la contraseña actual, en `c` |
| `addHeader` | Dominio Web | Subdominio | Nombre Cabecera (de 1 a 48 bytes: letras, dígitos, `-` y `.`) | Valor Cabecera (de 1 a 512 bytes), o una expresión (`=…`, §6.3). También pide la contraseña actual, en `c` |
| `addPreprocessor`| Dominio Web | Subdominio | Extensión (ej: `php`), sin punto dentro | Ejecutable CGI (ej: `/usr/bin/php-cgi`), o `dx>` y el programa de un worker (§6.4). También pide la contraseña actual, en `c` |
| `addIndex` | Dominio Web | Subdominio | Archivo Índice (`index.html`)| - |
| `addAlias` | Dominio Web | Subdominio | Dominio Alias | - |

*Notas:*
* *`addHeader`: una cabecera que solo se diferencia en mayúsculas de una del sitio la sustituye ("Header changed"): saldrían las dos, cualquiera primero. Las cabeceras que pone HTTP para la conexión y la longitud de un cuerpo (`Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Upgrade`) se rechazan (400 "Header reserved"); en `turbo.config`, se descartan con un aviso. `delHeader` borra la cabecera escrita con cualquier mayúscula.*
* *`addSubdomain`: un subdominio no puede llamarse como los archivos de certificado de su sitio (`fullchain.pem`, `privkey.pem`, `fullchain.pem.new`, `privkey.pem.new`), cuyo lugar ocuparía su carpeta. `addAlias`: un alias cuyo host cae bajo el dominio de un sitio (`m.example.com` con el sitio `example.com`) se rechaza (400 "The alias is a site's host"), también cuando ningún subdominio sirve ese host; con un sitio `*`, todo alias se rechaza. Un alias no puede ser una dirección IP (400): solo el sitio `*` sirve una, y entonces el alias es su host; en `turbo.config`, se descarta con un aviso. `addMIME` y `addPreprocessor`: la extensión es lo que sigue al último punto de un nombre (`php`, no `blade.php`); una vacía es la de los archivos sin extensión, pero el archivo de un reto ACME, que no tiene, se entrega siempre tal cual.*
* *`addSite` y `addSubdomain`: los nombres que Turbo usa para sus propias carpetas y archivos en el directorio de sitios (`turbo.dev`, `turbo.panel`, `turbo.certificates`, `turbo.config`, `turbo.visits`, `turbo.denials`) no pueden ser sitios, ni un nombre cuyos ajustes compartirían clave con otro sitio, ni el host de un alias, ni una dirección IP (`192.168.1.10`), que solo sirve el sitio `*` (400 con el motivo), ni un sitio o subdominio que Turbo conserva sin su carpeta (`~` de `sites`), hasta que su carpeta ya no esté y `delSite` lo olvide (400 "… is kept, with its settings…").*
* *`addRewrite`: La reescritura debe empezar por `/` (ruta interna), `http://` o `https://`. Los destinos con `http://` o `https://` se responden con una redirección `302`: al destino exacto si tiene ruta o consulta, o al dominio de destino seguido del URI original si es solo un dominio. El origen (`a`) se compara con la ruta pedida ya decodificada (`/a b` coincide con `/a%20b`); un origen que acaba en `/` toma también la carpeta nombrada sin ella (`/privado/` toma `/privado`, que serviría su índice), y en Windows y macOS, cuyos sistemas de archivos no distinguen mayúsculas, una ruta en otras mayúsculas (`/PRIVADO/`), y en macOS un nombre escrito con la letra y su acento por separado (NFD), que abre como el mismo nombre con los dos en un carácter (NFC), y un destino interno también es una ruta URL: se decodifica y tiene que quedar dentro del sitio (un destino con un segmento `..`, aunque quede dentro, o con `\`, una `/` o `\` codificada, `%00`, caracteres de control, UTF-8 inválido o un segmento que acaba en `.` o en espacio, se responde con 404).*
* *`addPreprocessor`: La ruta del ejecutable (como máximo 128 bytes tal como se escribe, sin el prefijo de su modo; puede usar `{TURBO_CURRENT_DIR}`, que se guarda tal cual y se sustituye al ejecutarlo) debe existir; el prefijo es `cgi>`, opcional, o `dx>` (§6.4), y cualquier otro prefijo se rechaza. En `turbo.config`, una entrada que no se puede usar (no es una cadena, extensión incorrecta, ruta demasiado larga o vacía, otro prefijo, ejecutable inexistente) se conserva con un aviso en el log, y la extensión a la que iba responde 500, salvo que haya una entrada de esa extensión que se pueda usar: sus archivos no se sirven como texto. Esa extensión es lo que sigue al último punto de la clave, en minúsculas, una vez quitado de sus extremos lo que no es una letra ni un dígito (`"php "`, `"php."`, `"*.PHP"` y `"blade.php"` son `php`); una clave de la que no se puede leer así ninguna extensión (con un espacio o una letra fuera de ASCII dentro, o `"."` a secas) solo recibe su aviso, y no casa con ningún archivo. La extensión cerrada así no se escribe al guardar la configuración, y vuelve a abrirse cuando se borra la entrada. El CGI recibe la ruta URL del script (tras la reescritura) en `SCRIPT_NAME`, un `PATH_INFO` vacío, lo que pidió el cliente en `REQUEST_URI` (sin los parámetros que fija la consulta de una reescritura, ver `addRewrite`), el archivo en disco en `SCRIPT_FILENAME` y la `@` del sitio en `DOCUMENT_ROOT`, y nunca la cookie de sesión del panel ni la cabecera `ok` de la API. `QUERY_STRING` lleva la consulta del cliente sin los parámetros que fija la de la reescritura, y después la de la reescritura, así que una aplicación obtiene el valor de la reescritura lea el primero o el último de un parámetro repetido; un CGI que lee sus parámetros de `REQUEST_URI` (uno de Go: `net/http/cgi`) encuentra los de la reescritura en `QUERY_STRING`. Una cabecera que fija el sitio (`addHeader`) gana a la del CGI con el mismo nombre. Las cabeceras sobre la conexión que escriba un CGI (`Transfer-Encoding`, `Connection`, `Keep-Alive`, `Trailer`, `Upgrade`…) se descartan, y también un `Content-Length` escrito dos veces y una cabecera cuyo valor tiene caracteres de control (salvo el tabulador): Turbo decide cómo se delimita la respuesta. Su cabecera `Status` se lee en mayúsculas o minúsculas (`status: 404`). Una página de error de Turbo para la petición de un script (413, 500, 503, 504) sale sin las cabeceras del sitio que describen cómo guardar o decodificar un cuerpo (`Cache-Control`, `Expires`, `CDN-Cache-Control`, `Surrogate-Control`, `X-Accel-Expires`, `ETag`, `Last-Modified`, `Content-Encoding`, `Content-Disposition`); las demás cabeceras del sitio se quedan. Lo que un CGI escribe en su salida de error va al log de Turbo, agrupado: una línea de cada tipo (el programa y las primeras palabras de la línea) en el momento, y el resto contado y escrito una vez por minuto. Un proceso que un CGI deja en marcha conserva esa salida de error, y no retiene la respuesta.*
* *`addRewrite`: el destino empieza por `/`, `http://` o `https://` (el esquema en mayúsculas o minúsculas; se guarda en minúsculas), y un destino `http(s)://` necesita host, escrito o dado por una palabra clave, que no empiece por `/`, `\`, `?` ni `#` (un navegador salta `/` y `\` tras el esquema y toma lo que sigue por el host; si al responder la palabra no da nada, 500). Las palabras clave desconocidas (`{X}`) se rechazan. Como en una expresión (§6.3), el host de una redirección solo lleva palabras clave de los nombres del sitio y de sus comodines (`{DOMAIN}`, `{SITE}`, `{FIRST_DOMAIN}`, `{FIRST_SITE}`, y `{WILDCARD_DOMAIN}`, `{WILDCARD_SUBDOMAIN}`, `{WILDCARD_SITE}`, que dan la clave del sitio con su `*`: ningún host), nunca `{REWRITE}`, la clave de la reescritura, que siempre empieza por `/` (escriba el host solo, y se añade la ruta pedida, o la ruta detrás); una dirección IPv6 (`{DOMAIN}` del sitio `*`) va en él entre corchetes, y una `\` se rechaza en él, donde un navegador termina el host; `{SUBDOMAIN}` y `{FIRST_SUBDOMAIN}`, que un subdominio comodín deja elegir al cliente, solo lo empiezan, con un `.` y el resto del host detrás (`https://{SUBDOMAIN}.example.org/`), que debe ser un dominio del sitio: con una sola etiqueta (`https://{SUBDOMAIN}.com/`), el visitante elige el dominio entero, y el log lo avisa. La regla se cumple con los valores de cada petición: donde la palabra clave que va detrás no da nada (`https://{SUBDOMAIN}.{FIRST_DOMAIN}/`, para una petición que no llega por un alias ni por un dominio comodín), la respuesta es 500, y el log avisa de una reescritura así cuando se añade o se lee; y las demás, que elige el cliente (`{FILE}`, `{FIRST_REQUEST}`…), se rechazan ahí, con el motivo. `{TURBO_CURRENT_DIR}` no es una palabra clave de una reescritura: pondría una carpeta del servidor en una URL. En `turbo.config`, una reescritura así se descarta con un aviso, y una guardada por una versión anterior responde 500. Las palabras se sustituyen por valores de la ruta decodificada de la petición (`{FIRST_REQUEST}`, `{DIR}`, `{FILE}`, `{EXT}`, `{REWRITE}`, `{REWRITE_COMPLEMENT}`) o de su consulta (`{FIRST_QUERY}`), codificados según dónde van: en la ruta, cada segmento, sin tocar `/`; en la consulta, como un valor; en el host, sin poder cambiar la URL. `{REWRITE_COMPLEMENT}` en la ruta toma el resto de la ruta, y la consulta de la petición se añade a la del destino: `/blog/` → `/new/{REWRITE_COMPLEMENT}` convierte `/blog/a/b?x=1` en `/new/a/b?x=1`; donde los nombres no distinguen mayúsculas, sigue a lo que casó el origen, lo escriba como lo escriba la ruta. Un CGI al que se llega por un destino interno con consulta recibe en `QUERY_STRING` la consulta de la petición sin los parámetros que fija la del destino (por su nombre decodificado; `&` y `;` los separan), y después la del destino: `/x` → `/app.cgi?role=user` da `z=1&role=user` a `/x?role=admin&z=1` en `QUERY_STRING`, y `/x?z=1` en `REQUEST_URI`, que es lo que pidió el cliente sin esos parámetros (`/x` para `/x?role=admin`, y la del cliente tal como llegó cuando no envió ninguno de ellos, como la dan Apache y nginx).*
* *`addIndex`: El índice se añade al final del orden; los índices se prueban en el orden en que se añadieron. Los sitios y subdominios nuevos empiezan con `index.html`, igual que un sitio que `turbo.config` nombra sin sección `""` (solo por sus subdominios, o como `{}` o `null`), como uno encontrado en el disco; una sección `""` conserva exactamente los índices que lista, ninguno si no lista ninguno. El nombre sigue las reglas de la subida de archivos en todos los sistemas (§9): un solo segmento, sin `\`, `/`, `..`, `:`, un `.` o un espacio al final, un nombre de dispositivo de Windows, `~` seguido de un dígito ni los caracteres que Windows no admite (`<`, `>`, `"`, `|`, `?`, `*` y los de control); si no, HTTP 400 `"Invalid index file"`, y en `turbo.config` el índice se descarta con un aviso.*
* *`turbo.config`: una entrada de una lista que no se puede usar y se descarta (una reescritura, un tipo MIME, una cabecera, un índice, un alias) deja un aviso en el log con su lista, su sitio, la entrada y el motivo.*

### 6.2. Eliminar Recursos (`del<Tipo>`)
* **Ruta Base:** `POST /admin:inside:del<TIPO>`

| Endpoint | `s` (Dominio) | `d` (Subdominio) | `a` (Clave/Identificador a borrar) |
|---|---|---|---|
| `delSite` | Dominio Web | Subdominio (Vacío = Borrar Sitio) | - (la contraseña actual va en `b`) |
| `delRewrite` | Dominio Web | Subdominio | URI origen |
| `delMIME` | Dominio Web | Subdominio | Extensión (la contraseña actual va en `b`) |
| `delHeader` | Dominio Web | Subdominio | Nombre de Cabecera (la contraseña actual va en `b`) |
| `delPreprocessor`| Dominio Web | Subdominio | Extensión (la contraseña actual va en `b`: sin el preprocesador, los archivos de la extensión se servirían como texto, con su código fuente) |
| `delIndex` | Dominio Web | Subdominio | Archivo Índice |
| `delAlias` | Dominio Web | Subdominio | Dominio Alias |

*Los tres parámetros son obligatorios (salvo `a` en `delSite`): si falta alguno, la respuesta es `400` "Missing data".*

*`delSite` de un sitio o subdominio que se conserva sin su carpeta (listado en `~`) olvida los ajustes que Turbo guarda de él (y que `turbo.config` conserva), para un sitio también los de sus subdominios, cuyas carpetas se fueron con la suya, y no borra ninguna carpeta. Solo cuando su carpeta ya no está: mientras esté (faltando solo su `@` o la de su sitio) o no se pueda mirar, la respuesta es `400` y los ajustes se quedan, porque la carpeta volvería como un sitio nuevo con los valores por defecto. Una carpeta con su nombre, después, es un sitio nuevo. Si no existe ni se conserva, la respuesta es `400` "Site not found" (o "Subdomain not found").*

### 6.3. Expresiones en Cabeceras y Reescrituras

El valor de una cabecera (`addHeader`, `b`) y el destino de una reescritura (`addRewrite`, `b`) pueden ser una **expresión** en lugar de un texto: un valor que empieza por `=` lo es, y se calcula en cada petición. El panel pone el `=` y lo quita según la opción "Text / Expression" del diálogo; en `turbo.config` el valor se guarda con él (`"Cache-Control": "=EXT in ['js'] ? 'public, max-age=31536000' : 'no-cache'"`). Una cabecera escrita como texto no puede empezar por `=`: se escribe como expresión, entre comillas (`='=texto'`).

**El lenguaje** es un subconjunto de CEL (Common Expression Language): sin bucles, sin variables propias y sin funciones del usuario, así que toda expresión termina y su coste depende de su tamaño.

| Elemento | Significado |
|---|---|
| `'texto'`, `"texto"` | Un texto. Los únicos escapes son `\\`, `\"` y `\'`; sin caracteres de control (tampoco un salto de línea) |
| `a + b` | Los dos textos unidos |
| `c ? a : b` | `a` si la condición `c` se cumple; si no, `b` (los dos textos, o las dos condiciones) |
| `a == b`, `a != b` | Dos textos, o dos condiciones, iguales o no |
| `a in ['x', 'y']` | `a` es uno de los textos de la lista (escritos en la expresión, 64 como mucho) |
| `!c`, `c && d`, `c \|\| d` | No, y, o (el lado derecho solo se evalúa cuando decide) |
| `(…)` | Agrupar |

Los espacios, tabuladores y saltos de línea separan los elementos y no significan nada: una expresión puede ocupar varias líneas.

**Variables:** las de las reescrituras (`DOMAIN`, `SUBDOMAIN`, `SITE`, `FIRST_DOMAIN`, `FIRST_SUBDOMAIN`, `FIRST_SITE`, `WILDCARD_DOMAIN`, `WILDCARD_SUBDOMAIN`, `WILDCARD_SITE`, `FIRST_REQUEST`, `FIRST_QUERY`, `DIR`, `FILE`, `EXT`, `REWRITE`, `REWRITE_COMPLEMENT`; [sus valores](https://turbo-server.github.io/es/#so-2)), y:

| Variable | Valor |
|---|---|
| `IP` | La dirección IP del cliente |
| `HTTPS` | Una condición: la petición llegó por HTTPS |
| `METHOD` | El método de la petición (`GET`…) |
| `PATH` | Solo en una cabecera: la ruta del archivo que se sirve |

En una cabecera, `DIR`, `FILE`, `EXT` y `PATH` son los del archivo que se sirve, tras la reescritura y el índice (`/` sirve `index.html`, cuyo `EXT` es `html`); en una reescritura, los de la ruta que pidió la petición. `{TURBO_CURRENT_DIR}` no tiene variable: una ruta del servidor nunca va a una cabecera ni a una redirección.

**Funciones:**

| Función | Da |
|---|---|
| `HEADER('Nombre')` | Los valores de esa cabecera de la petición, unidos con `, ` (`''` si no está); `HEADER('Host')` es el host de la petición, tal como eligió el sitio |
| `QUERY('nombre')` | El primer valor de ese parámetro de la consulta, descodificado (`&` y `;` los separan; `''` si no está o no se puede descodificar) |
| `COOKIE('nombre')` | El valor de la primera cookie con ese nombre |
| `oneOf(v, ['x', 'y'])` | El texto de la lista igual a `v`, o `''`: nunca lo que envió el cliente, sino el texto escrito en la lista |
| `token(v)` | `v` si son de 1 a 128 caracteres de `A-Z a-z 0-9 . _ ~ -`; si no, `''` |
| `quoted(v)` | `v` entre comillas dobles, con sus `\` y `"` escapados (`''` si tiene caracteres de control). No en `Set-Cookie`, `Content-Security-Policy` ni `Content-Security-Policy-Report-Only`, cuya gramática no mantiene unido un texto entre comillas (un `;` o un espacio dentro seguiría terminando el valor), ni en `Refresh`, cuya URL toma un navegador sin sus comillas |
| `urlencode(v)` | `v` con todo carácter que no sea `A-Z a-z 0-9 . _ ~ -` como `%XX`; en el destino de una reescritura va tal cual, sin codificarse otra vez |
| `lower(v)`, `upper(v)` | `v` en minúsculas o mayúsculas (letras ASCII) |
| `v.startsWith(s)`, `v.endsWith(s)`, `v.contains(s)` | Condiciones sobre textos |
| `v.matches('patrón')` | Una condición: `v` cumple el patrón (sintaxis RE2, escrito en la expresión, 256 bytes como mucho) |

Los nombres que leen `HEADER`, `QUERY` y `COOKIE` se escriben en la expresión. `HEADER` no puede leer `Cookie`, `Authorization`, `Proxy-Authorization` ni `ok`, y `COOKIE` no puede leer las cookies de sesión del panel (`turbo_session`, `__Host-turbo_session`), en mayúsculas o minúsculas: una expresión podría copiar credenciales a una cabecera o a una redirección.

**Qué puede ir dónde.** Todo texto que da una expresión viene de algún sitio, y eso decide adónde puede ir. Lo que podría romper estas reglas se rechaza al añadir la expresión (400 con el motivo y su posición: `Expression: … (position N)`), y se vuelve a comprobar en cada petición:
- **Una cabecera nunca lleva lo que la petición envía tal cual** (`HEADER`, `QUERY`, `COOKIE`, `FIRST_REQUEST`, `FIRST_QUERY`, `DIR`, `FILE`, `EXT`, `PATH`, `REWRITE_COMPLEMENT`, `METHOD`): pasa por `oneOf`, `token`, `quoted` o `urlencode`. Las condiciones leen cualquier cosa. Por ejemplo, `oneOf(HEADER('Origin'), ['https://app.example'])` da el origen permitido, y `'attachment; filename=' + quoted(FILE)`, un nombre de archivo.
- **`Refresh`, `Location` y `Content-Location` no llevan `SUBDOMAIN` ni `FIRST_SUBDOMAIN`,** tampoco a través de `token`, `urlencode`, `quoted`, `lower`, `upper` ni de una rama de `? :` (`oneOf` y las condiciones sí los toman): un navegador va adonde dice su valor, y un subdominio comodín deja elegirlos al cliente (`'0; url=https://' + SUBDOMAIN + '.' + FIRST_DOMAIN` iba al host que escribió el cliente, para una petición sin alias). Redirija con una reescritura, cuyo host se comprueba. En otra cabecera que nombra un origen o una URL (`Access-Control-Allow-Origin`, `Content-Security-Policy`, `Link`), escriba detrás un `.` y un dominio del sitio.
- **El destino de una reescritura empieza por un texto de la expresión**: `/…` (una ruta del sitio), `http://…` o `https://…` (una redirección). No puede tener `..` ni `//`, como un destino escrito como texto, ni en uno de sus textos ni donde se juntan dos (`'/' + '/x'`).
- **El host de una redirección se escribe en la expresión, se elige con `oneOf` o es un host que Turbo sirve** (`DOMAIN`, `SITE`…): `'https://' + oneOf(QUERY('to'), ['a.example', 'b.example']) + '/x'`. `SUBDOMAIN` y `FIRST_SUBDOMAIN`, las etiquetas antes del dominio, que un subdominio comodín deja elegir al cliente (`malo.example` de `malo.example.misitio.com`), solo empiezan un host: les siguen un `.` y el resto de él (`'https://' + SUBDOMAIN + '.example.org'`), que debe ser un dominio del sitio: con una sola etiqueta (`'.com'`), el visitante elige el dominio entero. No puede estar vacío ni empezar por `/`, `\`, `?` ni `#`: se rechaza al añadirla si sin duda lo haría (`'https://'`), y responde 500 en la petición en que lo hace (`oneOf` no dio nada). `REWRITE`, que siempre empieza por `/`, no puede ir en él, ni una `\` en un texto que pueda caer en él (un navegador termina ahí el host); una dirección IPv6 va en él entre corchetes.
- Todo lo demás que va a un destino, salvo lo que da `urlencode` (tal cual), se codifica según dónde cae, como las palabras clave de un destino escrito como texto: en la ruta, cada segmento (conservando `/`); en la consulta, como un solo valor. `REWRITE_COMPLEMENT` conserva su regla, también a través de `lower` o `upper`, que solo cambian su ruta. Una ruta del sitio se limpia después como la de una petición: si sale del sitio, responde 404.

**Cuándo se calcula:**
- Una expresión que da `''` no envía la cabecera (sale la del CGI con ese nombre, si la pone), o no aplica la reescritura (se sirve la ruta tal como se pidió).
- Las cabeceras que lee una expresión (`HEADER`), y `Cookie` si lee una cookie, se añaden al `Vary` de la respuesta, también al propio de un CGI y al de una redirección.
- Una expresión que falla para una petición responde **500**: un texto de más de 8 KiB mientras se calcula, un valor de cabecera de más de 512 bytes o con caracteres de control, o un destino de más de 2048 bytes una vez colocado. En una cabecera, el 500 llega antes de que se ejecute el CGI: una página nunca sale sin una cabecera que puede ser la que la protege. El log dice cuál, como mucho una vez por minuto y sin datos de la petición.
- Una expresión de `turbo.config` que no compila (editado a mano) se conserva y se guarda tal cual, con un aviso en el log; lo que cubre responde 500 hasta que se corrija: todo el sitio en una cabecera, las rutas que toma en una reescritura. El archivo de un desafío ACME se sirve sin las expresiones de las cabeceras.

**Límites:** 2048 bytes por expresión, 32 niveles de anidamiento (la propia expresión es el primero, y cada paréntesis, cada `!`, cada llamada a una función o a un método y cada `? :` dentro de otro es uno más), 512 elementos, 64 textos en una lista, de 512 bytes cada uno, y patrones de `matches` que sumen 1000 pasos una vez compilados (una repetición como `\pL{1000}` tiene miles): de eso depende lo que cuesta aplicarlos.

**Contraseña:** `addHeader` pide la contraseña actual, como siempre; `addRewrite` la pide para toda expresión (puede enviar a los visitantes a otra dirección en algunas peticiones).

### 6.4. El Modo dx: Workers que Turbo Mantiene

Un preprocesador ejecuta sus scripts en uno de dos **modos**, el prefijo de su valor: `cgi>` (el de siempre, que el valor puede omitir) arranca el programa en cada petición, como un CGI; `dx>` mantiene el programa en marcha, un **worker**, y le da las peticiones una tras otra por su entrada y su salida estándar. El panel elige el modo en una lista ("CGI: a process for each request", "DX: a worker kept running") y pone el prefijo; en `turbo.config` el valor se guarda con él (`"lua": "dx>/opt/turbo-dx/dx-lua"`). El worker de Lua, `dx-lua`, y la librería para escribir otros, `dx-core`, están en la carpeta [`dx/`](dx/README.md) de este repositorio (en Rust, compilados aparte de Turbo).

**Lo que hace Turbo con los workers:**
- Una petición toma un worker de su programa que espera, el último usado primero, o arranca uno; hay tantos como peticiones de ese programa se sirven a la vez (los turnos de `CGP` los acotan). Un arranque sigue después de que su petición se rindiera (`WT`), y cuenta hasta que termina: un programa que tarda en arrancar más que `WT` nunca tiene más de `CGP` workers en uso o arrancando, y sus peticiones de más reciben 503 con `Retry-After`, como sin un turno libre. Los workers de un programa los comparten todos los sitios que lo nombran.
- Un worker arranca en la carpeta de su programa, con lo que un CGI recibe del entorno de Turbo, y debe saludar (`DX3\n`) en 5 s. Su salida de error va al log de Turbo, agrupada como la de un CGI. Un programa cuyo worker no arrancó o no saludó no vuelve a arrancarse durante 1 s, luego 2, 4… hasta 30 s mientras siga fallando (los arranques que fallan a la vez cuentan una vez): entretanto, sus peticiones reciben 500 al momento.
- Un worker vuelve a usarse solo tras un intercambio que terminó como dice el protocolo. Cualquier otro final lo mata, con todo su grupo de procesos (un Job Object en Windows), y cierra los extremos de Turbo de sus tuberías, para que nada que arrancara fuera de su grupo retenga la petición: una respuesta que rompe el protocolo, más que la respuesta, `WT` vencido, el cliente que se va. Una petición cuyo cliente se fue antes de llegar a un worker (mientras esperaba turno) no toma ninguno, y el worker espera a la siguiente. Un worker que esperaba y terminó entretanto (uno que termina tras algunas peticiones), encontrado al darle una petición, pasa esa petición a otro una vez: cuando no pudo tomarla, o cuando terminó sin un byte de respuesta y la petición puede hacerse dos veces (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT` o `DELETE`, sin cuerpo). Una petición que no es idempotente (`POST`, `PATCH`), o que tiene cuerpo, nunca se hace dos veces.
- Un worker sin uso durante 60 s termina en el minuto siguiente (se le cierra la entrada; los workers sin uso se miran una vez por minuto); al parar Turbo terminan todos, tras las peticiones en curso.

**Todo lo demás es lo de un CGI,** por el mismo código: `MBB` y los turnos, `WT`, la petición sin la cookie de sesión del panel, la cabecera `ok` de la API ni las cabeceras con `_`, y la respuesta por los filtros de cabeceras de un CGI, ganando las del sitio, y las páginas de error de Turbo sin las cabeceras del sitio que describen un cuerpo. A diferencia de un CGI, un estado de error sin cuerpo recibe la plantilla del sitio, sin las cabeceras del worker que describen un cuerpo (`Content-Encoding`, `Content-Range`, `Content-Disposition`, `ETag`, `Last-Modified`) y con las demás, `Cache-Control` entre ellas: el estado es el del script; una cabecera `Status` de un worker es una cabecera más, y su estado, el del protocolo; y una respuesta sin cuerpo (204, 304) cuyo worker envía uno sale sin él, y el worker vuelve a usarse.

| Qué pasa | Respuesta | El worker |
|---|---|---|
| No arranca, no saluda, termina o rompe el protocolo antes de que empiece su respuesta (su cabecera y la longitud de su primer trozo) | 500; el log dice por qué, como mucho una vez por minuto | Muerto |
| `WT` vence antes de que empiece su respuesta | 504 | Muerto |
| El cliente se va | Ninguna | Muerto |
| Termina, vence `WT` o rompe el protocolo después de que empezara su respuesta | Se corta la conexión: una respuesta cortada nunca parece completa (salvo en HTTP/1.0, que no tiene trozos, una sin `Content-Length`, como la de un CGI); el log dice por qué, como mucho una vez por minuto | Muerto |

**El protocolo DX 3**, el contrato para quien escriba un worker. Los enteros son sin signo y *little-endian*: el id de una petición, de 64 bits, y el resto, de 32.

```text
worker, una vez, al arrancar:   "DX3\n"
Turbo, una petición:            u64 id, u32 M, M bytes de pares, luego el cuerpo (CONTENT_LENGTH bytes)
worker, su respuesta:           u64 id, u32 H, H bytes (u32 estado, pares de cabeceras), luego trozos: u32 n, n bytes … u32 0
pares:                          u32 cantidad, y para cada uno: u32 longitud, nombre, u32 longitud, valor
```

- Los pares de una petición son las variables que recibe un CGI, con los mismos nombres y valores (`REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`, `SCRIPT_NAME`, `SCRIPT_FILENAME`, `DOCUMENT_ROOT`, `HTTP_*`…), salvo las del entorno de Turbo, que el worker tiene en el suyo; y `DX_TIMEOUT_MS`, los milisegundos que tiene el worker: lo que falta para que venza `WT`, menos una décima parte (250 ms como mucho), para que detenga su script y responda antes de que Turbo abandone la petición y lo mate (0: sin límite). `DX_GRANTS`, los accesos concedidos al script, queda para lo que venga: Turbo no concede ninguno en esta versión. `CONTENT_LENGTH` llega solo con un cuerpo: sin él, el cuerpo está vacío.
- Una respuesta empieza por el id de su petición, un número aleatorio. Una respuesta con otro id (una escrita tarde, tras la respuesta de una petición anterior) se rechaza antes de que nada de ella llegue al cliente: su worker se mata y la petición recibe 500. Igual lo que se escriba tras el saludo, antes de la primera petición.
- La cabecera de una respuesta lleva un estado de 200 a 599 y tiene como mucho 64 KiB; un trozo, como mucho 1 MiB.
- Un worker lee la petición entera antes de responder (uno que no lo hace puede retener su petición hasta `WT`, o hasta que el cliente se va con `WT` a 0), escribe en su salida estándar solo el protocolo (sus mensajes van a su salida de error, que recoge el log de Turbo, agrupada) y termina cuando se cierra su entrada.
- Un worker sirve a todos los sitios que nombran su programa: no debe guardar nada de una petición para la siguiente, y debe comprobar que `SCRIPT_FILENAME` está dentro de `DOCUMENT_ROOT` antes de leerlo (`dx-lua` responde 404 si no).

---

## 7. API de Seguridad Global e Interfaz

### 7.1. Control de IPs Denegadas
Una IP denegada queda bloqueada hasta la fecha indicada: sus peticiones se responden con HTTP 429 y la cabecera `Retry-After` (segundos restantes), y sus conexiones nuevas se cierran.

* **`POST /admin:inside:addDenied`**
  * `s`: Dirección IP (IPv4 o IPv6). Una dirección IPv6 deniega su /64 entero, el cliente que cuentan los límites de peticiones (sus direcciones cambian solas). No se aceptan direcciones de loopback (`127.x.x.x`, `::1`, y cualquier otra de `::/64`, que contiene `::1`) ni la dirección desde la que se hace la petición, o en IPv6 una de su /64 (`400` "Current IP": el panel se bloquearía a sí mismo).
  * `d`: Timestamp UNIX de expiración de bloqueo (`0` o una fecha pasada elimina un bloqueo existente).
  * `b`: la contraseña actual (§1.2).
* **`POST /admin:inside:delDenied`**
  * `s`: Dirección IP a desbloquear de la lista de IPs denegadas.

### 7.2. Respuestas a Códigos HTTP
Una plantilla es la página de error de todos los sitios, así que las dos acciones piden la contraseña actual en `b` (tal como se envía; si falta o es errónea, como en `set<CLAVE>`, §5), y todos los parámetros van tal como se envían (§2.1). Una página de error nunca ejecuta scripts: lleva una `Content-Security-Policy` sin ellos en cualquier host (§1.2), y con `sandbox`, así que tampoco redirige por sí sola (`meta` refresh), envía formularios ni abre ventanas. También bloquea los estilos, fuentes e imágenes externos de la plantilla: una plantilla conserva sus estilos en línea y sus imágenes `data:`.

* **`POST /admin:inside:addHttpCodeResponse`**
  * `s`: Código de estado HTTP (entre `400` y `599`, o `0` para fallback universal).
  * `d`: Plantilla de respuesta, de 1 a 2 048 bytes. Se admiten saltos de línea y la macro `{TURBO_RESPONSE_CODE}` (el panel la escribe en un área de texto: Intro es un salto de línea, y Ctrl+Intro la envía).
  * `b`: La contraseña actual.
* **`POST /admin:inside:delHttpCodeResponse`**
  * `s`: Código de estado HTTP a devolver a comportamiento por defecto del sistema.
  * `b`: La contraseña actual.

### 7.3. Reemplazo Global de Caracteres en URIs
Un reemplazo cambia lo que leen las acciones a las que basta la sesión (§2.1), así que las dos acciones piden la contraseña actual en `b` (tal como se envía; si falta o es errónea, como en `set<CLAVE>`, §5), y todos los parámetros van tal como se envían.

* **`POST /admin:inside:addCharsReplace`**
  * `s`: Secuencia de caracteres a reemplazar (ej: `;`), de 1 a 4 bytes, sin letras ni dígitos (`"Letters and digits are never replaced"`: con ellos, un token podría convertir un nombre en otro).
  * `d`: Cifra codificada objetivo (ej: `-.-`): de 2 a 16 bytes, sin ningún carácter reemplazado (tampoco el suyo), sin contener otro token ni estar dentro de uno; y `s` no puede estar dentro de otro token. Si no, HTTP 400. Las sustituciones fijas de §2.1 no se pueden cambiar (`"Fixed replacement"`). En `turbo.config`, un reemplazo que incumple estas reglas se descarta con un aviso.
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
| **`cfgC`** | `"1"` = Ejecutar Certbot<br>`"0"` = Eliminar del disco (pide la contraseña actual en `b`) | Dominio Web | Subdominio o Vacío (`""`) | `z`: E-mail de registro.<br>`y`: Adaptador Certbot (`dns-<proveedor>`, ej: `dns-route53`); otro que el guardado pide la contraseña actual en `b`.<br>`x`: con `a="0"`, `1` deja además de usar el certificado (§8.1). |
| **`cfgS`** | `"1"` = Activar HTTPS<br>`"0"` = Desactivar HTTPS (pide la contraseña actual en `b`) | Dominio Web | Subdominio o Vacío (`""`) | `a` es `"0"` o `"1"` exactamente: otro valor (`"2"`, `"true"`) se rechaza con 400. |
| **`cfgR`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Solo vacío (`""`): se configura en la raíz del sitio | Redirige `www.<sitio>` a `<sitio>` (301). Con un subdominio, o para el sitio `*` (que atiende cualquier host, direcciones IP incluidas), HTTP 400. |
| **`cfgW`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Solo vacío (`""`): se configura en la raíz del sitio | Redirige `<sitio>` a `www.<sitio>` (301). Con un subdominio, o para el sitio `*`, HTTP 400. |
| **`cfgE`** | E-mail a registrar, o vacío para quitarlo | Dominio Web | Subdominio o Vacío (`""`) | Modifica silenciosamente el E-mail para futuras renovaciones de Certbot. Sin e-mail, el certificado se queda y ya no se renueva (`"E-mail removed"`; `"E-mail unchanged"` si no había ninguno): quitarlo pide la contraseña actual en `b`. El valor se guarda tal como llega (un `+` enviado como `%2B` queda `+`). |
| **`cfgA`** | Nombre del Adaptador (`dns-<proveedor>`, o vacío para webroot) | Dominio Web | Subdominio o Vacío (`""`) | Modifica el adaptador de Certbot, tomado tal como llega. Otro que el guardado pide la contraseña actual en `b`: con uno equivocado, fallan todas las renovaciones. |
| **`cfgZ`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Subdominio o Vacío (`""`) | Archivos precomprimidos, apagado por defecto: una petición que acepta `br` o `gzip` se responde con el `<archivo>.br` o el `<archivo>.gz` que hay junto al archivo que nombra (§8.4). Cada sitio y cada subdominio tiene el suyo. |

### 8.1. Detalle Operativo: Emisión de Certificados (`cfgC`)
Certbot solo se ejecuta cuando se pide con `a="1"`, y requiere un e-mail (guardado con `cfgE` o enviado en `z`); sin él, la API responde HTTP 400 `"E-mail required to create the certificate"`. Si el sitio ya tiene un certificado de menos de 75 días, la API responde `"SSL certificate active"` sin ejecutar Certbot. Con `a="0"`, los archivos del certificado se borran tengan la antigüedad que tengan y la API responde `"SSL certificate deleted"`; sin certificado en disco, no se borra nada y la API responde HTTP 400 `"No certificate"`; mientras Certbot lo emite o lo renueva, o espera para hacerlo, HTTP 400 `"The certificate is being issued or renewed: delete it once Certbot is done"`. El certificado en uso sigue hasta que se instale otro o Turbo se reinicie, para que sustituir un certificado no deje un hueco, salvo que se envíe `x=1`: entonces deja de usarse en el acto (`"SSL certificate deleted, and no longer in use"`; o `"SSL certificate no longer in use"`, para el que un borrado anterior dejó en uso, sin archivos que borrar). El sitio conserva su ajuste de HTTPS, pero no tiene HTTPS, ni se redirige a él, hasta que se instale otro certificado, que se pone en uso solo. Otro valor de `x` que no sea `0` o `1` se rechaza (HTTP 400). El e-mail de `cfgE` y el de `z` se comprueban igual: de 5 a 40 bytes, una `@` con algo delante y un dominio con un punto detrás, y sin espacios, `#`, `--` ni un `-` al principio (HTTP 400 `"Invalid e-mail value"` o `"Invalid e-mail length"`). Un `z` válido (y un `y` que se pueda usar) se guarda al leer la petición, también cuando la respuesta es después un error (`"No certificate"`, o el error de Certbot pendiente).

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

La interfaz lo hace sola: tras un 202 vuelve a preguntar cada 5 segundos, como máximo durante 11 minutos, y muestra el resultado. Certbot tiene 3 minutos, y 10 con un adaptador DNS. Cancelar cualquier paso de su diálogo (e-mail, adaptador, confirmación) no envía nada, y vaciar un adaptador que estaba guardado pregunta si se vuelve a webroot (`cfgA` con el valor vacío); otro adaptador que el guardado pide la contraseña actual.

### 8.2. El Certificado Propio del Panel (`cfgPC`)
`POST /admin:inside:cfgPC` emite o borra el certificado de los hosts propios del panel: los nombres de host de `PA` (las direcciones IP quedan fuera). No lleva `s` ni `d`.

* `a="1"`: ejecuta Certbot como `cfgC`, con un `-d` por cada host de `PA`, en modo webroot (`turbo.panel/webroot` dentro del directorio de sitios; Turbo responde a sus retos, `/.well-known/acme-challenge/<token>`, solo en los hosts de `PA`) o con el adaptador; Certbot trabaja en `turbo.certificates/turbo.panel`, y los archivos acaban en `turbo.panel/`. Las respuestas son las de `cfgC` (202 `WAIT` mientras corre, una emisión a la vez entre sitios y panel; 200 `"Panel certificate active"` cuando está en uso un certificado que cubre todos los hosts de `PA` y caduca en más de 30 días; 400 con el error del último intento, una vez). Sin e-mail: 400 `"E-mail required to create the certificate"`; sin un nombre de host en `PA`: 400.
* `a="0"`: borra `turbo.panel/fullchain.pem` y `privkey.pem` y deja de usar el certificado. Pide la contraseña actual en `b`, como `cfgC` con `a="0"`, y por HTTPS su respuesta envía `Strict-Transport-Security: max-age=0`, para que los navegadores puedan volver al panel por HTTP, como toda respuesta en el host del panel una vez que ningún certificado lo cubre (también la de un `setM` a un directorio sin `turbo.panel`); sin los archivos, 400 `"No panel certificate"`, también con esa cabecera. Si no se pueden borrar, 400 `"Error deleting the panel certificate files"`, y el certificado sigue en uso.
* `z`: el e-mail, que se guarda como `PCE` en `.` de `turbo.config`. `y`: el adaptador DNS (`dns-<proveedor>`), que se guarda como `PCA`; un `y` vacío vuelve a webroot, y sin `y` se mantiene el guardado. Un `y` distinto del guardado pide la contraseña actual en `b`, y `a="0"` mientras Certbot trabaja en él se rechaza con 400, como en `cfgC`.

La renovación automática también renueva el certificado del panel cuando caduca en menos de 30 días, y `/admin:inside:sites` da su estado en `.` como `PCC` (con `PCE` y `PCA` si están fijados): `true` (en uso), `"WAIT"` (Certbot en marcha) o `false`. Un certificado colocado a mano en `turbo.panel/` también se usa, pero no se renueva.

### 8.3. Detalle Operativo: Activación SSL en Caliente (`cfgS`)
Turbo no requiere reinicios para aplicar certificados. Cuando se recibe la orden de activación (`a="1"`):
1. Go lee los archivos `fullchain.pem` y `privkey.pem` directamente del disco y los inyecta inmediatamente en la memoria RAM compartida del servidor.
2. Si el puerto `443` (o la dirección de `TURBO_HTTPS_ADDR`) estaba cerrado (porque el servidor arrancó sin certificados), **se inicia un nuevo socket Listener automáticamente**.
3. A partir de este momento, Turbo fuerza una redirección `301 Moved Permanently` a `https://`, en el mismo host, para el tráfico HTTP que ingrese a ese dominio/subdominio cuando un certificado cubre el host pedido. Un alias sin un certificado que cubra su nombre se sigue sirviendo por HTTP.

En el handshake TLS, cada nombre recibe el certificado que lo cubre (exactamente o con un wildcard). Los nombres que ningún certificado cubre y las conexiones sin SNI (acceso por IP) se rechazan.

*Nota: Desactivar HTTPS (`a="0"`) purga el certificado de la memoria RAM (impidiendo futuras conexiones TLS para ese host, salvo que lo cubra otro certificado en uso: un comodín de su sitio padre, o el del panel), pero **no elimina** los archivos `.pem` del disco ni cierra el puerto 443 a nivel de red.*

### 8.4. Detalle Operativo: Archivos Precomprimidos (`cfgZ`)
Turbo no comprime sus respuestas. Un sitio, o un subdominio, con `cfgZ` en `"1"` sirve las copias comprimidas que su despliegue deja junto a cada archivo, con el nombre del archivo más `.br` (Brotli) o `.gz` (gzip): `site.css.br` para `site.css`. En `turbo.config` y en el JSON del panel es `"Z"`, entre los ajustes (`"!"`) del sitio.
* **Quién recibe una copia:** un `GET` o un `HEAD` cuyo `Accept-Encoding` acepta su codificación: nombrada con un `q` mayor que 0, o sin nombrar cuando `*` lo tiene. Si acepta las dos, la de mayor `q`, y `br` si tienen el mismo. Sin la cabecera, con una que no está escrita como dice HTTP, o cuando la copia no está, se sirve el archivo tal cual.
* **La respuesta:** `Content-Encoding` (`br` o `gzip`), el `Content-Type` del archivo (el del sitio para su extensión, o el de lo que el archivo contiene), el `Content-Length` de la copia y un `ETag` propio, con el que `If-None-Match` recibe su 304. Toda respuesta del sitio para un archivo, comprimida o no, lleva `Vary: Accept-Encoding`, añadido al `Vary` del sitio si lo pone.
* **Nunca una copia:** para una petición con `Range` (un rango es del archivo tal cual, y las respuestas con copia no ofrecen rangos); para un archivo que ejecuta un preprocesador; en un sitio cuyos preprocesadores incluyen `br` o `gz`, o cuyas cabeceras ponen `Content-Encoding` o `ETag`; para una URL que termina en `/index.html`; y cuando la copia está vacía, es una carpeta, o es un enlace que lleva fuera del sitio.
* **No se comparan las fechas:** una copia más antigua que su archivo se sirve igual, porque un despliegue que escribiera cada copia un momento antes que su archivo la dejaría sin usar. Quien cambia un archivo vuelve a generar sus copias, o las borra.
* Las copias son archivos del sitio como cualquier otro: `site.css.br` también se sirve por su propio nombre, tal cual.

---

## 9. API de Gestión Física de Archivos (`hardUpload`)

Utilizado para sustituir masivamente todos los archivos públicos asociados a un subdominio/dominio. El servidor escribe los archivos nuevos en una carpeta propia junto a `@` (`@.upload-<aleatorio>`) y después la pone en lugar de `@` de una vez (la `@` anterior es `@.previous-<aleatorio>` un instante, y después se borra), así que el contenido existente (subcarpetas incluidas) se sustituye entero: hasta entonces, `@` queda como estaba, y si algo falla, no cambia nada.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Formato del Cuerpo:** `multipart/form-data`
* **Parámetros de Formulario:**
  * `s`: Dominio principal (ej: `example.com`).
  * `d`: Subdominio (vacío `""` si se trata del dominio raíz).
  * `f`: Array de archivos adjuntos (`File[]`).
  * `b`: la contraseña actual, solo en el cuerpo multipart (nunca en la URL, que `turbo.visits` registra), y antes del primer archivo: se comprueba antes de leer los archivos.

  `s` y `d` se aceptan tanto en la URL como en el cuerpo *multipart*.
* **Manejo de Directorios Anidados:** 
  El backend analiza el parámetro `filename` dentro del encabezado HTTP `Content-Disposition` de cada bloque *multipart*. Se descarta el primer segmento de cada ruta (la carpeta elegida en el navegador), y `\` cuenta como separador. Si el resto del nombre contiene rutas relativas (ej: `sitio/assets/img/logo.png` → `assets/img/logo.png`), Turbo creará la estructura de carpetas. Un archivo y una carpeta no pueden tener el mismo nombre: de `a` y `a/b`, se descarta el segundo (sin distinguir mayúsculas en Windows y macOS). También los nombres que los sistemas de archivos no admiten: un nombre de archivo o carpeta de más de 255 bytes, o una ruta dentro de `@` de más de 1.024 bytes. Los nombres que saldrían de `@` (con `..`, absolutos o con `:`) se descartan, y también, en todos los sistemas, los que Windows trata de forma especial: acabados en `.` o en espacio, un nombre de dispositivo reservado (`CON`, `NUL`, `COM1`…), `~` seguido de un dígito (nombres cortos 8.3) o un carácter que Windows no admite (`<`, `>`, `"`, `|`, `?`, `*` y los de control).
* **Respuesta Exitosa (HTTP 200 OK):**
  Devuelve la cadena `"Data uploaded"`. Si se descartó algún archivo, la respuesta los enumera: `"Data uploaded. Discarded: <nombre>, <nombre>"`.
* **Manejo de Errores Específicos:**
  * Si el peso de la subida supera el límite global `MBB` (Max Body Bytes), o lleva más de 10 000 partes (los archivos y el campo `b`), la API corta la lectura y retorna HTTP 413 con el mensaje `"Maximum body size exceeded"`. Un cuerpo *multipart* mal formado recibe HTTP 400 `"Invalid parameters"`. (Los demás formularios multipart admiten como mucho 1 000 partes.) `MBB` acota la memoria que ocupa la subida, que se guarda en memoria: el contenido más unos 600 bytes por archivo (su nombre, cabeceras y entrada), así que un archivo de exactamente `MBB` bytes nunca cabe, y un sitio de muchos archivos pequeños necesita sitio para ellos. Como cada subida sustituye `@` entera, la salida de un 413 es un `MBB` mayor, no subir menos archivos; el panel lo dice.
  * Si `b` va después de un archivo, HTTP 400 `"The current password (b) must come before the files"`; si falta, o los campos anteriores al primer archivo ocupan más de 64 KiB o están mal formados, HTTP 400 también (`"Missing data: the current password (b), before the files"`; un cuerpo mal formado más adelante sigue recibiendo `"Invalid parameters"`). Una contraseña errónea se responde antes de leer los archivos, y la conexión se cierra.
  * Si se descartan todos los nombres, HTTP 400 `"No valid file; nothing was changed. Discarded: …"`, y `@` queda como estaba.
  * Si la carpeta del sitio no admite la subida (no se puede crear en ella la carpeta `@.upload-<aleatorio>`), HTTP 500 `"Directory inaccessible"`, que se registra.
  * Si Turbo se para entre los dos renombrados, el sitio queda sin `@`: en el arranque siguiente, antes de servir, Turbo vuelve a poner la `@.previous-<aleatorio>` si es la única que hay. De una `@.previous-<aleatorio>` junto a una `@` en su sitio solo se avisa.
  * Si no se puede sustituir `@` (en Windows, por ejemplo, mientras un archivo suyo está abierto), HTTP 400 `"The public directory could not be replaced (open files?); nothing was changed"`; un archivo que no se puede escribir da HTTP 500. En los dos casos `@` queda como estaba.
  * Si el sitio se borra durante la subida, HTTP 400 `"Site not found"`, y el sitio no vuelve a aparecer.
  * Si no llega ningún archivo en `f`, HTTP 400 `"No data"`.

---

## 10. Estándar de Códigos de Respuesta HTTP de la API

| Código HTTP | Significado Funcional | Causa y Cuerpo de la Petición |
|---|---|---|
| **`200 OK`** | Operación Procesada | La orden se ejecutó en memoria y/o disco. Devuelve un texto plano de confirmación (ej: `"Subdomain added"`). |
| **`202 Accepted`** | En Proceso | Solo `cfgC` y `cfgPC` mientras se emite un certificado: un cuerpo JSON con `"status":"WAIT"` (§8.1). Siga consultando. |
| **`400 Bad Request`** | Fallo de Validación / Lógica | Parámetros nulos, formato inválido, recurso inexistente, contraseñas erróneas o restricciones de límites sobrepasadas. El Body contiene el string del error literal que debe mostrarse al usuario. La quinta contraseña actual errónea en una sesión la cierra, con `X-Turbo-Login: required` (§3.1). |
| **`403 Forbidden`** | Bloqueo de Acceso | Login con credenciales incorrectas (Body vacío), un login desde otro origen, o con la contraseña por defecto desde otro sitio que no sea esta máquina (`X-Turbo-Login: local-only`, §3.1), o un `POST` autenticado con la cookie de sesión que no viene del mismo origen (§1.2). |
| **`404 Not Found`** | URL Incorrecta | Se ha consultado una URI (`RequestURI`) dentro del prefijo `/admin:` que no corresponde a ningún endpoint listado, o el panel no responde en ese host o red (`PA`). |
| **`413 Payload Too Large`** | Parámetros demasiado grandes | Los parámetros de una acción (o el cuerpo del login, §3.1) superan lo permitido: `MBB`, y como mucho 10 MiB en un cuerpo `application/x-www-form-urlencoded`. Una subida de archivos (§9) demasiado grande también recibe `413`. Los parámetros que no se pueden decodificar (por ejemplo, un escape `%` mal formado) reciben `400` `"Invalid parameters"`. |
| **`429 Too Many Requests`** | *Rate Limiter* Activado | La IP del cliente superó sus límites (CIL/CIS/CII), la IP está denegada (§7.1), o sus logins están bloqueados tras logins fallidos, o ya se comprueban cinco contraseñas actuales de la sesión (§3.1). Cada petición cuenta una vez. La respuesta lleva `Retry-After` con los segundos de espera, y las conexiones nuevas de una IP bloqueada se cierran. |
| **`503 Service Unavailable`** | Límite global alcanzado | El servidor en conjunto recibió más de `CGL` peticiones en el segundo actual (`Retry-After: 1`), la contraseña de un login o la contraseña actual de un `set<CLAVE>` o de una acción que la pide no se pudo comprobar en 2 segundos, o la contraseña nueva de `setP` derivar (`Retry-After: 2`, §3.1), o un CGI no encontró hueco en 2 segundos (`CGP`, `Retry-After: 2`), o los cuerpos de las peticiones de los CGI no caben en sus archivos temporales, o en la parte de ellos del cliente (`Retry-After: 2`). |
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
