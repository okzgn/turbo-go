# Turbo - API, Especificación Técnica

## 1. Arquitectura General y Protocolo de Comunicación

El backend de Turbo proporciona una API de estilo **RPC/REST sobre HTTP POST**. Toda la interacción entre la interfaz visual (GUI) o cualquier cliente externo y el servidor se realiza exclusivamente mediante peticiones `POST`.

### 1.1. Rutas de Acceso Principales (Base URLs)
* **Autenticación Pública / Login:** `/admin:`
* **Módulo Administrativo Autenticado:** `/admin:inside:`
* **Cierre de Sesión:** `/admin:signout:`

### 1.2. Cabeceras y Seguridad
* **Método HTTP:** Obligatoriamente `POST` para todas las acciones de la API.
* **Parámetros:** Los parámetros de las acciones (`s`, `d`, `a`, `b`…) pueden ir en la consulta de la URL o en un cuerpo `application/x-www-form-urlencoded`. La GUI los envía en el cuerpo, así que la contraseña actual (`b`) nunca aparece en la URL que registra `turbo.visits`; los clientes de la API deberían hacer lo mismo.
* **Manejo de Sesión:** Tras un login correcto, el servidor fija la cookie de sesión `turbo_session` (`Path=/; HttpOnly; SameSite=Strict`, más `Secure` cuando la petición llega por HTTPS), que el navegador envía por sí solo. Los clientes de la API pueden enviar en su lugar el token en la cabecera `ok: <token>`. Si llegan ambas, se usa la cookie. El token **no** se acepta como parámetro en la URL. La cookie `turbo_session` se quita de la cabecera `Cookie` que se pasa a los preprocesadores CGI.
* **Mismo Origen:** Un `POST` a `/admin:inside:` autenticado con la cookie debe venir del propio origen del panel: el navegador debe enviar `Sec-Fetch-Site: same-origin` (o `none`) o, sin `Sec-Fetch-Site`, una cabecera `Origin` igual a `<esquema>://<Host>`. Si no, el servidor responde `403`. Las peticiones autenticadas con la cabecera `ok` no lo necesitan.
* **Cabeceras de las Respuestas del Panel:** Las respuestas bajo `/admin:` llevan `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'` y `Cache-Control: no-store`.
* **Dónde Responde el Panel:** El ajuste global `PA` (ver `setPA`, §5) puede limitar `/admin:` a una lista de hosts o redes CIDR. Fuera de la lista, `/admin:` responde `404`. Vacío (por defecto) significa sin restricción.
* **CORS (Intercambio de Origen Cruzado):**
  * `Access-Control-Allow-Origin: default://home`
  * `Access-Control-Allow-Headers: ok`
* **Ciclo de Vida de la Sesión:** Los tokens son asignados a la IP del cliente y expiran tras **600 segundos (10 minutos)** de inactividad. Cada petición a `/admin:inside:` renueva el temporizador. Sin una sesión válida, `/admin:inside:` devuelve la redirección HTML a `/admin:` (ver §3.2).

---

## 2. Convenciones de Codificación de Datos y Reemplazo de Caracteres

Para evitar que caracteres especiales y delimitadores de URL interfieran o corrompan las peticiones HTTP (especialmente en reglas de reescritura o cabeceras), el backend exige que ciertos caracteres se codifiquen mediante una sustitución predefinida:

### 2.1. Sustituciones Inmutables (Fijas)
Cualquier parámetro de formulario (como `a`, `b`, `s`, `d`) es procesado en el servidor por la función de reemplazo de caracteres URI. Las siguientes sustituciones deben aplicarse en el lado del cliente antes de enviar la petición:

| Carácter Original | Token de Transmisión Esperado |
|---|---|
| `;` (Punto y coma) | `-.-` |
| `#` (Almohadilla) | `-,-` |
| `&` (Ampersand) | `-_-` |

*Nota: Los administradores pueden añadir reemplazos de caracteres adicionales dinámicamente mediante el endpoint `addCharsReplace`.*

---

## 3. API de Autenticación y Control de Sesión

### 3.1. Iniciar Sesión (Login)
Valida las credenciales del usuario y genera un token único enlazado a la dirección IP del cliente. *Nota: Puede ser frágil detrás de NAT/proxies compartidos, donde varios usuarios comparten una IP pública.*

* **Endpoint:** `POST /admin:`
* **Formato del Cuerpo:** `multipart/form-data`
* **Parámetros Requeridos:**
  * `u`: Nombre de usuario.
  * `p`: Contraseña.
* **Respuesta Exitosa (HTTP 200 OK):**
  El servidor genera un token opaco criptográficamente seguro (32 bytes aleatorios, 64 caracteres hexadecimales), distinto en cada login y asociado a la IP del cliente. Fija con él la cookie `turbo_session`, y el cuerpo contiene el token prefijado por la variable de éxito (por defecto `"ok"`), para los clientes que usan la cabecera `ok`.
  ```text
  ok<token>
  ```
* **Credenciales Incorrectas:** HTTP 403 con el cuerpo vacío.

### 3.2. Cerrar Sesión (Logout)
Invalida el token actual en la memoria RAM (las demás sesiones de la misma IP siguen activas) y caduca la cookie `turbo_session` (`Max-Age=0`).

* **Endpoint:** `POST /admin:signout:`
* **Autenticación:** La cookie de sesión o la cabecera `ok`.
* **Respuesta Exitosa (HTTP 200 OK):** 
  Devuelve un string HTML forzando la redirección del navegador.
  ```html
  <meta http-equiv='refresh' content='0; URL=/admin:'/>
  ```

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
    "sitio1.com": {
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "0",
        "E": "admin%40sitio1.com",
        "A": ""
      }
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
      "CII": "100"
    }
  }
  ```
  *(Nota: Las entradas fijas, que no se pueden borrar, se devuelven como `{"f": <valor>}`. Los valores de texto del bloque `!` van codificados para URL, p. ej. `@` → `%40`).*

### 4.2. Obtener Lista de Subdominios de un Sitio
Devuelve un objeto JSON con todos los subdominios que pertenecen a un dominio raíz específico, incluyendo el alias (si aplica) y la configuración SSL/Redirecciones de cada uno.

* **Endpoint:** `POST /admin:inside:subdomains`
* **Parámetros de Formulario:**
  * `s`: Dominio principal (ej: `ejemplo.com`).
* **Respuesta Exitosa (JSON):**
  La respuesta incluye siempre el subdominio raíz (bajo el nombre del dominio) y los demás subdominios anidados. El bloque `!` contiene el estado de la configuración (1 = Activado, 0 = Desactivado).
  ```json
  {
    "ejemplo.com": {
      "&": {},
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "1",
        "E": "contacto%40ejemplo.com",
        "A": ""
      }
    },
    "api": {
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "0",
        "E": "api-admin%40ejemplo.com",
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
  *(Nota: En este ejemplo, `*.dev` representa un subdominio wildcard que abarca cualquier petición dinámica de segundo nivel bajo `dev`, como `test.dev` o `admin.test.dev`).*

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

## 5. API de Configuración General (`set<KEY>`)

Modifica los parámetros globales del servidor y sus límites operativos. Varias de estas acciones forzan la reescritura del archivo `turbo.config` y el reinicio interno en caliente de la configuración.

* **Ruta Base:** `POST /admin:inside:set<CLAVE>`
* **Parámetros Requeridos:** `a` (valor) y `b` (contraseña actual) en **todos** los `set<CLAVE>`. Si falta `b`, el servidor responde HTTP 400 `"Faltan datos"`; si es incorrecta, HTTP 400 `"Contraseña actual incorrecta"`. Un valor igual al actual también se responde con HTTP 400 (por ejemplo, `"Usuario sin cambios"` o `"Contraseña sin cambios"`).

| Endpoint | Parámetro `a` | Parámetro `b` | Descripción / Validación |
|---|---|---|---|
| `setU` | Nuevo Usuario | Contraseña Actual | Cambia el nombre de usuario (1-24 chars). |
| `setP` | Nueva Contraseña | Contraseña Actual | Cambia la contraseña (1-24 chars). |
| `setM` | Ruta Directorio | Contraseña Actual | Cambia el directorio base de sitios (debe existir) y recarga la configuración. |
| `setC` | (Ignorado; `sobrescribir` para confirmar, ver abajo) | Contraseña Actual | Vuelca la configuración RAM actual al disco (`turbo.config`), incluidos el usuario y el hash de la contraseña (nunca la contraseña en claro). |
| `setPA` | Hosts / redes CIDR | Contraseña Actual | Dónde responde el panel: nombres de host y/o redes CIDR separados por comas (como máximo 32 entradas y 1,024 chars). Vacío o `*` = sin restricción. |
| `setMUB` | Valor entero | Contraseña Actual | Ajusta la longitud máxima de URI (40 - 10,240 bytes). |
| `setMHB` | Valor entero | Contraseña Actual | Ajusta la longitud máx. de cabeceras (600 - 20,480 bytes). |
| `setMBB` | Valor entero | Contraseña Actual | Ajusta tamaño máx. de cuerpo (1B - 100MB). |
| `setCIL` | Valor ms | Contraseña Actual | Reinicio de contador (1,000 - 800,000 ms). |
| `setCIS` | Valor ms | Contraseña Actual | Ventana de conteo (10 - 50,000 ms). |
| `setCII` | Valor entero | Contraseña Actual | Límite de peticiones por intervalo: de 1 hasta el valor de `CIS` en ms, y `CIS`/`CII` ≤ 66. |
| `setRT` | Tiempo (`5s`, `0s`) | Contraseña Actual | Read Timeout total de petición (100 ms - 15 min; `0s` lo desactiva). |
| `setRHT` | Tiempo (`1s`, `0s`) | Contraseña Actual | Read Header Timeout (50 ms - 7.5 min y como máximo la mitad de `RT`; `0s` lo desactiva). |
| `setWT` | Tiempo (`10s`, `0s`) | Contraseña Actual | Write Timeout para respuestas (100 ms - 30 min; `0s` lo desactiva). |
| `setIT` | Tiempo (`2s`, `0s`) | Contraseña Actual | Idle Timeout para *Keep-Alive* (100 ms - 5 min; `0s` lo desactiva). |

*Notas:*
* *`setPA`: Las entradas de host se comparan con la cabecera `Host` de la petición, que elige el cliente: mantienen el panel fuera de otros dominios, pero no limitan quién puede acceder. Lo que limita el acceso son las redes CIDR, que se comparan con la IP del cliente.*
* *`setC`: Si `turbo.config` lo escribió una versión posterior de Turbo (un esquema posterior), guardar perdería sus ajustes nuevos, así que el servidor responde HTTP 400 con una explicación; para confirmar y sobrescribirlo, envíe `a=sobrescribir`. La primera vez que se guarda un archivo de un esquema anterior, el original se conserva como `turbo.config.v<esquema>.bak`. Si el directorio de sitios no es el directorio de arranque, en este se escribe además un `turbo.config` mínimo que apunta a aquel.*

---

## 6. API de Gestión de Recursos del Sitio (Añadir y Eliminar)

El backend maneja las creaciones de carpetas en disco y modificaciones en los mapas RAM. *Nota sobre comodines: Enviar los dominios con asteriscos (ej. `*.ejemplo.com`). El servidor los traducirá a `#` físicamente en el disco de manera transparente.*

### 6.1. Añadir/Actualizar Recursos (`add<Tipo>`)
* **Ruta Base:** `POST /admin:inside:add<TIPO>`

| Endpoint | `s` (Dominio) | `d` (Subdominio) | `a` (Clave/Identificador) | `b` (Valor/Ruta) |
|---|---|---|---|---|
| `addSite` | Dominio Web | - | - | - |
| `addSubdomain` | Dominio Web | Subdominio | - | - |
| `addRewrite` | Dominio Web | Subdominio | URI de origen (ej: `/old`) | Reescritura (`/new`, `http://...`, `https://...`), [palabras clave dinámicas disponibles](https://turbo-server.github.io/#so-2)|
| `addMIME` | Dominio Web | Subdominio | Extensión (ej: `png`) | Tipo MIME (ej: `image/png`) |
| `addHeader` | Dominio Web | Subdominio | Nombre Cabecera | Valor Cabecera |
| `addPreprocessor`| Dominio Web | Subdominio | Extensión (ej: `php`) | Ejecutable CGI (ej: `/usr/bin/php-cgi`) |
| `addIndex` | Dominio Web | Subdominio | Archivo Índice (`index.html`)| - |
| `addAlias` | Dominio Web | Subdominio | Dominio Alias | - |

*Notas:*
* *`addRewrite`: La reescritura debe empezar por `/` (ruta interna), `http://` o `https://`. Los destinos con `http://` o `https://` se responden con una redirección `302`: al destino exacto si tiene ruta o consulta, o al dominio de destino seguido del URI original si es solo un dominio.*
* *`addPreprocessor`: La ruta del ejecutable (como máximo 128 caracteres) debe existir; el prefijo `cgi>` es opcional y cualquier otro prefijo se rechaza.*
* *`addIndex`: El índice se añade al final del orden; los índices se prueban en el orden en que se añadieron. Los sitios y subdominios nuevos empiezan con `index.html`.*

### 6.2. Eliminar Recursos (`del<Tipo>`)
* **Ruta Base:** `POST /admin:inside:del<TIPO>`

| Endpoint | `s` (Dominio) | `d` (Subdominio) | `a` (Clave/Identificador a borrar) |
|---|---|---|---|
| `delSite` | Dominio Web | Subdominio (Vacío = Borrar Sitio) | - |
| `delRewrite` | Dominio Web | Subdominio | URI origen |
| `delMIME` | Dominio Web | Subdominio | Extensión |
| `delHeader` | Dominio Web | Subdominio | Nombre de Cabecera |
| `delPreprocessor`| Dominio Web | Subdominio | Extensión |
| `delIndex` | Dominio Web | Subdominio | Archivo Índice |
| `delAlias` | Dominio Web | Subdominio | Dominio Alias |

*Los tres parámetros son obligatorios (salvo `a` en `delSite`): si falta alguno, la respuesta es `400` "Faltan datos".*

---

## 7. API de Seguridad Global e Interfaz

### 7.1. Control de IPs Denegadas
Una IP denegada queda bloqueada hasta la fecha indicada: sus peticiones se responden con HTTP 429 y la cabecera `Retry-After` (segundos restantes), y sus conexiones nuevas se cierran.

* **`POST /admin:inside:addDenied`**
  * `s`: Dirección IP (IPv4 o IPv6). No se aceptan direcciones de loopback (`127.x.x.x`, `::1`) ni la dirección desde la que se hace la petición (`400` "IP actual": el panel se bloquearía a sí mismo).
  * `d`: Timestamp UNIX de expiración de bloqueo (`0` o una fecha pasada elimina un bloqueo existente).
* **`POST /admin:inside:delDenied`**
  * `s`: Dirección IP a desbloquear de la lista de IPs denegadas.

### 7.2. Respuestas a Códigos HTTP
* **`POST /admin:inside:addHttpCodeResponse`**
  * `s`: Código de estado HTTP (entre `400` y `599`, o `0` para fallback universal).
  * `d`: Plantilla de respuesta. Se admiten saltos de línea y la macro `{TURBO_RESPONSE_CODE}`.
* **`POST /admin:inside:delHttpCodeResponse`**
  * `s`: Código de estado HTTP a devolver a comportamiento por defecto del sistema.

### 7.3. Reemplazo Global de Caracteres en URIs
* **`POST /admin:inside:addCharsReplace`**
  * `s`: Secuencia de caracteres a reemplazar (ej: `;`).
  * `d`: Cifra codificada objetivo (ej: `-.-`).
* **`POST /admin:inside:delCharsReplace`**
  * `s`: Secuencia de caracteres que deja de reemplazarse (las sustituciones fijas de §2.1 no se pueden borrar).

---

## 8. API de Certificados SSL y Redirecciones (`cfg<KEY>`)

Gestiona la habilitación de HTTPS, redirecciones en la capa de aplicación y la configuración/emisión de certificados mediante Certbot.

* **Ruta Base:** `POST /admin:inside:cfg<CLAVE>`

| Endpoint | Parámetro `a` (Acción) | Parámetro `s` (Dominio) | Parámetro `d` (Subdominio) | Parámetros Opcionales |
|---|---|---|---|---|
| **`cfgC`** | `"1"` = Ejecutar Certbot<br>`"0"` = Eliminar del disco | Dominio Web | Subdominio o Vacío (`""`) | `z`: E-mail de registro.<br>`y`: Adaptador Certbot (`dns-<proveedor>`, ej: `dns-route53`). |
| **`cfgS`** | `"1"` = Activar HTTPS<br>`"0"` = Desactivar HTTPS | Dominio Web | Subdominio o Vacío (`""`) | - |
| **`cfgR`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Subdominio o Vacío (`""`) | *Solo aplica al subdominio `www`.* Activa redirección a la Raíz. |
| **`cfgW`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Subdominio o Vacío (`""`) | *Solo aplica al subdominio Raíz.* Activa redirección a `www`. |
| **`cfgE`** | E-mail a registrar | Dominio Web | Subdominio o Vacío (`""`) | Modifica silenciosamente el E-mail para futuras renovaciones de Certbot. |
| **`cfgA`** | Nombre del Adaptador (`dns-<proveedor>`, o vacío para webroot) | Dominio Web | Subdominio o Vacío (`""`) | Modifica silenciosamente el flag del Adaptador para Certbot. |

### 8.1. Detalle Operativo: Emisión de Certificados (`cfgC`)
Certbot solo se ejecuta cuando se pide con `a="1"`, y requiere un e-mail (guardado con `cfgE` o enviado en `z`); sin él, la API responde HTTP 400 `"E-mail obligatorio para crear el certificado"`. Si el sitio ya tiene un certificado de menos de 75 días, la API responde `"Certificado SSL activo"` sin ejecutar Certbot. Con `a="0"` y sin certificado en disco, no se borra nada y la API responde HTTP 400 `"Sin certificado"`.

La emisión o renovación de certificados no bloquea el servidor. Al enviar `a="1"`, la API delega el trabajo a una Goroutine separada que se encarga de:
1. Ejecutar el binario de Certbot en modo webroot o mediante el adaptador especificado, con su carpeta de trabajo en `turbo.certificates/<sitio>`.
2. Leer la carpeta temporal de *archive*, localizar los archivos más recientes (`fullchain*.pem` y `privkey*.pem`) que tengan menos de 2.5 días (216,000 segundos) de creados.
3. Mover y renombrar físicamente estos archivos a la ruta raíz del sitio en Turbo.

**Renovación Automática:** Al arrancar y cada 24 horas, Turbo renueva los certificados que emitió él (sitios con e-mail y carpeta en `turbo.certificates`) cuando caducan en menos de 30 días, y los carga sin reiniciar. Los certificados puestos a mano no se renuevan.

**Flujo de Polling HTTP para el Frontend:**
Como la operación es asíncrona, el frontend debe realizar peticiones continuas (Polling) al endpoint `cfgC` evaluando la respuesta JSON:
* `{"message":"Espere, certificado en proceso","status":"WAIT"}`: La Goroutine acaba de iniciarse.
* `{"message":"Espere, certificado procesándose","status":"WAIT"}`: Certbot está trabajando.
* `{"message":"Espere, certificado ocupado en <dominio>","status":"WAIT"}`: Certbot está ocupado emitiendo un certificado para otro sitio.
* **Respuesta Exitosa (200 OK):** `"Certificado SSL activo"` (El cliente debe detener el polling).
* **Respuesta de Error (400 Bad Request):** Devuelve la salida cruda de error de Certbot o del sistema de archivos.

### 8.2. Detalle Operativo: Activación SSL en Caliente (`cfgS`)
Turbo no requiere reinicios para aplicar certificados. Cuando se recibe la orden de activación (`a="1"`):
1. Go lee los archivos `fullchain.pem` y `privkey.pem` directamente del disco y los inyecta inmediatamente en la memoria RAM compartida del servidor.
2. Si el puerto `443` (o la dirección de `TURBO_HTTPS_ADDR`) estaba cerrado (porque el servidor arrancó sin certificados), **se inicia un nuevo socket Listener automáticamente**.
3. A partir de este momento, Turbo fuerza una redirección `301 Moved Permanently` a `https://`, en el mismo host, para el tráfico HTTP que ingrese a ese dominio/subdominio cuando un certificado cubre el host pedido. Un alias sin un certificado que cubra su nombre se sigue sirviendo por HTTP.

En el handshake TLS, cada nombre recibe el certificado que lo cubre (exactamente o con un wildcard). Los nombres que ningún certificado cubre y las conexiones sin SNI (acceso por IP) se rechazan.

*Nota: Desactivar HTTPS (`a="0"`) purga el certificado de la memoria RAM (impidiendo futuras conexiones TLS para ese host), pero **no elimina** los archivos `.pem` del disco ni cierra el puerto 443 a nivel de red.*

---

## 9. API de Gestión Física de Archivos (`hardUpload`)

Utilizado para sustituir masivamente todos los archivos públicos asociados a un subdominio/dominio. El servidor eliminará de manera destructiva todo el contenido existente en la carpeta de contenido (`@`), subcarpetas incluidas, y volcará los nuevos datos.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Formato del Cuerpo:** `multipart/form-data`
* **Parámetros de Formulario:**
  * `s`: Dominio principal (ej: `ejemplo.com`).
  * `d`: Subdominio (vacío `""` si se trata del dominio raíz).
  * `f`: Array de archivos adjuntos (`File[]`).

  `s` y `d` se aceptan tanto en la URL como en el cuerpo *multipart*.
* **Manejo de Directorios Anidados:** 
  El backend analiza el parámetro `filename` dentro del encabezado HTTP `Content-Disposition` de cada bloque *multipart*. Se descarta el primer segmento de cada ruta (la carpeta elegida en el navegador), y `\` cuenta como separador. Si el resto del nombre contiene rutas relativas (ej: `sitio/assets/img/logo.png` → `assets/img/logo.png`), Turbo creará la estructura de carpetas. Los nombres que saldrían de `@` (con `..`, absolutos o con `:`) se descartan.
* **Respuesta Exitosa (HTTP 200 OK):**
  Devuelve la cadena `"Datos volcados"`. Si se descartó algún archivo, la respuesta los enumera: `"Datos volcados. Descartados: <nombre>, <nombre>"`.
* **Manejo de Errores Específicos:**
  * Si el peso de la subida supera el límite global `MBB` (Max Body Bytes), la API corta la lectura y retorna HTTP 400 con el mensaje `"Longitud máxima de contenidos excedida"`.

---

## 10. Estándar de Códigos de Respuesta HTTP de la API

| Código HTTP | Significado Funcional | Causa y Cuerpo de la Petición |
|---|---|---|
| **`200 OK`** | Operación Procesada | La orden se ejecutó en memoria y/o disco. Devuelve un texto plano de confirmación (ej: `"Subdominio agregado"`). |
| **`400 Bad Request`** | Fallo de Validación / Lógica | Parámetros nulos, formato inválido, recurso inexistente, contraseñas erróneas o restricciones de límites sobrepasadas. El Body contiene el string del error literal que debe mostrarse al usuario. |
| **`403 Forbidden`** | Bloqueo de Acceso | Login con credenciales incorrectas (Body vacío), o un `POST` autenticado con la cookie de sesión que no viene del mismo origen (§1.2). |
| **`404 Not Found`** | URL Incorrecta | Se ha consultado una URI (`RequestURI`) dentro del prefijo `/admin:` que no corresponde a ningún endpoint listado, o el panel no responde en ese host o red (`PA`). |
| **`429 Too Many Requests`** | *Rate Limiter* Activado | La IP del cliente superó los límites estipulados por el control del servidor (CIL/CIS/CII), por IP o en global, o la IP está denegada (§7.1). Cada petición cuenta una vez. La respuesta lleva `Retry-After` con los segundos de espera, y las conexiones nuevas de una IP bloqueada se cierran. |
| **`500 Internal Server Error`** | Fallo Interno | Un error inesperado al procesar la acción. |

---

## License

Turbo uses a dual licensing model.

* **Open Source (AGPL v3):**

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License (AGPL v3) as published by the Free Software Foundation. If you modify this software and offer it as a service over a network, you must release your modifications under the same license. See: https://www.gnu.org/licenses/agpl-3.0.html

* **Commercial License:**

    For those who intend to use Turbo in a proprietary project, integrate it into a closed-source product, or opt out of the AGPL v3 requirements, a commercial license is available for purchase.

    For commercial licensing inquiries, please visit one of the following:
    - https://okzgn.com/#contact
    - https://okzgn.github.io/#contact

* **Third-Party Components:**

    The `customNetHttp` package contains a modified version of the Go standard library `net/http` (based on Go 1.26.x; the exact version is in `customNetHttp/UPSTREAM` and the changes in `customNetHttp/PATCHES.md`), which is distributed under the **BSD 3-Clause License**. Please refer to the `customNetHttp/LICENCE`, `customNetHttp/PATENTS` and `customNetHttp/NOTICE` files within that directory for full details and attribution.

---

Copyright (C) 2026 [OKZGN](https://okzgn.com)
