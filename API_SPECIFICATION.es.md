# Turbo - API, Especificación Técnica

## 1. Arquitectura General y Protocolo de Comunicación

El backend de Turbo proporciona una API de estilo **RPC/REST sobre HTTP POST**. Toda la interacción entre la interfaz visual (GUI) o cualquier cliente externo y el servidor se realiza exclusivamente mediante peticiones `POST`.

### 1.1. Rutas de Acceso Principales (Base URLs)
* **Autenticación Pública / Login:** `/admin:`
* **Módulo Administrativo Autenticado:** `/admin:inside:`
* **Cierre de Sesión:** `/admin:signout:`

### 1.2. Cabeceras y Seguridad
* **Método HTTP:** Obligatoriamente `POST` para todas las acciones de la API.
* **Manejo de Sesión:** El token de autenticación debe enviarse en la cabecera `ok: <token_hash>` o, alternativamente, como parámetro en la URL `?ok=<token_hash>`.
* **CORS (Intercambio de Origen Cruzado):**
  * `Access-Control-Allow-Origin: default://home`
  * `Access-Control-Allow-Headers: ok`
* **Ciclo de Vida de la Sesión:** Los tokens son asignados a la IP del cliente y expiran tras **60 segundos (1 minuto)** de inactividad. Cada petición exitosa renueva el temporizador.

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
  El servidor genera un token opaco criptográficamente seguro asociado a la IP del cliente. El cuerpo contendrá el token prefijado por la variable de éxito (por defecto `"ok"`).
  ```text
  ok<sha256_token_hash>
  ```

### 3.2. Cerrar Sesión (Logout)
Invalida el token actual en la memoria RAM y desconecta la sesión de la IP activa.

* **Endpoint:** `POST /admin:signout:`
* **Autenticación:** Cabecera `ok` requerida.
* **Respuesta Exitosa (HTTP 200 OK):** 
  Devuelve un string HTML forzando la redirección del navegador.
  ```html
  <meta http-equiv='refresh' content='0; URL=/admin:'/>
  ```

---

## 4. API de Consulta y Obtención de Estado (Data Retrieval)

Endpoints destinados a volcar el estado en memoria de la configuración hacia el cliente. Requieren la cabecera `ok: <token>`.

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
        "E": "admin@sitio1.com",
        "A": ""
      }
    },
    "_": {
      "-.-": ";",
      "-,-": "#",
      "-_-": "&"
    },
    "@": {
      "192.168.1.50": "1735689600"
    },
    "#": {
      "404": "Página no encontrada: {TURBO_RESPONSE_CODE}"
    },
    ".": {
      "M": "/home/server/",
      "RT": "5s",
      "RHT": "1s",
      "WT": "10s",
      "IT": "2s",
      "MUB": "1000",
      "MHB": "5000",
      "MBB": "1048576",
      "CIL": "1000",
      "CIS": "100",
      "CII": "100"
    }
  }
  ```

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
        "E": "contacto@ejemplo.com",
        "A": ""
      }
    },
    "api": {
      "!": {
        "S": "1",
        "C": "1",
        "R": "0",
        "W": "0",
        "E": "api-admin@ejemplo.com",
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
  *(Nota: En este ejemplo, `*.dev` representa un subdominio wildcard que abarca cualquier petición dinámica de segundo nivel bajo `dev`, como `test.dev.ejemplo.com`).*

### 4.3. Obtener Datos Detallados de un Subdominio
Devuelve todas las reglas operativas (Reescrituras, Cabeceras, MIMEs, Índices, Preprocesadores y Alias) para un subdominio específico.

* **Endpoint:** `POST /admin:inside:subdomainData`
* **Parámetros de Formulario:**
  * `s`: Dominio principal.
  * `d`: Subdominio (enviar valor vacío `""` si se solicita el subdominio raíz).
* **Estructura de Respuesta (JSON):**
  ```json
  {
    "=": { "/old-path": "N/new-path" },
    "$": { "png": "image/png" },
    ".": { "Cache-Control": "max-age=3600" },
    "?": { "php": "cgi>/usr/bin/php-cgi" },
    "-": { "index.php": "" },
    "&": { "alias.com": "" },
    "!": { "S": "1", "C": "1" }
  }
  ```

---

## 5. API de Configuración General (`set<KEY>`)

Modifica los parámetros globales del servidor y sus límites operativos. Varias de estas acciones forzan la reescritura del archivo `turbo.config` y el reinicio interno en caliente de la configuración.

* **Ruta Base:** `POST /admin:inside:set<CLAVE>`

| Endpoint | Parámetro `a` | Parámetro `b` | Descripción / Validación |
|---|---|---|---|
| `setU` | Nuevo Usuario | Contraseña Actual | Cambia el nombre de usuario (1-24 chars). Exige `b` correcto. |
| `setP` | Nueva Contraseña | Contraseña Actual | Cambia la contraseña (1-24 chars). Exige `b` correcto. |
| `setM` | Ruta Directorio | Contraseña Actual | Cambia el directorio base de sitios. |
| `setC` | (Ignorado) | Contraseña Actual | Vuelca la configuración RAM actual al disco (`turbo.config`). |
| `setMUB` | Valor entero | Contraseña Actual | Ajusta la longitud máxima de URI (40 - 10,240 bytes). |
| `setMHB` | Valor entero | Contraseña Actual | Ajusta la longitud máx. de cabeceras (600 - 20,480 bytes). |
| `setMBB` | Valor entero | Contraseña Actual | Ajusta tamaño máx. de cuerpo (1B - 100MB). |
| `setCIL` | Valor ms | Contraseña Actual | Reinicio de contador (100 - 80,000 ms). |
| `setCIS` | Valor ms | Contraseña Actual | Ventana de conteo (1 - 5,000 ms). |
| `setCII` | Valor entero | Contraseña Actual | Límite de peticiones por intervalo. |
| `setRT` | Tiempo (`5s`, `0s`) | Contraseña Actual | Read Timeout total de petición. |
| `setRHT` | Tiempo (`1s`, `0s`) | Contraseña Actual | Read Header Timeout. |
| `setWT` | Tiempo (`10s`, `0s`) | Contraseña Actual | Write Timeout para respuestas. |
| `setIT` | Tiempo (`2s`, `0s`) | Contraseña Actual | Idle Timeout para *Keep-Alive*. |

---

## 6. API de Gestión de Recursos del Sitio (Añadir y Eliminar)

El backend maneja las creaciones de carpetas en disco y modificaciones en los mapas RAM. *Nota sobre comodines: Enviar los dominios con asteriscos (ej. `*.ejemplo.com`). El servidor los traducirá a `#` físicamente en el disco de manera transparente.*

### 6.1. Añadir/Actualizar Recursos (`add<Tipo>`)
* **Ruta Base:** `POST /admin:inside:add<TIPO>`

| Endpoint | `s` (Dominio) | `d` (Subdominio) | `a` (Clave/Identificador) | `b` (Valor/Ruta) |
|---|---|---|---|---|
| `addSite` | Dominio Web | - | - | - |
| `addSubdomain` | Dominio Web | Subdominio | - | - |
| `addRewrite` | Dominio Web | Subdominio | URI de origen (ej: `/old`) | Reescritura (`N/new`, `Hhttp://...`, `Shttps://...`), [palabras clave dinámicas disponibles](https://turbo-server.github.io/#so-2)|
| `addMIME` | Dominio Web | Subdominio | Extensión (ej: `png`) | Tipo MIME (ej: `image/png`) |
| `addHeader` | Dominio Web | Subdominio | Nombre Cabecera | Valor Cabecera |
| `addPreprocessor`| Dominio Web | Subdominio | Extensión (ej: `php`) | Ejecutable CGI (ej: `/usr/bin/php-cgi`) |
| `addIndex` | Dominio Web | Subdominio | Archivo Índice (`index.html`)| - |
| `addAlias` | Dominio Web | Subdominio | Dominio Alias | - |

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

---

## 7. API de Seguridad Global e Interfaz

### 7.1. Control de IPs Denegadas
* **`POST /admin:inside:addDenied`**
  * `s`: Dirección IP (IPv4 o IPv6).
  * `d`: Timestamp UNIX de expiración de bloqueo.
* **`POST /admin:inside:delDenied`**
  * `s`: Dirección IP a desbloquear de la memoria `persistentIPs`.

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

---

Aquí tienes la actualización exacta y exhaustiva del **Punto 8** del `API_SPECIFICATION.md`. 

Se ha desglosado con máxima precisión el manejo en caliente (*hot-swapping*) de certificados en memoria, la lógica asíncrona no bloqueante de Certbot, y el comportamiento de las respuestas al cliente.

---

## 8. API de Certificados SSL y Redirecciones (`cfg<KEY>`)

Gestiona la habilitación de HTTPS, redirecciones en la capa de aplicación y la configuración/emisión de certificados mediante Certbot.

* **Ruta Base:** `POST /admin:inside:cfg<CLAVE>`

| Endpoint | Parámetro `a` (Acción) | Parámetro `s` (Dominio) | Parámetro `d` (Subdominio) | Parámetros Opcionales |
|---|---|---|---|---|
| **`cfgC`** | `"1"` = Ejecutar Certbot<br>`"0"` = Eliminar del disco | Dominio Web | Subdominio o Vacío (`""`) | `z`: E-mail de registro.<br>`y`: Adaptador Certbot (ej: `dns-route53`). |
| **`cfgS`** | `"1"` = Activar HTTPS<br>`"0"` = Desactivar HTTPS | Dominio Web | Subdominio o Vacío (`""`) | - |
| **`cfgR`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Subdominio o Vacío (`""`) | *Solo aplica al subdominio `www`.* Activa redirección a la Raíz. |
| **`cfgW`** | `"1"` = Activar<br>`"0"` = Desactivar | Dominio Web | Subdominio o Vacío (`""`) | *Solo aplica al subdominio Raíz.* Activa redirección a `www`. |
| **`cfgE`** | E-mail a registrar | Dominio Web | Subdominio o Vacío (`""`) | Modifica silenciosamente el E-mail para futuras renovaciones de Certbot. |
| **`cfgA`** | Nombre del Adaptador | Dominio Web | Subdominio o Vacío (`""`) | Modifica silenciosamente el flag del Adaptador para Certbot. |

### 8.1. Detalle Operativo: Emisión de Certificados (`cfgC`)
La emisión o renovación de certificados no bloquea el servidor. Al enviar `a="1"`, la API delega el trabajo a una Goroutine separada que se encarga de:
1. Ejecutar el binario de Certbot en modo webroot o mediante el adaptador especificado.
2. Leer la carpeta temporal de *archive*, localizar los archivos más recientes (`fullchain*.pem` y `privkey*.pem`) que tengan menos de 3 días de creados.
3. Mover y renombrar físicamente estos archivos a la ruta raíz del sitio en Turbo.

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
2. Si el puerto `443` estaba cerrado (porque el servidor arrancó sin certificados), **se inicia un nuevo socket Listener automáticamente**.
3. A partir de este momento, Turbo fuerza una redirección `301 Moved Permanently` a `https://` para todo el tráfico HTTP que ingrese a ese dominio/subdominio.

*Nota: Desactivar HTTPS (`a="0"`) purga el certificado de la memoria RAM (impidiendo futuras conexiones TLS para ese host), pero **no elimina** los archivos `.pem` del disco ni cierra el puerto 443 a nivel de red.*

---

## 9. API de Gestión Física de Archivos (`hardUpload`)

Utilizado para sustituir masivamente todos los archivos públicos asociados a un subdominio/dominio. El servidor eliminará de manera destructiva el contenido existente en la carpeta de contenido (`@`) y volcará los nuevos datos.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Formato del Cuerpo:** `multipart/form-data`
* **Parámetros de Formulario:**
  * `s`: Dominio principal (ej: `ejemplo.com`).
  * `d`: Subdominio (vacío `""` si se trata del dominio raíz).
  * `f`: Array de archivos adjuntos (`File[]`).
* **Manejo de Directorios Anidados:** 
  El backend analiza el parámetro `filename` dentro del encabezado HTTP `Content-Disposition` de cada bloque *multipart*. Si el nombre del archivo contiene rutas relativas (ej: `assets/img/logo.png`), Turbo extraerá la ruta y creará la estructura de carpetas de forma segura, denegando cualquier intento de Directory Traversal (`..`).
* **Respuesta Exitosa (HTTP 200 OK):**
  Devuelve la cadena `"Datos volcados"`.
* **Manejo de Errores Específicos:**
  * Si el peso de la subida supera el límite global `MBB` (Max Body Bytes), la API corta la lectura y retorna HTTP 400 con el mensaje `"Longitud máxima de contenidos excedida"`.

---

## 10. Estándar de Códigos de Respuesta HTTP de la API

| Código HTTP | Significado Funcional | Causa y Cuerpo de la Petición |
|---|---|---|
| **`200 OK`** | Operación Procesada | La orden se ejecutó en memoria y/o disco. Devuelve un texto plano de confirmación (ej: `"Subdominio agregado"`). |
| **`400 Bad Request`** | Fallo de Validación / Lógica | Parámetros nulos, formato inválido, recurso inexistente, contraseñas erróneas o restricciones de límites sobrepasadas. El Body contiene el string del error literal que debe mostrarse al usuario. |
| **`403 Forbidden`** | Bloqueo de Acceso | Falla la primera autenticación o credenciales por defecto incorrectas. Body vacío. |
| **`404 Not Found`** | URL Incorrecta | Se ha consultado una URI (`RequestURI`) dentro del prefijo `/admin:` que no corresponde a ningún endpoint listado. |
| **`429 Too Many Requests`** | *Rate Limiter* Activado | La conexión se originó superando los límites de intervalos estipulados por el control del servidor (CIL/CIS/CII). El Request se interrumpe y la IP se archiva en la RAM. |

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

    The `customNetHttp` package contains a modified version of the Go standard library `net/http` (based on Go v1.19/1.18), which is distributed under the **BSD 3-Clause License**. Please refer to the `customNetHttp/LICENSE`, `customNetHttp/PATENTS` and `customNetHttp/NOTICE` files within that directory for full details and attribution.

---

Copyright (C) 2026 [OKZGN](https://okzgn.com)
