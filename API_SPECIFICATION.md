# Turbo - API, Technical Specification

## 1. General Architecture and Communication Protocol

The Turbo backend provides an **RPC/REST-style API over HTTP POST**. All interaction between the graphical interface (GUI) or any external client and the server takes place exclusively through `POST` requests.

### 1.1. Main Access Routes (Base URLs)
* **Public Authentication / Login:** `/admin:`
* **Authenticated Administrative Module:** `/admin:inside:`
* **Sign Out:** `/admin:signout:`

### 1.2. Headers and Security
* **HTTP Method:** `POST` is mandatory for all API actions.
* **Parameters:** The action parameters (`s`, `d`, `a`, `b`…) can go in the URL query or in an `application/x-www-form-urlencoded` body. The GUI sends them in the body, so the current password (`b`) never appears in the URL that `turbo.visits` records; API clients should do the same.
* **Session Handling:** After a successful login, the server sets the session cookie `turbo_session` (`Path=/; HttpOnly; SameSite=Strict`, plus `Secure` when the request arrives over HTTPS), which the browser sends by itself. API clients can instead send the token in the `ok: <token>` header. If both are present, the cookie is used. The token is **not** accepted as a URL parameter. The `turbo_session` cookie is removed from the `Cookie` header passed to CGI preprocessors.
* **Same Origin:** A `POST` to `/admin:inside:` authenticated with the cookie must come from the panel's own origin: the browser must send `Sec-Fetch-Site: same-origin` (or `none`) or, without `Sec-Fetch-Site`, an `Origin` header equal to `<scheme>://<Host>`. Otherwise the server responds `403`. Requests authenticated with the `ok` header don't need it.
* **Panel Response Headers:** Responses under `/admin:` carry `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'` and `Cache-Control: no-store`.
* **Where the Panel Answers:** The global `PA` setting (see `setPA`, §5) can limit `/admin:` to a list of hosts and/or CIDR networks: the request's `Host` must be one of the hosts (if there are any) and the client's IP must be in one of the networks (if there are any). Otherwise, `/admin:` responds `404`. Empty (the default) means no restriction, and then the panel shares the origin of every site served by Turbo: the recommended setup is a host of its own for the panel, one that serves no site. A `PA` host that serves a site is refused (§5), and so is a new site, subdomain or alias that would serve a `PA` host (`400` with the reason).
* **CORS (Cross-Origin Resource Sharing):**
  * `Access-Control-Allow-Origin: default://home`
  * `Access-Control-Allow-Headers: ok`
* **Session Lifecycle:** Tokens are assigned to the client's IP address and expire after **600 seconds (10 minutes)** of inactivity. Each request to `/admin:inside:` resets the timer. Without a valid session, `/admin:inside:` returns the HTML redirect to `/admin:` (see §3.2).

---

## 2. Data Encoding and Character Replacement Conventions

To prevent special characters and URL delimiters from interfering with or corrupting HTTP requests (especially in rewrite rules or headers), the backend requires certain characters to be encoded using a predefined substitution:

### 2.1. Immutable (Fixed) Substitutions
Any form parameter (such as `a`, `b`, `s`, `d`) is processed on the server by the URI character-replacement function. The following substitutions must be applied client-side before sending the request:

| Original Character | Expected Transmission Token |
|---|---|
| `;` (Semicolon) | `-.-` |
| `#` (Hash / pound sign) | `-,-` |
| `&` (Ampersand) | `-_-` |

*Note: Administrators can dynamically add additional character replacements via the `addCharsReplace` endpoint.*

### 2.2. Characters Not Accepted
No parameter may contain control characters (bytes below `0x20` and `0x7f`) or invalid UTF-8: the server responds HTTP 400 `"Caracteres de control no admitidos"` *(lit. "Control characters not accepted")* or `"Texto UTF-8 incorrecto"` *(lit. "Invalid UTF-8 text")*. The only exception is the response template of `addHttpCodeResponse` (§7.2), which may contain tabs and line breaks.

---

## 3. Authentication and Session Control API

### 3.1. Log In
Validates the user's credentials and generates a unique token bound to the client's IP address. *Note: It could be fragile behind shared NAT/proxies, where multiple users share a public IP.*

* **Endpoint:** `POST /admin:` (only this path and method; a `GET` serves the login page)
* **Body Format:** `multipart/form-data` or `application/x-www-form-urlencoded`, at most 4 KiB (larger: HTTP 413).
* **Required Parameters**, in the body (parameters in the URL are ignored):
  * `u`: Username.
  * `p`: Password.
* **Successful Response (HTTP 200 OK):**
  The server generates a cryptographically secure opaque token (32 random bytes, 64 hexadecimal characters), unique for each login and associated with the client's IP. It sets the `turbo_session` cookie with it, and the body contains the token prefixed by the success variable (`"ok"` by default), for clients that use the `ok` header.
  ```text
  ok<token>
  ```
* **Incorrect Credentials:** HTTP 403 with an empty body.
* **Too Many Failed Logins:** after 5 failures from the same IP within 10 minutes, every login from that IP (even with the right credentials) gets HTTP 429 with `Retry-After` in seconds, without checking the password: 1 minute the first time, then 2, 4, 8 and at most 15 minutes. Logins still being checked count towards the 5: simultaneous logins beyond them get 429 with `Retry-After: 2`. A correct login clears the count.
* **Server Busy:** if the password can't be checked within 2 seconds because too many checks are running, HTTP 503 with `Retry-After: 2`. The same applies to the current password (`b`) of `set<KEY>` (§5).

### 3.2. Log Out
Invalidates the current token in RAM memory (other sessions from the same IP stay active) and expires the `turbo_session` cookie (`Max-Age=0`).

* **Endpoint:** `POST /admin:signout:` (a `GET` does not sign out: it serves the login page)
* **Authentication:** The session cookie or the `ok` header.
* **Successful Response (HTTP 200 OK):**
  Returns an HTML string forcing browser redirection.
  ```html
  <meta http-equiv='refresh' content='0; URL=/admin:'/>
  ```

---

## 4. Query and State Retrieval API (Data Retrieval)

Endpoints intended to dump the in-memory configuration state to the client. They require an authenticated session (cookie or `ok: <token>` header, §1.2).

### 4.1. Get Global Server State
Returns the general configuration, root site maps, denied IPs, custom HTTP responses, and character replacements.

* **Endpoint:** `POST /admin:inside:sites`
* **Parameters:** None.
* **Response (JSON):**
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
      "404": "Page not found: {TURBO_RESPONSE_CODE}"
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
      "CGL": "0"
    }
  }
  ```
  *(Note: Fixed entries, which cannot be deleted, are returned as `{"f": <value>}`. Text values in the `!` block are URL-encoded, e.g. `@` → `%40`).*

### 4.2. Get List of Subdomains for a Site
Returns a JSON object with all subdomains belonging to a specific root domain, including the alias (if applicable) and the SSL/Redirect configuration for each.

* **Endpoint:** `POST /admin:inside:subdomains`
* **Form Parameters:**
  * `s`: Primary domain (e.g.: `ejemplo.com`).
* **Successful Response (JSON):**
  The response always includes the root subdomain, under the empty key `""`, and the other nested subdomains. The `!` block contains the configuration status (1 = Enabled, 0 = Disabled).
  ```json
  {
    "": {
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
  *(Note: In this example, `*.dev` represents a wildcard subdomain that covers any dynamic second-level request under `dev`, such as `test.dev` or `admin.test.dev`).*

### 4.3. Get Detailed Data for a Subdomain
Returns all operational rules (Rewrites, Headers, MIME types, Indexes, Preprocessors, and Aliases) for a specific subdomain.

* **Endpoint:** `POST /admin:inside:subdomainData`
* **Form Parameters:**
  * `s`: Primary domain.
  * `d`: Subdomain (send an empty value `""` when requesting the root subdomain).
* **Response Structure (JSON):**
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
  *(Note: Each index in `-` comes with its position, the order in which indexes are tried).*

---

## 5. General Configuration API (`set<KEY>`)

Modifies the server's global parameters and operational limits. Several of these actions force a rewrite of the `turbo.config` file and an internal hot-reload of the configuration.

* **Base Route:** `POST /admin:inside:set<KEY>`
* **Required Parameters:** `a` (value) and `b` (current password) in **every** `set<KEY>`. If `b` is missing, the server responds HTTP 400 `"Faltan datos"` *(lit. "Missing data")*; if it is incorrect, HTTP 400 `"Contraseña actual incorrecta"` *(lit. "Incorrect current password")*. A value equal to the current one is also answered with HTTP 400 (for example, `"Usuario sin cambios"` or `"Contraseña sin cambios"`).

| Endpoint | Parameter `a` | Parameter `b` | Description / Validation |
|---|---|---|---|
| `setU` | New Username | Current Password | Changes the username (1-24 chars). |
| `setP` | New Password | Current Password | Changes the password (1-24 chars). |
| `setM` | Directory Path | Current Password | Changes the base site directory (it must exist) and reloads the configuration. If that directory has a `turbo.config` that is not valid JSON, it responds 400 with where the error is. |
| `setC` | (Ignored; `sobrescribir` to confirm, see below) | Current Password | Dumps the current in-RAM configuration to disk (`turbo.config`), including the username and the password hash (never the plain password). |
| `setPA` | Hosts / CIDR networks | Current Password | Where the panel answers: comma-separated host names and/or CIDR networks (at most 32 entries and 1,024 chars); with both, a request needs both. Empty or `*` = no restriction. A host that serves a site (directly, through a wildcard or as an alias) is refused with 400 `"El host del panel <host> sirve el sitio <site>: …"`. |
| `setMUB` | Integer value | Current Password | Adjusts the maximum URI length (40 - 10,240 bytes). |
| `setMHB` | Integer value | Current Password | Adjusts the max. header length (600 - 20,480 bytes). |
| `setMBB` | Integer value | Current Password | Adjusts the max. body size (1B - 100MB). |
| `setCIL` | Value in ms | Current Password | Counter reset interval (1,000 - 800,000 ms). |
| `setCIS` | Value in ms | Current Password | Counting window (10 - 50,000 ms). |
| `setCII` | Integer value | Current Password | Request limit per interval: from 1 up to the value of `CIS` in ms, and `CIS`/`CII` ≤ 66. |
| `setCGL` | Integer value | Current Password | Requests per second for the whole server, among all clients (10 - 1,000,000; `0` = no limit, the default). Requests above it get `503` with `Retry-After: 1`; no IP is blocked. |
| `setRT` | Time (`5s`, `0s`) | Current Password | Total request Read Timeout (100 ms - 15 min; `0s` disables it). |
| `setRHT` | Time (`1s`, `0s`) | Current Password | Read Header Timeout (50 ms - 7.5 min and, when `RT` is not `0s`, at most half of `RT`; `0s` uses `RT`). |
| `setWT` | Time (`10s`, `0s`) | Current Password | Write Timeout for responses (100 ms - 30 min; `0s` disables it). |
| `setIT` | Time (`2s`, `0s`) | Current Password | Idle Timeout for *Keep-Alive* (100 ms - 5 min; `0s` uses `RT`). |

*Notes:*
* *`setPA`: Host entries are compared with the request's `Host` header, which the client chooses: they give the panel an origin of its own, apart from the sites, but do not limit who can reach it. CIDR networks, compared with the client's IP, are what limit access. A `turbo.config` whose `PA` host serves a site still loads, with a warning in the log.*
* *`setC`: If `turbo.config` was written by a later version of Turbo (a later schema), saving would lose its new settings, so the server responds HTTP 400 with an explanation; send `a=sobrescribir` to confirm and overwrite it. The first time a file from an earlier schema is saved, the original is kept as `turbo.config.v<schema>.bak`. If the site directory is not the startup directory, a minimal `turbo.config` pointing to it is also written in the startup directory.*

---

## 6. Site Resource Management API (Add and Delete)

The backend handles folder creation on disk and modifications to the in-RAM maps. *Note on wildcards: Send domains with asterisks (e.g., `*.ejemplo.com`). The server will transparently translate them to `#` on disk.*

### 6.1. Add/Update Resources (`add<Type>`)
* **Base Route:** `POST /admin:inside:add<TYPE>`

| Endpoint | `s` (Domain) | `d` (Subdomain) | `a` (Key/Identifier) | `b` (Value/Path) |
|---|---|---|---|---|
| `addSite` | Web Domain | - | - | - |
| `addSubdomain` | Web Domain | Subdomain | - | - |
| `addRewrite` | Web Domain | Subdomain | Source URI (e.g.: `/old`) | Rewrite (`/new`, `http://...`, `https://...`), [dynamic keywords available](https://turbo-server.github.io/#so-2)|
| `addMIME` | Web Domain | Subdomain | Extension (e.g.: `png`) | MIME Type (e.g.: `image/png`) |
| `addHeader` | Web Domain | Subdomain | Header Name | Header Value |
| `addPreprocessor`| Web Domain | Subdomain | Extension (e.g.: `php`) | CGI Executable (e.g.: `/usr/bin/php-cgi`) |
| `addIndex` | Web Domain | Subdomain | Index File (`index.html`)| - |
| `addAlias` | Web Domain | Subdomain | Alias Domain | - |

*Notes:*
* *`addRewrite`: The rewrite must start with `/` (internal path), `http://` or `https://`. Targets with `http://` or `https://` are answered with a `302` redirect: to the exact target when it has a path or a query, or to the target domain followed by the original URI when it is only a domain. The source (`a`) is compared with the decoded request path (`/a b` matches `/a%20b`), and an internal target is a URL path too: it is decoded and must stay inside the site (a target with a `..` segment, even one that stays inside, or with `\`, an encoded `/` or `\`, `%00`, control characters, invalid UTF-8 or a segment ending in `.` or a space, is answered with 404).*
* *`addPreprocessor`: The executable path (at most 128 chars) must exist; the `cgi>` prefix is optional and other prefixes are rejected.*
* *`addIndex`: The index is added at the end of the order; indexes are tried in the order in which they were added. New sites and subdomains start with `index.html`.*

### 6.2. Delete Resources (`del<Type>`)
* **Base Route:** `POST /admin:inside:del<TYPE>`

| Endpoint | `s` (Domain) | `d` (Subdomain) | `a` (Key/Identifier to delete) |
|---|---|---|---|
| `delSite` | Web Domain | Subdomain (Empty = Delete Site) | - |
| `delRewrite` | Web Domain | Subdomain | Source URI |
| `delMIME` | Web Domain | Subdomain | Extension |
| `delHeader` | Web Domain | Subdomain | Header Name |
| `delPreprocessor`| Web Domain | Subdomain | Extension |
| `delIndex` | Web Domain | Subdomain | Index File |
| `delAlias` | Web Domain | Subdomain | Alias Domain |

*All three parameters are required (except `a` in `delSite`): if one is missing, the response is `400` "Faltan datos".*

---

## 7. Global Security and Interface API

### 7.1. Denied IP Control
A denied IP is blocked until the given date: its requests are answered with HTTP 429 and a `Retry-After` header (seconds left), and its new connections are closed.

* **`POST /admin:inside:addDenied`**
  * `s`: IP address (IPv4 or IPv6). Loopback addresses (`127.x.x.x`, `::1`) and the address the request comes from (`400` "IP actual": the panel would lock itself out) are not accepted.
  * `d`: UNIX timestamp for block expiration (`0` or a past date removes an existing block).
* **`POST /admin:inside:delDenied`**
  * `s`: IP address to unblock from the denied IP list.

### 7.2. HTTP Status Code Responses
* **`POST /admin:inside:addHttpCodeResponse`**
  * `s`: HTTP status code (between `400` and `599`, or `0` for a universal fallback).
  * `d`: Response template. Line breaks and the `{TURBO_RESPONSE_CODE}` macro are supported.
* **`POST /admin:inside:delHttpCodeResponse`**
  * `s`: HTTP status code to revert to the system's default behavior.

### 7.3. Global Character Replacement in URIs
* **`POST /admin:inside:addCharsReplace`**
  * `s`: Character sequence to replace (e.g.: `;`).
  * `d`: Target encoded token (e.g.: `-.-`).
* **`POST /admin:inside:delCharsReplace`**
  * `s`: Character sequence to stop replacing (the fixed substitutions of §2.1 cannot be deleted).

---

## 8. SSL Certificate and Redirect API (`cfg<KEY>`)

Manages HTTPS enablement, application-layer redirects, and certificate configuration/issuance via Certbot.

* **Base Route:** `POST /admin:inside:cfg<KEY>`

| Endpoint | Parameter `a` (Action) | Parameter `s` (Domain) | Parameter `d` (Subdomain) | Optional Parameters |
|---|---|---|---|---|
| **`cfgC`** | `"1"` = Run Certbot<br>`"0"` = Remove from disk | Web Domain | Subdomain or Empty (`""`) | `z`: Registration e-mail.<br>`y`: Certbot adapter (`dns-<provider>`, e.g.: `dns-route53`). |
| **`cfgS`** | `"1"` = Enable HTTPS<br>`"0"` = Disable HTTPS | Web Domain | Subdomain or Empty (`""`) | - |
| **`cfgR`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Empty (`""`) only: it is set at the site's root | Redirects `www.<site>` to `<site>` (301). With a subdomain, HTTP 400. |
| **`cfgW`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Empty (`""`) only: it is set at the site's root | Redirects `<site>` to `www.<site>` (301). With a subdomain, HTTP 400. |
| **`cfgE`** | E-mail to register | Web Domain | Subdomain or Empty (`""`) | Silently updates the E-mail for future Certbot renewals. |
| **`cfgA`** | Adapter Name (`dns-<provider>`, or empty for webroot) | Web Domain | Subdomain or Empty (`""`) | Silently updates the Adapter flag for Certbot. |

### 8.1. Operational Detail: Certificate Issuance (`cfgC`)
Certbot only runs when it is requested with `a="1"`, and an e-mail is required (saved with `cfgE` or sent in `z`); without it the API responds HTTP 400 `"E-mail obligatorio para crear el certificado"` *(lit. "E-mail required to create the certificate")*. If the site already has a certificate less than 75 days old, the API responds `"Certificado SSL activo"` without running Certbot. With `a="0"`, the certificate files are deleted whatever their age and the API responds `"Certificado SSL borrado"` *(lit. "SSL certificate deleted")*; with no certificate on disk, nothing is deleted and the API responds HTTP 400 `"Sin certificado"` *(lit. "No certificate")*.

Certificate issuance or renewal does not block the server. When `a="1"` is sent, the API delegates the work to a separate Goroutine, which handles:
1. Running the Certbot binary in webroot mode or via the specified adapter, with its working folder in `turbo.certificates/<site>`.
2. Reading the temporary `archive` folder and locating the most recent files (`fullchain*.pem` and `privkey*.pem`) that are less than 2.5 days (216,000 seconds) old.
3. Physically moving and renaming these files to the site's root path in Turbo.

**Automatic Renewal:** At startup and every 24 hours, Turbo renews the certificates it issued (sites with an e-mail and a folder in `turbo.certificates`) that expire in less than 30 days, and loads them without a restart. Certificates placed by hand are not renewed.

**HTTP Polling Flow for the Frontend:**
Since the operation is asynchronous, the frontend must make continuous requests (polling) to the `cfgC` endpoint, evaluating the JSON response. While the issuance is in progress the API responds **HTTP 202** with one of these bodies:
* `{"message":"Espere, certificado en proceso","status":"WAIT"}` *(lit. "Please wait, certificate in process")*: The Goroutine has just started.
* `{"message":"Espere, certificado procesándose","status":"WAIT"}` *(lit. "Please wait, certificate being processed")*: Certbot is working.
* `{"message":"Espere, certificado ocupado en <dominio>","status":"WAIT"}` *(lit. "Please wait, certificate busy on <domain>")*: Certbot is busy issuing a certificate for another site.
* **Successful Response (200 OK):** `"Certificado SSL activo"` *(lit. "SSL certificate active")* (the client should stop polling).
* **Error Response (400 Bad Request):** Returns the raw error output from Certbot or the filesystem.

### 8.2. Operational Detail: Hot SSL Activation (`cfgS`)
Turbo does not require restarts to apply certificates. When the activation command (`a="1"`) is received:
1. Go reads the `fullchain.pem` and `privkey.pem` files directly from disk and immediately injects them into the server's shared RAM memory.
2. If port `443` (or the address in `TURBO_HTTPS_ADDR`) was closed (because the server started without certificates), **a new socket Listener is automatically started**.
3. From this point on, Turbo forces a `301 Moved Permanently` redirect to `https://`, on the same host, for the HTTP traffic entering that domain/subdomain when a certificate covers the requested host. An alias without a certificate that covers its name keeps being served over HTTP.

During the TLS handshake, each name receives the certificate that covers it (exactly or with a wildcard). Names that no certificate covers, and connections without SNI (access by IP), are rejected.

*Note: Disabling HTTPS (`a="0"`) purges the certificate from RAM memory (preventing future TLS connections for that host), but it **does not delete** the `.pem` files from disk, nor does it close port 443 at the network level.*

---

## 9. Physical File Management API (`hardUpload`)

Used to bulk-replace all public files associated with a subdomain/domain. The server will destructively delete all the existing content in the content folder (`@`), subfolders included, and dump the new data.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Body Format:** `multipart/form-data`
* **Form Parameters:**
  * `s`: Primary domain (e.g.: `ejemplo.com`).
  * `d`: Subdomain (empty `""` for the root domain).
  * `f`: Array of attached files (`File[]`).

  `s` and `d` are accepted both in the URL and in the multipart body.
* **Nested Directory Handling:**
  The backend parses the `filename` parameter within the `Content-Disposition` HTTP header of each multipart block. The first segment of each path (the folder chosen in the browser) is discarded, and `\` counts as a separator. If the rest of the name contains relative paths (e.g.: `site/assets/img/logo.png` → `assets/img/logo.png`), Turbo will create the folder structure. Names that would leave `@` (with `..`, absolute or with `:`) are discarded, and so are, on every system, the names Windows treats specially: ending in `.` or a space, a reserved device name (`CON`, `NUL`, `COM1`…) or `~` followed by a digit (8.3 short names).
* **Successful Response (HTTP 200 OK):**
  Returns the string `"Datos volcados"` *(lit. "Data dumped")*. If any file was discarded, the response lists them: `"Datos volcados. Descartados: <name>, <name>"` *(lit. "Data dumped. Discarded: ...")*.
* **Specific Error Handling:**
  * If the upload size exceeds the global `MBB` (Max Body Bytes) limit, or it has more than 10,000 files, the API cuts off the read and returns HTTP 400 with the message `"Longitud máxima de contenidos excedida"` *(lit. "Maximum content length exceeded")*. (Other multipart forms admit at most 1,000 parts.)

---

## 10. API HTTP Response Code Standard

| HTTP Code | Functional Meaning | Cause and Request Body |
|---|---|---|
| **`200 OK`** | Operation Processed | The command was executed in memory and/or on disk. Returns a plain-text confirmation (e.g.: `"Subdominio agregado"` *(lit. "Subdomain added")*). |
| **`202 Accepted`** | In Progress | Only `cfgC` while a certificate is being issued: a JSON body with `"status":"WAIT"` (§8.1). Keep polling. |
| **`400 Bad Request`** | Validation / Logic Failure | Null parameters, invalid format, nonexistent resource, incorrect passwords, or exceeded limit restrictions. The Body contains the literal error string that should be shown to the user. |
| **`403 Forbidden`** | Access Blocked | Login with incorrect credentials (empty Body), or a `POST` authenticated with the session cookie that does not come from the same origin (§1.2). |
| **`404 Not Found`** | Incorrect URL | A URI (`RequestURI`) was requested within the `/admin:` prefix that does not correspond to any listed endpoint, or the panel does not answer on that host or network (`PA`). |
| **`413 Payload Too Large`** | Parameters Too Large | The parameters of an action (or the login body, §3.1) are larger than allowed: `MBB`, and at most 10 MiB in an `application/x-www-form-urlencoded` body. A file upload that is too large gets `400` instead (§9). Parameters that can't be decoded (for example, a malformed `%` escape) get `400` `"Parámetros incorrectos"` *(lit. "Incorrect parameters")*. |
| **`429 Too Many Requests`** | *Rate Limiter* Triggered | The client's IP exceeded its limits (CIL/CIS/CII), the IP is denied (§7.1), or its logins are blocked after failed attempts (§3.1). Each request counts once. The response carries `Retry-After` with the seconds to wait, and new connections from a blocked IP are closed. |
| **`503 Service Unavailable`** | Global Limit Reached | The whole server received more than `CGL` requests in the current second (`Retry-After: 1`), or the password of a login or the current password (`b`) of a `set<KEY>` couldn't be checked within 2 seconds (`Retry-After: 2`, §3.1). |
| **`500 Internal Server Error`** | Internal Failure | An unexpected error while processing the action. |

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
