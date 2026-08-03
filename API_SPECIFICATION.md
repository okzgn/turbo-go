# Turbo - API, Technical Specification

## 1. General Architecture and Communication Protocol

The Turbo backend provides an **RPC/REST-style API over HTTP POST**. All interaction between the graphical interface (GUI) or any external client and the server takes place exclusively through `POST` requests.

### 1.1. Main Access Routes (Base URLs)
* **Public Authentication / Login:** `/admin:`
* **Authenticated Administrative Module:** `/admin:inside:`
* **Sign Out:** `/admin:signout:`

### 1.2. Headers and Security
* **HTTP Method:** `POST` is mandatory for all API actions.
* **Session Handling:** The authentication token must be sent in the `ok: <token_hash>` header or, alternatively, as a URL parameter `?ok=<token_hash>`.
* **CORS (Cross-Origin Resource Sharing):**
  * `Access-Control-Allow-Origin: default://home`
  * `Access-Control-Allow-Headers: ok`
* **Session Lifecycle:** Tokens are assigned to the client's IP address and expire after **60 seconds (1 minute)** of inactivity. Each successful request resets the timer.

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

---

## 3. Authentication and Session Control API

### 3.1. Log In
Validates the user's credentials and generates a unique token bound to the client's IP address. *Note: It could be fragile behind shared NAT/proxies, where multiple users share a public IP.*

* **Endpoint:** `POST /admin:`
* **Body Format:** `multipart/form-data`
* **Required Parameters:**
  * `u`: Username.
  * `p`: Password.
* **Successful Response (HTTP 200 OK):**
  The server generates a cryptographically secure opaque token associated with the client's IP. The body will contain the token prefixed by the success variable (`"ok"` by default).
  ```text
  ok<sha256_token_hash>
  ```

### 3.2. Log Out
Invalidates the current token in RAM memory and disconnects the session from the active IP.

* **Endpoint:** `POST /admin:signout:`
* **Authentication:** `ok` header required.
* **Successful Response (HTTP 200 OK):**
  Returns an HTML string forcing browser redirection.
  ```html
  <meta http-equiv='refresh' content='0; URL=/admin:'/>
  ```

---

## 4. Query and State Retrieval API (Data Retrieval)

Endpoints intended to dump the in-memory configuration state to the client. They require the `ok: <token>` header.

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
      "404": "Page not found: {TURBO_RESPONSE_CODE}"
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

### 4.2. Get List of Subdomains for a Site
Returns a JSON object with all subdomains belonging to a specific root domain, including the alias (if applicable) and the SSL/Redirect configuration for each.

* **Endpoint:** `POST /admin:inside:subdomains`
* **Form Parameters:**
  * `s`: Primary domain (e.g.: `ejemplo.com`).
* **Successful Response (JSON):**
  The response always includes the root subdomain (under the domain name) and the other nested subdomains. The `!` block contains the configuration status (1 = Enabled, 0 = Disabled).
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

## 5. General Configuration API (`set<KEY>`)

Modifies the server's global parameters and operational limits. Several of these actions force a rewrite of the `turbo.config` file and an internal hot-reload of the configuration.

* **Base Route:** `POST /admin:inside:set<KEY>`

| Endpoint | Parameter `a` | Parameter `b` | Description / Validation |
|---|---|---|---|
| `setU` | New Username | Current Password | Changes the username (1-24 chars). Requires correct `b`. |
| `setP` | New Password | Current Password | Changes the password (1-24 chars). Requires correct `b`. |
| `setM` | Directory Path | Current Password | Changes the base site directory. |
| `setC` | (Ignored) | Current Password | Dumps the current in-RAM configuration to disk (`turbo.config`). |
| `setMUB` | Integer value | Current Password | Adjusts the maximum URI length (40 - 10,240 bytes). |
| `setMHB` | Integer value | Current Password | Adjusts the max. header length (600 - 20,480 bytes). |
| `setMBB` | Integer value | Current Password | Adjusts the max. body size (1B - 100MB). |
| `setCIL` | Value in ms | Current Password | Counter reset interval (100 - 80,000 ms). |
| `setCIS` | Value in ms | Current Password | Counting window (1 - 5,000 ms). |
| `setCII` | Integer value | Current Password | Request limit per interval. |
| `setRT` | Time (`5s`, `0s`) | Current Password | Total request Read Timeout. |
| `setRHT` | Time (`1s`, `0s`) | Current Password | Read Header Timeout. |
| `setWT` | Time (`10s`, `0s`) | Current Password | Write Timeout for responses. |
| `setIT` | Time (`2s`, `0s`) | Current Password | Idle Timeout for *Keep-Alive*. |

---

## 6. Site Resource Management API (Add and Delete)

The backend handles folder creation on disk and modifications to the in-RAM maps. *Note on wildcards: Send domains with asterisks (e.g., `*.ejemplo.com`). The server will transparently translate them to `#` on disk.*

### 6.1. Add/Update Resources (`add<Type>`)
* **Base Route:** `POST /admin:inside:add<TYPE>`

| Endpoint | `s` (Domain) | `d` (Subdomain) | `a` (Key/Identifier) | `b` (Value/Path) |
|---|---|---|---|---|
| `addSite` | Web Domain | - | - | - |
| `addSubdomain` | Web Domain | Subdomain | - | - |
| `addRewrite` | Web Domain | Subdomain | Source URI (e.g.: `/old`) | Rewrite (`N/new`, `Hhttp://...`, `Shttps://...`), [dynamic keywords available](https://turbo-server.github.io/#so-2)|
| `addMIME` | Web Domain | Subdomain | Extension (e.g.: `png`) | MIME Type (e.g.: `image/png`) |
| `addHeader` | Web Domain | Subdomain | Header Name | Header Value |
| `addPreprocessor`| Web Domain | Subdomain | Extension (e.g.: `php`) | CGI Executable (e.g.: `/usr/bin/php-cgi`) |
| `addIndex` | Web Domain | Subdomain | Index File (`index.html`)| - |
| `addAlias` | Web Domain | Subdomain | Alias Domain | - |

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

---

## 7. Global Security and Interface API

### 7.1. Denied IP Control
* **`POST /admin:inside:addDenied`**
  * `s`: IP address (IPv4 or IPv6).
  * `d`: UNIX timestamp for block expiration.
* **`POST /admin:inside:delDenied`**
  * `s`: IP address to unblock from the `persistentIPs` memory map.

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

---

Here is the exact and exhaustive update to Point 8 of `API_SPECIFICATION.md`.

The hot-swapping of certificates in memory, Certbot's non-blocking asynchronous logic, and client response behavior have been broken down with maximum precision.

---

## 8. SSL Certificate and Redirect API (`cfg<KEY>`)

Manages HTTPS enablement, application-layer redirects, and certificate configuration/issuance via Certbot.

* **Base Route:** `POST /admin:inside:cfg<KEY>`

| Endpoint | Parameter `a` (Action) | Parameter `s` (Domain) | Parameter `d` (Subdomain) | Optional Parameters |
|---|---|---|---|---|
| **`cfgC`** | `"1"` = Run Certbot<br>`"0"` = Remove from disk | Web Domain | Subdomain or Empty (`""`) | `z`: Registration e-mail.<br>`y`: Certbot adapter (e.g.: `dns-route53`). |
| **`cfgS`** | `"1"` = Enable HTTPS<br>`"0"` = Disable HTTPS | Web Domain | Subdomain or Empty (`""`) | - |
| **`cfgR`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Subdomain or Empty (`""`) | *Only applies to the `www` subdomain.* Enables redirection to the Root. |
| **`cfgW`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Subdomain or Empty (`""`) | *Only applies to the Root subdomain.* Enables redirection to `www`. |
| **`cfgE`** | E-mail to register | Web Domain | Subdomain or Empty (`""`) | Silently updates the E-mail for future Certbot renewals. |
| **`cfgA`** | Adapter Name | Web Domain | Subdomain or Empty (`""`) | Silently updates the Adapter flag for Certbot. |

### 8.1. Operational Detail: Certificate Issuance (`cfgC`)
Certificate issuance or renewal does not block the server. When `a="1"` is sent, the API delegates the work to a separate Goroutine, which handles:
1. Running the Certbot binary in webroot mode or via the specified adapter.
2. Reading the temporary `archive` folder and locating the most recent files (`fullchain*.pem` and `privkey*.pem`) that are less than 3 days old.
3. Physically moving and renaming these files to the site's root path in Turbo.

**HTTP Polling Flow for the Frontend:**
Since the operation is asynchronous, the frontend must make continuous requests (polling) to the `cfgC` endpoint, evaluating the JSON response:
* `{"message":"Espere, certificado en proceso","status":"WAIT"}` *(lit. "Please wait, certificate in process")*: The Goroutine has just started.
* `{"message":"Espere, certificado procesándose","status":"WAIT"}` *(lit. "Please wait, certificate being processed")*: Certbot is working.
* `{"message":"Espere, certificado ocupado en <dominio>","status":"WAIT"}` *(lit. "Please wait, certificate busy on <domain>")*: Certbot is busy issuing a certificate for another site.
* **Successful Response (200 OK):** `"Certificado SSL activo"` *(lit. "SSL certificate active")* (the client should stop polling).
* **Error Response (400 Bad Request):** Returns the raw error output from Certbot or the filesystem.

### 8.2. Operational Detail: Hot SSL Activation (`cfgS`)
Turbo does not require restarts to apply certificates. When the activation command (`a="1"`) is received:
1. Go reads the `fullchain.pem` and `privkey.pem` files directly from disk and immediately injects them into the server's shared RAM memory.
2. If port `443` was closed (because the server started without certificates), **a new socket Listener is automatically started**.
3. From this point on, Turbo forces a `301 Moved Permanently` redirect to `https://` for all HTTP traffic entering that domain/subdomain.

*Note: Disabling HTTPS (`a="0"`) purges the certificate from RAM memory (preventing future TLS connections for that host), but it **does not delete** the `.pem` files from disk, nor does it close port 443 at the network level.*

---

## 9. Physical File Management API (`hardUpload`)

Used to bulk-replace all public files associated with a subdomain/domain. The server will destructively delete the existing content in the content folder (`@`) and dump the new data.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Body Format:** `multipart/form-data`
* **Form Parameters:**
  * `s`: Primary domain (e.g.: `ejemplo.com`).
  * `d`: Subdomain (empty `""` for the root domain).
  * `f`: Array of attached files (`File[]`).
* **Nested Directory Handling:**
  The backend parses the `filename` parameter within the `Content-Disposition` HTTP header of each multipart block. If the file name contains relative paths (e.g.: `assets/img/logo.png`), Turbo will extract the path and safely create the folder structure, denying any Directory Traversal (`..`) attempts.
* **Successful Response (HTTP 200 OK):**
  Returns the string `"Datos volcados"` *(lit. "Data dumped")*.
* **Specific Error Handling:**
  * If the upload size exceeds the global `MBB` (Max Body Bytes) limit, the API cuts off the read and returns HTTP 400 with the message `"Longitud máxima de contenidos excedida"` *(lit. "Maximum content length exceeded")*.

---

## 10. API HTTP Response Code Standard

| HTTP Code | Functional Meaning | Cause and Request Body |
|---|---|---|
| **`200 OK`** | Operation Processed | The command was executed in memory and/or on disk. Returns a plain-text confirmation (e.g.: `"Subdominio agregado"` *(lit. "Subdomain added")*). |
| **`400 Bad Request`** | Validation / Logic Failure | Null parameters, invalid format, nonexistent resource, incorrect passwords, or exceeded limit restrictions. The Body contains the literal error string that should be shown to the user. |
| **`403 Forbidden`** | Access Blocked | Initial authentication fails, or default credentials are incorrect. Empty Body. |
| **`404 Not Found`** | Incorrect URL | A URI (`RequestURI`) was requested within the `/admin:` prefix that does not correspond to any listed endpoint. |
| **`429 Too Many Requests`** | *Rate Limiter* Triggered | The connection originated while exceeding the interval limits stipulated by the server's control settings (CIL/CIS/CII). The Request is interrupted, and the IP is logged in RAM. |

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
