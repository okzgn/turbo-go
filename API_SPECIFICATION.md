# Turbo - API, Technical Specification

*En español: [API_SPECIFICATION.es.md](./API_SPECIFICATION.es.md).*

## 1. General Architecture and Communication Protocol

The Turbo backend provides an **RPC/REST-style API over HTTP POST**. All interaction between the graphical interface (GUI) or any external client and the server takes place exclusively through `POST` requests.

### 1.1. Main Access Routes (Base URLs)
* **Public Authentication / Login:** `/admin:`
* **Authenticated Administrative Module:** `/admin:inside:`
* **Sign Out:** `/admin:signout:`

### 1.2. Headers and Security
* **HTTP Method:** `POST` is mandatory for all API actions.
* **Parameters:** The action parameters (`s`, `d`, `a`, `b`…) can go in the URL query or in an `application/x-www-form-urlencoded` body. The GUI sends them in the body, so the current password (`b`) never appears in the URL that `turbo.visits` records; API clients should do the same. The exception is `hardUpload` (§9), whose site and subdomain (`s`, `d`, not sensitive) go in the URL, and its password in the multipart body.
* **Session Handling:** After a successful login, the server sets the session cookie (`Path=/; HttpOnly; SameSite=Strict`), which the browser sends by itself: `turbo_session` over HTTP, and `__Host-turbo_session` over HTTPS (with `Secure` and no `Domain`, so browsers only take it from the panel's host and another subdomain can't put one in its place). API clients can instead send the token in the `ok: <token>` header. Every session cookie of the request is tried (a cookie with the same name set by another subdomain may come first), and then the `ok` header. The token is **not** accepted as a URL parameter. Both cookies are removed from the `Cookie` header passed to CGI preprocessors.
* **Same Origin:** A `POST` to `/admin:inside:` authenticated with the cookie must come from the panel's own origin: the browser must send `Sec-Fetch-Site: same-origin` (or `none`) or, without `Sec-Fetch-Site`, an `Origin` header equal to `<scheme>://<Host>`. Otherwise the server responds `403`. Requests authenticated with the `ok` header don't need it.
* **Panel Response Headers:** Responses under `/admin:` carry `X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and a `Content-Security-Policy`: `frame-ancestors 'none'` on the panel's pages, and on everything else (API answers, errors with the error template) one without scripts, frames, forms or plugins (`default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`). On a host of `PA`, every answer outside the panel's pages carries that one too, so an error template never runs scripts on the panel's origin. JSON answers (`sites`, `subdomains`, `subdomainData`, the `WAIT` of `cfgC` and `cfgPC`) are `application/json; charset=utf-8`, and text messages `text/plain; charset=utf-8`.
* **Missing Session:** a request to `/admin:inside:` without a valid session gets the same HTML redirect as always (§3.2) and the header `X-Turbo-Login: required`, which is what clients should look at: the content of a valid answer (an error template, a header or a rewrite of a site) may contain any text.
* **Where the Panel Answers:** The global `PA` setting (see `setPA`, §5) can limit `/admin:` to a list of hosts and/or CIDR networks: the request's `Host` must be one of the hosts (if there are any) and the client's IP must be in one of the networks (if there are any). Otherwise, `/admin:` responds `404`. Empty (the default) means no restriction, and then the panel shares the origin of every site served by Turbo: the recommended setup is a host of its own for the panel, one that serves no site. A `PA` host that serves a site is refused (§5), and so is a new site, subdomain or alias that would serve a `PA` host (`400` with the reason).
* **Session Lifecycle:** Tokens are assigned to the client's IP address and expire after **600 seconds (10 minutes)** of inactivity. Each request to `/admin:inside:` of the panel's own origin (or without `Sec-Fetch-Site`, as API clients send them) resets the timer; one from another origin, such as a resource loaded by another page, doesn't. Changing the username or the password (`setU`, `setP`) closes every other session, and so does `setM` when the `turbo.config` of the new directory brings other credentials; a reload of `turbo.config` that changes them closes every session. Without a valid session, `/admin:inside:` returns the HTML redirect to `/admin:` (see §3.2).

---

## 2. Data Encoding and Character Replacement Conventions

To prevent special characters and URL delimiters from interfering with or corrupting HTTP requests (especially in rewrite rules or headers), the backend requires certain characters to be encoded using a predefined substitution:

### 2.1. Immutable (Fixed) Substitutions
Every form parameter (such as `a`, `s`, `d`) is processed on the server by the URI character-replacement function, except the credentials: the current password (`b` of `set<KEY>`, `delPreprocessor`, `delSite`, `cfgC` and `cfgPC`, and `c` of `addPreprocessor`) and the new username or password (`a` of `setU` and `setP`) are used exactly as sent. `hardUpload` takes all its parameters as sent. The following substitutions must be applied client-side before sending the other parameters, and they can't be changed or deleted:

| Original Character | Expected Transmission Token |
|---|---|
| `;` (Semicolon) | `-.-` |
| `#` (Hash / pound sign) | `-,-` |
| `&` (Ampersand) | `-_-` |

*Note: Administrators can dynamically add additional character replacements via the `addCharsReplace` endpoint (§7.3). The server undoes them all in one pass, the longest tokens first, and values read from `turbo.config` are not decoded again (they are saved decoded).*

*Limit: a text where a replaced character is next to the start or the end of a token can't always be told apart: `-,#` and `#,-` are both sent as `-,-,-`, and the server reads `#,-`. A client can check it before sending: undo the replacements of what it is going to send and compare with the original. The panel doesn't send such a text and says so.*

### 2.2. Characters Not Accepted
No parameter may contain control characters (bytes below `0x20` and `0x7f`) or invalid UTF-8: the server responds HTTP 400 `"Control characters not allowed"` or `"Invalid UTF-8 text"`. The only exception is the response template of `addHttpCodeResponse` (§7.2), which may contain tabs and line breaks.

---

## 3. Authentication and Session Control API

**HTTPS:** over HTTP, every panel request (login and actions included) on a host covered by a certificate (the panel's own, in `turbo.panel/`, or a site's) is redirected to HTTPS while HTTPS is open: 301 for `GET` and `HEAD`, 308 for the rest, which keeps the method and the body. Over HTTPS, on a host of `PA`, the panel answers with `Strict-Transport-Security: max-age=31536000`.

### 3.1. Log In
Validates the user's credentials and generates a unique token bound to the client's IP address. *Note: It could be fragile behind shared NAT/proxies, where multiple users share a public IP.*

* **Endpoint:** `POST /admin:` (only this path and method; a `GET` serves the login page)
* **Body Format:** `multipart/form-data` or `application/x-www-form-urlencoded`, at most 4 KiB (larger: HTTP 413).
* **Required Parameters**, in the body (parameters in the URL are ignored):
  * `u`: Username.
  * `p`: Password.
* **Successful Response (HTTP 200 OK):**
  The server generates a cryptographically secure opaque token (32 random bytes, 64 hexadecimal characters), unique for each login and associated with the client's IP. It sets the session cookie with it (`turbo_session`, or `__Host-turbo_session` over HTTPS), and the body contains the token prefixed by the success variable (`"ok"` by default), for clients that use the `ok` header.
  ```text
  ok<token>
  ```
* **Incorrect Credentials:** HTTP 403 with an empty body.
* **Too Many Failed Logins:** after 5 failures from the same IP within 10 minutes, every login from that IP (even with the right credentials) gets HTTP 429 with `Retry-After` in seconds, without checking the password: 1 minute the first time, then 2, 4, 8 and at most 15 minutes. Logins still being checked count towards the 5: simultaneous logins beyond them get 429 with `Retry-After: 2`. A correct login clears the count. A wrong current password of a `set<KEY>` (§5) or of an action that needs it (`addPreprocessor`, `delPreprocessor`, `hardUpload`, `delSite`, `cfgC` and `cfgPC` with `a=0`) counts as a failed login, and while the IP is blocked, those actions get the same 429 without checking it.
* **Server Busy:** if the password can't be checked within 2 seconds because too many checks are running, HTTP 503 with `Retry-After: 2`. The same applies to the current password (`b`) of `set<KEY>` (§5).

### 3.2. Log Out
Invalidates the current token in RAM memory (other sessions from the same IP stay active) and expires the session cookie (`Max-Age=0`). With the cookie, the request must come from the panel's own origin, as the actions do (§1.2); otherwise, `403` and the session stays open.

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
      "CGL": "0",
      "CGP": "0",
      "PCC": false
    }
  }
  ```
  *(Note: Fixed entries, which cannot be deleted, are returned as `{"f": <value>}`. Text values in the `!` block are URL-encoded, e.g. `@` → `%40`).*

### 4.2. Get List of Subdomains for a Site
Returns a JSON object with all subdomains belonging to a specific root domain, including the alias (if applicable) and the SSL/Redirect configuration for each.

* **Endpoint:** `POST /admin:inside:subdomains`
* **Form Parameters:**
  * `s`: Primary domain (e.g.: `example.com`).
* **Successful Response (JSON):**
  The response always includes the root subdomain, under the empty key `""`, and the other nested subdomains. The `!` block contains the configuration status (1 = Enabled, 0 = Disabled). `C`, the certificate, can also hold the text of Certbot's error when the last attempt failed.
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
  *(Note: In this example, `*.dev` represents a wildcard subdomain that covers any dynamic second-level request under `dev`, such as `test.dev` or `admin.test.dev`. A subdomain without a wildcard, such as `dev`, serves only its own host: `test.dev` needs `*.dev`, or the site's `*`).*

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

Modifies the server's global parameters and operational limits. They change the configuration in use, in memory: only `setC` writes `turbo.config` (the panel's **Save configuration**), and what isn't saved is lost when Turbo stops or reloads the file. `setM` also reads the `turbo.config` of the new directory, if it has one.

* **Base Route:** `POST /admin:inside:set<KEY>`
* **Required Parameters:** `a` (value) and `b` (current password) in **every** `set<KEY>`. If `b` is missing, the server responds HTTP 400 `"Missing data"`; if it is incorrect, HTTP 400 `"Wrong current password"`, and it counts as a failed login of the IP: after 5 failures (logins and `b` together), HTTP 429 with `Retry-After` (§3.1). A value equal to the current one is also answered with HTTP 400 (for example, `"User unchanged"` or `"Password unchanged"`).

| Endpoint | Parameter `a` | Parameter `b` | Description / Validation |
|---|---|---|---|
| `setU` | New Username | Current Password | Changes the username (1-24 bytes in UTF-8: `ñ` or `é` count as 2). |
| `setP` | New Password | Current Password | Changes the password (1-24 bytes in UTF-8: `ñ` or `é` count as 2). |
| `setM` | Directory Path | Current Password | Changes the base site directory (it must exist) and reloads the configuration. The path may be relative to the working directory or use `{TURBO_CURRENT_DIR}`, and is saved as written; the same directory written another way is "Sites directory unchanged". If that directory has a `turbo.config` that is not valid JSON, it responds 400 with where the error is. |
| `setC` | (Ignored; `overwrite` to confirm, see below) | Current Password | Dumps the current in-RAM configuration to disk (`turbo.config`), including the username and the password hash (never the plain password). |
| `setPA` | Hosts / CIDR networks | Current Password | Where the panel answers: comma-separated host names and/or CIDR networks (at most 32 entries and 1,024 chars); with both, a request needs both. Empty or `*` = no restriction (`*` only alone). A host that serves a site (directly, through a wildcard or as an alias) is refused with 400 `"The panel host <host> serves the site <site>: …"`, and so are host wildcards (`*.example.com`, which never match) and a value that would leave out the request that sets it (its host or its IP), with the reason. An IP without `/` is a host, compared with the `Host` header (an IPv6 one as `[::1]` or `::1`); to limit the client's IP, use `/32` or `/128`. |
| `setMUB` | Integer value | Current Password | Adjusts the maximum URI length (40 - 10,240 bytes). |
| `setMHB` | Integer value | Current Password | Adjusts the max. header length (600 - 20,480 bytes). |
| `setMBB` | Integer value | Current Password | Adjusts the max. body size (1B - 100MB). |
| `setCIL` | Value in ms | Current Password | Counter reset interval (1,000 - 800,000 ms). |
| `setCIS` | Value in ms | Current Password | Counting window (10 - 50,000 ms), at least `CII` and at most 66 times `CII`. |
| `setCII` | Integer value | Current Password | Request limit per interval: from 1 up to the value of `CIS` in ms, and `CIS`/`CII` ≤ 66. |
| `setCGL` | Integer value | Current Password | Requests per second for the whole server, among all clients (10 - 1,000,000; `0` = no limit, the default). Requests above it get `503` with `Retry-After: 1`; no IP is blocked. |
| `setCGP` | Integer value | Current Password | CGI processes (preprocessors) running at a time (1 - 100,000; `0` = automatic, the default: 4 per CPU, at least 16). A CGI request that finds no free slot within 2 s gets `503` with `Retry-After: 2`. |
| `setRT` | Time (`5s`, `0s`) | Current Password | Total request Read Timeout (100 ms - 15 min; `0s` disables it). At least twice `RHT`, unless `RHT` is `0s`. |
| `setRHT` | Time (`1s`, `0s`) | Current Password | Read Header Timeout (50 ms - 7.5 min and, when `RT` is not `0s`, at most half of `RT`; `0s` uses `RT`). |
| `setWT` | Time (`10s`, `0s`) | Current Password | Write Timeout for responses (100 ms - 30 min; `0s` disables it). |
| `setIT` | Time (`2s`, `0s`) | Current Password | Idle Timeout for *Keep-Alive* (100 ms - 5 min; `0s` uses `RT`). |

*Notes:*
* *`setPA`: Host entries are compared with the request's `Host` header, which the client chooses: they give the panel an origin of its own, apart from the sites, but do not limit who can reach it. CIDR networks, compared with the client's IP, are what limit access. A `turbo.config` whose `PA` host serves a site still loads, with a warning in the log.*
* *Per-IP limit (`CIL`, `CIS`, `CII`): "IP" is an IPv4 address, or the /64 of an IPv6 address (the block a client usually gets), also for the failed-login limit. Each IP may make `CII` requests per `CIS` window on average, counted from its first request, the current one included: after `t` ms, `CII` × (⌊`t`/`CIS`⌋ + 1) requests in all, so what it didn't use in one window it can use in a later one, until the count starts again. The request beyond that gets 429 and blocks the IP for 5 s. The count starts again `CIL` ms after it began. Times are measured with the monotonic clock, so moving the system clock doesn't block anyone. Turbo keeps up to 200,000 IPs; beyond that, new IPs share a single count (as one client) until the old ones are forgotten, and the IPs already known are not affected. `CGL` counts fixed seconds, so a burst across two of them can reach twice `CGL`; spreading the server among clients is what `CII`/`CIS` do.*
* *`CIS`/`CII` and `RT`/`RHT`: their conditions are checked whichever of them is changed (a change that would break them gets 400), and compared exactly (66.5 is more than 66). In `turbo.config` they are checked once all the settings are read: if they are not met, `CII` (or `RHT`) gets its default value, with a warning in the log; if the default doesn't fit either, so does `CIS` (or `RHT` becomes `0s`, which uses `RT`).*
* *`setM`: errors come in this order: missing `b`, wrong current password (nothing of the new directory is read before), a directory that doesn't exist (400 `"Sites directory not found"`), the same directory written another way (400 `"Sites directory unchanged"`) and a `turbo.config` there that can't be read or is not valid JSON (400 with where the error is). The `turbo.config` of the new directory is always read, also with the same date as the one in use. If it has none, the global settings, the credentials and the lists in use (`@`, `_`, `#`) stay, and are written there with the next `setC`; the answer says so. If it has one, it applies whole, and the answer says what it changed of `PA` and of the credentials. Going back to the start directory doesn't follow the pointer that `setC` left there.*
* *Reloading `turbo.config`: when the file changes (it is checked every 30 s), it applies whole and replaces what came from it: what the file no longer has stops applying, and changes made with `set<KEY>`, `add<KEY>` or `del<KEY>` and not saved with `setC` are lost. The fixed character replacements and responses always stay.*
* *`PA`, `U`, `PH` and `P` in `turbo.config`: if one of them can't be used (another type, a `PA` that `setPA` would refuse, a username or a password out of 1-24 bytes, a hash that isn't Turbo's), the file is invalid: Turbo doesn't start, and a reload or a `setM` to that directory keeps the configuration in use.*
* *`setC`: If `turbo.config` was written by a later version of Turbo (a later schema), saving would lose its new settings, so the server responds HTTP 400 with an explanation; send `a=overwrite` to confirm and overwrite it. The first time a file from an earlier schema is saved, the original is kept as `turbo.config.v<schema>.bak`, and so is a file of a later schema overwritten with `a=overwrite`. A `turbo.config` changed outside Turbo since Turbo read or saved it (an edit not reloaded yet, or one the reload refused) is first copied to `turbo.config.<date>.bak`. If the site directory is not the startup directory, a minimal `turbo.config` pointing to it is also written in the startup directory.*

---

## 6. Site Resource Management API (Add and Delete)

The backend handles folder creation on disk and modifications to the in-RAM maps. *Note on wildcards: Send domains with asterisks (e.g., `*.example.com`). The server will transparently translate them to `#` on disk.*

### 6.1. Add/Update Resources (`add<Type>`)
* **Base Route:** `POST /admin:inside:add<TYPE>`

| Endpoint | `s` (Domain) | `d` (Subdomain) | `a` (Key/Identifier) | `b` (Value/Path) |
|---|---|---|---|---|
| `addSite` | Web Domain | - | - | - |
| `addSubdomain` | Web Domain | Subdomain | - | - |
| `addRewrite` | Web Domain | Subdomain | Source URI (e.g.: `/old`) | Rewrite (`/new`, `http://...`, `https://...`), [dynamic keywords available](https://turbo-server.github.io/#so-2)|
| `addMIME` | Web Domain | Subdomain | Extension (e.g.: `png`) | MIME Type (e.g.: `image/png`), 4 to 128 characters |
| `addHeader` | Web Domain | Subdomain | Header Name (1 to 48 bytes: letters, digits, `-` and `.`) | Header Value (1 to 512 bytes) |
| `addPreprocessor`| Web Domain | Subdomain | Extension (e.g.: `php`) | CGI Executable (e.g.: `/usr/bin/php-cgi`). It also needs the current password, in `c` |
| `addIndex` | Web Domain | Subdomain | Index File (`index.html`)| - |
| `addAlias` | Web Domain | Subdomain | Alias Domain | - |

*Notes:*
* *`addSite` and `addSubdomain`: the names Turbo keeps for its own folders and files in the sites directory (`turbo.dev`, `turbo.panel`, `turbo.certificates`, `turbo.config`, `turbo.visits`, `turbo.denials`) can't be sites, nor can a name whose settings would share a key with another site, or the host of an alias (400 with the reason).*
* *`addRewrite`: The rewrite must start with `/` (internal path), `http://` or `https://`. Targets with `http://` or `https://` are answered with a `302` redirect: to the exact target when it has a path or a query, or to the target domain followed by the original URI when it is only a domain. The source (`a`) is compared with the decoded request path (`/a b` matches `/a%20b`); a source that ends in `/` also takes the folder named without it (`/private/` takes `/private`, which would serve its index), and on Windows and macOS, whose file systems ignore case, a path in another case (`/PRIVATE/`), and an internal target is a URL path too: it is decoded and must stay inside the site (a target with a `..` segment, even one that stays inside, or with `\`, an encoded `/` or `\`, `%00`, control characters, invalid UTF-8 or a segment ending in `.` or a space, is answered with 404).*
* *`addPreprocessor`: The executable path (at most 128 chars as written, without the `cgi>` prefix; it may use `{TURBO_CURRENT_DIR}`, kept as written and replaced when it runs) must exist; the `cgi>` prefix is optional and other prefixes are rejected. In `turbo.config`, an entry that can't be used (not a string, a wrong extension, a path too long or empty, another prefix, a missing executable) is kept with a warning in the log, and its extension answers 500: the files are never served as text. The CGI gets the URL path of the script (after the rewrite) in `SCRIPT_NAME`, an empty `PATH_INFO`, the original URI in `REQUEST_URI`, the file on disk in `SCRIPT_FILENAME` and the site's `@` in `DOCUMENT_ROOT`. `QUERY_STRING` has the client's query first and then the rewrite's, so an application that reads the last value of a repeated parameter (PHP does) gets the rewrite's. A header the site sets (`addHeader`) wins over the CGI's header with the same name. The headers about the connection that a CGI writes (`Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`…) are dropped, and so are a `Content-Length` written twice and a header whose value has control characters (other than a tab): Turbo frames the response.*
* *`addRewrite`: the target starts with `/`, `http://` or `https://` (the scheme in any case; it is saved in lower case), and an `http(s)://` target needs a host, written or given by a keyword (if the keyword gives nothing when answering, 500). Unknown keywords (`{X}`) are refused. Keywords are replaced by values of the decoded request path (`{FIRST_REQUEST}`, `{DIR}`, `{FILE}`, `{EXT}`, `{REWRITE}`, `{REWRITE_COMPLEMENT}`) or of its query (`{FIRST_QUERY}`), encoded for where they go: in the path, each segment, keeping `/`; in the query, as one value; in the host, so that they can't change the URL. `{REWRITE_COMPLEMENT}` in the path takes the rest of the path, and the request's query is added to the target's: `/blog/` → `/new/{REWRITE_COMPLEMENT}` turns `/blog/a/b?x=1` into `/new/a/b?x=1`.*
* *`addIndex`: The index is added at the end of the order; indexes are tried in the order in which they were added. New sites and subdomains start with `index.html`. The name follows the rules of file upload on every system (§9): one segment, without `\`, `/`, `..`, `:`, a final `.` or space, a Windows device name, `~` followed by a digit or a character Windows doesn't allow (`<`, `>`, `"`, `|`, `?`, `*` and control characters); otherwise, HTTP 400 `"Invalid index file"`, and in `turbo.config` the index is dropped with a warning.*

### 6.2. Delete Resources (`del<Type>`)
* **Base Route:** `POST /admin:inside:del<TYPE>`

| Endpoint | `s` (Domain) | `d` (Subdomain) | `a` (Key/Identifier to delete) |
|---|---|---|---|
| `delSite` | Web Domain | Subdomain (Empty = Delete Site) | - (the current password goes in `b`) |
| `delRewrite` | Web Domain | Subdomain | Source URI |
| `delMIME` | Web Domain | Subdomain | Extension |
| `delHeader` | Web Domain | Subdomain | Header Name |
| `delPreprocessor`| Web Domain | Subdomain | Extension (the current password goes in `b`: without the preprocessor, the extension's files would be served as text, their source included) |
| `delIndex` | Web Domain | Subdomain | Index File |
| `delAlias` | Web Domain | Subdomain | Alias Domain |

*All three parameters are required (except `a` in `delSite`): if one is missing, the response is `400` "Missing data".*

---

## 7. Global Security and Interface API

### 7.1. Denied IP Control
A denied IP is blocked until the given date: its requests are answered with HTTP 429 and a `Retry-After` header (seconds left), and its new connections are closed.

* **`POST /admin:inside:addDenied`**
  * `s`: IP address (IPv4 or IPv6). Loopback addresses (`127.x.x.x`, `::1`) and the address the request comes from (`400` "Current IP": the panel would lock itself out) are not accepted.
  * `d`: UNIX timestamp for block expiration (`0` or a past date removes an existing block).
* **`POST /admin:inside:delDenied`**
  * `s`: IP address to unblock from the denied IP list.

### 7.2. HTTP Status Code Responses
* **`POST /admin:inside:addHttpCodeResponse`**
  * `s`: HTTP status code (between `400` and `599`, or `0` for a universal fallback).
  * `d`: Response template, 1 to 2,048 characters. Line breaks and the `{TURBO_RESPONSE_CODE}` macro are supported.
* **`POST /admin:inside:delHttpCodeResponse`**
  * `s`: HTTP status code to revert to the system's default behavior.

### 7.3. Global Character Replacement in URIs
* **`POST /admin:inside:addCharsReplace`**
  * `s`: Character sequence to replace (e.g.: `;`), 1 to 4 bytes.
  * `d`: Target encoded token (e.g.: `-.-`): 2 to 16 characters, without any replaced character (its own included), not containing another token nor inside one; and `s` can't be inside another token. Otherwise, HTTP 400. The fixed substitutions of §2.1 can't be changed (`"Fixed replacement"`). In `turbo.config`, a replacement that breaks these rules is dropped with a warning.
* **`POST /admin:inside:delCharsReplace`**
  * `s`: Character sequence to stop replacing (the fixed substitutions of §2.1 cannot be deleted).

---

## 8. SSL Certificate and Redirect API (`cfg<KEY>`)

Manages HTTPS enablement, application-layer redirects, and certificate configuration/issuance via Certbot.

* **Base Route:** `POST /admin:inside:cfg<KEY>`

| Endpoint | Parameter `a` (Action) | Parameter `s` (Domain) | Parameter `d` (Subdomain) | Optional Parameters |
|---|---|---|---|---|
| **`cfgC`** | `"1"` = Run Certbot<br>`"0"` = Remove from disk (needs the current password in `b`) | Web Domain | Subdomain or Empty (`""`) | `z`: Registration e-mail.<br>`y`: Certbot adapter (`dns-<provider>`, e.g.: `dns-route53`). |
| **`cfgS`** | `"1"` = Enable HTTPS<br>`"0"` = Disable HTTPS | Web Domain | Subdomain or Empty (`""`) | - |
| **`cfgR`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Empty (`""`) only: it is set at the site's root | Redirects `www.<site>` to `<site>` (301). With a subdomain, HTTP 400. |
| **`cfgW`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Empty (`""`) only: it is set at the site's root | Redirects `<site>` to `www.<site>` (301). With a subdomain, HTTP 400. |
| **`cfgE`** | E-mail to register | Web Domain | Subdomain or Empty (`""`) | Silently updates the E-mail for future Certbot renewals. The value is saved as it arrives (a `+` sent encoded as `%2B` stays `+`). |
| **`cfgA`** | Adapter Name (`dns-<provider>`, or empty for webroot) | Web Domain | Subdomain or Empty (`""`) | Silently updates the Adapter flag for Certbot. |

### 8.1. Operational Detail: Certificate Issuance (`cfgC`)
Certbot only runs when it is requested with `a="1"`, and an e-mail is required (saved with `cfgE` or sent in `z`); without it the API responds HTTP 400 `"E-mail required to create the certificate"`. If the site already has a certificate less than 75 days old, the API responds `"SSL certificate active"` without running Certbot. With `a="0"`, the certificate files are deleted whatever their age and the API responds `"SSL certificate deleted"`; with no certificate on disk, nothing is deleted and the API responds HTTP 400 `"No certificate"`. The e-mail of `cfgE` and of `z` is checked the same way: 5 to 40 bytes, one `@` with something before it and a domain with a dot after it, and no spaces, `#`, `--` or a leading `-` (HTTP 400 `"Invalid e-mail value"` or `"Invalid e-mail length"`).

Certificate issuance or renewal does not block the server. When `a="1"` is sent, the API delegates the work to a separate Goroutine, which handles:
1. Running the Certbot binary in webroot mode or via the specified adapter, with its working folder in `turbo.certificates/<site>`.
2. Reading the temporary `archive` folder and locating the most recent files (`fullchain*.pem` and `privkey*.pem`) that are less than 2.5 days (216,000 seconds) old.
3. Physically moving and renaming these files to the site's root path in Turbo.

**Automatic Renewal:** At startup and every 24 hours, Turbo renews the certificates it issued (sites with an e-mail and a folder in `turbo.certificates`) that expire in less than 30 days, and loads them without a restart. Certificates placed by hand are not renewed.

**HTTP Polling Flow for the Frontend:**
Since the operation is asynchronous, the frontend must make continuous requests (polling) to the `cfgC` endpoint, evaluating the JSON response. While the issuance is in progress the API responds **HTTP 202** with one of these bodies:
* `{"message":"Please wait, certificate in process","status":"WAIT"}`: The Goroutine has just started.
* `{"message":"Please wait, certificate being processed","status":"WAIT"}`: Certbot is working.
* `{"message":"Please wait, certificate busy on <domain>","status":"WAIT"}`: Certbot is busy issuing a certificate for another site. Turbo retries this request by itself every 30 seconds until Certbot is free: the client only has to keep polling.
* **Successful Response (200 OK):** `"SSL certificate active"` (the client should stop polling).
* **Error Response (400 Bad Request):** Returns the raw error output from Certbot or the filesystem.

The GUI does this by itself: after a 202 it asks again every 5 seconds, for 4 minutes at most, and shows the result. Cancelling any step of its dialog (e-mail, adapter, confirmation) sends nothing, and emptying an adapter that was saved asks whether to go back to webroot (`cfgA` with an empty value).

### 8.2. The Panel's Own Certificate (`cfgPC`)
`POST /admin:inside:cfgPC` issues or deletes the certificate of the panel's own hosts: the host names in `PA` (IP addresses are left out). It takes no `s` or `d`.

* `a="1"`: runs Certbot as `cfgC` does, with a `-d` for each host of `PA`, in webroot mode (`turbo.panel/webroot` inside the sites directory; Turbo answers its challenges, `/.well-known/acme-challenge/<token>`, only on the hosts of `PA`) or with the adapter; Certbot works in `turbo.certificates/turbo.panel`, and the files end up in `turbo.panel/`. The answers are those of `cfgC` (202 `WAIT` while it runs, one issuance at a time among sites and panel; 200 `"Panel certificate active"` when a certificate that covers every host of `PA`, and expires in more than 30 days, is in use; 400 with the error of the last attempt, once). Without an e-mail: 400 `"E-mail required to create the certificate"`; without a host name in `PA`: 400.
* `a="0"`: deletes `turbo.panel/fullchain.pem` and `privkey.pem` and stops using the certificate. It needs the current password in `b`, as `cfgC` with `a="0"`, and over HTTPS its answer sends `Strict-Transport-Security: max-age=0`, so that browsers can reach the panel by HTTP again; without the files, 400 `"No panel certificate"`.
* `z`: the e-mail, saved as `PCE` in `.` of `turbo.config`. `y`: the DNS adapter (`dns-<provider>`), saved as `PCA`; an empty `y` goes back to webroot, and without `y` the saved one stays.

The automatic renewal also renews the panel's certificate when it expires in less than 30 days, and `/admin:inside:sites` says its state in `.` as `PCC` (with `PCE` and `PCA` when they are set): `true` (in use), `"WAIT"` (Certbot running) or `false`. A certificate placed by hand in `turbo.panel/` is used too, but not renewed.

### 8.3. Operational Detail: Hot SSL Activation (`cfgS`)
Turbo does not require restarts to apply certificates. When the activation command (`a="1"`) is received:
1. Go reads the `fullchain.pem` and `privkey.pem` files directly from disk and immediately injects them into the server's shared RAM memory.
2. If port `443` (or the address in `TURBO_HTTPS_ADDR`) was closed (because the server started without certificates), **a new socket Listener is automatically started**.
3. From this point on, Turbo forces a `301 Moved Permanently` redirect to `https://`, on the same host, for the HTTP traffic entering that domain/subdomain when a certificate covers the requested host. An alias without a certificate that covers its name keeps being served over HTTP.

During the TLS handshake, each name receives the certificate that covers it (exactly or with a wildcard). Names that no certificate covers, and connections without SNI (access by IP), are rejected.

*Note: Disabling HTTPS (`a="0"`) purges the certificate from RAM memory (preventing future TLS connections for that host), but it **does not delete** the `.pem` files from disk, nor does it close port 443 at the network level.*

---

## 9. Physical File Management API (`hardUpload`)

Used to bulk-replace all public files associated with a subdomain/domain. The server writes the new files to a folder of its own next to `@` (`@.upload-<random>`) and then puts it in place of `@` all at once (the previous `@` is `@.previous-<random>` for an instant, and is then removed), so the existing content (subfolders included) is replaced as a whole: until then, `@` is left as it was, and if anything fails, nothing changes.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Body Format:** `multipart/form-data`
* **Form Parameters:**
  * `s`: Primary domain (e.g.: `example.com`).
  * `d`: Subdomain (empty `""` for the root domain).
  * `f`: Array of attached files (`File[]`).
  * `b`: the current password, only in the multipart body (never in the URL, which `turbo.visits` records).

  `s` and `d` are accepted both in the URL and in the multipart body.
* **Nested Directory Handling:**
  The backend parses the `filename` parameter within the `Content-Disposition` HTTP header of each multipart block. The first segment of each path (the folder chosen in the browser) is discarded, and `\` counts as a separator. If the rest of the name contains relative paths (e.g.: `site/assets/img/logo.png` → `assets/img/logo.png`), Turbo will create the folder structure. A file and a folder can't have the same name: of `a` and `a/b`, the later one is discarded (compared without case on Windows and macOS). So are names that the file systems can't hold: a file or folder name longer than 255 bytes, or a path inside `@` longer than 1,024 bytes. Names that would leave `@` (with `..`, absolute or with `:`) are discarded, and so are, on every system, the names Windows treats specially: ending in `.` or a space, a reserved device name (`CON`, `NUL`, `COM1`…), `~` followed by a digit (8.3 short names) or a character Windows doesn't allow (`<`, `>`, `"`, `|`, `?`, `*` and control characters).
* **Successful Response (HTTP 200 OK):**
  Returns the string `"Data uploaded"`. If any file was discarded, the response lists them: `"Data uploaded. Discarded: <name>, <name>"`.
* **Specific Error Handling:**
  * If the upload size exceeds the global `MBB` (Max Body Bytes) limit, or it has more than 10,000 parts (the files and the `b` field), the API cuts off the read and returns HTTP 413 with the message `"Maximum body size exceeded"`. A malformed multipart body gets HTTP 400 `"Invalid parameters"`. (Other multipart forms admit at most 1,000 parts.) `MBB` bounds the memory the upload takes, as it is kept in memory: the contents plus about 600 bytes per file (its name, headers and entry), so a file of exactly `MBB` bytes never fits, and a site of many small files needs room for them. As each upload replaces the whole `@`, the way out of a 413 is a larger `MBB`, not uploading fewer files; the panel says so.
  * If every name is discarded, HTTP 400 `"No valid file; nothing was changed. Discarded: …"`, and `@` is left as it was.
  * If `@` can't be replaced (on Windows, for example, while a file in it is open), HTTP 400 `"The public directory could not be replaced (open files?); nothing was changed"`; a file that can't be written gives HTTP 500. In both cases `@` is left as it was.
  * If the site is deleted during the upload, HTTP 400 `"Site not found"`, and the site does not come back.
  * If no file comes in `f`, HTTP 400 `"No data"`.

---

## 10. API HTTP Response Code Standard

| HTTP Code | Functional Meaning | Cause and Request Body |
|---|---|---|
| **`200 OK`** | Operation Processed | The command was executed in memory and/or on disk. Returns a plain-text confirmation (e.g.: `"Subdomain added"`). |
| **`202 Accepted`** | In Progress | Only `cfgC` and `cfgPC` while a certificate is being issued: a JSON body with `"status":"WAIT"` (§8.1). Keep polling. |
| **`400 Bad Request`** | Validation / Logic Failure | Null parameters, invalid format, nonexistent resource, incorrect passwords, or exceeded limit restrictions. The Body contains the literal error string that should be shown to the user. |
| **`403 Forbidden`** | Access Blocked | Login with incorrect credentials (empty Body), or a `POST` authenticated with the session cookie that does not come from the same origin (§1.2). |
| **`404 Not Found`** | Incorrect URL | A URI (`RequestURI`) was requested within the `/admin:` prefix that does not correspond to any listed endpoint, or the panel does not answer on that host or network (`PA`). |
| **`413 Payload Too Large`** | Parameters Too Large | The parameters of an action (or the login body, §3.1) are larger than allowed: `MBB`, and at most 10 MiB in an `application/x-www-form-urlencoded` body. A file upload (§9) too large gets `413` too. Parameters that can't be decoded (for example, a malformed `%` escape) get `400` `"Invalid parameters"`. |
| **`429 Too Many Requests`** | *Rate Limiter* Triggered | The client's IP exceeded its limits (CIL/CIS/CII), the IP is denied (§7.1), or its logins are blocked after failed attempts, which include wrong current passwords of `set<KEY>` and of the actions that need one (§3.1). Each request counts once. The response carries `Retry-After` with the seconds to wait, and new connections from a blocked IP are closed. |
| **`503 Service Unavailable`** | Global Limit Reached | The whole server received more than `CGL` requests in the current second (`Retry-After: 1`), the password of a login or the current password of a `set<KEY>` or of an action that needs it couldn't be checked within 2 seconds (`Retry-After: 2`, §3.1), or a CGI found no free slot within 2 seconds (`CGP`, `Retry-After: 2`). |
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
