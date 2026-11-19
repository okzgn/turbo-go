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
* **Session Handling:** After a successful login, the server sets the session cookie (`Path=/; HttpOnly; SameSite=Strict`), which the browser sends by itself: `turbo_session` over HTTP, and `__Host-turbo_session` over HTTPS (with `Secure` and no `Domain`, so browsers only take it from the panel's host and another subdomain can't put one in its place). The cookie of HTTP, which has no `Secure`, is no session in a request by HTTPS: a session opened by HTTP signs in again once the panel is reached by HTTPS. API clients can instead send the token in the `ok: <token>` header, which is a session by either. Every session cookie of the request is tried (a cookie with the same name set by another subdomain may come first), and then the `ok` header. The token is **not** accepted as a URL parameter. Both cookies are removed from the `Cookie` header passed to the preprocessors (a CGI, a worker of the mode dx), and so is the `ok` header.
* **Same Origin:** A `POST` to `/admin:inside:` authenticated with the cookie must come from the panel's own origin: the browser must send `Sec-Fetch-Site: same-origin` (or `none`) or, without `Sec-Fetch-Site`, an `Origin` header equal to `<scheme>://<Host>`. Otherwise the server responds `403`. Requests authenticated with the `ok` header don't need it.
* **Panel Response Headers:** Responses under `/admin:` carry `X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and a `Content-Security-Policy`: on the pages of the panel embedded in the binary, one that lets them run only their own script and style (by their hashes) and load only the panel's own files; on a page of your own in `turbo.dev/`, `frame-ancestors 'none'`; and on everything else (API answers, errors with the error template) one without scripts, frames, forms or plugins (`default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`). Every error that Turbo answers with the error template carries that one too, on every host, before or after reading the request, so an error template never runs scripts: with `PA` empty (the default) the sites share the panel's origin. On a host of `PA`, so does every answer outside the panel's pages. JSON answers (`sites`, `subdomains`, `subdomainData`, the `WAIT` of `cfgC` and `cfgPC`) are `application/json; charset=utf-8`, and text messages `text/plain; charset=utf-8`.
* **Missing Session:** a request to `/admin:inside:` without a valid session gets the same HTML redirect as always (§3.2) and the header `X-Turbo-Login: required`, which is what clients should look at: the content of a valid answer (an error template, a header or a rewrite of a site) may contain any text. An action is checked against its session again once its body has arrived (or, for `hardUpload`, its files): one whose session was closed meanwhile (`closeSessions`, new credentials, its expiry) applies nothing and gets the same answer.
* **Where the Panel Answers:** The global `PA` setting (see `setPA`, §5) can limit `/admin:` to a list of hosts and/or CIDR networks: the request's `Host` must be one of the hosts (if there are any) and the client's IP must be in one of the networks (if there are any). Otherwise, `/admin:` responds `404`. Empty (the default) means no restriction, and then the panel shares the origin of every site served by Turbo: the recommended setup is a host of its own for the panel, one that serves no site. With networks and no host, the panel answers only when the `Host` is an IP address or `localhost`, never a name: a page whose name resolves to Turbo (DNS rebinding) would otherwise reach the panel from the browser of someone in those networks, on its own origin. In that mode the IP addresses and `localhost` are the panel's hosts, and a site `*` (which serves every IP address), a site `localhost` or an alias `localhost` would share its origin: a new one is refused (`400` with the reason), and one that `turbo.config` has, or a folder brings, is kept, with a warning in the log when `turbo.config` is read, when the folder of a site appears and when `PA` changes. A `PA` host that serves a site is refused (§5), and so is a new site, subdomain or alias that would serve a `PA` host (`400` with the reason).
* **Session Lifecycle:** Tokens are assigned to the client's IP address and expire after **600 seconds (10 minutes)** of inactivity, and **12 hours** after the login at most, however they are used. Each request to `/admin:inside:` of the panel's own origin (or without `Sec-Fetch-Site`, as API clients send them) resets the timer, up to that limit; one from another origin, such as a resource loaded by another page, doesn't. An upload (`hardUpload`, §9) resets it too while its files arrive: one that takes longer than those ten minutes isn't dropped at its end. Changing the username or the password (`setU`, `setP`) closes every session, the request's own too, and opens a new one for its client: the answer sets the new cookie and, for a request whose session came in the `ok` header (an API client), carries the new token in its `ok` header, which API clients must send from then on; a browser, whose session came in the cookie, gets it only there, where its pages' scripts can't read it (a copy of the old token is worth nothing). So do `setM`, when the `turbo.config` of the new directory brings other credentials, and `closeSessions` (§3.3); a reload of `turbo.config` that changes them closes every session. Without a valid session, `/admin:inside:` returns the HTML redirect to `/admin:` (see §3.2).
* **What the Session Alone Can Do:** read the state (`sites`, `subdomains`, `subdomainData`); add and delete sites and subdomains, rewrites inside the site, indexes and aliases (`delSite` aside), and delete denied IPs; and the `cfg<KEY>` that neither delete a certificate, turn a site's HTTPS off nor stop the renewal of a certificate (those of a site but `cfgC` and `cfgS` with `a=0`, `cfgE` that removes the e-mail, `cfgA` with another adapter and `cfgC` with another adapter in `y`; and `cfgPC` with `a=1` and the adapter saved, or no `y`). Every other action also needs the current password: `addRewrite` when its target starts with `http://` or `https://` or is an expression (§6.3), `addDenied` and `cfgS` with `a=0` (they send the visitors of a site to another address, cut a client off from every site, and take a site's HTTPS away), what stops the renewal of a certificate, which takes its site down when it expires (`cfgE` with an empty value when the site has an e-mail, `cfgA` with another adapter, and `cfgC` or `cfgPC` with another adapter in `y`), `set<KEY>`, `addPreprocessor` and `delPreprocessor`, `addMIME` and `delMIME`, `addHeader` and `delHeader` (a MIME type or a header can make a site's file run as a page), `delSite`, `hardUpload`, `cfgC` and `cfgPC` with `a=0`, `addHttpCodeResponse` and `delHttpCodeResponse` (a template is the error page of every site), `addCharsReplace` and `delCharsReplace` (a replacement changes what the actions read) and `closeSessions`.

---

## 2. Data Encoding and Character Replacement Conventions

To prevent special characters and URL delimiters from interfering with or corrupting HTTP requests (especially in rewrite rules or headers), the backend requires certain characters to be encoded using a predefined substitution:

### 2.1. Immutable (Fixed) Substitutions
The server undoes the character replacements (the fixed ones below and those added with `addCharsReplace`, §7.3) in the paths, types and values that the actions on the resources of a site read, and never in the site and the subdomain (`s` and `d`) of any action: in practice, `a` and `b` of `addRewrite`, `addMIME`, `addHeader`, `addIndex` and `addAlias`, and `a` of their `del<Type>`; the current password of those that need it (`c` of `addRewrite`, `addMIME` and `addHeader`, and `b` of `delMIME`, `delHeader` and `addDenied`) is taken as sent. The other actions that need the current password, `cfg<KEY>` and `hardUpload` take every parameter exactly as sent: send them URL-encoded, as an `application/x-www-form-urlencoded` body does by itself. A replacement then can't change what the administrator confirms with the password (an extension, the program of a preprocessor, the site to delete). The following substitutions must be applied client-side before sending the parameters that the server decodes, and they can't be changed or deleted:

| Original Character | Expected Transmission Token |
|---|---|
| `;` (Semicolon) | `-.-` |
| `#` (Hash / pound sign) | `-,-` |
| `&` (Ampersand) | `-_-` |

*Note: Administrators can add more character replacements with `addCharsReplace` (§7.3), which needs the current password. The server undoes them all in one pass, the longest tokens first, and values read from `turbo.config` are not decoded again (they are saved decoded).*

*Limit: a text where a replaced character is next to the start or the end of a token can't always be told apart: `-,#` and `#,-` are both sent as `-,-,-`, and the server reads `#,-`. A client can check it before sending: undo the replacements of what it is going to send and compare with the original. The panel doesn't send such a text and says so.*

### 2.2. Characters Not Accepted
No parameter may contain control characters (bytes below `0x20` and `0x7f`) or invalid UTF-8: the server responds HTTP 400 `"Control characters not allowed"` or `"Invalid UTF-8 text"`. The only exceptions are the response template of `addHttpCodeResponse` (§7.2) and an expression (§6.3) of `addHeader` or `addRewrite`, which may contain tabs and line breaks.

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
  The server generates a cryptographically secure opaque token (32 random bytes, 64 hexadecimal characters), unique for each login and associated with the client's IP. It sets the session cookie with it (`turbo_session`, or `__Host-turbo_session` over HTTPS), and the body is `ok` followed by the token, for clients that use the `ok` header. A browser's request (one with `Sec-Fetch-Site` or, where the browser doesn't send it, as to a panel reached by HTTP on another host than `localhost`, with `Origin`), as the login page of the panel sends it, gets `ok` alone: its session is in the cookie, which its scripts can't read.
  ```text
  ok<token>
  ```
* **Incorrect Credentials:** HTTP 403 with an empty body.
* **The Default Password:** the password `Admin`, while it is the panel's, opens a session only from this machine: from a loopback address (`127.0.0.1`, `::1`), to a `Host` that is `localhost`, a loopback address or a host of `PA` (a page of another name whose name resolves to this machine can't use it), and without a header that a proxy in front sends (`Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, `Via`, `CF-Connecting-IP`, `True-Client-IP`). From elsewhere, HTTP 403 with `X-Turbo-Login: local-only` and a message that says so, without counting as a failure. Sign in on the machine (an SSH tunnel to its port 80 works) and change it, or set `TURBO_PASSWORD`.
* **Another Origin:** a login that the browser says comes from another origin (`Sec-Fetch-Site` other than `same-origin` or `none` or, without it, an `Origin` other than `<scheme>://<Host>`) gets HTTP 403 before its body is read, without counting as a failure: any page could otherwise make the administrator's browser log in with wrong credentials and lock its IP out. A client without those headers (curl, a script) isn't affected.
* **Too Many Failed Logins:** after 5 failures from the same IP (an IPv4 address, or an IPv6 /64) within 10 minutes, every login from that IP (even with the right credentials) gets HTTP 429 with `Retry-After` in seconds, without checking the password: 1 minute the first time, then 2, 4, 8 and at most 15 minutes. The /64s of an IPv6 /48 also share a count of 20 failures within 10 minutes, with the same blocks for all of them. Logins still being checked count towards the limits: simultaneous logins beyond them get 429 with `Retry-After: 2`. A correct login clears the count of its IP and trusts its client (an IPv4 address or an IPv6 /64) for 12 hours: its logins skip the count of its /48, though not its own, and may take the check kept for the sessions (below). It doesn't clear the count of its /48). The wrong current passwords of a `set<KEY>` (§5) or of an action that needs it (§1.2) count per session, not for the IP, with those still being checked: the fifth in a session closes it (HTTP 400 with `X-Turbo-Login: required`, as a request without a session gets), one more while five are being checked gets HTTP 429 with `Retry-After: 2`, and a right one clears the count.
* **Server Busy:** if the password can't be checked within 2 seconds because too many checks are running, HTTP 503 with `Retry-After: 2`. One of the checks that run at a time is kept for the current password of a request with a session and for the logins of the trusted clients (above), so a flood of logins from elsewhere doesn't keep the administrator out. The same 503 applies to the current password (`b`) of `set<KEY>` (§5) and of the actions that need it.

### 3.2. Log Out
Invalidates the current token in RAM memory (other sessions from the same IP stay active) and, when the request brings the session cookie, expires it (`Max-Age=0`). With the cookie, the request must come from the panel's own origin, as the actions do (§1.2); otherwise, `403` and the session stays open.

* **Endpoint:** `POST /admin:signout:` (a `GET` does not sign out: it serves the login page)
* **Authentication:** The session cookie or the `ok` header.
* **Successful Response (HTTP 200 OK):**
  Returns an HTML string forcing browser redirection.
  ```html
  <meta http-equiv='refresh' content='0; URL=/admin:'/>
  ```

### 3.3. Close Every Session
Closes every session of the panel, the request's own too (and any copy of its token), and opens a new one for its client, as changing the credentials does. The panel's **Close every session**.

* **Endpoint:** `POST /admin:inside:closeSessions`
* **Parameters:** `b`, the current password, as sent. Missing: HTTP 400 `"Missing data: the current password (b)"`; wrong: HTTP 400 `"Wrong current password"`, which counts for the session (§3.1).
* **Successful Response (HTTP 200 OK):** `"Every session closed: this one goes on with a new token"`, with the new cookie and, for an API client, the new token in the `ok` response header.

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
      "404": "Page not found: {TURBO_RESPONSE_CODE}"
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
  *(Note: Fixed entries, which cannot be deleted, are returned as `{"f": <value>}`. Text values in the `!` block are URL-encoded, e.g. `@` → `%40`. `~` lists the sites whose folder isn't there, with their subdomains in the same case (`""` is the site itself): Turbo keeps their settings, also in `turbo.config`, for when the folder comes back, until their folder is gone and `delSite` forgets them, which deletes no folder).*

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
* **Required Parameters:** `a` (value) and `b` (current password) in **every** `set<KEY>`. If `b` is missing, the server responds HTTP 400 `"Missing data"`; if it is incorrect, HTTP 400 `"Wrong current password"`, which counts for the session: the fifth in a session closes it (`X-Turbo-Login: required`, §3.1). A value equal to the current one is also answered with HTTP 400 (for example, `"User unchanged"` or `"Password unchanged"`).

| Endpoint | Parameter `a` | Parameter `b` | Description / Validation |
|---|---|---|---|
| `setU` | New Username | Current Password | Changes the username (1-24 bytes in UTF-8: `ñ` or `é` count as 2). Every session ends, and the answer brings a new one (§1.2). With `TURBO_USER` set, 400: it is changed there, and Turbo restarted. |
| `setP` | New Password | Current Password | Changes the password: 12 to 64 bytes in UTF-8 (`ñ` or `é` count as 2); otherwise, 400 `"The password must have 12 to 64 bytes"`. A shorter password already in use (`Admin`, `TURBO_PASSWORD`, `turbo.config`) keeps working. Every session ends, and the answer brings a new one (§1.2). With `TURBO_PASSWORD` set, 400: it is changed there, and Turbo restarted. |
| `setM` | Directory Path | Current Password | Changes the base site directory (it must exist) and reloads the configuration. The path may be relative to the working directory or use `{TURBO_CURRENT_DIR}`, and is saved as written; the same directory written another way is "Sites directory unchanged". If that directory has a `turbo.config` that is not valid JSON, it responds 400 with where the error is. |
| `setC` | (Ignored; `overwrite` to confirm, see below) | Current Password | Dumps the current in-RAM configuration to disk (`turbo.config`), including the username and the password hash (never the plain password). |
| `setPA` | Hosts / CIDR networks | Current Password | Where the panel answers: comma-separated host names and/or CIDR networks (at most 32 entries and 1,024 bytes); with both, a request needs both. Empty or `*` = no restriction (`*` only alone). A host that serves a site (directly, through a wildcard or as an alias) is refused with 400 `"The panel host <host> serves the site <site>: …"`, and so are host wildcards (`*.example.com`, which never match) and a value that would leave out the request that sets it (its host or its IP), with the reason. An IP without `/` is a host, compared with the `Host` header (an IPv6 one as `[::1]` or `::1`); to limit the client's IP, use `/32` or `/128`. With networks only, a site `*` or `localhost`, or an alias `localhost`, shares the panel's origin (§1.2): the answer is the same, and the log warns of it. |
| `setMUB` | Integer value | Current Password | Adjusts the maximum URI length (40 - 10,240 bytes). |
| `setMHB` | Integer value | Current Password | Adjusts the max. header length (600 - 20,480 bytes). |
| `setMBB` | Integer value | Current Password | Adjusts the max. body size (1B - 100MB). |
| `setCIL` | Value in ms | Current Password | Counter reset interval (1,000 - 800,000 ms). |
| `setCIS` | Value in ms | Current Password | Counting window (10 - 50,000 ms), at least `CII` and at most 66 times `CII`. |
| `setCII` | Integer value | Current Password | Request limit per interval: from 1 up to the value of `CIS` in ms, and `CIS`/`CII` ≤ 66. |
| `setCGL` | Integer value | Current Password | Requests per second for the whole server, among all clients (10 - 1,000,000; `0` = no limit, the default). Requests above it get `503` with `Retry-After: 1`; no IP is blocked. |
| `setCGP` | Integer value | Current Password | CGI processes (preprocessors) running at a time (1 - 100,000; `0` = automatic, the default: 4 per CPU, at least 16). A CGI request that finds no free slot within 2 s gets `503` with `Retry-After: 2`. The output of a CGI waits for its client in memory and in temporary files, so the CGI frees its slot when it ends; at most a quarter of the slots (at least one; half for an IPv6 /48) may wait for responses of one client (an IPv4 address or an IPv6 /64) that are over their limits or its share, and a response that would wait beyond that is cut. The requests that wait for a slot get one in their order of arrival, but one client may hold a quarter of the slots, and an IPv6 /48 a half (at least one), while others wait: beyond, its requests wait behind theirs; while no one else waits, a free slot is anyone's. Behind a proxy every client is the proxy (README, "Known Limitations"), and they get their slots in their order of arrival. A request whose client goes away while it waits takes no slot, and a higher `CGP` gives its slots at once to those that wait. |
| `setRT` | Time (`5s`, `0s`) | Current Password | Total request Read Timeout (100 ms - 15 min; `0s` disables it). At least twice `RHT`, unless `RHT` is `0s`. |
| `setRHT` | Time (`1s`, `0s`) | Current Password | Read Header Timeout (50 ms - 7.5 min and, when `RT` is not `0s`, at most half of `RT`; `0s` uses `RT`). |
| `setWT` | Time (`10s`, `0s`) | Current Password | Write Timeout for responses, and how long a CGI may run (100 ms - 30 min; `0s` disables it). A file that a client takes longer to download is cut, unless `WFT` gives it more. |
| `setWFT` | Time (`10m`, `0s`) | Current Password | Write Timeout for the files of the sites, apart from `WT` (100 ms - 24 h; `0s`, the default, uses `WT`). |
| `setIT` | Time (`2s`, `0s`) | Current Password | Idle Timeout for *Keep-Alive* (100 ms - 5 min; `0s` uses `RT`). |

*Notes:*
* *`setPA`: Host entries are compared with the request's `Host` header, which the client chooses: they give the panel an origin of its own, apart from the sites, but do not limit who can reach it. CIDR networks, compared with the client's IP, are what limit access. A `turbo.config` whose `PA` host serves a site still loads, with a warning in the log.*
* *Per-IP limit (`CIL`, `CIS`, `CII`): "IP" is an IPv4 address, or the /64 of an IPv6 address (the block a client usually gets), also for the failed-login limit. Each IP may make `CII` requests per `CIS` window on average, counted from its first request, the current one included: after `t` ms, `CII` × (⌊`t`/`CIS`⌋ + 1) requests in all, so what it didn't use in one window it can use in a later one, until the count starts again. The request beyond that gets 429 and blocks the IP for 5 s. The count starts again `CIL` ms after it began. Times are measured with the monotonic clock, so moving the system clock doesn't block anyone. Turbo keeps up to 200,000 IPs; beyond that, until the old ones are forgotten, a new IP shares the count of its network, an IPv4 /24 or an IPv6 /48 (up to 25,000 of those), then that of a /16 or a /32 (up to 3,125), and only then a single count with every other new IP. A shared count answers 429, but closes no connection, and the IPs already known are not affected. `CGL` counts fixed seconds, so a burst across two of them can reach twice `CGL`; spreading the server among clients is what `CII`/`CIS` do.*
* *`CIS`/`CII` and `RT`/`RHT`: their conditions are checked whichever of them is changed (a change that would break them gets 400), and compared exactly (66.5 is more than 66). In `turbo.config` they are checked once all the settings are read: if they are not met, `CII` (or `RHT`) gets its default value, with a warning in the log; if the default doesn't fit either, so does `CIS` (or `RHT` becomes `0s`, which uses `RT`).*
* *`setM`: errors come in this order: missing `b`, wrong current password (nothing of the new directory is read before), a directory that doesn't exist (400 `"Sites directory not found"`), one that can't be listed (400 `"Sites directory can't be read"`), the same directory written another way (400 `"Sites directory unchanged"`) and a `turbo.config` there that can't be used, or whose `M` leads to a directory that doesn't exist or can't be listed, to a `turbo.config` that can't be used, or back to a directory on the way (400 with where the error is): all of it is checked before anything changes. The `turbo.config` of the new directory is always read, also with the same date as the one in use. If it has none, the global settings, the credentials and the lists in use (`@`, `_`, `#`) stay, and are written there with the next `setC`; the answer says so. If it has one, it applies whole, and the answer says what it changed of `PA` and of the credentials. Going back to the start directory doesn't follow the pointer that `setC` left there, nor the `M` of a whole `turbo.config` there. The new directory is put in use together with its configuration, at once: if that fails (its `turbo.config` changed after the checks, for one), nothing changes and the answer is 400 with why. Turbo follows at most two directories counted from the start directory, for `setM` as at the start.*
* *Reloading `turbo.config`: when the file changes (it is checked every 30 s), it applies whole and replaces what came from it: what the file no longer has stops applying, and changes made with `set<KEY>`, `add<KEY>` or `del<KEY>` and not saved with `setC` are lost. The fixed character replacements and responses always stay.*
* *`PA`, `U`, `PH` and `P` in `turbo.config`: if one of them can't be used (another type, a `PA` that `setPA` would refuse, a username out of 1-24 bytes or a password out of 1-64, a hash that isn't Turbo's), the file is invalid: Turbo doesn't start, and a reload or a `setM` to that directory keeps the configuration in use. So is a site or a subdomain whose key isn't the name of one (`Example.com`, `example.com.`, with a space), as its folder is named, a site, or a list of a site (`!`, `=`, `$`, `.`, `?`, `-`, `&`), that isn't a JSON object, and a whole `turbo.config` whose `M` names a directory that doesn't exist or can't be listed: skipped, the site would be served without its settings, its scripts as text.*
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
| `addRewrite` | Web Domain | Subdomain | Source URI (e.g.: `/old`) | Rewrite (`/new`, `http://...`, `https://...`), [dynamic keywords available](https://turbo-server.github.io/#so-2), or an expression (`=…`, §6.3). A target that starts with `http://` or `https://`, and an expression, also need the current password, in `c` |
| `addMIME` | Web Domain | Subdomain | Extension (e.g.: `png`), without a dot inside | MIME Type (e.g.: `image/png`), 4 to 128 characters. It also needs the current password, in `c` |
| `addHeader` | Web Domain | Subdomain | Header Name (1 to 48 bytes: letters, digits, `-` and `.`) | Header Value (1 to 512 bytes), or an expression (`=…`, §6.3). It also needs the current password, in `c` |
| `addPreprocessor`| Web Domain | Subdomain | Extension (e.g.: `php`), without a dot inside | CGI Executable (e.g.: `/usr/bin/php-cgi`), or `dx>` and the program of a worker (§6.4). It also needs the current password, in `c` |
| `addIndex` | Web Domain | Subdomain | Index File (`index.html`)| - |
| `addAlias` | Web Domain | Subdomain | Alias Domain | - |

*Notes:*
* *`addHeader`: a header that only differs in case from one of the site replaces it ("Header changed"): both would go out, either one first. The headers that HTTP sets for the connection and the length of a body (`Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Upgrade`) are refused (400 "Header reserved"); in `turbo.config`, dropped with a warning. `delHeader` deletes the header in any case.*
* *`addSubdomain`: a subdomain can't be called as the certificate files of its site (`fullchain.pem`, `privkey.pem`, `fullchain.pem.new`, `privkey.pem.new`), whose place its folder would take. `addAlias`: an alias whose host falls under the domain of a site (`m.example.com` with the site `example.com`) is refused (400 "The alias is a site's host"), also when no subdomain serves that host; with a site `*`, every alias is. An alias can't be an IP address (400): only the site `*` serves one, and then the alias is its host; in `turbo.config`, it is dropped with a warning. `addMIME` and `addPreprocessor`: the extension is what follows the last dot of a name (`php`, not `blade.php`); an empty one is that of the files without an extension, but the file of an ACME challenge, which has none, is always given as it is.*
* *`addSite` and `addSubdomain`: the names Turbo keeps for its own folders and files in the sites directory (`turbo.dev`, `turbo.panel`, `turbo.certificates`, `turbo.config`, `turbo.visits`, `turbo.denials`) can't be sites, nor can a name whose settings would share a key with another site, the host of an alias, or an IP address (`192.168.1.10`), which only the site `*` serves (400 with the reason), nor a site or subdomain that Turbo keeps without its folder (`~` of `sites`), until its folder is gone and `delSite` forgets it (400 "… is kept, with its settings…").*
* *`addRewrite`: The rewrite must start with `/` (internal path), `http://` or `https://`. Targets with `http://` or `https://` are answered with a `302` redirect: to the exact target when it has a path or a query, or to the target domain followed by the original URI when it is only a domain. The source (`a`) is compared with the decoded request path (`/a b` matches `/a%20b`); a source that ends in `/` also takes the folder named without it (`/private/` takes `/private`, which would serve its index), and on Windows and macOS, whose file systems ignore case, a path in another case (`/PRIVATE/`), and on macOS a name written with a letter and its accent apart (NFD), which it opens as the same name with them in one character (NFC), and an internal target is a URL path too: it is decoded and must stay inside the site (a target with a `..` segment, even one that stays inside, or with `\`, an encoded `/` or `\`, `%00`, control characters, invalid UTF-8 or a segment ending in `.` or a space, is answered with 404).*
* *`addPreprocessor`: The executable path (at most 128 chars as written, without the prefix of its mode; it may use `{TURBO_CURRENT_DIR}`, kept as written and replaced when it runs) must exist; the prefix is `cgi>`, optional, or `dx>` (§6.4), and other prefixes are rejected. In `turbo.config`, an entry that can't be used (not a string, a wrong extension, a path too long or empty, another prefix, a missing executable) is kept with a warning in the log, and the extension it was meant for answers 500, unless an entry of that extension can be used: its files aren't served as text. That extension is what follows the last dot of the key, in lower case, once what isn't a letter or a digit is taken from its ends (`"php "`, `"php."`, `"*.PHP"` and `"blade.php"` are `php`); a key that no extension can be read from so (with a space or a letter outside ASCII inside it, or `"."` alone) only gets its warning, and matches no file. The extension closed so isn't written when the configuration is saved, and opens again when the entry is deleted. The CGI gets the URL path of the script (after the rewrite) in `SCRIPT_NAME`, an empty `PATH_INFO`, the original URI in `REQUEST_URI`, the file on disk in `SCRIPT_FILENAME` and the site's `@` in `DOCUMENT_ROOT`, and never the panel's session cookie nor the `ok` header of the API. `QUERY_STRING` has the client's query first and then the rewrite's, so an application that reads the last value of a repeated parameter (PHP does) gets the rewrite's. A header the site sets (`addHeader`) wins over the CGI's header with the same name. The headers about the connection that a CGI writes (`Transfer-Encoding`, `Connection`, `Keep-Alive`, `Trailer`, `Upgrade`…) are dropped, and so are a `Content-Length` written twice and a header whose value has control characters (other than a tab): Turbo frames the response. Its `Status` header is read in any case (`status: 404`). An error page of Turbo for the request of a script (413, 500, 503, 504) goes without the site's headers that describe how to keep or decode a body (`Cache-Control`, `Expires`, `CDN-Cache-Control`, `Surrogate-Control`, `X-Accel-Expires`, `ETag`, `Last-Modified`, `Content-Encoding`, `Content-Disposition`); the site's other headers stay. What a CGI writes to its standard error goes to Turbo's log, grouped: a line of each kind (the program and the first words of the line) at once, and the rest counted and written once a minute. A process that a CGI leaves running keeps that standard error, and doesn't hold the answer.*
* *`addRewrite`: the target starts with `/`, `http://` or `https://` (the scheme in any case; it is saved in lower case), and an `http(s)://` target needs a host, written or given by a keyword, that doesn't start with `/`, `\`, `?` or `#` (a browser skips `/` and `\` after the scheme and takes what follows for the host; if the keyword gives nothing when answering, 500). Unknown keywords (`{X}`) are refused. As in an expression (§6.3), the host of a redirection only gets the keywords of the names of the site, of its wildcards and of the rewrite's key (`{DOMAIN}`, `{SITE}`, `{FIRST_DOMAIN}`, `{FIRST_SITE}`, `{WILDCARD_DOMAIN}`, `{WILDCARD_SUBDOMAIN}`, `{WILDCARD_SITE}`, `{REWRITE}`); `{SUBDOMAIN}` and `{FIRST_SUBDOMAIN}`, which a wildcard subdomain lets the client choose, only start it, with a `.` and the rest of the host after them (`https://{SUBDOMAIN}.example.org/`), which is meant to be a domain of the site's: with one label only (`https://{SUBDOMAIN}.com/`), the visitor chooses the whole domain, and the log warns of it; and the others, which the client chooses (`{FILE}`, `{FIRST_REQUEST}`…), are refused there, with the reason. `{TURBO_CURRENT_DIR}` is no keyword of a rewrite: it would put a folder of the server in a URL. In `turbo.config`, such a rewrite is dropped with a warning, and one kept by an earlier version answers 500. Keywords are replaced by values of the decoded request path (`{FIRST_REQUEST}`, `{DIR}`, `{FILE}`, `{EXT}`, `{REWRITE}`, `{REWRITE_COMPLEMENT}`) or of its query (`{FIRST_QUERY}`), encoded for where they go: in the path, each segment, keeping `/`; in the query, as one value; in the host, so that they can't change the URL. `{REWRITE_COMPLEMENT}` in the path takes the rest of the path, and the request's query is added to the target's: `/blog/` → `/new/{REWRITE_COMPLEMENT}` turns `/blog/a/b?x=1` into `/new/a/b?x=1`; where names fold, it follows what the source matched, however the path writes it. A CGI reached through an internal target with a query gets in `QUERY_STRING` the request's query without the parameters that the target's sets (by their decoded names; `&` and `;` separate them), and then the target's: `/x` → `/app.cgi?role=user` gives `z=1&role=user` to `/x?role=admin&z=1`.*
* *`addIndex`: The index is added at the end of the order; indexes are tried in the order in which they were added. New sites and subdomains start with `index.html`, and so does a site that `turbo.config` names without a `""` section (only through its subdomains, or as `{}` or `null`), as one found on disk; a `""` section keeps exactly the indexes it lists, none if it lists none. The name follows the rules of file upload on every system (§9): one segment, without `\`, `/`, `..`, `:`, a final `.` or space, a Windows device name, `~` followed by a digit or a character Windows doesn't allow (`<`, `>`, `"`, `|`, `?`, `*` and control characters); otherwise, HTTP 400 `"Invalid index file"`, and in `turbo.config` the index is dropped with a warning.*
* *`turbo.config`: an entry of a list that can't be used and is dropped (a rewrite, a MIME type, a header, an index, an alias) leaves a warning in the log with its list, its site, the entry and why.*

### 6.2. Delete Resources (`del<Type>`)
* **Base Route:** `POST /admin:inside:del<TYPE>`

| Endpoint | `s` (Domain) | `d` (Subdomain) | `a` (Key/Identifier to delete) |
|---|---|---|---|
| `delSite` | Web Domain | Subdomain (Empty = Delete Site) | - (the current password goes in `b`) |
| `delRewrite` | Web Domain | Subdomain | Source URI |
| `delMIME` | Web Domain | Subdomain | Extension (the current password goes in `b`) |
| `delHeader` | Web Domain | Subdomain | Header Name (the current password goes in `b`) |
| `delPreprocessor`| Web Domain | Subdomain | Extension (the current password goes in `b`: without the preprocessor, the extension's files would be served as text, their source included) |
| `delIndex` | Web Domain | Subdomain | Index File |
| `delAlias` | Web Domain | Subdomain | Alias Domain |

*All three parameters are required (except `a` in `delSite`): if one is missing, the response is `400` "Missing data".*

*`delSite` of a site or subdomain kept without its folder (listed in `~`) forgets the settings Turbo keeps for it (and `turbo.config` keeps), for a site also those of its subdomains, whose folders went with it, and deletes no folder. Only once its folder is gone: while it is there (only its `@`, or that of its site, missing) or can't be looked at, the response is `400` and the settings stay, as the folder would come back as a new site with the defaults. A folder with its name, later, is a new site. Neither existing nor kept, the response is `400` "Site not found" (or "Subdomain not found").*

### 6.3. Expressions in Headers and Rewrites

The value of a header (`addHeader`, `b`) and the target of a rewrite (`addRewrite`, `b`) can be an **expression** instead of a text: a value that starts with `=` is one, computed for each request. The panel adds the `=` and takes it away by the choice "Text / Expression" of the dialog; in `turbo.config` the value is kept with it (`"Cache-Control": "=EXT in ['js'] ? 'public, max-age=31536000' : 'no-cache'"`). A header written as a text can't start with `=`: write it as an expression, between quotes (`='=text'`).

**The language** is a subset of CEL (Common Expression Language): no loops, no variables of its own, no functions of the user, so every expression ends and its cost follows its size.

| Element | Meaning |
|---|---|
| `'text'`, `"text"` | A text. The only escapes are `\\`, `\"` and `\'`; no control characters (a line break neither) |
| `a + b` | The two texts joined |
| `c ? a : b` | `a` if the condition `c` is true, else `b` (both texts, or both conditions) |
| `a == b`, `a != b` | Two texts, or two conditions, equal or not |
| `a in ['x', 'y']` | `a` is one of the texts of the list (written in the expression, 64 at most) |
| `!c`, `c && d`, `c \|\| d` | Not, and, or (the right side is only evaluated when it decides) |
| `(…)` | Grouping |

Spaces, tabs and line breaks separate the elements and mean nothing: an expression can span lines.

**Variables:** those of the rewrites (`DOMAIN`, `SUBDOMAIN`, `SITE`, `FIRST_DOMAIN`, `FIRST_SUBDOMAIN`, `FIRST_SITE`, `WILDCARD_DOMAIN`, `WILDCARD_SUBDOMAIN`, `WILDCARD_SITE`, `FIRST_REQUEST`, `FIRST_QUERY`, `DIR`, `FILE`, `EXT`, `REWRITE`, `REWRITE_COMPLEMENT`; [their values](https://turbo-server.github.io/#so-2)), and:

| Variable | Value |
|---|---|
| `IP` | The client's IP address |
| `HTTPS` | A condition: the request came by HTTPS |
| `METHOD` | The method of the request (`GET`…) |
| `PATH` | Only in a header: the path of the file served |

In a header, `DIR`, `FILE`, `EXT` and `PATH` are those of the file served, after the rewrite and the index (`/` serves `index.html`, whose `EXT` is `html`); in a rewrite, those of the path the request named. `{TURBO_CURRENT_DIR}` has no variable: a path of the server never goes into a header or a redirection.

**Functions:**

| Function | Gives |
|---|---|
| `HEADER('Name')` | The values of that header of the request, joined with `, ` (`''` if it isn't there); `HEADER('Host')` is the host of the request, as it chose the site |
| `QUERY('name')` | The first value of that parameter of the query, decoded (`&` and `;` separate them; `''` if it isn't there or can't be decoded) |
| `COOKIE('name')` | The value of the first cookie of that name |
| `oneOf(v, ['x', 'y'])` | The text of the list equal to `v`, or `''`: never what the client sent, but the text written in the list |
| `token(v)` | `v` if it is 1 to 128 characters of `A-Z a-z 0-9 . _ ~ -`, else `''` |
| `quoted(v)` | `v` between double quotes, with its `\` and `"` escaped (`''` if it has control characters). Not in `Set-Cookie` nor `Content-Security-Policy`, whose grammar doesn't keep a quoted text together: a `;` or a space inside would still end the value |
| `urlencode(v)` | `v` with every character but `A-Z a-z 0-9 . _ ~ -` as `%XX` |
| `lower(v)`, `upper(v)` | `v` in lower or upper case (ASCII letters) |
| `v.startsWith(s)`, `v.endsWith(s)`, `v.contains(s)` | Conditions on texts |
| `v.matches('pattern')` | A condition: `v` matches the pattern (RE2 syntax, written in the expression, 256 bytes at most) |

The names that `HEADER`, `QUERY` and `COOKIE` read are written in the expression. `HEADER` can't read `Cookie`, `Authorization`, `Proxy-Authorization` or `ok`, and `COOKIE` can't read the session cookies of the panel (`turbo_session`, `__Host-turbo_session`), in any case: an expression could copy credentials into a header or a redirection.

**What may go where.** Every text an expression gives comes from somewhere, and that decides where it may go; what could break these rules is refused when the expression is added (400 with the reason and its position: `Expression: … (position N)`), and checked again for each request:
- **A header never carries what the request sends as it came** (`HEADER`, `QUERY`, `COOKIE`, `FIRST_REQUEST`, `FIRST_QUERY`, `DIR`, `FILE`, `EXT`, `PATH`, `REWRITE_COMPLEMENT`, `METHOD`): it goes through `oneOf`, `token`, `quoted` or `urlencode`. Conditions read anything. For example, `oneOf(HEADER('Origin'), ['https://app.example'])` gives the allowed origin, `'attachment; filename=' + quoted(FILE)` a file name.
- **The target of a rewrite starts with a text of the expression**: `/…` (a path of the site), `http://…` or `https://…` (a redirection). It can't have `..` or `//`, as a target written as a text, neither in one of its texts nor where two of them meet (`'/' + '/x'`).
- **The host of a redirection is written in the expression, chosen with `oneOf`, or a host that Turbo serves** (`DOMAIN`, `SITE`…): `'https://' + oneOf(QUERY('to'), ['a.example', 'b.example']) + '/x'`. `SUBDOMAIN` and `FIRST_SUBDOMAIN`, the labels before the domain, which a wildcard subdomain lets the client choose (`evil.example` of `evil.example.mysite.com`), only start a host: a `.` and the rest of it follow (`'https://' + SUBDOMAIN + '.example.org'`), which is meant to be a domain of the site's: with one label only (`'.com'`), the visitor chooses the whole domain. It can't be empty, nor start with `/`, `\`, `?` or `#`: refused when added if it surely would (`'https://'`), and 500 for a request where it does (`oneOf` gave nothing).
- Everything else that goes into a target is encoded for where it goes, as the keywords of a target written as a text: in the path, each segment (keeping `/`); in the query, as one value. `REWRITE_COMPLEMENT` keeps its rule, also through `lower` or `upper`, which change only its path. A path of the site is then cleaned as a request path: one that leaves the site answers 404.

**When it is computed:**
- An expression that gives `''` sends no header (a CGI's header of that name goes out), or applies no rewrite (the path is served as it was named).
- The headers that an expression reads (`HEADER`), and `Cookie` if it reads a cookie, are added to the `Vary` of the response, also to a CGI's own and to that of a redirection.
- An expression that fails for a request answers **500**: a text longer than 8 KiB while it is computed, a header value longer than 512 bytes or with control characters, a target longer than 2048 bytes once placed. In a header the 500 comes before the CGI runs: a page never goes out without a header that may be what keeps it safe. The log says which, at most once a minute, without data of the request.
- An expression of `turbo.config` that doesn't compile (edited by hand) is kept and saved as it is, with a warning in the log; what it covers answers 500 until it is fixed: the whole site for a header, the paths it takes for a rewrite. The file of an ACME challenge is served without the expressions of the headers.

**Limits:** 2048 bytes for an expression, 32 levels of nesting, 512 elements, 64 texts in a list of 512 bytes each, and patterns of `matches` that make 1000 steps in all as they are compiled (a repetition such as `\pL{1000}` has thousands): what matching them costs follows that.

**Password:** `addHeader` needs the current password, as always; `addRewrite` needs it for every expression (it may send the visitors to another address for some requests).

### 6.4. The Mode dx: Workers That Turbo Keeps

A preprocessor runs its scripts in one of two **modes**, the prefix of its value: `cgi>` (the default, which the value may leave out) starts the program for each request, as a CGI; `dx>` keeps the program running, a **worker**, and gives it the requests one after another through its standard input and output. The panel chooses the mode in a list ("CGI: a process for each request", "DX: a worker kept running") and adds the prefix; in `turbo.config` the value is kept with it (`"lua": "dx>/opt/turbo-dx/dx-lua"`). The worker of Lua, `dx-lua`, and the library for writing others, `dx-core`, are in the folder [`dx/`](dx/README.md) of this repository (in Rust, built apart from Turbo).

**What Turbo does with the workers:**
- A request takes a worker of its program that waits, the last used first, or starts one; there are as many as requests of that program being served at once (the turns of `CGP` bound them). A start goes on after its request gave up (`WT`), and counts until it ends: a program slower to start than `WT` never has more than `CGP` workers in use or starting, and its requests beyond them get 503 with `Retry-After`, as without a free turn. The workers of a program are shared by every site that names it.
- A worker starts in the folder of its program, with what a CGI gets of Turbo's environment, and must greet (`DX3\n`) within 5 s. Its standard error goes to Turbo's log, grouped as a CGI's. A program whose worker didn't start or didn't greet isn't started again for 1 s, then 2, 4… up to 30 s while it keeps failing (starts that fail together count once): meanwhile its requests get 500 at once.
- A worker is used again only after an exchange that ended as the protocol says. Any other end kills it, with its whole process group (a Job Object on Windows), and closes Turbo's ends of its pipes, so that nothing it started outside its group holds the request: an answer that breaks the protocol, more than the answer, `WT` over, the client gone. A request whose client went away before it reached a worker (while it waited for a turn) takes none, and the worker waits for the next. A worker that waited and ended meanwhile (one that ends after some requests), found as it is given a request, passes that request to another once: when it couldn't take it, or when it ended without a byte of an answer and the request may be made twice (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT` or `DELETE`, without a body). A request that changes something is never made twice.
- A worker idle for 60 s ends within the next minute (its input is closed; idle workers are looked at once a minute); when Turbo stops, every worker does, after the requests in progress.

**Everything else is a CGI's,** by the same code: `MBB` and the turns, `WT`, the request without the panel's session cookie, the `ok` header of the API nor the headers with `_`, and the answer through the filters of a CGI's headers, with the site's headers winning, and Turbo's error pages without the site's headers that describe a body. Unlike a CGI's, an error status without a body gets the site's template, without the worker's headers that describe a body (`Content-Encoding`, `Content-Range`, `Content-Disposition`, `ETag`, `Last-Modified`) and with its others, `Cache-Control` among them: the status is the script's; a header `Status` of a worker is one more header, its status being the one of the protocol; and an answer without a body (204, 304) whose worker sends one goes out without it, and the worker is used again.

| What happens | Answer | The worker |
|---|---|---|
| It doesn't start, doesn't greet, ends or breaks the protocol before its answer starts (its head and the length of its first chunk) | 500; the log says why, at most once a minute | Killed |
| `WT` is over before its answer starts | 504 | Killed |
| The client goes away | None | Killed |
| It ends, `WT` is over or it breaks the protocol after its answer started | The connection is cut: an answer cut short never looks complete (but over HTTP/1.0, which has no chunks, one without `Content-Length`, as a CGI's); the log says why, at most once a minute | Killed |

**The protocol DX 3**, the contract for whoever writes a worker. Integers are unsigned and little-endian: the id of a request has 64 bits, the rest 32.

```text
worker, once, when it starts:  "DX3\n"
Turbo, a request:               u64 id, u32 M, M bytes of pairs, then the body (CONTENT_LENGTH bytes)
worker, its answer:             u64 id, u32 H, H bytes (u32 status, pairs of headers), then chunks: u32 n, n bytes … u32 0
pairs:                          u32 count, then for each: u32 length, name, u32 length, value
```

- The pairs of a request are the variables a CGI gets, with the same names and values (`REQUEST_METHOD`, `REQUEST_URI`, `QUERY_STRING`, `SCRIPT_NAME`, `SCRIPT_FILENAME`, `DOCUMENT_ROOT`, `HTTP_*`…), but those of Turbo's environment, which the worker has in its own; and `DX_TIMEOUT_MS`, the milliseconds the worker has: what is left of `WT`, less a tenth of it (250 ms at most), so that it stops its script and answers before Turbo gives up and kills it (0: no limit). `DX_GRANTS`, the accesses granted to the script, is kept for what is to come: Turbo grants none in this version. `CONTENT_LENGTH` comes only with a body: without it, the body is empty.
- An answer starts with the id of its request, a random number. An answer with another id (one written late, after the answer of an earlier request) is refused before anything of it reaches the client: its worker is killed, and the request gets 500. So is anything written after the greeting, before the first request.
- The head of an answer has a status from 200 to 599 and is 64 KiB at most; a chunk is 1 MiB at most.
- A worker reads the whole request before it answers (one that doesn't may hold its request until `WT`, or until the client goes away with `WT` at 0), writes only the protocol to its standard output (its messages go to its standard error, which Turbo's log takes, grouped), and ends when its input closes.
- A worker serves every site that names its program: it must keep nothing of a request for the next, and must check that `SCRIPT_FILENAME` is inside `DOCUMENT_ROOT` before it reads it (`dx-lua` answers 404 otherwise).

---

## 7. Global Security and Interface API

### 7.1. Denied IP Control
A denied IP is blocked until the given date: its requests are answered with HTTP 429 and a `Retry-After` header (seconds left), and its new connections are closed.

* **`POST /admin:inside:addDenied`**
  * `s`: IP address (IPv4 or IPv6). An IPv6 address denies its whole /64, the client that the rate limits count (its addresses change by themselves). Loopback addresses (`127.x.x.x`, `::1`, and any other of `::/64`, which holds `::1`) and the address the request comes from, or for IPv6 one of its /64 (`400` "Current IP": the panel would lock itself out), are not accepted.
  * `d`: UNIX timestamp for block expiration (`0` or a past date removes an existing block).
  * `b`: the current password (§1.2).
* **`POST /admin:inside:delDenied`**
  * `s`: IP address to unblock from the denied IP list.

### 7.2. HTTP Status Code Responses
A template is the error page of every site, so both actions need the current password in `b` (as sent; missing or wrong, as in `set<KEY>`, §5), and every parameter goes as sent (§2.1). An error page never runs scripts: it carries a `Content-Security-Policy` without them on every host (§1.2), and with `sandbox`, so it doesn't redirect by itself (`meta` refresh), send forms or open windows either. It also blocks the template's external styles, fonts and images: a template keeps its inline styles and `data:` images.

* **`POST /admin:inside:addHttpCodeResponse`**
  * `s`: HTTP status code (between `400` and `599`, or `0` for a universal fallback).
  * `d`: Response template, 1 to 2,048 bytes. Line breaks and the `{TURBO_RESPONSE_CODE}` macro are supported (the panel writes it in a text area: Enter is a new line, and Ctrl+Enter sends it).
  * `b`: The current password.
* **`POST /admin:inside:delHttpCodeResponse`**
  * `s`: HTTP status code to revert to the system's default behavior.
  * `b`: The current password.

### 7.3. Global Character Replacement in URIs
A replacement changes what the actions of the session alone read (§2.1), so both actions need the current password in `b` (as sent; missing or wrong, as in `set<KEY>`, §5), and every parameter goes as sent.

* **`POST /admin:inside:addCharsReplace`**
  * `s`: Character sequence to replace (e.g.: `;`), 1 to 4 bytes, without letters or digits (`"Letters and digits are never replaced"`: with them, a token could turn a name into another one).
  * `d`: Target encoded token (e.g.: `-.-`): 2 to 16 bytes, without any replaced character (its own included), not containing another token nor inside one; and `s` can't be inside another token. Otherwise, HTTP 400. The fixed substitutions of §2.1 can't be changed (`"Fixed replacement"`). In `turbo.config`, a replacement that breaks these rules is dropped with a warning.
  * `b`: The current password.
* **`POST /admin:inside:delCharsReplace`**
  * `s`: Character sequence to stop replacing (the fixed substitutions of §2.1 cannot be deleted).
  * `b`: The current password.

---

## 8. SSL Certificate and Redirect API (`cfg<KEY>`)

Manages HTTPS enablement, application-layer redirects, and certificate configuration/issuance via Certbot.

* **Base Route:** `POST /admin:inside:cfg<KEY>`

| Endpoint | Parameter `a` (Action) | Parameter `s` (Domain) | Parameter `d` (Subdomain) | Optional Parameters |
|---|---|---|---|---|
| **`cfgC`** | `"1"` = Run Certbot<br>`"0"` = Remove from disk (needs the current password in `b`) | Web Domain | Subdomain or Empty (`""`) | `z`: Registration e-mail.<br>`y`: Certbot adapter (`dns-<provider>`, e.g.: `dns-route53`); another than the one saved needs the current password in `b`.<br>`x`: with `a="0"`, `1` also takes the certificate out of use (§8.1). |
| **`cfgS`** | `"1"` = Enable HTTPS<br>`"0"` = Disable HTTPS (needs the current password in `b`) | Web Domain | Subdomain or Empty (`""`) | `a` is `"0"` or `"1"` exactly: another value (`"2"`, `"true"`) is refused with 400. |
| **`cfgR`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Empty (`""`) only: it is set at the site's root | Redirects `www.<site>` to `<site>` (301). With a subdomain, HTTP 400. |
| **`cfgW`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Empty (`""`) only: it is set at the site's root | Redirects `<site>` to `www.<site>` (301). With a subdomain, HTTP 400. |
| **`cfgE`** | E-mail to register, or empty to remove it | Web Domain | Subdomain or Empty (`""`) | Silently updates the E-mail for future Certbot renewals. Without an e-mail, the certificate stays and is no longer renewed (`"E-mail removed"`; `"E-mail unchanged"` if there was none): removing it needs the current password in `b`. The value is saved as it arrives (a `+` sent encoded as `%2B` stays `+`). |
| **`cfgA`** | Adapter Name (`dns-<provider>`, or empty for webroot) | Web Domain | Subdomain or Empty (`""`) | Updates the adapter for Certbot, taken as sent. Another than the one saved needs the current password in `b`: with a wrong one, every renewal fails. |
| **`cfgZ`** | `"1"` = Enable<br>`"0"` = Disable | Web Domain | Subdomain or Empty (`""`) | Precompressed files, off by default: a request that accepts `br` or `gzip` is answered with the `<file>.br` or `<file>.gz` that is next to the file it names (§8.4). Each site and each subdomain has its own. |

### 8.1. Operational Detail: Certificate Issuance (`cfgC`)
Certbot only runs when it is requested with `a="1"`, and an e-mail is required (saved with `cfgE` or sent in `z`); without it the API responds HTTP 400 `"E-mail required to create the certificate"`. If the site already has a certificate less than 75 days old, the API responds `"SSL certificate active"` without running Certbot. With `a="0"`, the certificate files are deleted whatever their age and the API responds `"SSL certificate deleted"`; with no certificate on disk, nothing is deleted and the API responds HTTP 400 `"No certificate"`; while Certbot issues or renews it, or waits to, HTTP 400 `"The certificate is being issued or renewed: delete it once Certbot is done"`. The certificate in use stays until another one is installed or Turbo restarts, so that replacing a certificate leaves no gap, unless `x=1` is sent: it is then taken out of use at once (`"SSL certificate deleted, and no longer in use"`; or `"SSL certificate no longer in use"`, for the one that an earlier deletion left in use, with no files to delete). The site keeps its HTTPS setting, but has no HTTPS, and isn't redirected to it, until another certificate is installed, which is put in use by itself. Another value of `x` than `0` or `1` is refused (HTTP 400). The e-mail of `cfgE` and of `z` is checked the same way: 5 to 40 bytes, one `@` with something before it and a domain with a dot after it, and no spaces, `#`, `--` or a leading `-` (HTTP 400 `"Invalid e-mail value"` or `"Invalid e-mail length"`).

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

The GUI does this by itself: after a 202 it asks again every 5 seconds, for 11 minutes at most, and shows the result. Certbot has 3 minutes, and 10 with a DNS adapter. Cancelling any step of its dialog (e-mail, adapter, confirmation) sends nothing, and emptying an adapter that was saved asks whether to go back to webroot (`cfgA` with an empty value); another adapter than the one saved asks for the current password.

### 8.2. The Panel's Own Certificate (`cfgPC`)
`POST /admin:inside:cfgPC` issues or deletes the certificate of the panel's own hosts: the host names in `PA` (IP addresses are left out). It takes no `s` or `d`.

* `a="1"`: runs Certbot as `cfgC` does, with a `-d` for each host of `PA`, in webroot mode (`turbo.panel/webroot` inside the sites directory; Turbo answers its challenges, `/.well-known/acme-challenge/<token>`, only on the hosts of `PA`) or with the adapter; Certbot works in `turbo.certificates/turbo.panel`, and the files end up in `turbo.panel/`. The answers are those of `cfgC` (202 `WAIT` while it runs, one issuance at a time among sites and panel; 200 `"Panel certificate active"` when a certificate that covers every host of `PA`, and expires in more than 30 days, is in use; 400 with the error of the last attempt, once). Without an e-mail: 400 `"E-mail required to create the certificate"`; without a host name in `PA`: 400.
* `a="0"`: deletes `turbo.panel/fullchain.pem` and `privkey.pem` and stops using the certificate. It needs the current password in `b`, as `cfgC` with `a="0"`, and over HTTPS its answer sends `Strict-Transport-Security: max-age=0`, so that browsers can reach the panel by HTTP again; without the files, 400 `"No panel certificate"`. If they can't be deleted, 400 `"Error deleting the panel certificate files"`, and the certificate stays in use.
* `z`: the e-mail, saved as `PCE` in `.` of `turbo.config`. `y`: the DNS adapter (`dns-<provider>`), saved as `PCA`; an empty `y` goes back to webroot, and without `y` the saved one stays. A `y` other than the one saved needs the current password in `b`, and `a="0"` while Certbot works on it is refused with 400, as with `cfgC`.

The automatic renewal also renews the panel's certificate when it expires in less than 30 days, and `/admin:inside:sites` says its state in `.` as `PCC` (with `PCE` and `PCA` when they are set): `true` (in use), `"WAIT"` (Certbot running) or `false`. A certificate placed by hand in `turbo.panel/` is used too, but not renewed.

### 8.3. Operational Detail: Hot SSL Activation (`cfgS`)
Turbo does not require restarts to apply certificates. When the activation command (`a="1"`) is received:
1. Go reads the `fullchain.pem` and `privkey.pem` files directly from disk and immediately injects them into the server's shared RAM memory.
2. If port `443` (or the address in `TURBO_HTTPS_ADDR`) was closed (because the server started without certificates), **a new socket Listener is automatically started**.
3. From this point on, Turbo forces a `301 Moved Permanently` redirect to `https://`, on the same host, for the HTTP traffic entering that domain/subdomain when a certificate covers the requested host. An alias without a certificate that covers its name keeps being served over HTTP.

During the TLS handshake, each name receives the certificate that covers it (exactly or with a wildcard). Names that no certificate covers, and connections without SNI (access by IP), are rejected.

*Note: Disabling HTTPS (`a="0"`) purges the certificate from RAM memory (preventing future TLS connections for that host), but it **does not delete** the `.pem` files from disk, nor does it close port 443 at the network level.*

### 8.4. Operational Detail: Precompressed Files (`cfgZ`)
Turbo does not compress its responses. A site, or a subdomain, with `cfgZ` at `"1"` serves the compressed copies that its deployment leaves next to each file, named as the file plus `.br` (Brotli) or `.gz` (gzip): `site.css.br` for `site.css`. In `turbo.config` and in the JSON of the panel it is `"Z"`, among the settings (`"!"`) of the site.
* **Who gets a copy:** a `GET` or a `HEAD` whose `Accept-Encoding` accepts its encoding: named with a `q` above 0, or not named when `*` has one. With both accepted, the one with the higher `q`, and `br` when they have the same. Without the header, with one that isn't written as HTTP says, or when the copy isn't there, the file is served as it is.
* **The response:** `Content-Encoding` (`br` or `gzip`), the `Content-Type` of the file (the site's for its extension, or the one of what the file has), the `Content-Length` of the copy and an `ETag` of its own, with which `If-None-Match` gets its 304. Every response of the site for a file, compressed or not, has `Vary: Accept-Encoding`, added to the `Vary` of the site if it sets one.
* **Never a copy:** for a request with `Range` (a range is of the file as it is, and the responses with a copy don't offer ranges); for a file that a preprocessor runs; in a site whose preprocessors include `br` or `gz`, or whose headers set `Content-Encoding` or `ETag`; for a URL that ends in `/index.html`; and when the copy is empty, a folder, or a link that leads outside the site.
* **The dates aren't compared:** a copy older than its file is served all the same, as a deployment that wrote each copy a moment before its file would otherwise leave it unused. Whoever changes a file makes its copies again, or deletes them.
* The copies are files of the site like any other: `site.css.br` is also served by its own name, as it is.

---

## 9. Physical File Management API (`hardUpload`)

Used to bulk-replace all public files associated with a subdomain/domain. The server writes the new files to a folder of its own next to `@` (`@.upload-<random>`) and then puts it in place of `@` all at once (the previous `@` is `@.previous-<random>` for an instant, and is then removed), so the existing content (subfolders included) is replaced as a whole: until then, `@` is left as it was, and if anything fails, nothing changes.

* **Endpoint:** `POST /admin:inside:hardUpload`
* **Body Format:** `multipart/form-data`
* **Form Parameters:**
  * `s`: Primary domain (e.g.: `example.com`).
  * `d`: Subdomain (empty `""` for the root domain).
  * `f`: Array of attached files (`File[]`).
  * `b`: the current password, only in the multipart body (never in the URL, which `turbo.visits` records), and before the first file: it is checked before the files are read.

  `s` and `d` are accepted both in the URL and in the multipart body.
* **Nested Directory Handling:**
  The backend parses the `filename` parameter within the `Content-Disposition` HTTP header of each multipart block. The first segment of each path (the folder chosen in the browser) is discarded, and `\` counts as a separator. If the rest of the name contains relative paths (e.g.: `site/assets/img/logo.png` → `assets/img/logo.png`), Turbo will create the folder structure. A file and a folder can't have the same name: of `a` and `a/b`, the later one is discarded (compared without case on Windows and macOS). So are names that the file systems can't hold: a file or folder name longer than 255 bytes, or a path inside `@` longer than 1,024 bytes. Names that would leave `@` (with `..`, absolute or with `:`) are discarded, and so are, on every system, the names Windows treats specially: ending in `.` or a space, a reserved device name (`CON`, `NUL`, `COM1`…), `~` followed by a digit (8.3 short names) or a character Windows doesn't allow (`<`, `>`, `"`, `|`, `?`, `*` and control characters).
* **Successful Response (HTTP 200 OK):**
  Returns the string `"Data uploaded"`. If any file was discarded, the response lists them: `"Data uploaded. Discarded: <name>, <name>"`.
* **Specific Error Handling:**
  * If the upload size exceeds the global `MBB` (Max Body Bytes) limit, or it has more than 10,000 parts (the files and the `b` field), the API cuts off the read and returns HTTP 413 with the message `"Maximum body size exceeded"`. A malformed multipart body gets HTTP 400 `"Invalid parameters"`. (Other multipart forms admit at most 1,000 parts.) `MBB` bounds the memory the upload takes, as it is kept in memory: the contents plus about 600 bytes per file (its name, headers and entry), so a file of exactly `MBB` bytes never fits, and a site of many small files needs room for them. As each upload replaces the whole `@`, the way out of a 413 is a larger `MBB`, not uploading fewer files; the panel says so.
  * If `b` comes after a file, HTTP 400 `"The current password (b) must come before the files"`; if it is missing, or the fields before the first file take more than 64 KiB or are malformed, HTTP 400 too (`"Missing data: the current password (b), before the files"`; a body malformed further on still gets `"Invalid parameters"`). A wrong password is answered before the files are read, and the connection is closed.
  * If every name is discarded, HTTP 400 `"No valid file; nothing was changed. Discarded: …"`, and `@` is left as it was.
  * If the site's folder can't take the upload (the folder `@.upload-<random>` can't be created there), HTTP 500 `"Directory inaccessible"`, logged.
  * If Turbo stops between the two renames, the site is left without `@`: at the next start, before serving, Turbo puts back the `@.previous-<random>` if it is the only one there. A `@.previous-<random>` next to an `@` in place is only warned about.
  * If `@` can't be replaced (on Windows, for example, while a file in it is open), HTTP 400 `"The public directory could not be replaced (open files?); nothing was changed"`; a file that can't be written gives HTTP 500. In both cases `@` is left as it was.
  * If the site is deleted during the upload, HTTP 400 `"Site not found"`, and the site does not come back.
  * If no file comes in `f`, HTTP 400 `"No data"`.

---

## 10. API HTTP Response Code Standard

| HTTP Code | Functional Meaning | Cause and Request Body |
|---|---|---|
| **`200 OK`** | Operation Processed | The command was executed in memory and/or on disk. Returns a plain-text confirmation (e.g.: `"Subdomain added"`). |
| **`202 Accepted`** | In Progress | Only `cfgC` and `cfgPC` while a certificate is being issued: a JSON body with `"status":"WAIT"` (§8.1). Keep polling. |
| **`400 Bad Request`** | Validation / Logic Failure | Null parameters, invalid format, nonexistent resource, incorrect passwords, or exceeded limit restrictions. The Body contains the literal error string that should be shown to the user. The fifth wrong current password in a session closes it, with `X-Turbo-Login: required` (§3.1). |
| **`403 Forbidden`** | Access Blocked | Login with incorrect credentials (empty Body), a login from another origin, or with the default password from elsewhere than this machine (`X-Turbo-Login: local-only`, §3.1), or a `POST` authenticated with the session cookie that does not come from the same origin (§1.2). |
| **`404 Not Found`** | Incorrect URL | A URI (`RequestURI`) was requested within the `/admin:` prefix that does not correspond to any listed endpoint, or the panel does not answer on that host or network (`PA`). |
| **`413 Payload Too Large`** | Parameters Too Large | The parameters of an action (or the login body, §3.1) are larger than allowed: `MBB`, and at most 10 MiB in an `application/x-www-form-urlencoded` body. A file upload (§9) too large gets `413` too. Parameters that can't be decoded (for example, a malformed `%` escape) get `400` `"Invalid parameters"`. |
| **`429 Too Many Requests`** | *Rate Limiter* Triggered | The client's IP exceeded its limits (CIL/CIS/CII), the IP is denied (§7.1), or its logins are blocked after failed logins, or five current passwords of the session are being checked already (§3.1). Each request counts once. The response carries `Retry-After` with the seconds to wait, and new connections from a blocked IP are closed. |
| **`503 Service Unavailable`** | Global Limit Reached | The whole server received more than `CGL` requests in the current second (`Retry-After: 1`), the password of a login or the current password of a `set<KEY>` or of an action that needs it couldn't be checked within 2 seconds, or the new password of `setP` hashed (`Retry-After: 2`, §3.1), or a CGI found no free slot within 2 seconds (`CGP`, `Retry-After: 2`). |
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
