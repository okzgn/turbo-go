# Turbo changelog

[Español](CHANGELOG.es.md)

v2.4 is the next release after v2.3.rc3. If you upgrade from **v2.3.rc3**, every stage of v2.4 applies: read [Upgrading from v2.3.rc3](#upgrading-from-v23rc3) first.

## Upgrading from v2.3.rc3

**Recommendation: upgrade as soon as possible.** This version fixes security and stability issues: some could expose files outside a site, stop or hang the server, or affected the admin panel, certificates and the TLS configuration. Details are published in the repository's security advisory.

Before upgrading:

1. **Back up the sites folder**, `turbo.config` included. Turbo also keeps an automatic copy (next point), but it does not cover certificates or site content.
2. **`turbo.config` changes format.** Turbo reads old files and converts them in memory. The first time you save the configuration from the panel, it keeps the original as `turbo.config.v1.bak`, with `0600` permissions, and writes the new format, marked with `"^": {"v": "2"}`.
3. **Going back to an earlier version is not transparent.** To do it, restore `turbo.config.v1.bak` as `turbo.config`. If you keep the new file:
   - the old version reads `CIL` and `CIS` as 10 ms units, so the intervals would be 10 times longer;
   - it ignores the saved password (`PH`) and falls back to `Admin` or `TURBO_PASSWORD`;
   - it tries indexes in random order;
   - it does not apply the panel restriction (`PA`).
4. **Give the panel a host of its own** in `PA`, one that serves no site (see the README), and change the default credentials.
5. **Review the breaking changes** of each stage, especially:
   - Turbo does not start if `turbo.config` is not valid JSON, and says where the error is;
   - the panel logs in only by `POST /admin:`, and `PA` combines hosts and networks with AND;
   - rewrite sources are compared with the decoded path;
   - TLS 1.2 minimum;
   - Certbot no longer runs on its own;
   - the panel session moves to a cookie;
   - "Denied IP" now blocks;
   - the process exits if it cannot open port 80;
   - the reference systemd unit runs without root.

Published binaries are static and built with the latest Go 1.26 patch. Check the download with `SHA256SUMS`, for example `sha256sum -c SHA256SUMS`.

---

## v2.4

The first release after v2.3.rc3. It brings together four stages of work, none of them released on its own: they are listed below, newest first, with their changes. Every stage applies when upgrading from v2.3.rc3.

### Stage 4: full security and robustness review

#### Fixes
- **Paths stay inside the site:** the requested path is decoded and cleaned, and files are looked up and opened through the site's `@` folder only (`os.Root`), so no path, rewrite or symbolic link reaches a file or a preprocessor outside it. Please read the security advisory.
- **Percent-encoded paths:** `/a%20b.txt` or `/caf%C3%A9.txt` now serve the files `a b.txt` and `café.txt` (they answered 404).
- **`turbo.config` is always valid JSON:** it is written with a JSON encoder and replaced atomically (a temporary file, then a rename), so a failure while saving leaves the previous file. The new file has `0600` permissions and belongs to the user running Turbo; if `turbo.config` is a symbolic link, its target is replaced and the link stays. If the file on disk is not valid JSON when saving, it is first copied to `turbo.config.invalido.<date>.bak`.
- **Concurrency:** some panel actions (adding a site or a subdomain) read shared state without the lock while it could be written, which could stop the process; a slow panel client no longer holds the lock that every request needs; the password hash of `setP` is computed outside the lock; and two sessions can no longer share a key. A certificate is not requested twice at the same time.
- **Redirections and ports:** the redirection to HTTPS goes to the port of `TURBO_HTTPS_ADDR` when it is not 443, and the `W`/`R` redirections keep the port of the `Host`.
- **Keep-alive after a POST:** a connection whose request body was read to the end is kept open (it was closed).
- **Denied IPs in canonical form:** `2001:DB8::1` and `::ffff:192.0.2.1` now match `2001:db8::1` and `192.0.2.1`; the keys of `@` in `turbo.config` are written in that form when it is saved.

#### Breaking changes
- **Request paths:** a path with `..`, `\`, `%00`, control characters, an invalid `%` escape, invalid UTF-8 (`%FF`), an encoded `/` (`%2F`) or `\` (`%5C`) is answered with 404, whether the file exists or not (before, some got 400). An encoded `/` no longer separates folders.
- **Extensions without case:** preprocessors and MIME types match the extension in any case (`.PHP`, `.Php` run as `.php`), on every system, and are saved in lower case (also those read from an old `turbo.config`).
- **Special file names:** a path segment that ends in `.` or a space is answered with 404, and so is a file requested with a trailing `/` (`/x.php/`); on Windows, also a segment with `:` (alternate data streams), a reserved device name (`CON`, `NUL`, `COM1`…) or `~` followed by a digit (8.3 short names, such as `INDEX~1.PHP`). File upload discards those names on every system.
- **Rewrites:** the source of a rewrite is compared with the decoded path, so a source saved with `%` escapes (`/a%20b`) must be saved again decoded (`/a b`). An internal target is decoded too (write a literal `%` as `%25`), and `{REWRITE_COMPLEMENT}` is what follows the source in the decoded path (plus the query).
- **Control characters:** the panel rejects any value with control characters with 400 "Caracteres de control no admitidos", and invalid UTF-8 with "Texto UTF-8 incorrecto". Response templates may still have tabs and line breaks. Such values in `turbo.config` are discarded on load, with a warning in the log.
- **Invalid `turbo.config`:** Turbo no longer starts with the default settings (and the `Admin` password) when `turbo.config` is not valid JSON or cannot be read. It exits with code 1 and shows the file, the line and column of the error, the line itself and the backups next to it. If the file breaks while Turbo is running, the configuration in use is kept and the same message goes to the log. `setM` refuses a sites folder whose `turbo.config` is invalid.
- **Global request limit:** the server-wide limiter no longer reuses the per-IP settings, which could answer 429 to every client once the whole server reached about 100 requests per second. It has its own setting, `CGL` (requests per second among all clients), **off by default**; above it, new requests get 503 with `Retry-After: 1` and no IP is blocked. Per-IP blocks always last 5 seconds (the longer "persistent" block is gone).
- **Panel host (`PA`):** host entries and networks now combine with AND: with both, a request needs one of the hosts **and** one of the networks (before, either was enough, so from an allowed network the panel answered on the sites' hosts too). A `PA` host that serves a site is refused, and so is a new site, subdomain or alias that would serve a `PA` host. A `turbo.config` with such a `PA` still loads, with a warning. Without a host in `PA` (empty, or networks only), Turbo warns at startup that the panel shares the sites' origin: give it a host of its own (see the README).
- **Failed logins:** after 5 failed logins from the same IP within 10 minutes, logins from that IP get 429 with `Retry-After` (1 minute, then 2, 4… up to 15) without checking the password. Attempts still being checked count towards the 5, so simultaneous attempts beyond them get 429 with `Retry-After: 2`. If the password can't be checked within 2 seconds because too many checks are running, the login (and the current password of `set*`) gets 503 with `Retry-After: 2`. The default credentials stay `Turbo`/`Admin`, and Turbo warns at startup while they are in use.
- **`RHT` and `IT` at 0:** they now use `RT`, as Go does, instead of leaving header reading and idle keep-alive connections without a limit. With `RT` also at 0, there is still no limit.
- **One `Server` header:** every response carries a single `Server: OKZGN Turbo`. A `Server` header set by a site (custom headers) or a CGI is replaced instead of being sent next to Turbo's, and a response whose handler sets `Date` no longer goes out without `Server`.
- **HTTP/2 header limit (`MHB`):** each header field now counts 32 bytes on top of its name and value, as HTTP/2 and Go count it, so with the same `MHB` an HTTP/2 request admits fewer headers than before (a long list of tiny fields no longer fits).
- **`application/x-www-form-urlencoded` forms:** at most 10 MiB, even with a larger `MBB` (they are kept whole in memory). Multipart uploads still go up to `MBB`.
- **Panel API parameters that can't be read:** 400 "Parámetros incorrectos" for a malformed encoding, and 413 when they are too large. Before, the error was ignored and the action ran with whatever had been decoded, or answered "Faltan datos".
- **`cfgR` and `cfgW`:** they are set at the site's root (`d` empty), where they apply (`cfgR` redirects `www.<site>` to the site); with a subdomain they answer 400. The panel only offers them at the root.
- **`cfgC` in progress:** while a certificate is being issued, `cfgC` answers 202 (it was 400) with the same `"status":"WAIT"` JSON.
- **"Delete SSL" (`cfgC a=0`):** it also deletes a certificate older than 75 days (it answered "Sin certificado" and left the files).
- **Character replacements in every parameter:** as the API specification says, the replacements of §2.1 (`-,-` for `#` and the rest) are undone in every parameter of the panel API (except the site and subdomain of `hardUpload`, which can't contain those characters), also the response template, the header name, the MIME extension, the alias and the site of `addSite` and `addDenied`.
- **Multipart forms:** at most 1,000 parts, as in Go (it was 10,000). File upload (`hardUpload`), already authenticated, takes up to 10,000 files at once (before, the limit on part headers stopped it at about 500).
- **Login only by `POST /admin:`:** credentials are read only from the body, never from the URL, and the body may be at most 4 KiB (413 otherwise). A `GET`, another method or another path under `/admin:` does not sign in. `/admin:signout:` signs out only by `POST`.

### Stage 3: technical base, documentation and deployment

#### New
- **Updated `net/http`:** `customNetHttp` is now the `net/http` of Go 1.26 plus Turbo's patches, documented in [`customNetHttp/PATCHES.md`](customNetHttp/PATCHES.md). It brings every Go security fix released up to that version. File-serving performance is markedly higher than in v2.3.rc3.
- **Configurable ports:** the `TURBO_HTTP_ADDR` and `TURBO_HTTPS_ADDR` variables change where Turbo listens, for example to run it behind a proxy.
- **Reference systemd unit:** [`deploy/turbo.service`](deploy/turbo.service) runs as an unprivileged user with `CAP_NET_BIND_SERVICE`, logs to the journal and restarts on failure.
- **Messages with level and time:** console messages use `log/slog` (`time=… level=… msg=…`) and are in Spanish.
- **GUI embedded from `turbo.dev/`:** a single copy of the GUI, embedded with `//go:embed`.
- **Checks before publishing:** the README lists the checks to run by hand before each change or release: formatting, `vet`, `staticcheck`, `govulncheck`, `gosec`, `regenerar -comprobar`, tests, `-race`, fuzzing and cross-compilation.

#### Breaking changes
- **Panic in a handler:** closes the connection, as in Go.
- **`charset`:** error responses say `charset=utf-8`, in lower case.
- **Console message format:** changes; scripts that read the old texts must be adapted.
- **Logs in a fresh copy:** a freshly cloned repository no longer ships `turbo.visits` or `turbo.denials`, so nothing is logged until you create them.
- **`TURBO_HTTP_ADDR` and `TURBO_HTTPS_ADDR`:** an invalid value ends the process.
- **Reference systemd unit:** uses an unprivileged `turbo` user instead of root.
- **Panel API:**
  - `addDenied` rejects with 400 "IP actual" the IP the panel is being used from.
  - `del*` actions without all their parameters respond 400 "Faltan datos" (previously, an empty 200).
  - `setU` and `setP` with the current value respond 400 "Usuario sin cambios" or "Contraseña sin cambios".
  - `hardUpload` responds 400 and uploads nothing if it cannot empty `@`. It used to mix new files with the ones it could not delete.
  - "Denied IP" rejects the unspecified address (`0.0.0.0`, `::`).
- **The panel sends its parameters in the request body:** the password no longer appears in the URL or in `turbo.visits`. An API client that puts it in the URL would still leave it in the log.

### Stage 2: functional fixes and hardening

#### New
- **Cookie-based panel session:** `turbo_session` is `HttpOnly`, `SameSite=Strict` and `Secure` over HTTPS, bound to the client IP and expires after 10 minutes of inactivity. The token no longer travels in the URL.
- **Hashed saved password:** "Save configuration" stores the user and a password hash (PBKDF2-HMAC-SHA256). A plain-text password in `turbo.config` is converted.
- **Automatic certificate renewal:** certificates issued by Turbo are renewed when fewer than 30 days remain.
- **Certificates by name:** each name gets its own certificate through SNI.
- **Panel restriction (`PA`):** the panel can be limited to some hosts or networks; empty by default. Host entries compare the `Host` header, which the client chooses, so only CIDR networks limit who gets in.
- **Security headers:** the panel cannot be embedded in an `iframe` and is not cached, and error responses carry `nosniff`.
- **Default index:** new sites come with `index.html` as their index.

#### Breaking changes
- **Limits that were not applied before:** `MUB`, `MHB` and `MBB` really limit the URI, the headers and the body. Check whether you saved values lower than you need.
- **CGI:** the body sent to a CGI is limited to `MBB` and CGI programs have a maximum run time. A failure to start one responds 500 without details.
- **Rate limiter:**
  - responds 429 instead of closing the connection;
  - counts once per request, so the effective limit is about 3 times higher;
  - `CIL` and `CIS` become real milliseconds (the migration multiplies saved values by 10).
- **Panel API:**
  - `b` (the current password) is required in every `set*`;
  - a POST authenticated with the cookie must come from the same origin (403 otherwise); with the `ok` header it does not have to;
  - the token is no longer accepted in the URL.
- **Session cookie:** uses `Path=/`. Turbo removes it from the `Cookie` header before starting a CGI.
- **Preprocessors:** if the executable is missing, they respond 500 instead of serving the file as is.
- **Rewrites and indexes:**
  - a rewrite to `http(s)://` with a path or query redirects to that exact target; if it is only a domain, the original URI is appended;
  - indexes are tried in the order they were added.
- **File upload:** deletes all of `@`, subfolders included, and reports the discarded names.
- **HTTPS:**
  - the connection is rejected for names without a certificate, without SNI or by IP;
  - an alias needs a certificate that covers its name.
- **Port 80:** the process exits if it cannot open it, so systemd notices and restarts it.
- **`turbo.certificates`:** Certbot works in one folder per site.

### Stage 1: immediate stability and security

#### Fixes
- **Hangs and crashes:**
  - some configuration values no longer hang the server or end the process;
  - there are no more unsynchronized concurrent accesses that could abort it;
  - a slow download no longer leaves the other clients without an answer.
- **TLS:** the minimum version is TLS 1.2.
- **Denied IPs:** "Denied IP" really blocks.
- **Certbot:** only runs when the administrator asks for it.
- **HTTPS redirection:** only sites that have it enabled are redirected.
- **Go patches:** Go's HTTP server security fixes are ported to `customNetHttp` (chunked, Range, CONNECT and HTTP/2).
- **Binaries:** published static (the Linux one works regardless of the glibc version), built with the latest Go patch and tagged on the exact commit.

#### Breaking changes
- **TLS:** TLS 1.0, TLS 1.1, 3DES and RSA key exchange are rejected. With Go 1.26, certificates with a negative serial number and RSA keys under 1024 bits are rejected too, and ML-KEM is enabled.
- **HTTPS redirection:** hosts without a configured site are no longer redirected to HTTPS, and a host is redirected only when its site has HTTPS on and a certificate covers the host; otherwise it is served over HTTP.
- **"Denied IP":** blocks. `"@"` only stores IPs denied by hand, not the rate limiter's temporary marks.
- **Certbot:**
  - no longer starts on its own;
  - "Delete SSL" without a certificate does nothing;
  - an email is required;
  - only `dns-<provider>` adapters are accepted.
- **Rewrites:** those that do not start with `/`, `http://` or `https://` are rejected. Those already in `turbo.config` are dropped on load, with a warning in the log.
- **Logs:** `turbo.visits` and `turbo.denials` are detected by the periodic check, so logging starts up to 30 s after the file is created.
