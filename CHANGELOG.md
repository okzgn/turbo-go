# Turbo changelog

[Español](CHANGELOG.es.md)

Each version includes the previous ones. If you upgrade directly from **v2.3.rc3**, every section of this file applies: read [Upgrading from v2.3.rc3](#upgrading-from-v23rc3) first.

## Upgrading from v2.3.rc3

**Recommendation: upgrade as soon as possible.** These versions fix security and stability issues: some could stop or hang the server, and others affected the admin panel, certificates and the TLS configuration. Details are published in the repository's security advisory.

Before upgrading:

1. **Back up the sites folder**, `turbo.config` included. Turbo also keeps an automatic copy (next point), but it does not cover certificates or site content.
2. **`turbo.config` changes format.** Turbo reads old files and converts them in memory. The first time you save the configuration from the panel, it keeps the original as `turbo.config.v1.bak`, with `0600` permissions, and writes the new format, marked with `"^": {"v": "2"}`.
3. **Going back to an earlier version is not transparent.** To do it, restore `turbo.config.v1.bak` as `turbo.config`. If you keep the new file:
   - the old version reads `CIL` and `CIS` as 10 ms units, so the intervals would be 10 times longer;
   - it ignores the saved password (`PH`) and falls back to `Admin` or `TURBO_PASSWORD`;
   - it tries indexes in random order;
   - it does not apply the panel restriction (`PA`).
4. **Review the breaking changes** of each version, especially:
   - TLS 1.2 minimum;
   - Certbot no longer runs on its own;
   - the panel session moves to a cookie;
   - "Denied IP" now blocks;
   - the process exits if it cannot open port 80;
   - the reference systemd unit runs without root.

Published binaries are static and built with the latest Go 1.26 patch. Check the download with `SHA256SUMS`, for example `sha256sum -c SHA256SUMS`.

---

## v2.4

Technical base, documentation and deployment.

### New
- **Updated `net/http`:** `customNetHttp` is now the `net/http` of Go 1.26 plus Turbo's patches, documented in [`customNetHttp/PATCHES.md`](customNetHttp/PATCHES.md). It brings every Go security fix released up to that version. File-serving performance is markedly higher than in v2.3.rc3.
- **Configurable ports:** the `TURBO_HTTP_ADDR` and `TURBO_HTTPS_ADDR` variables change where Turbo listens, for example to run it behind a proxy.
- **Reference systemd unit:** [`deploy/turbo.service`](deploy/turbo.service) runs as an unprivileged user with `CAP_NET_BIND_SERVICE`, logs to the journal and restarts on failure.
- **Messages with level and time:** console messages use `log/slog` (`time=… level=… msg=…`) and are in Spanish.
- **GUI embedded from `turbo.dev/`:** a single copy of the GUI, embedded with `//go:embed`.
- **CI:** every change runs formatting, `vet`, `staticcheck`, `govulncheck`, tests, `-race`, fuzzing and cross-compilation.

### Breaking changes
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

---

## v2.3

Functional fixes and hardening.

### New
- **Cookie-based panel session:** `turbo_session` is `HttpOnly`, `SameSite=Strict` and `Secure` over HTTPS, bound to the client IP and expires after 10 minutes of inactivity. The token no longer travels in the URL.
- **Hashed saved password:** "Save configuration" stores the user and a password hash (PBKDF2-HMAC-SHA256). A plain-text password in `turbo.config` is converted.
- **Automatic certificate renewal:** certificates issued by Turbo are renewed when fewer than 30 days remain.
- **Certificates by name:** each name gets its own certificate through SNI.
- **Panel restriction (`PA`):** the panel can be limited to some hosts or networks; empty by default. Host entries compare the `Host` header, which the client chooses, so only CIDR networks limit who gets in.
- **Security headers:** the panel cannot be embedded in an `iframe` and is not cached, and error responses carry `nosniff`.
- **Default index:** new sites come with `index.html` as their index.

### Breaking changes
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

---

## v2.3.rc4

Immediate stability and security.

### Fixes
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

### Breaking changes
- **TLS:** TLS 1.0, TLS 1.1, 3DES and RSA key exchange are rejected. With Go 1.26, certificates with a negative serial number and RSA keys under 1024 bits are rejected too, and ML-KEM is enabled.
- **HTTPS redirection:** hosts without a configured site are no longer redirected to HTTPS, and wildcard subdomains are served over HTTP.
- **"Denied IP":** blocks. `"@"` only stores IPs denied by hand, not the rate limiter's temporary marks.
- **Certbot:**
  - no longer starts on its own;
  - "Delete SSL" without a certificate does nothing;
  - an email is required;
  - only `dns-<provider>` adapters are accepted.
- **Rewrites:** those that do not start with `/`, `http://` or `https://` are rejected. Those already in `turbo.config` are dropped on load, with a warning in the log.
- **Logs:** `turbo.visits` and `turbo.denials` are detected by the periodic check, so logging starts up to 30 s after the file is created.
