![Turbo Icon](turbo.icon.nano.png)

# Turbo

![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/okzgn/turbo-go)
![Status](https://img.shields.io/badge/Status-Release%20Candidate-orange)

A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.

![Turbo GUI](turbo.gui.png)

---

## Key Features
- **High-Performance:** Built for speed and efficiency.
- **Visual Management:** Real-time, intuitive administrative interface.
- **Flexible Domain Handling:** Unlimited domains, multi-level wildcard subdomains, and aliases.
- **Security:** Integrated SSL certificate management and concurrency safety. See [Dependencies](#dependencies).
- **Traffic Control:** Fine-grained request rate and size limiting.
- **Deep Customization:** URI rewrites, request preprocessing, headers/MIMEs, and indexes.
- **HTTP/2 Rapid Reset Mitigation:** Go's protection against the [attack](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack) (CVE-2023-44487) plus Turbo's own limit of 50 `RST_STREAM` frames per second and connection.

---

## Documentation

**Visual documentation (website aliases):** [turbo.okzgn.com](https://turbo.okzgn.com), [turbo-server.github.io](https://turbo-server.github.io)

**API documentation:** [API_SPECIFICATION.md](./API_SPECIFICATION.md)

**Changes and upgrading:** [CHANGELOG.md](./CHANGELOG.md) ([español](./CHANGELOG.es.md)). Upgrading from v2.3.rc3 changes the `turbo.config` format (the original is kept as `turbo.config.v1.bak`) and introduces breaking changes: read "Upgrading from v2.3.rc3" first.

---

## Requirements

### Operating Systems
- **Windows:** Windows 10 or later.
- **Linux:** Ubuntu and other mainstream distributions. The release binaries are static (`CGO_ENABLED=0`) and need no system libraries; a binary built with cgo needs glibc 2.34 or later.
- **macOS:** Builds; not tested.

### System Architecture
- **x86-64** (Intel/AMD 64-bit processors).
- **ARM64** (ARMv8 and later, including AWS Graviton processors).

### Dependencies
- **Go 1.26+** (for building from source; releases use the latest Go 1.26 patch).
- No external runtime dependencies — Turbo is distributed as a single, self-contained static binary, except for **[Certbot](https://certbot.eff.org/)** for SSL certificate issuance. See [Commercial Version](#commercial-version).

### Minimum Recommended Requirements
- **CPU:** 1 vCPU (1.5 GHz clock speed or higher).
- **RAM:** ~128 MB for runtime or 1 GB+ to build from source.
- **Storage:** ~100 MB for binary + websites + configuration files.
- **Network:** Standard HTTP/HTTPS ports (80, 443), which need `CAP_NET_BIND_SERVICE` (or root) on Linux; other addresses can be set with `TURBO_HTTP_ADDR` and `TURBO_HTTPS_ADDR`.

---

## Installation

### From Source
```bash
git clone https://github.com/okzgn/turbo-go.git
cd turbo-go
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o turbo .

# Let a standard user open ports 80 and 443 (Linux), then run it without sudo
sudo setcap cap_net_bind_service=+ep ./turbo
./turbo
```

### As a systemd Service (Linux)
[`deploy/turbo.service`](./deploy/turbo.service) is a reference unit: Turbo runs as an unprivileged `turbo` user with `CAP_NET_BIND_SERVICE`, is restarted if it fails, and its messages go to the journal (`journalctl -u turbo`). The comments in the file explain how to install it.

### Supported Platforms
```bash
# Linux x86-64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o turbo-linux-amd64 .

# Linux ARM64 (AWS Graviton, Raspberry Pi, etc.)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o turbo-linux-arm64 .

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o turbo.exe .

# macOS x86-64
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o turbo-darwin-amd64 .

# macOS ARM64 (Apple Silicon)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o turbo-darwin-arm64 .
```

Releases are built with [`release.sh`](./release.sh), which also checks that `customNetHttp` matches the Go version in use (see [customNetHttp/PATCHES.md](./customNetHttp/PATCHES.md)).

Before a release, [`deploy/prueba-puertos-reales.sh`](./deploy/prueba-puertos-reales.sh) checks a build on Linux with the real ports 80 and 443: HTTP, HTTPS redirection, HTTP/1.1 and HTTP/2, TLS versions, SNI, size limits, log messages and the exit when port 80 is taken. It needs `sudo -n setcap` and free ports.

### Execution
- **Windows:** Run `turbo.exe` as Administrator for ports 80/443.
- **Linux:** Grant execution permissions with `chmod +x` and run it: `./turbo` (requires free ports 80 and 443, or the addresses in `TURBO_HTTP_ADDR` and `TURBO_HTTPS_ADDR`). If it cannot open the HTTP address, Turbo exits with an error.

---

## Getting Started

Once Turbo is running, access the admin interface (GUI) at:

- `http://localhost/admin:`
- `http://<your-server-ip>/admin:`
- `http://<your-domain>/admin:`

**Default credentials:**
- **Username:** `Turbo`
- **Password:** `Admin`

> Change the default credentials immediately after your first login, **or compile from source**. See [GUI section](https://turbo-server.github.io/#Get-started-on-interface).

**Notes:**

- If you run `./turbo` directly or without a `turbo.config` file, the folder to be served must be registered through the GUI using the exact site name routed to your server, the exact IP address, or `localhost` if running locally.
- The **GUI can be customized or fully replaced**: copy the `turbo.dev` folder to the sites directory and modify its files. Each file there replaces the embedded one; files that are missing are served from the binary.
- On Windows, use [`rsrc`](https://github.com/akavel/rsrc) (installed beforehand) to generate a `.syso` file from `turbo.windows.manifest` and `turbo.icon.png`, then link it with the executable to produce an `.exe` with a custom icon.
- **Sites directory:** by default, the working directory; `TURBO_DIR` sets another one. If it is changed from the GUI and the configuration is saved, the `turbo.config` of the starting directory keeps a pointer to the new one.
- **Environment Variables:**
  - `TURBO_USER`, `TURBO_PASSWORD`: panel credentials. They take priority over the configuration.
  - `TURBO_DIR`: sites directory.
  - `TURBO_HTTP_ADDR`, `TURBO_HTTPS_ADDR`: listening addresses (`host:port`, `:port` or just the port; by default `:80` and `:443`), for example to run Turbo behind a proxy.

  Credentials can also be changed via the GUI: saving the configuration stores the username and a PBKDF2 hash of the password in `turbo.config`.
- A request for a path ending in `/index.html` is redirected (301) to its folder (`./`), as Go's file server does.

**Logs:**
- To log rate-limiter denials, create an accessible file named `turbo.denials` in the sites directory; to log every access to every file or route on the server, create one named `turbo.visits`. Turbo checks for these files every 30 seconds, so logging starts (or stops, after deleting the file) within that time. Do not create these files if logging is not needed, as they can grow very large.
- **Privacy:** for every request, `turbo.visits` records the client IP, the time, the method, the host and the full URL with its query string, including the requests to the GUI. It never records request bodies.
  - The GUI sends its parameters, including the current password (`b`) of the general settings, in the request body, so they do not appear in the URL or in `turbo.visits`.
  - An API client that put the password (or any other sensitive value) in the URL would leave it in `turbo.visits`: send the parameters in the body (`application/x-www-form-urlencoded`), as the GUI does.
  - Treat `turbo.visits` as sensitive: restrict its permissions, do not share it, rotate or delete it, and do not commit it to version control (both log files are in `.gitignore`). Nothing is logged if the file does not exist.
- Any other message (startup, configuration, sites, certificates, errors) goes to `stdout` with a level and a timestamp (`time=… level=INFO msg=…`); under systemd, to the journal.

---

## Known Limitations
- Open-source GUI and API only available in Spanish language.
- Linux distributions like Alpine or Amazon Linux have not been tested with this version. macOS has not been tested.
  > **Ubuntu 24.04 LTS has been tested and is supported. Previous versions were successfully and extensively tested on Alpine and Amazon Linux.**
- Admin interface (GUI) not extensively tested on older OS versions or old browsers.
- Behind a proxy, Turbo sees the proxy's address as the client IP (rate limits, denied IPs and logs).

---

## Commercial Version

The commercial license includes the following features:

- **Rust Plugins:** Extend and customize Turbo's behavior with high-performance native plugins written in Rust (e.g., dynamic content serving as a [CGI alternative](https://turbo-server.github.io/#so-3), and more).
- **English GUI and API:** Full support for English language in both the admin interface and API responses.
- **More powerful features:** Integrated SSL certificate issuance, smarter rate-limiting and routing engine, and **updated `customNetHttp`**.

Interested in the commercial version? Contact:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact

---

## Architecture & Design Philosophy

Turbo is engineered as a high-performance, single-binary solution with a focus on efficiency, developer experience, and architectural integrity.

*   **Real-Time Admin Interface:** Turbo provides a fully embedded, zero-dependency Web GUI, enabling real-time management of domains, SSL certificates, and traffic policies without requiring external tooling or complex deployments. See [Dependencies](#dependencies). It is not intended to be used through API.

---

## Contributing

1. **Report Issues:** Found a bug? Open an issue and include:
   - **Steps to reproduce:** A clear, step-by-step description of how to trigger the issue.
   - **Expected behavior:** What you expected to happen.
   - **Actual behavior:** What actually happened, including any error messages or logs.
   - **Environment:**
     - OS and version (e.g., Ubuntu 22.04, Windows 11)
     - Architecture (e.g., x86-64, ARM64)
     - Environment/Image/VM description (e.g., RAM, disk space, running processes, capabilities, limitations...)
     - Go version (if building from source)
     - Relevant Turbo configuration files, denial logs, visit logs (redact sensitive data before sharing)
     - Turbo version or commit hash

2. **Suggest Features:** Describe your use case and expected behavior in a GitHub issue.

3. **Security Concerns:** For non-critical vulnerabilities, open a GitHub issue. For critical vulnerabilities, please contact us privately and await our response and decision before disclosing publicly at:
   - https://okzgn.com/#contact
   - https://okzgn.github.io/#contact

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

    The `customNetHttp` package contains the Go standard library `net/http` of Go 1.26.x (the exact version is in `customNetHttp/UPSTREAM`) with Turbo's patches, described in [`customNetHttp/PATCHES.md`](./customNetHttp/PATCHES.md). It is distributed under the **BSD 3-Clause License**. Please refer to the `customNetHttp/LICENCE`, `customNetHttp/PATENTS` and `customNetHttp/NOTICE` files within that directory for full details and attribution.

---

Copyright (C) 2026 [OKZGN](https://okzgn.com)
