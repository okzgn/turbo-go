![Turbo Icon](turbo.icon.nano.png)

# Turbo

![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/okzgn/turbo-go)
![Status](https://img.shields.io/badge/Status-Release%20Candidate-orange)

A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.

---

## Key Features
- **High-Performance:** Built for speed and efficiency.
- **Visual Management:** Real-time, intuitive administrative interface.
- **Flexible Domain Handling:** Unlimited domains, multi-level wildcard subdomains and aliases.
- **Security:** Integrated SSL certificate management and concurrency safety. See [Dependencies](#dependencies).
- **Traffic Control:** Fine-grained request rate and size limiting.
- **Deep Customization:** URI rewrites, request preprocessing, headers/MIMEs, and indexes.

---

## Documentation

**Visual documentation (website aliases):** [turbo.okzgn.com](https://turbo.okzgn.com), [turbo-server.github.io](https://turbo-server.github.io)

---

## Requirements

### Operating Systems
- **Windows:** Windows 11, 10, 8*, 7*.
- **Linux:** Ubuntu, Alpine, Amazon Linux, and other mainstream distributions.
- **macOS:** Compatible.

### System Architecture
- **x86-64** (Intel/AMD 64-bit processors).
- **ARM64** (ARMv8 and later, including AWS Graviton processors).

### Dependencies
- **Go 1.18+** (for building from source).
- No external runtime dependencies — Turbo is distributed as a single, self-contained binary, except for **[Certbot](https://certbot.eff.org/)** for SSL certificate issuance. See [Commercial Version](#commercial-version).

### Minimum Requirements
- **CPU:** 1 vCPU minimum (2.2 GHz clock speed or higher recommended).
- **RAM:** 128 MB minimum (runtime) or 1 GB+ recommended (build from source).
- **Storage:** ~100 MB for binary + websites + configuration files.
- **Network:** Standard HTTP/HTTPS ports (80, 443) require elevated privileges on Linux/macOS.

---

## Installation

### From Source
```bash
git clone https://github.com/okzgn/turbo-go.git
cd turbo-go
go build -ldflags "-s -w" -o turbo .
sudo ./turbo

# Or:

# Alternative without sudo (Linux)
sudo setcap cap_net_bind_service=+ep ./turbo

# Run the binary as a standard user
./turbo
```

### Supported Platforms
```bash
# Linux x86-64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o turbo-linux-amd64 .

# Linux ARM64 (AWS Graviton, Raspberry Pi, etc.)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o turbo-linux-arm64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o turbo.exe .

# macOS x86-64
GOOS=darwin GOARCH=amd64 go build -o turbo-darwin-amd64 .

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o turbo-darwin-arm64 .
```

### Execution
- **Windows:** Run `turbo.exe` as Administrator for ports 80/443.
- **Linux:** Grant execution permissions with `chmod +x` and run it: `./turbo` (requires free ports 80 and 443).

---

## Getting Started

Once Turbo is running, access the admin interface at:

- `http://localhost/admin:`
- `http://<your-server-ip>/admin:`
- `http://<your-domain>/admin:`

**Default credentials:**
- **Username:** `Turbo`
- **Password:** `Admin`

> Change the default credentials immediately after your first login, **or compile from source**. See [GUI section](https://turbo-server.github.io/#Get-started-on-interface).

**Notes:**

- If you run `./turbo` directly or without a `turbo.config` file, the folder to be served must be registered through the GUI using the exact site name routed to your server, the exact IP address, or `localhost` if running locally.
- The **GUI can be customized or fully replaced** by modifying the files inside the `turbo.dev` folder.
- On Windows, use [`rsrc`](https://github.com/akavel/rsrc) (installed beforehand) to generate a `.syso` file from `turbo.windows.manifest` and `turbo.icon.png`, then link it with the executable to produce an `.exe` with a custom icon.

**Logs:**
- To log rate-limiter denials, create an accessible file named `turbo.denials`; to log every access to every file or route on the server, create one named `turbo.visits`. Do not create these files if logging is not needed, as they can grow very large.
- Any other log will be shown at `stdout` or `console`.

---

## Known Limitations
- Open-source GUI and API only available in spanish language.
- Linux distributions like Alpine or Amazon Linux have not been tested. macOS has not been tested.
  > **Ubuntu 24.04 LTS has been tested and is supported. Previous versions were successfully and extensively tested on Alpine and Amazon Linux.**
- Admin interface (GUI) not extensively tested on older OS versions or old browsers.
- Windows 8*-7* support requires Go 1.20 or earlier for compilation.
- The [HTTP/2 Rapid Reset vulnerability](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack) patch has not been implemented in this open-source release; it is available exclusively in the [commercial version](#commercial-version).
- **See [Commercial Version](#commercial-version) features.**

---

## Commercial Version

The commercial license includes the following features:

- **HTTP/2 Rapid Reset Mitigation:** Full patch and protection against the [HTTP/2 Rapid Reset vulnerability](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack) (CVE-2023-44487).
- **Rust Plugins:** Extend and customize Turbo's behavior with high-performance native plugins written in Rust (e.g., dynamic content serving as a [CGI alternative](https://turbo-server.github.io/#so-3), and more).
- **Multilingual GUI and API:** Full support for multiple languages in both the admin interface and API responses.
- **More powerful features:** Integrated SSL certificate issuance, smarter rate-limiting and routing engine, cleaner code (unobfuscated variables), **updated `customNetHttp`**, and more.

Interested in the commercial version? Contact:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact

---

## Architecture & Design Philosophy

Turbo is engineered as a high-performance, single-binary solution with a focus on efficiency, developer experience, and architectural integrity.

*   **Real-Time Admin Interface:** Turbo provides a fully embedded, zero-dependency Web GUI, enabling real-time management of domains, SSL certificates, and traffic policies without requiring external tooling or complex deployments. See [Dependencies](#dependencies).

*   **Source Code Integrity:** Turbo is open-source, and its source code is available for review and modification. However, **some of the logic is intentionally obfuscated** to raise the barrier against casual code copying. This design choice safeguards our core routing engine and management logic from trivial reproduction, while still allowing dedicated users to analyze, audit, or modify the codebase through the necessary effort of reverse-engineering and analysis.

*   **Logic Transparency & Auditability:** Turbo maintains a distinct separation between internal state abstraction and operational logic. While internal variable naming is obfuscated, function signatures and system workflows remain descriptive and transparent. This architectural balance ensures that the server’s operational flow remains fully auditable for security review and compliance, providing the necessary transparency for professional evaluation while effectively deterring the trivial reproduction of proprietary implementation details. **The consistent structure of the function flow facilitates mapping via standard static analysis or automated refactoring tools, allowing qualified auditors to de-obfuscate the codebase for deep inspection whenever necessary.**

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

    The `customNetHttp` package contains a modified version of the Go standard library `net/http` (based on Go v1.19/1.18), which is distributed under the **BSD 3-Clause License**. Please refer to the `customNetHttp/LICENSE`, `customNetHttp/PATENTS` and `customNetHttp/NOTICE` files within that directory for full details and attribution.

---

Copyright (C) 2026 [OKZGN](https://okzgn.com)