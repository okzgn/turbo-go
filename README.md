![Turbo Icon](turbo.icon.nano.png)

# Turbo

![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/okzgn/turbo-go)
![Status](https://img.shields.io/badge/Status-In%20Development-yellow)

A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.

---

## Key Features
- **High-Performance:** Built for speed and efficiency.
- **Visual Management:** Real-time, intuitive administrative interface.
- **Flexible Domain Handling:** Unlimited domains, multi-level wildcard subdomains and aliases.
- **Security:** Integrated SSL certificate management and concurrency safety.
- **Traffic Control:** Fine-grained request rate and size limiting.
- **Deep Customization:** URI rewrites, request preprocessing, headers/MIMEs, and indexes.

---

## Project Status

This repository codebase is actively being finalized ahead of a stable release. 
The binaries for v2.3.rc1 are available in the Releases section.

---

## Architecture & Design Philosophy

Turbo is engineered as a high-performance, single-binary solution with a focus on efficiency, developer experience, and architectural integrity.

*   **Real-Time Admin Interface:** Turbo provides a fully embedded, zero-dependency Web GUI, enabling real-time management of domains, SSL certificates, and traffic policies without requiring external tooling or complex deployments.

*   **Source Code Integrity:** Turbo is open-source, and its source code is available for review and modification. However, the backend logic is intentionally obfuscated to raise the barrier against casual code copying. This design choice safeguards our core routing engine and management logic from trivial reproduction, while still allowing dedicated users to analyze, audit, or modify the codebase through the necessary effort of reverse-engineering and analysis.

---

## Requirements

### Operating Systems
- **Windows:** Windows 11, 10, 8*, 7*
- **Linux:** Alpine, Amazon Linux, Ubuntu, and other mainstream distributions
- **macOS:** Compatible (not tested)

*Windows 8-7 compilation is only available with Go 1.20 or earlier.

### System Architecture
- **x86-64** (Intel/AMD 64-bit processors)
- **ARM64** (ARMv8 and later, including AWS Graviton processors)

### Dependencies
- **Go 1.18+** (for building from source)
- No external runtime dependencies, Turbo is distributed as a single, self-contained binary

### Minimum Requirements
- **RAM:** 512 MB minimum (runtime) · 1 GB+ recommended (build from source)
- **Storage:** ~100 MB for binary + websites + configuration files
- **Network:** Standard HTTP/HTTPS ports (80, 443) require elevated privileges on Linux/macOS

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

> Change the default credentials immediately after your first login.

---

## Known Limitations
- Windows 8, 7 support requires Go 1.20 or earlier for compilation.
- Linux distributions like Alpine or Amazon Linux have not been tested.
- Admin interface not extensively tested on older OS versions or old browsers.

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