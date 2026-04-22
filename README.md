# Turbo

![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)
![Go Version](https://img.shields.io/github/go-mod/go-version/okzgn/turbo-go)
![Status](https://img.shields.io/badge/Status-In%20Development-yellow)

A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.

## Key Features
- **High-Performance:** Built for speed and efficiency.
- **Visual Management:** Real-time, intuitive administrative interface.
- **Flexible Domain Handling:** Unlimited domains and multi-level wildcard subdomains and aliases.
- **Security:** Integrated SSL certificate management and concurrency safety.
- **Traffic Control:** Fine-grained request rate and size limiting.
- **Deep Customization:** URI rewrites, request preprocessing, headers/MIMEs, and indexes.


## Installation
```bash
go build -ldflags "-s -w" -o turbo .
./turbo
```

## Project Status: In Development

This repository is currently undergoing maintenance and initial setup, actively finalizing the architecture and documentation for the upcoming version 2.3.**rc1** release.

While this repository is currently empty, the source code and initial files will be available shortly.

---

## License

**Turbo** uses a dual licensing model.

* 1. **Open Source (AGPL v3):** 
    This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License (AGPL v3) as published by the Free Software Foundation. If you modify this software and offer it as a service over a network, you must release your modifications under the same license. See: https://www.gnu.org/licenses/agpl-3.0.html

* 2. **Commercial License:**
    If you wish to use **Turbo** in a proprietary project, integrate it into a closed product, or do not wish to comply with the AGPL v3 requirements, you may purchase a commercial license.

    For commercial licensing inquiries, please visit one of the following:
    - https://okzgn.com/#contact
    - https://okzgn.github.io/#contact

* 3. **Third-Party Components:**
    The `customNetHttp` package contains a modified version of the Go standard library `net/http` (based on Go v1.19/1.18), which is distributed under the **BSD 3-Clause License**. Please refer to the `customNetHttp/LICENSE` and `customNetHttp/NOTICE` files within that directory for full details and attribution.

---

Copyright (C) 2026 [OKZGN](https://okzgn.com)