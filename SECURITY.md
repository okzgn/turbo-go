# Security policy

## Supported versions

Security fixes go into the latest release. Earlier releases (`v2.4`, `v2.3.rc3` and before) and builds of `main` that are not a release don't get fixes: upgrade, following the notes of [CHANGELOG.md](CHANGELOG.md).

To know which version you run, look at the first line Turbo writes when it starts (`journalctl -u turbo | grep msg=Starting` under systemd):

```
level=INFO msg=Starting server="OKZGN Turbo" version=v2.4.1 commit=<hash> go=go1.26.10
```

A binary built from the source says `version=development`, and `commit=unknown` if it was built without version-control information (from a source archive, for example).

## Reporting a vulnerability

- **Non-critical vulnerabilities:** open a GitHub issue.
- **Critical vulnerabilities:** contact us privately, and wait for our response and decision before disclosing anything publicly:
  - https://okzgn.com/#contact
  - https://okzgn.github.io/#contact

Include the steps to reproduce it, what happens and what you expected, the Turbo version (the line above), the operating system and, if it matters, the relevant part of `turbo.config` (without the password hash).

## Advisories

Fixed vulnerabilities are described in the repository's security advisories (*Security → Advisories*), published together with the release that fixes them.
