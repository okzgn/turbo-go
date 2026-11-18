# Security policy

## Supported versions

Security fixes go into the latest release. Earlier releases (`v2.4.3`, `v2.4.2`, `v2.4.1`, `v2.4`, `v2.3.rc3` and before) and builds of `main` that are not a release don't get fixes: upgrade, following the notes of [CHANGELOG.md](CHANGELOG.md).

To know which version you run, look at the first line Turbo writes when it starts (`journalctl -u turbo | grep msg=Starting` under systemd):

```
level=INFO msg=Starting server="OKZGN Turbo" version=v2.4.4 commit=<hash> go=go1.26.11
```

A binary built from the source says `version=development`, and `commit=unknown` if it was built without version-control information (from a source archive, for example).

## Checking a download

Each release has `SHA256SUMS`, the SHA-256 of its binaries: in the folder of the download, `sha256sum -c --ignore-missing SHA256SUMS`. A release signed by its publisher also has `SHA256SUMS.sig`, an SSH signature of that file (`ssh-keygen -Y sign`, namespace `file`), which shows that the sums are the publisher's and not of whoever could change the files where they are published:

```
echo "releases@turbo <the publisher's public key>" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I releases@turbo -n file -s SHA256SUMS.sig < SHA256SUMS
```

The publisher's public key: not published yet. Until it is, the releases come without `SHA256SUMS.sig`.

## Reporting a vulnerability

Report every vulnerability privately, whatever its severity, and never in a public issue: an issue shows it to everyone before there is a fix. Wait for our response and decision before disclosing anything publicly.

- On GitHub: the repository's *Security* tab, **Report a vulnerability** (private reporting).
- Or through the contact forms:
  - https://okzgn.com/#contact
  - https://okzgn.github.io/#contact

Include the steps to reproduce it, what happens and what you expected, the Turbo version (the line above), the operating system and, if it matters, the relevant part of `turbo.config` (without the password hash).

## Advisories

Fixed vulnerabilities are described in the repository's security advisories (*Security → Advisories*), published together with the release that fixes them.
