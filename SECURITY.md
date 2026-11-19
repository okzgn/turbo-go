# Security policy

## Supported versions

Security fixes go into the latest release. Earlier releases (`v2.5`, `v2.4.4`, `v2.4.3`, `v2.4.2`, `v2.4.1`, `v2.4`, `v2.3.rc3` and before) and builds of `main` that are not a release don't get fixes: upgrade, following the notes of [CHANGELOG.md](CHANGELOG.md).

To know which version you run, look at the first line Turbo writes when it starts (`journalctl -u turbo | grep msg=Starting` under systemd):

```
level=INFO msg=Starting server="OKZGN Turbo" version=v2.5.1 commit=<hash> go=go1.26.11
```

A binary built from the source says `version=development`, and `commit=unknown` if it was built without version-control information (from a source archive, for example).

## The workers of the mode dx

The releases don't include the workers of the mode dx that are in `dx/` (`dx-lua`): whoever uses one builds it from the source (see [dx/README.md](dx/README.md)), so a fix to `dx/` reaches a server only when its worker is built and installed again (Turbo starts the new program once the workers of the old one end, or when it restarts). `dx-lua --version` gives its version and the commit it was built from, to compare with an advisory (`<hash>+modified` if the source in `dx/` wasn't as that commit has it, and `commit unknown` if it was built outside a checkout of Turbo, or where git couldn't tell):

```
dx-lua 0.3.1 (commit <hash>, protocol DX 3, LuaJIT 2.1.1794386141)
```

A script that gets out of the sandbox of `dx-lua` (that reads a file, the network, the system or another request, or goes beyond its limits of memory or time) is a vulnerability of Turbo: report it as below.

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
