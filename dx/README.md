# dx

The workers of Turbo's preprocessor mode **dx** ([§6.4 of the API](../API_SPECIFICATION.md#64-the-mode-dx-workers-that-turbo-keeps)):
programs that Turbo starts once and keeps running, and that answer the requests of a site's scripts one after another,
through their standard input and output. A CGI starts a process for each request; a worker of dx starts once, so a
script is answered without starting anything.

| Crate | What it is |
|---|---|
| [`dx-core`](dx-core/README.md) | The library every worker is built on: the protocol DX 3 and its loop, the request and the answer, pure helpers (queries, cookies, forms, escapes), and the **capabilities**, the accesses a script may get, which Turbo grants for each request (none by default). It knows no language. |
| [`dx-lua`](dx-lua/README.md) | A worker that runs Lua scripts (LuaJIT) in a sandbox: no files, no network, no system. |

A worker for another language is another crate on `dx-core`: it only converts between its language and `dx-core`'s
values. A capability (a database, files of the site, the network...) is written once on `dx-core` and serves every
worker.

## Build

Rust 1.88 or later, in this folder (Turbo itself is built apart, with Go, and doesn't need Rust):

```bash
cd dx
cargo build --locked --release
```

With rustup, a build in this folder uses the Rust of `rust-toolchain.toml`, the one the continuous integration checks
with, and installs it if it isn't there; any other Rust from 1.88 builds it too (`cargo +1.88 build --locked
--release`). The worker is `dx/target/release/dx-lua` (`dx-lua.exe` on Windows); copy it where Turbo will run it,
somewhere Turbo's user can't change it: under the reference systemd unit, owned by root, `0755` and outside `/home`,
for example `/opt/turbo-dx/dx-lua` (see `deploy/turbo.service`). LuaJIT is built from its sources with the crate (a C
compiler is needed: MSVC on Windows, `cc` and `make` elsewhere).

On Windows the program takes the static C runtime, as LuaJIT does, so it needs no runtime library installed. That is
set by `.cargo/config.toml`, which applies only to a build run from this folder (not to one with `--manifest-path`
from elsewhere), and which `RUSTFLAGS` replaces: a build without it stops, and says so.

`dx-lua --version` gives its version and the commit it was built from (followed by `+modified` when `dx/` isn't as
that commit has it; `unknown` outside a checkout of Turbo, or where git can't tell). The releases
of Turbo don't include `dx-lua`: a fix to `dx/` reaches a server when its worker is built again. A binary carries the
paths of the crates of Cargo's registry it was built from; to give one to others, map them to another name (on
Windows, add to `RUSTFLAGS` the options of `.cargo/config.toml`, which it replaces):

```bash
RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=cargo" cargo build --locked --release
```

On Windows, if the build fails with `"minilua" is not recognized as an internal or external command`, the environment
has `NoDefaultCurrentDirectoryInExePath` set, and the build of LuaJIT runs a program of its own folder: build without
it (`set NoDefaultCurrentDirectoryInExePath=` in `cmd`, or `env -u NoDefaultCurrentDirectoryInExePath cargo build
--release` in a POSIX shell).

## Use it in Turbo

In the panel, a site's **Add preprocessor**: the extension (`lua`), the mode **DX**, and the path of `dx-lua`. Or in
`turbo.config`, the preprocessors of the site:

```json
"?": { "lua": "dx>/opt/turbo-dx/dx-lua" }
```

Turbo starts a worker when a request needs one, keeps up to one per request being served at once (never more than its
turns, `CGP`, in use or starting), and ends a worker that has been idle for 60 seconds (within the next minute: the
idle workers are looked at once a minute). Workers are shared by every site that names the same program; each request gets a
new Lua state, so nothing of one request reaches the next.

What Turbo already does for a CGI it does for a worker: the size of the body (`MBB`), the turns, the time of a response (`WT`),
no session cookie nor `ok` header of the panel, no request header with `_`, the site's headers over the script's. A worker that
breaks the protocol, doesn't answer within `WT`, or loses its client is killed and replaced, never reused.

## The protocol DX 3

The contract for whoever writes a worker without `dx-core`. Integers are unsigned and little-endian: the id has 64
bits, the rest 32.

```text
worker, once, when it starts:  "DX3\n"
Turbo, a request:               u64 id, u32 M, M bytes of pairs, then the body (CONTENT_LENGTH bytes)
worker, its answer:             u64 id, u32 H, H bytes (u32 status, pairs of headers), then chunks: u32 n, n bytes … u32 0
pairs:                          u32 count, then for each: u32 length, name, u32 length, value
```

- The pairs of a request are those a CGI gets in its environment, with the same names (`REQUEST_METHOD`,
  `REQUEST_URI`, `QUERY_STRING`, `SCRIPT_NAME`, `SCRIPT_FILENAME`, `DOCUMENT_ROOT`, `SERVER_NAME`, `SERVER_PORT`,
  `REMOTE_ADDR`, `HTTPS`, `CONTENT_TYPE`, `CONTENT_LENGTH` (absent without a body: 0), `HTTP_*`...), plus `DX_TIMEOUT_MS`, the milliseconds the
  worker has (a tenth less than what is left of Turbo's `WT`, 250 ms at most, so that it answers before Turbo gives up
  and kills it; 0: no limit), and `DX_GRANTS`, the capabilities granted, by name, separated by commas (none, in this
  version).
- An answer starts with the id of its request, a random number: Turbo refuses an answer with another id (one written
  late, after the answer of an earlier request), and kills its worker. So it does with anything written after the
  greeting, before the first request.
- An answer has a status from 200 to 599, a head of 64 KiB at most, and chunks of 1 MiB at most; one that breaks
  this before it starts (its head and the length of its first chunk) gets a 500, and one that breaks it later is cut,
  with a line in the log. An error status without a body is answered with the site's template, without the worker's
  headers that describe a body (`Content-Encoding`, `Content-Range`, `Content-Disposition`, `ETag`,
  `Last-Modified`) and with its others, `Cache-Control` among them: this a CGI doesn't get. The body of a status that
  has none (204, 304) is read and dropped. The status is the one of the answer: a header named `Status` is one more
  header, not the status that a CGI gives with it.
- A worker reads a whole request before it answers, writes only the protocol to its standard output (its messages go
  to its standard error, which Turbo's log takes, grouped), and ends when its input closes.

## What a worker must not do

- Keep anything of a request for the next one: a worker serves every site that names it.
- Trust `SCRIPT_FILENAME` without checking it is inside `DOCUMENT_ROOT`: `dx-lua` resolves both and answers 404
  otherwise. Turbo checked the path, but the worker opens it afterwards, as a CGI does.
- Write the text of an error to the answer: it goes to the standard error, and the client gets a 500.
- End by itself between requests: a worker ends when its input closes. One that ends after an answer may already
  have the next request; Turbo gives it to another worker only if it can be made twice (`GET`, `HEAD`, `OPTIONS`,
  `TRACE`, `PUT` or `DELETE`, without a body) or didn't reach it, and otherwise answers 500.

## Tests

```bash
cargo test
```

The tests of Turbo with the real `dx-lua` (`server/turbo_dx_lua_test.go`) run when `TURBO_DX_LUA` names the
program, or it is in the `PATH`; from the root of the repository:

```bash
TURBO_DX_LUA="$PWD/dx/target/release/dx-lua" go test -count=1 -run 'TestDXLua' ./server
```

The continuous integration of Turbo does both, on Linux, Windows and macOS (without blocking), and builds with Rust
1.88 too; every week it checks `Cargo.lock` against RustSec's advisories (`cargo deny check advisories`).

## License

AGPL-3.0-or-later, as Turbo (`LICENSE` at the root of the repository).
