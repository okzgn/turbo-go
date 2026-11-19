# Testing Turbo

How the tests of Turbo are run, how they are organized and what the names of the oldest ones mean. The checks that a version passes before it is published (formatting, static analysis, the race detector, the fuzz targets, the builds) are listed in the [README](./README.md#checks-before-publishing), and [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) runs them on every push.

## Running Them

```bash
go test -count=1 ./...
```

That is everything: about six minutes for the package `server`, which is Turbo, and less than one for `customNetHttp` and its regenerator and for `internal/expr`, the language of the expressions of headers and rewrites. It needs the Go of `go.mod` and nothing else: no network, no ports of the system (each test listens on `127.0.0.1:0`) and no Certbot.

- **The helper tools.** The tests build three programs of `internal/testtools` before they start: `cgiecho`, a CGI that answers with what it received, `dxecho`, a worker of the mode dx that does the same (or breaks the protocol, as the request asks), and `fakecertbot`, which stands for Certbot. They go to a temporary folder, or to the one named in `TOOLS_BIN`. On Windows that folder has to be a short path: Turbo refuses a preprocessor whose path has more than 128 bytes.
- **One test, or some.** `go test -count=1 -run 'TestR6_O11' ./server` runs the tests whose name matches. The tests of `server` share the state of the server, so they don't run in parallel with each other.
- **The race detector.** `go test -race -count=1 -timeout 60m ./...`, on Linux or in WSL (it needs cgo and a C compiler). It takes several times longer than the plain run.
- **Another order.** `go test -count=1 -shuffle=on ./...` runs them in a random order, which the log names so that it can be repeated. No test may depend on the ones before it.
- **Fuzz targets.** Each `Fuzz…` function runs its seeds as a test in every run. To let one look for new inputs: `go test -run '^$' -fuzz '^FuzzHost$' -fuzztime 1m ./server` (one target at a time; those of `internal/expr`, with `./internal/expr`).
- **Benchmarks.** `go test -run '^$' -bench 'ResolveRequest' -benchtime 2s ./server` The continuous integration runs every benchmark once, so that they keep working; it doesn't compare their times.
- **What isn't here.** `deploy/systemd-test.sh`, `deploy/real-ports-test.sh` and `deploy/upgrade-test.sh` check, on a real system, the reference unit, the ports 80 and 443 and the upgrade from the previous version. Certbot against a certificate authority, and PHP, are checked by hand before a version (`turbo_php_real_test.go` runs where `php-cgi` is installed, as in the continuous integration, and is skipped elsewhere). So is `dx-lua`, the worker of Lua of `dx/`: `turbo_dx_lua_test.go` runs where `TURBO_DX_LUA` names it or it is in the `PATH` (`TURBO_DX_LUA="$PWD/dx/target/release/dx-lua" go test -count=1 -run TestDXLua ./server`, after `cd dx && cargo build --locked --release`), and the job `dx` of the continuous integration runs it with the `dx-lua` it builds, on Linux, Windows and macOS, and fails unless every `TestDXLua` that `go test -list` names passes. The tests of `dx/` itself are Rust's: `cd dx && cargo test`.

## How They Are Organized

All the tests of Turbo itself are in the folder [`server`](./server), next to the code they test (the files `a.turbo.*.go`), in files named `turbo_<subject>_test.go`. They are of the same package as the code, which Go only allows in its folder: that is why the code and its tests are there together, and the root of the repository has only `main.go`, which starts the program. They test the server from as far out as each thing allows: most make requests to a server started for the test, or call the handler with a request; some call a validator or a function directly.

[`turbo_harness_test.go`](./server/turbo_harness_test.go) has what they share:

- `initForTest(t)` leaves Turbo as `Main()` leaves it before reading its configuration, with a temporary sites directory that has the site `localhost`. Every test that touches the state of the server starts with it.
- `startServer(t)` starts an HTTP server like the one of `Main()` on a free port and returns its address; `login`, `post` and `rawGet` talk to it.
- `useFakeCertbot(t, mode)` puts the simulated Certbot in the `PATH`.

Two things are checked for every test that starts with `initForTest`, whatever it tests:

- **What is kept of the sites is what the state says.** Turbo keeps, between two changes of its state, what each site serves its requests with. While the tests run, each use of what is kept is compared with the same thing made anew: a test fails if a site was changed without the write lock, which no request would notice.
- **What a test changes, it puts back.** The tests replace functions of Turbo (the one that looks at a folder, the clock, the one that loads a certificate) and move its waits and limits. A test that ends with one of them changed fails, by the name of the variable, and so does the run if any is left at its end.

## Writing One

- Name it for what it checks, and say above it, in a sentence, what must happen and what happened before, if it is the test of a fix: `TestHostWithAPortAbove65535IsRefused` needs no list to be understood.
- A fix comes with a test that fails without it.
- Start with `initForTest(t)` if the test touches the state of the server, and put back with `t.Cleanup` whatever it changes of Turbo's variables.
- Change the state of the sites as Turbo does: through a validator, or with `withGlobalLock`.
- Keep times out of it where possible: wait for what must happen, with a limit, instead of sleeping for how long it takes on one machine.

## What the Names of the Older Tests Mean

Most tests were written to check the fix of a finding of a review, and are named for it: a prefix for the review or the list where the finding is, then its identifier there, then what the test checks. The identifiers are the ones of the working notes of each review, which aren't part of the repository: the comment above each test, and the one at the top of each file, say what it checks without them. This table is only to place a name.

| Prefix | Where it comes from |
|---|---|
| `TestT<n>_`, `TestP<n>_`, `TestP_`, `TestS_`, `TestW_`, `TestC_` | The first correction of the code, before v2.4. `T` and a number is one of its tasks (`T21` is task 2.1), `P` and a number a finding by its number; the others gather tests by subject: the panel and its API (`P`), crashes and hangs (`S`), the limits, the limiter and the denied IPs (`W`), `turbo.config` across its schemas (`C`). |
| `TestA<n>_`, `TestB<n>_`, `TestC<n>_` | The comprehensive review that followed it: its tasks of high (`A`), medium (`B`) and low (`C`) severity. |
| `TestI<n>_`, `TestN<n>_`, `TestV<n>_` | The two reviews before v2.4, whose findings are numbered `I` and `N`; `V` are verifications with the real programs (PHP). `TestN…` is the largest group. |
| `TestRA<n>_`, `TestRL_` | The code review of v2.4: its findings of high severity (`RA`) and the rest (`RL`). |
| `TestRP_`, `TestRP2_`, `TestRP3_` | The production reviews made between v2.4 and v2.4.2, each with the identifiers of its own report. |
| `TestR6_` | The review of v2.4.2, whose fixes are v2.4.3. Within it, `TestR6_O<n>_` are its optimizations and `TestR6_M7<n>_` its changes for maintainability, which change nothing of what Turbo does: their tests check that. |
| `TestV25R_` | The review of v2.5 before its release, in the files `turbo_review_v25_<subject>_test.go` (and `TestV25R_S1_…` in `turbo_panel_hardening_test.go`, next to the test it completes): a letter for the area of the finding (`S` the panel, `E` the engine and `turbo.config`, `R` the expressions, `X` the mode dx) and its number; those of its second pass, over the fixes of the first, have `P` (the panel), `M` (the engine and `turbo.config`) or `D` (the mode dx). |
| `TestR250_` | The review of v2.5 as it was published (v2.5.0), whose fixes are v2.5.1, in the files `turbo_review_v250_<subject>_test.go`: two letters for the area of the finding (`CF` `turbo.config` and the sites directory, `EX` the expressions and the rewrites, `CG` the CGIs, `DX` the mode dx, `SV` the serving path, `CT` the certificates and the periodic work, `PA` the panel) and its number. |
| `TestR251_` | The review of v2.5.1 as it was published, whose fixes are v2.5.2, in the files `turbo_review_v251_<subject>_test.go`: two letters for the area of the finding (`PN` the panel, `CO` `turbo.config`, the certificates and the life cycle, `SR` the serving path and the rewrites, `XP` the expressions and the headers, `CP` the CGIs, `RS` the workers of Rust) and its number. Those of the workers of Rust are in `dx/dx-lua` too. |
| `Fuzz…`, `Benchmark…` | Named for what they exercise. |

The fork of `net/http` has, in `customNetHttp`, the tests of what Turbo adds to it for the processes of the CGIs. Go's own tests aren't copied there: the regenerator, whose tests are in `customNetHttp/regenerate`, checks that the fork is Go plus the patches, and `turbo_patches_test.go` tests the patches from Turbo.
