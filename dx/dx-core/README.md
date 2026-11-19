# dx-core

The library every worker of Turbo's mode dx is built on. It is the protocol DX 3 and its loop, and the two things a
worker is made of:

- an **engine** ([`Engine`]), which runs the script of a request: a language;
- the **capabilities** ([`Capability`]), the accesses a script may get (a database, files of the site, the network...),
  which Turbo grants for each request. None is granted by default.

They meet only in [`Value`]: an engine converts between its language and `Value`, and a capability takes and gives
`Value`. So an engine knows no capability, a capability knows no engine, and each one written serves all the others.

## Writing a worker for a language

A crate with a program whose `main` calls `dx_core::run` with its engine and the capabilities it offers:

```rust
use dx_core::{Capabilities, Engine, Granted, Request, Response};

struct MyEngine;

impl Engine for MyEngine {
    fn handle(&mut self, request: &Request, granted: &Granted, response: &mut Response) -> Result<(), String> {
        // request.get("SCRIPT_FILENAME"), request.get("DOCUMENT_ROOT"): the script, and the folder it must be in.
        // request.body(), request.headers(), request.deadline(): the rest of the request, and when Turbo gives it up.
        // granted.list(): the capabilities this request may expose to its script; granted.call(name, function, args).
        response.status = 200;
        response.headers.push((b"Content-Type".to_vec(), b"text/plain".to_vec()));
        response.body = b"hello".to_vec();
        Ok(())
    }
}

fn main() {
    dx_core::run(MyEngine, Capabilities::none())
}
```

What the loop does for the engine: it greets Turbo, reads each request (a body larger than `Limits::body` is read,
dropped and answered 413), calls `handle`, and writes the answer in chunks. `run` takes the default limits
(`Limits::default()`: a body of 64 MiB); an engine whose scripts can't use a body that large calls
`dx_core::run_with(engine, capabilities, limits)` with its own, so that a larger one is never kept in memory
(`dx-lua`: 8 MiB, half the memory of its states). An error of `handle` is answered 500 without a
body, which Turbo answers with the site's template, and its text goes to the standard error, on one line: it never
reaches the client.

What the engine must do:

- **Check the script:** `SCRIPT_FILENAME` resolved must be inside `DOCUMENT_ROOT` resolved; otherwise, 404.
- **Keep nothing of a request** for the next one. A worker serves every site that names it, one request after another.
- **Stop at `request.deadline()`**, if there is one: Turbo kills the worker when the time is over, so stopping first
  keeps the worker alive and the answer a 500 instead of a 504.
- **Write nothing to the standard output:** it is the protocol. What a script prints goes to the standard error
  (`util::escape_line` makes it one line).
- **Expose only `granted`.** A capability the worker has but the request wasn't granted doesn't exist for its script.

`dx-lua` is the model: [`dx-lua/src/engine.rs`](../dx-lua/src/engine.rs).

## Writing a capability

A type that implements [`Capability`]:

```rust
use dx_core::{CapError, Call, Capability, Value};

/// "clock": the time, as a capability of the tests would be.
struct Clock;

impl Capability for Clock {
    fn name(&self) -> &'static str {
        "clock" // In Lua: turbox.clock.now()
    }

    fn functions(&self) -> &'static [&'static str] {
        &["now"]
    }

    fn call(&mut self, function: usize, call: &Call, args: &[Value]) -> Result<Value, CapError> {
        match function {
            0 if args.is_empty() => Ok(Value::Int(1_700_000_000)),
            0 => Err(CapError::Arguments("now() takes nothing".into())),
            _ => unreachable!("an index of functions()"),
        }
    }
}
```

and the worker offers it: `Capabilities::none().with(Clock)`. A script sees it only in the requests that Turbo grants
it to, by its name in the pair `DX_GRANTS` (which Turbo doesn't send in this version); a client can't name it, since
its headers arrive as `HTTP_*` pairs.

What a capability must do:

- **Keep to its request:** `call.document_root()` is the folder of the site, the only one a capability with files may
  use; `call.deadline()` is when the request ends, and `call.check_time()` says whether it has (each call checks it
  before it starts too).
- **Forget the request in `end_request`**, which runs after every request it was granted to, whatever happened: an
  open transaction, a file, a cache of the site.
- **Fail with `CapError`**, never panic: the engine raises it as an error of the script.
- **Take care of its arguments:** they come from the script. Engines bound what crosses (`dx-lua`: 100 000 values,
  16 MiB of texts, 32 levels deep).

Turbo grants nothing in this version: the capabilities are the abstraction for the accesses to come, tested with the
capabilities of the tests of both crates.

## The helpers

`dx_core::util`: `url_decode`, `path_decode`, `parse_query` and `parse_cookies` (1000 pairs at most),
`parse_multipart` (1000 parts at most; each `Part` borrows its data from the body, which isn't copied), `html_escape`
and `json_escape` (also `<`, `>` and `&`), with `html_escaped_len` and `json_escaped_len`, the length of what they give,
to check before building it, and `escape_line`, `log_text` and `log_start` (a text as one line of a log; `log_text` with
a limit, and `log_start` with the beginning of a text and its whole length). Pure functions: nothing reads a file or
the network. `log_line` writes a line to the standard error, the log of a worker, and loses it if that fails, where
`eprintln!` would panic in the middle of an answer.

The loop logs the text of an engine's error on one line, 4 KiB of it at most (`MAX_LOGGED_ERROR`).
