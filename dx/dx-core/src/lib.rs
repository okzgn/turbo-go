//! dx-core: the worker side of Turbo's preprocessor mode dx.
//!
//! Turbo starts a worker (a program built on this crate) and keeps it running: it gives the worker each request by its
//! standard input and reads the answer from its standard output, one request at a time, in the protocol DX 3. This
//! crate is that protocol and its loop, and what a worker needs to be one: an [`Engine`], which runs a script for a
//! request, and the [`Capability`] values, the accesses that a script may get (files, a database, the network...), which
//! Turbo grants for each request (none by default) and which any engine can expose, since they only deal in [`Value`].
//!
//! The protocol, little-endian unsigned integers (the id of a request of 64 bits, the rest of 32):
//!
//! ```text
//! worker, once, when it starts:  "DX3\n"
//! Turbo, a request:               u64 id, u32 M, M bytes of pairs, then the body (CONTENT_LENGTH bytes)
//! worker, its answer:             u64 id, u32 H, H bytes (u32 status, pairs of headers), then chunks: u32 n, n bytes … u32 0
//! pairs:                          u32 count, then for each: u32 length, name, u32 length, value
//! ```
//!
//! The pairs of a request are what a CGI gets in its environment, with the same names (`REQUEST_METHOD`,
//! `SCRIPT_FILENAME`, `HTTP_*`...), and `DX_TIMEOUT_MS`, the milliseconds the worker has, a little less than what Turbo
//! waits, so that it answers before Turbo gives up (0: no limit). `DX_GRANTS`, the capabilities granted, by name,
//! separated by commas, is kept for what is to come: Turbo doesn't send it in this version (nothing is granted): take
//! its absence as none. The answer starts with the id of its request,
//! a random number: Turbo refuses an answer with another id, and kills its worker. A worker reads the whole request
//! before it answers, writes only the protocol to its standard output (its messages go to its standard error), and
//! ends when its input closes.

mod capability;
mod protocol;
pub mod util;

pub use capability::{Call, CapError, Capabilities, Capability, Granted, Value};
pub use protocol::{
    read_request, read_response, write_request, write_response, Limits, Request, Response, GREETING, MAX_CHUNK,
    MAX_HEAD,
};

use std::io::{self, BufReader, BufWriter, Read, Write};

/// The most of the text of an error that goes to the standard error, for each request: a script could make it as large
/// as its body, on every request.
pub const MAX_LOGGED_ERROR: usize = 4 << 10;

/// An engine runs the script of a request: a language, or anything else that answers requests.
pub trait Engine {
    /// Answers the request in `response`. `granted` are the capabilities Turbo granted to this request, the only ones
    /// the engine may expose to its script. An error answers 500 without a body, which Turbo answers with the site's
    /// template; its text goes to the worker's standard error, never to the client.
    fn handle(&mut self, request: &Request, granted: &Granted, response: &mut Response) -> Result<(), String>;
}

/// Runs a worker on its standard input and output, and ends the process when Turbo lets it go (0) or the protocol
/// breaks (1), with the limits of [`Limits::default`].
pub fn run<E: Engine>(engine: E, capabilities: Capabilities) -> ! {
    run_with(engine, capabilities, Limits::default())
}

/// [`run`] with the limits of a request that the engine takes: an engine whose scripts can't use a body larger than
/// some size gives it, so that a larger one is read, dropped and answered 413 without being kept in memory.
pub fn run_with<E: Engine>(engine: E, capabilities: Capabilities, limits: Limits) -> ! {
    let code = serve(engine, capabilities, io::stdin().lock(), io::stdout().lock(), &limits);
    std::process::exit(code)
}

/// The loop of a worker on any input and output: it greets, and then answers each request until the input ends.
/// Returns 0 when the input ended between two requests, and 1 when the protocol broke (the input ended in the middle of
/// a request, or what came isn't the protocol, or the output closed): Turbo kills and replaces such a worker anyway.
pub fn serve<E: Engine, R: Read, W: Write>(
    mut engine: E,
    capabilities: Capabilities,
    input: R,
    output: W,
    limits: &Limits,
) -> i32 {
    let mut input = BufReader::with_capacity(64 << 10, input);
    let mut output = BufWriter::with_capacity(64 << 10, output);
    if output.write_all(GREETING).and_then(|_| output.flush()).is_err() {
        return 1;
    }
    loop {
        let request = match read_request(&mut input, limits) {
            Ok(Some(request)) => request,
            Ok(None) => return 0,
            Err(e) => {
                util::log_line(&format!("[dx] a request that isn't the protocol DX 3: {e}"));
                return 1;
            }
        };
        let mut response = Response::new();
        if request.too_large() {
            response = Response::empty(413);
        } else {
            let granted = capabilities.grant(&request);
            if let Err(e) = engine.handle(&request, &granted, &mut response) {
                let script = util::escape_line(request.get("SCRIPT_FILENAME").unwrap_or_default());
                util::log_line(&format!("[dx] {script}: {}", util::log_text(e.as_bytes(), MAX_LOGGED_ERROR)));
                response = Response::empty(500); // Turbo answers it with the site's template, as any other error
            }
        }
        if write_response(&mut output, request.id(), &response).and_then(|_| output.flush()).is_err() {
            return 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An engine for the tests: it answers with what it got, and fails when the script is named "fail".
    struct Echo;

    impl Engine for Echo {
        fn handle(&mut self, request: &Request, granted: &Granted, response: &mut Response) -> Result<(), String> {
            if request.get("SCRIPT_FILENAME") == Some(b"fail") {
                return Err("secret detail\nwith a second line".into());
            }
            response.headers.push((b"X-Granted".to_vec(), format!("{:?}", granted.list()).into_bytes()));
            response.body = request.body().to_vec();
            Ok(())
        }
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        list.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()
    }

    #[test]
    fn a_worker_answers_each_request_in_order() {
        let mut input = Vec::new();
        write_request(&mut input, 11, &pairs(&[("CONTENT_LENGTH", "3")]), b"one").unwrap();
        write_request(&mut input, 12, &pairs(&[("SCRIPT_FILENAME", "fail")]), b"").unwrap();
        write_request(&mut input, 13, &pairs(&[("CONTENT_LENGTH", "9")]), b"123456789").unwrap();
        write_request(&mut input, 14, &pairs(&[("CONTENT_LENGTH", "3")]), b"two").unwrap();
        let mut output = Vec::new();
        let limits = Limits { body: 8, ..Limits::default() };
        assert_eq!(serve(Echo, Capabilities::none(), input.as_slice(), &mut output, &limits), 0);
        assert!(output.starts_with(GREETING));
        let mut answers = &output[GREETING.len()..];
        let (id, first) = read_response(&mut answers).unwrap();
        assert_eq!((id, first.status, first.body.as_slice()), (11, 200, &b"one"[..]), "the id of its request first");
        assert_eq!(first.headers, pairs(&[("X-Granted", "[]")]), "nothing granted without DX_GRANTS");
        let (id, failed) = read_response(&mut answers).unwrap();
        assert_eq!(id, 12);
        assert_eq!(
            (failed.status, failed.body.as_slice()),
            (500, &b""[..]),
            "the detail never reaches the client: without a body, Turbo gives it the site's template"
        );
        let (id, too_large) = read_response(&mut answers).unwrap();
        assert_eq!((id, too_large.status), (13, 413));
        assert_eq!(
            read_response(&mut answers).unwrap(),
            (14, Response { status: 200, headers: pairs(&[("X-Granted", "[]")]), body: b"two".to_vec() })
        );
        assert!(answers.is_empty());
    }

    #[test]
    fn a_broken_request_ends_the_worker() {
        let mut input = Vec::new();
        write_request(&mut input, 5, &pairs(&[("CONTENT_LENGTH", "10")]), b"short").unwrap();
        let mut output = Vec::new();
        assert_eq!(serve(Echo, Capabilities::none(), input.as_slice(), &mut output, &Limits::default()), 1);
        assert_eq!(output, GREETING, "nothing answered to half a request");
    }
}
