//! The protocol DX 3: reading a request, writing an answer.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// What a worker writes first, before any request.
pub const GREETING: &[u8] = b"DX3\n";

/// The most a worker takes of a request, and what Turbo takes of an answer.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Bytes of the pairs of a request.
    pub pairs: usize,
    /// Bytes of a body kept in memory: a longer one is read and dropped, and the request answered 413.
    pub body: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { pairs: 1 << 20, body: 64 << 20 }
    }
}

/// The most Turbo takes of the head of an answer (its status and headers), and of each chunk of its body.
pub const MAX_HEAD: usize = 64 << 10;
pub const MAX_CHUNK: usize = 1 << 20;

/// A request, as Turbo gives it: its id, its pairs (the names a CGI gets in its environment) and its body.
#[derive(Debug, Default)]
pub struct Request {
    id: u64,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
    deadline: Option<Instant>,
    too_large: bool,
}

impl Request {
    /// A request made of its parts (for tests, and for engines that answer requests of other origins).
    pub fn new(pairs: Vec<(Vec<u8>, Vec<u8>)>, body: Vec<u8>) -> Request {
        let mut request = Request { id: 0, pairs, body, deadline: None, too_large: false };
        request.deadline = request.timeout().map(|left| Instant::now() + left);
        request
    }

    /// Its id: a random number that its answer brings back first, so that Turbo never takes an answer for another
    /// request's (one written late, after another).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Its pairs, in the order Turbo gave them.
    pub fn pairs(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.pairs
    }

    /// The value of the first pair of that name.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.pairs.iter().find(|(n, _)| n.as_slice() == name.as_bytes()).map(|(_, v)| v.as_slice())
    }

    /// Its body: empty if it was too large for the worker (and then answered 413).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// When Turbo gives up the request (WT), if it has a limit: an engine stops its script before it.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The names of the capabilities that Turbo granted to the request (DX_GRANTS).
    pub fn grants(&self) -> Vec<&str> {
        let granted = self.get("DX_GRANTS").and_then(|v| std::str::from_utf8(v).ok()).unwrap_or("");
        granted.split(',').map(str::trim).filter(|name| !name.is_empty()).collect()
    }

    /// The headers of the request (the pairs HTTP_*), by their names in lower case with "-" ("x-forwarded-for").
    pub fn headers(&self) -> Vec<(String, &[u8])> {
        self.pairs
            .iter()
            .filter_map(|(name, value)| {
                let rest = name.strip_prefix(b"HTTP_")?;
                let lower = String::from_utf8_lossy(rest).to_ascii_lowercase().replace('_', "-");
                Some((lower, value.as_slice()))
            })
            .collect()
    }

    pub(crate) fn too_large(&self) -> bool {
        self.too_large
    }

    fn timeout(&self) -> Option<Duration> {
        let milliseconds: u64 = std::str::from_utf8(self.get("DX_TIMEOUT_MS")?).ok()?.parse().ok()?;
        (milliseconds > 0).then(|| Duration::from_millis(milliseconds))
    }
}

/// An answer: its status, headers and body.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Response {
    /// 200 without headers or body: an engine fills it.
    pub fn new() -> Response {
        Response { status: 200, headers: Vec::new(), body: Vec::new() }
    }

    /// A status without a body: Turbo answers an error status that way with the template of the site.
    pub fn empty(status: u16) -> Response {
        Response { status, headers: Vec::new(), body: Vec::new() }
    }

    /// A status with a text.
    pub fn text(status: u16, text: &str) -> Response {
        Response {
            status,
            headers: vec![(b"Content-Type".to_vec(), b"text/plain; charset=utf-8".to_vec())],
            body: text.as_bytes().to_vec(),
        }
    }
}

impl Default for Response {
    fn default() -> Response {
        Response::new()
    }
}

fn read_u32<R: Read>(input: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    input.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// Reads a request. `None` when the input ends before one (Turbo let the worker go); an error when it ends in the middle
/// of one, or what came isn't the protocol.
pub fn read_request<R: Read>(input: &mut R, limits: &Limits) -> io::Result<Option<Request>> {
    let mut first = [0u8; 8];
    let mut read = 0;
    while read < 8 {
        match input.read(&mut first[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let id = u64::from_le_bytes(first);
    let size = read_u32(input)? as usize;
    if size < 4 || size > limits.pairs {
        return Err(invalid("pairs larger than the limit, or without their count"));
    }
    let mut block = vec![0u8; size];
    input.read_exact(&mut block)?;
    let pairs = read_pairs(&block).ok_or_else(|| invalid("pairs that aren't the protocol"))?;
    let mut request = Request::new(pairs, Vec::new());
    request.id = id;
    let length: u64 = match request.get("CONTENT_LENGTH") {
        Some(value) => std::str::from_utf8(value)
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| invalid("CONTENT_LENGTH isn't a number"))?,
        None => 0,
    };
    if length > limits.body {
        io::copy(&mut input.take(length), &mut io::sink())?; // Read and dropped: the next request comes after it
        request.too_large = true;
        return Ok(Some(request));
    }
    let mut body = vec![0u8; length as usize];
    input.read_exact(&mut body)?;
    request.body = body;
    Ok(Some(request))
}

/// The pairs of a block, if it is exactly that.
pub(crate) fn read_pairs(block: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut rest = block;
    let take_u32 = |rest: &mut &[u8]| -> Option<usize> {
        let (head, tail) = rest.split_first_chunk::<4>()?;
        *rest = tail;
        Some(u32::from_le_bytes(*head) as usize)
    };
    let count = take_u32(&mut rest)?;
    if count > rest.len() / 8 {
        return None;
    }
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let mut pair: [Vec<u8>; 2] = Default::default();
        for text in pair.iter_mut() {
            let n = take_u32(&mut rest)?;
            if n > rest.len() {
                return None;
            }
            let (value, tail) = rest.split_at(n);
            *text = value.to_vec();
            rest = tail;
        }
        let [name, value] = pair;
        pairs.push((name, value));
    }
    rest.is_empty().then_some(pairs)
}

/// The block of pairs.
pub(crate) fn write_pairs(pairs: &[(Vec<u8>, Vec<u8>)], block: &mut Vec<u8>) {
    block.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
    for (name, value) in pairs {
        block.extend_from_slice(&(name.len() as u32).to_le_bytes());
        block.extend_from_slice(name);
        block.extend_from_slice(&(value.len() as u32).to_le_bytes());
        block.extend_from_slice(value);
    }
}

/// Writes the answer of the request `id`: the id, its head, its body in chunks of 1 MiB at most, and the end. A status
/// outside 200-599, or a head larger than Turbo takes, is written as a 500 without a body instead (Turbo answers it with
/// the site's template): Turbo would cut the connection otherwise.
pub fn write_response<W: Write>(output: &mut W, id: u64, response: &Response) -> io::Result<()> {
    let mut head = Vec::with_capacity(64);
    head.extend_from_slice(&u32::from(response.status).to_le_bytes());
    write_pairs(&response.headers, &mut head);
    if !(200..=599).contains(&response.status) || head.len() > MAX_HEAD {
        crate::util::log_line(&format!(
            "[dx] an answer with status {} and a head of {} bytes: answered 500",
            response.status,
            head.len()
        ));
        return write_response(output, id, &Response::empty(500));
    }
    output.write_all(&id.to_le_bytes())?;
    output.write_all(&(head.len() as u32).to_le_bytes())?;
    output.write_all(&head)?;
    for chunk in response.body.chunks(MAX_CHUNK) {
        output.write_all(&(chunk.len() as u32).to_le_bytes())?;
        output.write_all(chunk)?;
    }
    output.write_all(&0u32.to_le_bytes())
}

/// Reads an answer, and the id it brings back: what Turbo does, for the tests of a worker. As Turbo, it refuses a head
/// out of its limits, a status out of 200-599 and a chunk larger than [`MAX_CHUNK`]; the caller compares the id with the
/// request's, as Turbo does before anything of the answer goes out.
pub fn read_response<R: Read>(input: &mut R) -> io::Result<(u64, Response)> {
    let mut id = [0u8; 8];
    input.read_exact(&mut id)?;
    let size = read_u32(input)? as usize;
    if !(8..=MAX_HEAD).contains(&size) {
        return Err(invalid("a head out of its limits"));
    }
    let mut head = vec![0u8; size];
    input.read_exact(&mut head)?;
    let status = u32::from_le_bytes(head[..4].try_into().unwrap());
    if !(200..=599).contains(&status) {
        return Err(invalid("a status out of 200-599"));
    }
    let headers = read_pairs(&head[4..]).ok_or_else(|| invalid("headers that aren't the protocol"))?;
    let mut body = Vec::new();
    loop {
        let n = read_u32(input)? as usize;
        if n == 0 {
            break;
        }
        if n > MAX_CHUNK {
            return Err(invalid("a chunk larger than the limit"));
        }
        let start = body.len();
        body.resize(start + n, 0);
        input.read_exact(&mut body[start..])?;
    }
    Ok((u64::from_le_bytes(id), Response { status: status as u16, headers, body }))
}

/// Writes a request with its id: what Turbo does, for the tests of a worker.
pub fn write_request<W: Write>(output: &mut W, id: u64, pairs: &[(Vec<u8>, Vec<u8>)], body: &[u8]) -> io::Result<()> {
    let mut block = Vec::new();
    write_pairs(pairs, &mut block);
    output.write_all(&id.to_le_bytes())?;
    output.write_all(&(block.len() as u32).to_le_bytes())?;
    output.write_all(&block)?;
    output.write_all(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        list.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()
    }

    #[test]
    fn request_round_trip() {
        let sent = pairs(&[
            ("REQUEST_METHOD", "POST"),
            ("CONTENT_LENGTH", "5"),
            ("HTTP_X_TEST", "a\0b"),
            ("DX_GRANTS", " kv, fs ,"),
        ]);
        let mut wire = Vec::new();
        write_request(&mut wire, 7, &sent, b"hello").unwrap();
        let request = read_request(&mut wire.as_slice(), &Limits::default()).unwrap().unwrap();
        assert_eq!(request.id(), 7);
        assert_eq!(request.pairs(), sent.as_slice());
        assert_eq!(request.body(), b"hello");
        assert_eq!(request.get("HTTP_X_TEST"), Some(&b"a\0b"[..]));
        assert_eq!(request.grants(), vec!["kv", "fs"]);
        assert_eq!(request.headers(), vec![("x-test".to_string(), &b"a\0b"[..])]);
        assert!(request.deadline().is_none());
    }

    #[test]
    fn end_and_truncation() {
        assert!(read_request(&mut &b""[..], &Limits::default()).unwrap().is_none());
        let mut wire = Vec::new();
        write_request(&mut wire, 1, &pairs(&[("CONTENT_LENGTH", "10")]), b"short").unwrap();
        for cut in 1..wire.len() {
            assert!(read_request(&mut &wire[..cut], &Limits::default()).is_err(), "cut at {cut}");
        }
        assert!(read_request(&mut &[1, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 9, 9, 9, 9][..], &Limits::default()).is_err());
        assert!(read_pairs(&[1, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0]).is_none());
        assert!(read_pairs(&[0, 0, 0, 0, 1]).is_none(), "trailing bytes");
    }

    #[test]
    fn body_too_large_is_dropped() {
        let mut wire = Vec::new();
        write_request(&mut wire, 1, &pairs(&[("CONTENT_LENGTH", "8")]), b"12345678").unwrap();
        write_request(&mut wire, 1, &pairs(&[("REQUEST_METHOD", "GET")]), b"").unwrap();
        let limits = Limits { body: 4, ..Limits::default() };
        let mut input = wire.as_slice();
        let first = read_request(&mut input, &limits).unwrap().unwrap();
        assert!(first.too_large() && first.body().is_empty());
        let second = read_request(&mut input, &limits).unwrap().unwrap();
        assert_eq!(second.get("REQUEST_METHOD"), Some(&b"GET"[..]));
    }

    #[test]
    fn response_round_trip_in_chunks() {
        let sent = Response { status: 201, headers: pairs(&[("X-A", "1")]), body: vec![7u8; MAX_CHUNK * 2 + 3] };
        let mut wire = Vec::new();
        write_response(&mut wire, 9, &sent).unwrap();
        assert_eq!(read_response(&mut wire.as_slice()).unwrap(), (9, sent));
        let mut wire = Vec::new();
        write_response(&mut wire, 9, &Response::empty(99)).unwrap();
        assert_eq!(
            read_response(&mut wire.as_slice()).unwrap(),
            (9, Response::empty(500)),
            "the site's template, in Turbo"
        );
    }

    #[test]
    fn deadline_from_turbo() {
        let request = Request::new(pairs(&[("DX_TIMEOUT_MS", "1500")]), Vec::new());
        let left = request.deadline().unwrap() - Instant::now();
        assert!(left > Duration::from_millis(1000) && left <= Duration::from_millis(1500));
        assert!(Request::new(pairs(&[("DX_TIMEOUT_MS", "0")]), Vec::new()).deadline().is_none());
    }
}

#[cfg(test)]
mod reading_answers {
    use super::*;

    /// read_response refuses what Turbo refuses: a status out of 200-599 was taken, cut to 16 bits (v2.5 review X-12).
    #[test]
    fn a_status_out_of_range_is_refused() {
        for status in [99u32, 600, 65536 + 200] {
            let mut answer = Vec::new();
            answer.extend_from_slice(&7u64.to_le_bytes());
            answer.extend_from_slice(&8u32.to_le_bytes());
            answer.extend_from_slice(&status.to_le_bytes());
            answer.extend_from_slice(&0u32.to_le_bytes());
            answer.extend_from_slice(&0u32.to_le_bytes());
            assert!(read_response(&mut answer.as_slice()).is_err(), "status {status}");
        }
    }
}

#[cfg(test)]
mod reading_requests {
    use super::*;

    /// read_request, with requests that are the protocol, cut or changed at random, and with random bytes: an error or a
    /// request, never a panic, and never more memory than the limits (v2.5 review C-6).
    #[test]
    fn requests_never_panic() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let pairs = vec![(b"CONTENT_LENGTH".to_vec(), b"5".to_vec()), (b"REQUEST_METHOD".to_vec(), b"POST".to_vec())];
        let mut valid = Vec::new();
        write_request(&mut valid, 7, &pairs, b"hello").unwrap();
        let limits = Limits { pairs: 256, body: 64 };
        for round in 0..20_000 {
            let mut data = valid.clone();
            if round % 3 == 0 {
                data = (0..(next() % 128)).map(|_| next() as u8).collect();
            } else {
                for _ in 0..(next() % 6) {
                    let at = (next() % data.len() as u64) as usize;
                    data[at] = next() as u8;
                }
                data.truncate((next() % (data.len() as u64 + 1)) as usize);
            }
            let mut input = data.as_slice();
            while let Ok(Some(_)) = read_request(&mut input, &limits) {}
        }
    }
}
