//! Pure helpers that any engine gives its scripts: the query, the cookies, the forms (`multipart` too, in memory) and
//! the escapes. Nothing here reads a file or the network.

/// Names and values, in order.
pub type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

/// The most pairs read of a query, a form or the cookies: the rest is ignored. A body of `a&a&a…` would cost a worker
/// some 40 times its size in memory otherwise, before any script runs (PHP's `max_input_vars` is 1000 too).
pub const MAX_PAIRS: usize = 1000;

/// Decodes `%XX` and `+` (a space). A `%` not followed by two hexadecimal digits stays as it is.
pub fn url_decode(text: &[u8]) -> Vec<u8> {
    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        match text[i] {
            b'+' => out.push(b' '),
            b'%' => match (text.get(i + 1).copied().and_then(hex), text.get(i + 2).copied().and_then(hex)) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    out
}

/// Decodes `%XX` of a path: unlike in a query, `+` is a `+`.
pub fn path_decode(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for (i, piece) in text.split(|&c| c == b'+').enumerate() {
        if i > 0 {
            out.push(b'+');
        }
        out.extend_from_slice(&url_decode(piece));
    }
    out
}

/// At most `max` bytes of a text as one line of a log (see `escape_line`), and how many more there were.
pub fn log_text(text: &[u8], max: usize) -> String {
    log_start(text, text.len(), max)
}

/// `log_text` of a text of `total` bytes of which `start` is the beginning: what a caller has that doesn't join a long
/// text whole only to cut it. `start` must have the whole text, or more than `max` bytes of it.
pub fn log_start(start: &[u8], total: usize, max: usize) -> String {
    if total <= max || start.len() <= max {
        return escape_line(start);
    }
    let mut cut = max;
    while cut > 0 && cut + 3 > max && start[cut] & 0xC0 == 0x80 {
        cut -= 1; // Not in the middle of a character of UTF-8: the byte after the cut isn't a continuation
    }
    format!("{}… ({} bytes more)", escape_line(&start[..cut]), total - cut)
}

/// A text as one line of a log: line breaks and the other control characters escaped, so that what a script writes
/// can't pass for another line.
pub fn escape_line(text: &[u8]) -> String {
    let text = String::from_utf8_lossy(text);
    let mut line = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push('\t'),
            c if c.is_control() => line.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => line.push(c),
        }
    }
    line
}

/// The pairs of a query or of a form `application/x-www-form-urlencoded`, decoded, in order (a name may repeat).
pub fn parse_query(query: &[u8]) -> Pairs {
    query
        .split(|&c| c == b'&')
        .filter(|part| !part.is_empty())
        .take(MAX_PAIRS)
        .map(|part| match part.iter().position(|&c| c == b'=') {
            Some(i) => (url_decode(&part[..i]), url_decode(&part[i + 1..])),
            None => (url_decode(part), Vec::new()),
        })
        .collect()
}

/// The cookies of a header `Cookie` (`a=1; b=2`), in order, as they came: a cookie isn't encoded by HTTP.
pub fn parse_cookies(header: &[u8]) -> Pairs {
    header
        .split(|&c| c == b';')
        .filter_map(|part| {
            let part = part.trim_ascii();
            let i = part.iter().position(|&c| c == b'=')?;
            let name = part[..i].trim_ascii();
            let mut value = part[i + 1..].trim_ascii();
            if value.len() >= 2 && value[0] == b'"' && value[value.len() - 1] == b'"' {
                value = &value[1..value.len() - 1];
            }
            (!name.is_empty()).then(|| (name.to_vec(), value.to_vec()))
        })
        .take(MAX_PAIRS)
        .collect()
}

/// A part of a form `multipart/form-data`.
#[derive(Debug, Clone, PartialEq)]
pub struct Part<'a> {
    pub name: Vec<u8>,
    /// The name of the file, for a file: a name as the client gave it, never a path to use.
    pub filename: Option<Vec<u8>>,
    pub content_type: Vec<u8>,
    /// Its content, in the body: not copied, so that a form doesn't take twice its size.
    pub data: &'a [u8],
}

/// The most parts of a form that are read: the rest is ignored.
pub const MAX_PARTS: usize = 1000;

/// The parts of a form `multipart/form-data`, given its `Content-Type` and its body. `None` when it isn't such a form,
/// or it is broken: a script then sees no form, as with any other body.
pub fn parse_multipart<'a>(content_type: &[u8], body: &'a [u8]) -> Option<Vec<Part<'a>>> {
    let (kind, params) = split_header_value(content_type, true);
    if !kind.eq_ignore_ascii_case(b"multipart/form-data") {
        return None;
    }
    let boundary = params.into_iter().find(|(name, _)| name.eq_ignore_ascii_case(b"boundary"))?.1;
    if boundary.is_empty() || boundary.len() > 70 || boundary.iter().any(|&c| c == b'\r' || c == b'\n') {
        return None;
    }
    let mut delimiter = b"\r\n--".to_vec();
    delimiter.extend_from_slice(&boundary);
    // The first delimiter may start the body, without the line break before it.
    let mut rest = if body.starts_with(&delimiter[2..]) && ends_delimiter(&body[delimiter.len() - 2..]) {
        &body[delimiter.len() - 2..]
    } else {
        let at = find_delimiter(body, &delimiter)?;
        &body[at + delimiter.len()..]
    };
    let mut parts = Vec::new();
    loop {
        if rest.starts_with(b"--") {
            return Some(parts); // The last delimiter
        }
        rest = &rest[find(rest, b"\r\n")? + 2..]; // After the padding that ends_delimiter allowed
        let (headers, data) = match rest.strip_prefix(b"\r\n") {
            Some(data) => (&rest[..0], data), // A part without headers
            None => {
                let end = find(rest, b"\r\n\r\n")?;
                (&rest[..end], &rest[end + 4..])
            }
        };
        let data_end = find_delimiter(data, &delimiter)?;
        if parts.len() < MAX_PARTS {
            if let Some(part) = make_part(headers, &data[..data_end]) {
                parts.push(part);
            }
        }
        rest = &data[data_end + delimiter.len()..];
    }
}

/// Where the next delimiter starts: `delimiter` followed by `--`, or by spaces and a line break. Otherwise those bytes
/// are content (`--XyZnot` isn't the boundary `XyZ`).
fn find_delimiter(text: &[u8], delimiter: &[u8]) -> Option<usize> {
    let mut from = 0;
    loop {
        let at = from + find(&text[from..], delimiter)?;
        if ends_delimiter(&text[at + delimiter.len()..]) {
            return Some(at);
        }
        from = at + 1;
    }
}

fn ends_delimiter(after: &[u8]) -> bool {
    if after.starts_with(b"--") {
        return true;
    }
    let padding = after.iter().take_while(|&&c| c == b' ' || c == b'\t').count();
    after[padding..].starts_with(b"\r\n")
}

fn make_part<'a>(headers: &[u8], data: &'a [u8]) -> Option<Part<'a>> {
    let mut part = Part { name: Vec::new(), filename: None, content_type: Vec::new(), data };
    let mut has_name = false;
    for line in headers.split(|&c| c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&c| c == b':') else { continue };
        let (name, value) = (line[..colon].trim_ascii(), line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"content-disposition") {
            // As browsers write the names of a form (HTML, RFC 7578): between quotes, with `"`, CR and LF as %22, %0D
            // and %0A, and a `\` as it is, not an escape: `filename="a\b.txt"` is `a\b.txt`.
            let (kind, params) = split_header_value(value, false);
            if !kind.eq_ignore_ascii_case(b"form-data") {
                return None;
            }
            for (param, value) in params {
                if param.eq_ignore_ascii_case(b"name") {
                    part.name = form_name_decode(&value);
                    has_name = true;
                } else if param.eq_ignore_ascii_case(b"filename") {
                    part.filename = Some(form_name_decode(&value));
                }
            }
        } else if name.eq_ignore_ascii_case(b"content-type") {
            part.content_type = value.to_vec();
        }
    }
    has_name.then_some(part)
}

/// `%22`, `%0D` and `%0A` of a name of a form back to `"`, CR and LF: what browsers write for them.
fn form_name_decode(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        let decoded = match name.get(i..i + 3) {
            Some(b"%22") => Some(b'"'),
            Some(code) if code.eq_ignore_ascii_case(b"%0d") => Some(b'\r'),
            Some(code) if code.eq_ignore_ascii_case(b"%0a") => Some(b'\n'),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                i += 3;
            }
            None => {
                out.push(name[i]);
                i += 1;
            }
        }
    }
    out
}

/// A header value with parameters (`kind; a=1; b="x"`): the first part, and the parameters with their quotes taken out.
/// With `escapes`, a `\` between quotes escapes the next byte, as in the quoted strings of HTTP (the `Content-Type` of
/// the request); without, a value between quotes is what is up to the next quote, as browsers write the names of a form.
fn split_header_value(value: &[u8], escapes: bool) -> (&[u8], Pairs) {
    let kind_end = value.iter().position(|&c| c == b';').unwrap_or(value.len());
    let kind = value[..kind_end].trim_ascii();
    let mut params = Vec::new();
    let mut rest = &value[kind_end..];
    while let Some(after) = rest.strip_prefix(b";") {
        let after = after.trim_ascii_start();
        let name_end = after.iter().position(|&c| c == b'=' || c == b';').unwrap_or(after.len());
        let name = after[..name_end].trim_ascii().to_vec();
        rest = &after[name_end..];
        let mut param = Vec::new();
        if let Some(after) = rest.strip_prefix(b"=") {
            let after = after.trim_ascii_start();
            if let Some(quoted) = after.strip_prefix(b"\"") {
                let mut i = 0;
                while i < quoted.len() && quoted[i] != b'"' {
                    if escapes && quoted[i] == b'\\' && i + 1 < quoted.len() {
                        i += 1;
                    }
                    param.push(quoted[i]);
                    i += 1;
                }
                rest = &quoted[(i + 1).min(quoted.len())..];
                let next = rest.iter().position(|&c| c == b';').unwrap_or(rest.len());
                rest = &rest[next..];
            } else {
                let end = after.iter().position(|&c| c == b';').unwrap_or(after.len());
                param = after[..end].trim_ascii().to_vec();
                rest = &after[end..];
            }
        }
        if !name.is_empty() {
            params.push((name, param));
        }
    }
    (kind, params)
}

/// Writes a line to the standard error, the log of a worker. A standard error that fails (closed, or full) loses the line
/// and nothing else: `eprintln!` would panic, and end the worker in the middle of an answer.
pub fn log_line(line: &str) {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(line.as_bytes()).and_then(|_| stderr.write_all(b"\n"));
}

/// Where `needle` starts in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        let at = haystack[i..=last_start].iter().position(|&c| c == first)? + i;
        if &haystack[at..at + needle.len()] == needle {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

/// The length of a text once escaped by [`html_escape`]: an engine checks it against its memory before the text is made.
pub fn html_escaped_len(text: &[u8]) -> usize {
    text.iter().fold(0usize, |length, &c| {
        length.saturating_add(match c {
            b'&' | b'\'' => 5,
            b'<' | b'>' => 4,
            b'"' => 6,
            _ => 1,
        })
    })
}

/// Escapes a text for HTML: `& < > " '`.
pub fn html_escape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(html_escaped_len(text));
    for &c in text {
        match c {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The length of a text once escaped by [`json_escape`]: an engine checks it against its memory before the text is made.
pub fn json_escaped_len(text: &[u8]) -> usize {
    text.iter().fold(0usize, |length, &c| {
        length.saturating_add(match c {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0c => 2,
            c if c < 0x20 || c == b'<' || c == b'>' || c == b'&' || c == 0x7f => 6,
            _ => 1,
        })
    })
}

/// Escapes a text for a JSON string (without its quotes): `"`, `\`, the control characters, and `<`, `>` and `&` as
/// `\u00XX`, so that the string can't end a `<script>` it is written in.
pub fn json_escape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(json_escaped_len(text));
    for &c in text {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            c if c < 0x20 || c == b'<' || c == b'>' || c == b'&' || c == 0x7f => {
                out.extend_from_slice(format!("\\u{c:04x}").as_bytes())
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        list.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()
    }

    #[test]
    fn decode_and_escape() {
        assert_eq!(url_decode(b"a%20b+c%zz%4"), b"a b c%zz%4");
        assert_eq!(url_decode(b"%41%e2%82%ac"), "A€".as_bytes());
        assert_eq!(url_decode(b"%"), b"%");
        assert_eq!(html_escape(b"<a&'\">"), b"&lt;a&amp;&#39;&quot;&gt;");
        let texts: [&[u8]; 4] = [b"<a&'\">", b"plain", b"", b"a\"\\\n\x01</script>\x7f\x08\x0c\r\t"];
        for text in texts {
            assert_eq!(html_escaped_len(text), html_escape(text).len(), "{text:?}");
            assert_eq!(json_escaped_len(text), json_escape(text).len(), "{text:?}");
        }
        assert_eq!(json_escape(b"a\"\\\n\x01</script>\x7f"), &b"a\\\"\\\\\\n\\u0001\\u003c/script\\u003e\\u007f"[..]);
        assert_eq!(json_escape("é".as_bytes()), "é".as_bytes());
        assert_eq!(path_decode(b"/a+b%2B%20c"), b"/a+b+ c");
        assert_eq!(escape_line(b"a\nb\rc\td\x1b\xff"), "a\\nb\\rc\td\\u{1b}\u{fffd}");
    }

    #[test]
    fn at_most_max_pairs() {
        let many = b"a&".repeat(5 * MAX_PAIRS);
        assert_eq!(parse_query(&many).len(), MAX_PAIRS);
        let cookies = b"a=1; ".repeat(5 * MAX_PAIRS);
        assert_eq!(parse_cookies(&cookies).len(), MAX_PAIRS);
    }

    #[test]
    fn logged_texts_are_bounded() {
        assert_eq!(log_text(b"short\n", 100), "short\\n");
        let long = log_text(&b"x".repeat(10_000), 100);
        assert!(long.starts_with(&"x".repeat(100)) && long.ends_with("(9900 bytes more)"), "{long}");
        let accented = log_text("é".repeat(100).as_bytes(), 101);
        assert!(accented.starts_with(&"é".repeat(50)) && !accented.contains('\u{fffd}'), "{accented}");
        // Of the start of a text, as from the whole text
        assert_eq!(log_start(&b"x".repeat(101), 10_000, 100), long);
        assert_eq!(log_start(b"short\n", 6, 100), "short\\n");
    }

    #[test]
    fn queries_and_cookies() {
        assert_eq!(
            parse_query(b"a=1&&b&c=x%3Dy&a=2&=v"),
            pairs(&[("a", "1"), ("b", ""), ("c", "x=y"), ("a", "2"), ("", "v")])
        );
        assert_eq!(
            parse_cookies(b" a=1; b = \"two\" ;c=x=y; noequal; =v"),
            pairs(&[("a", "1"), ("b", "two"), ("c", "x=y")])
        );
    }

    const FORM: &[u8] = b"preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHello\r\n--XyZ\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"a %22b%22.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\
\x00\x01\r\n--XyZnot\r\n\r\n--XyZ \t\r\nContent-Disposition: form-data; name=empty\r\n\r\n\r\n--XyZ--\r\nepilogue";

    #[test]
    fn multipart() {
        let parts = parse_multipart(b"Multipart/Form-Data; charset=x; boundary=\"XyZ\"", FORM).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            (parts[0].name.as_slice(), parts[0].data, parts[0].filename.is_none()),
            (&b"title"[..], &b"Hello"[..], true)
        );
        assert_eq!(parts[1].filename.as_deref(), Some(&b"a \"b\".bin"[..]));
        assert_eq!(parts[1].content_type, b"application/octet-stream");
        assert_eq!(parts[1].data, b"\x00\x01\r\n--XyZnot\r\n");
        assert_eq!((parts[2].name.as_slice(), parts[2].data), (&b"empty"[..], &b""[..]));
        let starts = b"--b\r\nContent-Disposition: form-data; name=x\r\n\r\n1\r\n--b--";
        assert_eq!(parse_multipart(b"multipart/form-data; boundary=b", starts).unwrap()[0].data, b"1");
    }

    /// The names of a form as browsers write them: a `\` is part of the name, not an escape (`a\b.txt` was `ab.txt`,
    /// and `name="a\"; filename="f.txt"` took the file for a field), and `"`, CR and LF come as %22, %0D and %0A.
    #[test]
    fn multipart_names_as_browsers_write_them() {
        let form = b"--b\r\nContent-Disposition: form-data; name=\"up\"; filename=\"C:\\docs\\a\\b.txt\"\r\n\r\n1\r\n\
--b\r\nContent-Disposition: form-data; name=\"a\\\"; filename=\"f.txt\"\r\n\r\n2\r\n\
--b\r\nContent-Disposition: form-data; name=\"x%0D%0Ay%22\"\r\n\r\n3\r\n--b--";
        let parts = parse_multipart(b"multipart/form-data; boundary=\"b\"", form).unwrap();
        assert_eq!(parts[0].filename.as_deref(), Some(&b"C:\\docs\\a\\b.txt"[..]));
        assert_eq!((parts[1].name.as_slice(), parts[1].filename.as_deref()), (&b"a\\"[..], Some(&b"f.txt"[..])));
        assert_eq!(parts[2].name, b"x\r\ny\"");
        // The boundary of the Content-Type is a quoted string of HTTP: a \ escapes there
        assert_eq!(parse_multipart(b"multipart/form-data; boundary=\"\\b\"", form).unwrap().len(), 3);
    }

    #[test]
    fn multipart_refused() {
        assert!(parse_multipart(b"multipart/mixed; boundary=XyZ", FORM).is_none());
        assert!(parse_multipart(b"multipart/form-data", FORM).is_none());
        assert!(parse_multipart(b"multipart/form-data; boundary=", FORM).is_none());
        assert!(parse_multipart(
            b"multipart/form-data; boundary=XyZ",
            b"--XyZ\r\nContent-Disposition: form-data; name=a\r\n\r\nno end"
        )
        .is_none());
        for cut in 0..FORM.len() - 12 {
            let _ = parse_multipart(b"multipart/form-data; boundary=XyZ", &FORM[..cut]);
            // No panic
        }
        let mut many = Vec::new();
        for _ in 0..MAX_PARTS + 5 {
            many.extend_from_slice(b"--b\r\nContent-Disposition: form-data; name=x\r\n\r\n1\r\n");
        }
        many.extend_from_slice(b"--b--");
        assert_eq!(parse_multipart(b"multipart/form-data; boundary=b", &many).unwrap().len(), MAX_PARTS);
    }

    /// Random bytes, and the forms of the tests cut and changed at random, in every parser of what a client sends: none
    /// panics, whatever comes (a fuzzing without the tools of nightly, as the CI runs it).
    #[test]
    fn parsers_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet: &[u8] = b"=&;%+\"\\-\r\n \taA0bB=\xff\x00XyZ:";
        for round in 0..20_000 {
            let length = (next() % 300) as usize;
            let mut data: Vec<u8> = if round % 2 == 0 {
                (0..length).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect()
            } else {
                let mut form = FORM.to_vec();
                for _ in 0..(next() % 8) {
                    let at = (next() % form.len() as u64) as usize;
                    form[at] = alphabet[(next() % alphabet.len() as u64) as usize];
                }
                form.truncate((next() % (form.len() as u64 + 1)) as usize);
                form
            };
            let _ = parse_query(&data);
            let _ = parse_cookies(&data);
            let _ = url_decode(&data);
            let _ = path_decode(&data);
            let _ = log_text(&data, 64);
            let _ = escape_line(&data);
            let _ = parse_multipart(b"multipart/form-data; boundary=XyZ", &data);
            let _ = parse_multipart(&data, FORM);
            data.reverse();
            let _ = split_header_value(&data, round % 3 == 0);
        }
    }

    #[test]
    fn finding() {
        assert_eq!(find(b"aab", b"ab"), Some(1));
        assert_eq!(find(b"ab", b"abc"), None);
        assert_eq!(find(b"", b"a"), None);
        assert_eq!(find(b"xxab", b"ab"), Some(2));
    }
}
