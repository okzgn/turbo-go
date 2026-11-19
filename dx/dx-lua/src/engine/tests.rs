use super::*;
use dx_core::{read_request, read_response, write_request, Call, CapError, Capabilities, Capability, Limits};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// The allocator of the tests: the system's, noting the largest block that each thread asks for (LARGEST), to see what
/// the worker allocates outside the memory of its states.
struct Noting;

thread_local! {
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
}

unsafe impl GlobalAlloc for Noting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Noting = Noting;

/// A folder of a site for one test, with its scripts.
struct Site {
    root: PathBuf,
}

impl Site {
    fn new() -> Site {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!("dx-lua-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let root = std::env::temp_dir().join(name);
        std::fs::create_dir_all(root.join("www")).unwrap();
        Site { root }
    }

    fn www(&self) -> PathBuf {
        self.root.join("www")
    }

    fn script(&self, name: &str, code: &str) -> &Site {
        std::fs::write(self.www().join(name), code).unwrap();
        self
    }

    /// The pairs Turbo gives for a script of this site.
    fn pairs(&self, script: &str, extra: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let root = self.www().to_string_lossy().replace('\\', "/");
        let mut pairs = vec![
            ("REQUEST_METHOD".to_string(), "GET".to_string()),
            ("REQUEST_URI".to_string(), format!("/{script}")),
            ("SCRIPT_NAME".to_string(), format!("/{script}")),
            ("SCRIPT_FILENAME".to_string(), format!("{root}/{script}")),
            ("DOCUMENT_ROOT".to_string(), root),
            ("QUERY_STRING".to_string(), String::new()),
            ("HTTP_HOST".to_string(), "example.test".to_string()),
            ("REMOTE_ADDR".to_string(), "192.0.2.1".to_string()),
        ];
        for (name, value) in extra {
            match pairs.iter_mut().find(|(n, _)| n == name) {
                Some(pair) => pair.1 = value.to_string(),
                None => pairs.push((name.to_string(), value.to_string())),
            }
        }
        pairs.into_iter().map(|(n, v)| (n.into_bytes(), v.into_bytes())).collect()
    }

    fn run(&self, script: &str, extra: &[(&str, &str)], body: &[u8]) -> Result<Response, String> {
        self.run_with(&mut LuaEngine::new(Config::default()), &Capabilities::none(), script, extra, body)
    }

    fn run_with(
        &self,
        engine: &mut LuaEngine,
        capabilities: &Capabilities,
        script: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, String> {
        let mut extra = extra.to_vec();
        let length = body.len().to_string();
        if !body.is_empty() {
            extra.push(("CONTENT_LENGTH", &length));
        }
        let request = Request::new(self.pairs(script, &extra), body.to_vec());
        let granted = capabilities.grant(&request);
        let mut response = Response::new();
        engine.handle(&request, &granted, &mut response)?;
        Ok(response)
    }

    fn body(&self, script: &str) -> String {
        let response = self.run(script, &[], b"").unwrap();
        String::from_utf8_lossy(&response.body).into_owned()
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn header<'a>(response: &'a Response, name: &str) -> Vec<&'a [u8]> {
    response
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| v.as_slice())
        .collect()
}

#[test]
fn what_a_script_returns() {
    let site = Site::new();
    site.script(
        "table.lua",
        r#"return { status = 201, headers = { ["X-Test"] = "yes", ["Set-Cookie"] = {"a=1", "b=2"} },
        body = REQUEST.method .. " " .. REQUEST.path .. " " .. (REQUEST.params.a or "-") }"#,
    )
    .script("html.lua", r#"return "  <p>hola</p>""#)
    .script("text.lua", r#"return "hola""#)
    .script("nil.lua", "return nil")
    .script("empty.lua", r#"return """#)
    .script("code.lua", "return 418")
    .script("number.lua", "return { body = 12 }")
    .script("bad-status.lua", "return 99")
    .script("bad-type.lua", "return function() end")
    .script("bad-header.lua", "return { headers = { X = {} , Y = function() end } }")
        .script("meta.lua", "local list = setmetatable({}, { __index = function() error('ran after the end') end }) return { headers = { X = list } }");
    let table =
        site.run("table.lua", &[("REQUEST_URI", "/table%20x.lua?a=1%202"), ("QUERY_STRING", "a=1%202")], b"").unwrap();
    assert_eq!((table.status, table.body.as_slice()), (201, &b"GET /table x.lua 1 2"[..]));
    assert_eq!(header(&table, "X-Test"), vec![&b"yes"[..]]);
    assert_eq!(header(&table, "Set-Cookie"), vec![&b"a=1"[..], &b"b=2"[..]]);
    let html = site.run("html.lua", &[], b"").unwrap();
    assert_eq!(header(&html, "Content-Type"), vec![&b"text/html; charset=utf-8"[..]]);
    let text = site.run("text.lua", &[], b"").unwrap();
    assert_eq!(header(&text, "Content-Type"), vec![&b"text/plain; charset=utf-8"[..]]);
    assert_eq!(site.run("nil.lua", &[], b"").unwrap(), Response::empty(204));
    assert_eq!(site.run("empty.lua", &[], b"").unwrap(), Response::empty(204));
    assert_eq!(site.run("code.lua", &[], b"").unwrap(), Response::empty(418));
    assert_eq!(site.body("number.lua"), "12");
    assert_eq!(
        site.run("meta.lua", &[], b"").unwrap().headers,
        vec![],
        "a metamethod of what a script returns doesn't run"
    );
    for bad in ["bad-status.lua", "bad-type.lua", "bad-header.lua"] {
        assert!(site.run(bad, &[], b"").is_err(), "{bad}");
    }
}

#[test]
fn missing_and_outside_the_site() {
    let site = Site::new();
    std::fs::write(site.root.join("outside.lua"), "return 'out'").unwrap();
    std::fs::create_dir(site.www().join("folder.lua")).unwrap();
    assert_eq!(site.run("missing.lua", &[], b"").unwrap(), Response::empty(404));
    assert_eq!(site.run("../outside.lua", &[], b"").unwrap(), Response::empty(404));
    assert_eq!(site.run("folder.lua", &[], b"").unwrap(), Response::empty(404));
    let mut engine = LuaEngine::new(Config::default());
    let request = Request::new(vec![(b"SCRIPT_FILENAME".to_vec(), b"/x.lua".to_vec())], Vec::new());
    assert!(engine.handle(&request, &Granted::none(&request), &mut Response::new()).is_err(), "without DOCUMENT_ROOT");
}

#[test]
fn the_sandbox() {
    let site = Site::new();
    let forbidden = [
        "io",
        "os",
        "require",
        "load",
        "loadstring",
        "dofile",
        "loadfile",
        "debug",
        "ffi",
        "jit",
        "package",
        "coroutine",
        "module",
        "newproxy",
        "setfenv",
        "getfenv",
        "gcinfo",
        "rawlen",
    ];
    let code = format!("local t = {{}} for _, n in ipairs({{'{}'}}) do if _G[n] ~= nil then t[#t + 1] = n end end return table.concat(t, ',') .. '|'", forbidden.join("','"));
    site.script("sandbox.lua", &code);
    assert_eq!(site.body("sandbox.lua"), "|", "every forbidden global is nil");
    site.script("string.lua", "return tostring(string.dump ~= nil) .. tostring(getmetatable('').__index == string)");
    assert_eq!(site.body("string.lua"), "truetrue", "the string library is whole, and has nothing to reach out");
    let bytecode = Lua::new().load("return 'compiled'").into_function().unwrap().dump(true);
    std::fs::write(site.www().join("bytecode.lua"), bytecode).unwrap();
    let refused = site.run("bytecode.lua", &[], b"").unwrap_err();
    assert!(refused.contains("binary") || refused.contains("mode"), "bytecode refused: {refused}");
    site.script("calls.lua", "local n = 0 for i = 1, 20000 do n = n + #tostring(i) end return tostring(n)");
    assert_eq!(site.body("calls.lua"), "88894", "more than 5000 calls");
    site.script("print.lua", "print('a\\nfake line', 1, nil, {}) return 'printed'");
    assert_eq!(site.body("print.lua"), "printed", "print goes to the standard error, not to the answer");
}

thread_local! {
    /// The lines that print wrote, in the test of this thread.
    static PRINTED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn keep_line(line: &str) {
    PRINTED.with(|lines| lines.borrow_mut().push(line.to_string()));
}

/// print writes at most max_print bytes in a request, counting each line with its start and its end: an empty line
/// counted nothing, and a script that printed nothing in a loop filled the log until its time was over.
#[test]
fn print_counts_every_line() {
    let site = Site::new();
    site.script("empty.lua", "for i = 1, 100000 do print() end return 'ok'");
    let mut engine = LuaEngine::new(Config { print_line: keep_line, ..Config::default() });
    PRINTED.with(|lines| lines.borrow_mut().clear());
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "empty.lua", &[], b"").unwrap().body, b"ok");
    let written: usize = PRINTED.with(|lines| lines.borrow().iter().map(|line| line.len() + 1).sum());
    assert!(written <= (64 << 10) + 200, "{written} bytes written by print in a request");
    assert!(PRINTED.with(|lines| lines.borrow().last().unwrap().contains("the rest is dropped")));
}

/// math.random gives another sequence for each request (seeded with its id, which Turbo makes at random): every
/// request, of every site, got the same numbers.
#[test]
fn random_differs_between_requests() {
    let site = Site::new();
    site.script("random.lua", "return tostring(math.random(1, 2^30)) .. ' ' .. tostring(math.random(1, 2^30))");
    let mut engine = LuaEngine::new(Config::default());
    let mut numbers = |id: u64| {
        let mut wire = Vec::new();
        write_request(&mut wire, id, &site.pairs("random.lua", &[]), b"").unwrap();
        let request = read_request(&mut wire.as_slice(), &Limits::default()).unwrap().unwrap();
        let mut response = Response::new();
        engine.handle(&request, &Capabilities::none().grant(&request), &mut response).unwrap();
        response.body
    };
    let (first, second, again) = (numbers(0x5eed_0001 << 11), numbers(0x5eed_0002 << 11), numbers(0x5eed_0001 << 11));
    assert_ne!(first, second, "two requests got the same numbers");
    assert_eq!(first, again, "the same id, the same numbers");
}

/// What a script returns as its headers is counted as Turbo takes it (MAX_HEAD) before it is copied: a list with the
/// same text of 1 MiB a hundred times was a copy of 100 MiB, out of the state's memory limit, and then a 500.
#[test]
fn headers_are_counted_before_they_are_copied() {
    let site = Site::new();
    site.script(
        "copies.lua",
        "local big, v = string.rep('y', 2^20), {} for i = 1, 100 do v[i] = big end return { headers = { X = v } }",
    )
    .script(
        "names.lua",
        "local h = {} for i = 1, 5000 do h['X-' .. i] = string.rep('v', 100) end return { headers = h }",
    )
    .script("fits.lua", "return { headers = { X = { string.rep('a', 30000), string.rep('b', 30000) } } }");
    for script in ["copies.lua", "names.lua"] {
        let error = site.run(script, &[], b"").unwrap_err();
        assert!(error.contains("headers larger than"), "{script}: {error}");
    }
    assert_eq!(header(&site.run("fits.lua", &[], b"").unwrap(), "X").len(), 2, "within 64 KiB");
}

#[test]
fn print_joins_only_what_it_writes() {
    let lua = Lua::new();
    let large = Value::String(lua.create_string("x".repeat(1 << 20)).unwrap());
    // 200 times a text of 1 MiB: 200 MiB joined, before, of which 64 KiB at most were written
    let args = MultiValue::from_vec(vec![large; 200]);
    let (line, total) = print_line(&lua, &args, 100).unwrap();
    assert_eq!((line.len(), total), (101, 200 * (1 << 20) + 199), "the line is cut, its length counted whole");
    let short = MultiValue::from_vec(vec![Value::Nil, Value::Boolean(true), Value::Number(1.5)]);
    assert_eq!(print_line(&lua, &short, 100).unwrap(), (b"nil\ttrue\t1.5".to_vec(), 12));
}

#[test]
fn errors_stay_in_the_worker() {
    let site = Site::new();
    site.script("err.lua", r#"error("boom: a secret")"#);
    let error = site.run("err.lua", &[], b"").unwrap_err();
    assert!(error.contains("boom") && error.contains("err.lua:1"), "{error}");
    // Through the loop, as Turbo sees it: a 500 without the detail.
    let mut input = Vec::new();
    write_request(&mut input, 42, &site.pairs("err.lua", &[]), b"").unwrap();
    let mut output = Vec::new();
    dx_core::serve(
        LuaEngine::new(Config::default()),
        Capabilities::none(),
        input.as_slice(),
        &mut output,
        &Limits::default(),
    );
    let (id, answer) = read_response(&mut &output[dx_core::GREETING.len()..]).unwrap();
    assert_eq!((id, answer.status), (42, 500));
    assert!(!String::from_utf8_lossy(&answer.body).contains("secret"));
}

#[test]
fn bodies_forms_and_files() {
    let site = Site::new();
    site.script("echo.lua", r#"
        local f = REQUEST.files[1]
        local info = f and (f.field .. "|" .. f.filename .. "|" .. f.size .. "|" .. f.content_type .. "|" .. f.data) or "nofile"
        return { headers = { ["Content-Type"] = "application/octet-stream" },
                 body = info .. "|" .. (REQUEST.form.name or "") .. "|" .. #REQUEST.body .. "|" .. BODY }"#);
    let raw = [0xffu8, 0x00, 0xfe];
    let binary = site
        .run("echo.lua", &[("REQUEST_METHOD", "POST"), ("CONTENT_TYPE", "application/octet-stream")], &raw)
        .unwrap();
    assert_eq!(binary.body, [&b"nofile||3|"[..], &raw].concat(), "a binary body as it came");
    let form = b"--B\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nana\r\n--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a;b|c.txt\"\r\nContent-Type: text/plain\r\n\r\n12\x0045\r\n--B--\r\n";
    let multipart = site
        .run("echo.lua", &[("REQUEST_METHOD", "POST"), ("CONTENT_TYPE", "multipart/form-data; boundary=B")], form)
        .unwrap();
    assert_eq!(
        multipart.body, b"doc|a;b|c.txt|5|text/plain|12\x0045|ana|0|",
        "the files in memory, the body not twice"
    );
    let urlencoded = site
        .run("echo.lua", &[("CONTENT_TYPE", "Application/X-WWW-Form-Urlencoded; charset=utf-8")], b"name=a+b%21&name=c")
        .unwrap();
    assert_eq!(urlencoded.body, b"nofile|a b!|18|name=a+b%21&name=c");
}

#[test]
fn the_request() {
    let site = Site::new();
    site.script(
        "request.lua",
        r#"
        return table.concat({ METHOD, URI, QUERY, REQUEST.host, REQUEST.remote_addr, REQUEST.headers["x-forwarded-for"],
            REQUEST.cookies.a, REQUEST.vars.SCRIPT_NAME, tostring(REQUEST.vars.DX_GRANTS), REQUEST.params.q,
            turbox.urldecode("a%2Bb+c"), turbox.html_escape("<&>"), turbox.json_escape('"\n'),
            turbox.parse_query("x=1&x=2").x, type(turbox.now_ms()) }, "|")"#,
    );
    let response = site
        .run(
            "request.lua",
            &[
                ("REQUEST_URI", "/request.lua?q=1"),
                ("QUERY_STRING", "q=%C3%A9"),
                ("HTTP_X_FORWARDED_FOR", "203.0.113.9"),
                ("HTTP_COOKIE", "a=1; a=2"),
            ],
            b"",
        )
        .unwrap();
    assert_eq!(String::from_utf8(response.body).unwrap(), "GET|/request.lua?q=1|q=%C3%A9|example.test|192.0.2.1|203.0.113.9|1|/request.lua|nil|é|a+b c|&lt;&amp;&gt;|\\\"\\n|1|number");
}

#[test]
fn time_is_limited() {
    let site = Site::new();
    site.script("loop.lua", "while true do end")
        .script("caught.lua", "while true do pcall(function() while true do end end) end")
        .script(
            "handler.lua",
            "while true do xpcall(function() while true do end end, function() while true do end end) end",
        )
        .script("ok.lua", "return 'ok'");
    let mut engine = LuaEngine::new(Config::default());
    for script in ["loop.lua", "caught.lua", "handler.lua"] {
        let start = Instant::now();
        let error =
            site.run_with(&mut engine, &Capabilities::none(), script, &[("DX_TIMEOUT_MS", "300")], b"").unwrap_err();
        assert!(error.contains("time of the request is over"), "{script}: {error}");
        assert!(start.elapsed() < Duration::from_secs(3), "{script} took {:?}", start.elapsed());
    }
    assert_eq!(
        site.run_with(&mut engine, &Capabilities::none(), "ok.lua", &[], b"").unwrap().body,
        b"ok",
        "the engine goes on"
    );
}

/// The time is limited in every thread of Lua, were a script ever able to make one: the hook is the state's.
#[test]
fn time_is_limited_in_any_thread() {
    let lua = new_state(Config::default().memory_limit).unwrap();
    limit_time(&lua, Instant::now() + Duration::from_millis(300), Config::default().hook_every).unwrap();
    let start = Instant::now();
    let error = lua.load("coroutine.wrap(function() while true do end end)()").exec().unwrap_err().to_string();
    assert!(error.contains("time of the request is over"), "{error}");
    assert!(start.elapsed() < Duration::from_secs(3), "it took {:?}", start.elapsed());
    let error = lua.load("while true do end").exec().unwrap_err().to_string();
    assert!(error.contains("time of the request is over"), "the main thread, after another: {error}");
}

/// The JIT is off: a state has no `jit` library, which is what turns it on when it is loaded (its compiled code doesn't
/// call the hook of the time, and `time_is_limited` would never end). Looked at before the sandbox, which takes the
/// global out whether the library was loaded or not.
#[test]
fn the_jit_is_off() {
    let lua = new_state(Config::default().memory_limit).unwrap();
    assert!(matches!(lua.globals().raw_get::<Value>("jit"), Ok(Value::Nil)), "a state with the jit library");
    assert!(matches!(lua.globals().raw_get::<Value>("ffi"), Ok(Value::Nil)), "a state with the ffi library");
}

#[test]
fn memory_is_limited() {
    let site = Site::new();
    site.script("table.lua", "local t = {} for i = 1, 50000000 do t[i] = i end return 'unreachable'")
        .script("string.lua", "local s = 'x' for i = 1, 40 do s = s .. s end return #s")
        .script("rep.lua", "return #string.rep('x', 1e9)")
        .script("ok.lua", "return 'ok'");
    let mut engine = LuaEngine::new(Config::default());
    for script in ["table.lua", "string.lua", "rep.lua"] {
        let error =
            site.run_with(&mut engine, &Capabilities::none(), script, &[("DX_TIMEOUT_MS", "20000")], b"").unwrap_err();
        assert!(error.to_lowercase().contains("memory"), "{script}: {error}");
    }
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "ok.lua", &[], b"").unwrap().body, b"ok");
}

#[test]
fn scripts_are_limited_and_kept() {
    let site = Site::new();
    site.script("large.lua", &format!("return '{}'", "x".repeat(64 << 10)));
    assert!(site.run("large.lua", &[], b"").unwrap_err().contains("larger than"));
    let mut engine = LuaEngine::new(Config::default());
    site.script("changes.lua", "return 'one'");
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "changes.lua", &[], b"").unwrap().body, b"one");
    site.script("changes.lua", "return 'two!'"); // Another size: seen even within the same second
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "changes.lua", &[], b"").unwrap().body, b"two!");
}

/// A capability for the tests.
struct Probe;

impl Capability for Probe {
    fn name(&self) -> &'static str {
        "probe"
    }
    fn functions(&self) -> &'static [&'static str] {
        &["echo", "fail"]
    }
    fn call(&mut self, function: usize, _: &Call, args: &[DxValue]) -> Result<DxValue, CapError> {
        match function {
            0 => Ok(DxValue::List(args.to_vec())),
            _ => Err(CapError::Failed("it failed".into())),
        }
    }
}

#[test]
fn capabilities_only_when_granted() {
    let site = Site::new();
    site.script("probe.lua", r#"
        if not turbox.probe then return "none" end
        local r = turbox.probe.echo(1, "a", { 1, 2, { x = true } })
        local ok, e = pcall(turbox.probe.fail)
        return table.concat({ r[1], r[2], r[3][2], tostring(r[3][3].x), tostring(ok), tostring(e):match("it failed") or e }, "|")"#)
        .script("cycle.lua", "local t = {} t.t = t return turbox.probe.echo(t)")
        .script("copies.lua", "local s, t = string.rep('x', 1e6), {} for i = 1, 100 do t[i] = s end return turbox.probe.echo(t)");
    let capabilities = Capabilities::none().with(Probe);
    let mut engine = LuaEngine::new(Config::default());
    let mut run =
        |script: &str, grants: &str| site.run_with(&mut engine, &capabilities, script, &[("DX_GRANTS", grants)], b"");
    assert_eq!(run("probe.lua", "").unwrap().body, b"none", "denied by default");
    assert_eq!(run("probe.lua", "other").unwrap().body, b"none");
    assert_eq!(run("probe.lua", "probe").unwrap().body, b"1|a|2|true|false|it failed");
    assert!(run("cycle.lua", "probe").unwrap_err().contains("too large or too deep"));
    assert!(run("copies.lua", "probe").unwrap_err().contains("texts too large"), "100 copies of 1 MB");
}

#[test]
fn a_client_cant_grant() {
    let site = Site::new();
    site.script("probe.lua", "return tostring(turbox.probe)");
    let capabilities = Capabilities::none().with(Probe);
    let mut engine = LuaEngine::new(Config::default());
    // What a client sends arrives as HTTP_*: a header "DX-Grants" isn't DX_GRANTS.
    let response = site.run_with(&mut engine, &capabilities, "probe.lua", &[("HTTP_DX_GRANTS", "probe")], b"").unwrap();
    assert_eq!(response.body, b"nil");
}

/// The scripts of examples/www run as their comments say.
#[test]
fn the_examples() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/www");
    let site = Site::new();
    for entry in std::fs::read_dir(&examples).unwrap() {
        let path = entry.unwrap().path();
        std::fs::copy(&path, site.www().join(path.file_name().unwrap())).unwrap();
    }
    let hello = site.run("hello.lua", &[("QUERY_STRING", "name=%3Ci%3E")], b"").unwrap();
    assert!(String::from_utf8_lossy(&hello.body).contains("Hello, &lt;i&gt;"), "{hello:?}");
    let echo = site.run("echo.lua", &[("QUERY_STRING", "a=1")], b"").unwrap();
    assert!(
        echo.body.starts_with(b"{\"method\":\"GET\"")
            && String::from_utf8_lossy(&echo.body).contains("\"params\":{\"a\":\"1\"}")
    );
    assert_eq!(site.run("status.lua", &[], b"").unwrap(), Response::empty(404));
    assert_eq!(site.run("status.lua", &[("QUERY_STRING", "found=yes")], b"").unwrap().body, b"found");
    assert!(site
        .run("timeout.lua", &[("DX_TIMEOUT_MS", "200")], b"")
        .unwrap_err()
        .contains("time of the request is over"));
    let form = b"--B\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nT\r\n--B\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"f.txt\"\r\n\r\nabc\r\n--B--\r\n";
    let upload = site
        .run("upload.lua", &[("REQUEST_METHOD", "POST"), ("CONTENT_TYPE", "multipart/form-data; boundary=B")], form)
        .unwrap();
    let upload = String::from_utf8_lossy(&upload.body).into_owned();
    assert!(upload.contains("Title: T") && upload.contains("f.txt") && upload.contains("3 bytes"), "{upload}");
}

/// A body larger than max_body is read, dropped and answered 413, without being kept: a worker kept every body up to
/// 64 MiB, and dx-lua copied it again, beyond the memory of its states (v2.5 review X-2).
#[test]
fn a_body_larger_than_the_limit_is_413() {
    let site = Site::new();
    site.script("ok.lua", "return 'ok'");
    let engine = LuaEngine::new(Config { max_body: 1000, ..Config::default() });
    let limits = engine.limits();
    let mut input = Vec::new();
    let mut pairs = site.pairs("ok.lua", &[("CONTENT_LENGTH", "1001")]);
    write_request(&mut input, 1, &pairs, &[b'x'; 1001]).unwrap();
    pairs = site.pairs("ok.lua", &[("CONTENT_LENGTH", "1000")]);
    write_request(&mut input, 2, &pairs, &[b'x'; 1000]).unwrap();
    let mut output = Vec::new();
    assert_eq!(dx_core::serve(engine, Capabilities::none(), input.as_slice(), &mut output, &limits), 0);
    let mut answers = &output[dx_core::GREETING.len()..];
    assert_eq!(read_response(&mut answers).unwrap().1.status, 413);
    assert_eq!(read_response(&mut answers).unwrap().1.body, b"ok");
}

/// An escaped text counts in the memory of the state before it is made: it was made outside it, up to six times its
/// length, as often as a script called it inside a pcall (v2.5 review X-6).
#[test]
fn escapes_count_in_the_memory() {
    let site = Site::new();
    site.script(
        "escape.lua",
        r#"local quotes, lts = string.rep('"', 3 * 1024 * 1024), string.rep('<', 3 * 1024 * 1024)
        local ok1, e1 = pcall(turbox.html_escape, quotes) -- 6 times: 18 MiB, in a state of 16
        local ok2, e2 = pcall(turbox.json_escape, lts) -- 6 times too
        return tostring(ok1) .. "|" .. tostring(e1) .. "|" .. tostring(ok2) .. "|" .. tostring(e2) .. "|" .. #turbox.html_escape('"')"#,
    );
    LARGEST.with(|largest| largest.set(0));
    let body = site.body("escape.lua");
    let largest = LARGEST.with(|largest| largest.get());
    assert!(largest < 8 << 20, "a block of {largest} bytes for texts of 3 MiB: the escaped text was made");
    assert!(
        body.starts_with("false|") && body.contains("|false|") && body.contains("memory") && body.ends_with("|6"),
        "{body}"
    );
}

/// A line of print names its site and the path of its script in the site: two scripts named the same, of two sites,
/// couldn't be told apart (v2.5 review X-13).
#[test]
fn print_names_the_site_and_the_path() {
    let site = Site::new();
    std::fs::create_dir_all(site.www().join("blog")).unwrap();
    site.script("blog/index.lua", "print('hello') return 'ok'");
    let mut engine = LuaEngine::new(Config { print_line: keep_line, ..Config::default() });
    PRINTED.with(|lines| lines.borrow_mut().clear());
    let extra = [("SERVER_NAME", "site.example")];
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "blog/index.lua", &extra, b"").unwrap().body, b"ok");
    assert_eq!(
        PRINTED.with(|lines| lines.borrow().clone()),
        vec!["[dx-lua] site.example/blog/index.lua: hello".to_string()]
    );
}

/// The cache of scripts lets go of the one used least recently when it is full: emptied whole, a site with more scripts
/// than the cache read them all again on every request (v2.5 review X-14).
#[test]
fn the_cache_keeps_the_scripts_used_recently() {
    let site = Site::new();
    site.script("a.lua", "return 'a'").script("b.lua", "return 'b'").script("c.lua", "return 'c'");
    let mut engine = LuaEngine::new(Config { cache_entries: 2, ..Config::default() });
    for script in ["a.lua", "b.lua", "a.lua", "c.lua"] {
        site.run_with(&mut engine, &Capabilities::none(), script, &[], b"").unwrap();
    }
    let kept = |name: &str| engine.cache.contains_key(&std::fs::canonicalize(site.www().join(name)).unwrap());
    assert!(
        kept("a.lua") && !kept("b.lua") && kept("c.lua"),
        "a {}, b {}, c {}",
        kept("a.lua"),
        kept("b.lua"),
        kept("c.lua")
    );
}

/// On Unix, a script replaced by another file of the same size and date (written apart and renamed, keeping the date,
/// as some deployments do) is read again: its inode changed (v2.5 review X-14).
#[cfg(unix)]
#[test]
fn a_script_replaced_by_another_file_is_read_again() {
    let site = Site::new();
    site.script("same.lua", "return 'one'");
    let mut engine = LuaEngine::new(Config::default());
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "same.lua", &[], b"").unwrap().body, b"one");
    let path = site.www().join("same.lua");
    let date = std::fs::metadata(&path).unwrap().modified().unwrap();
    let other = site.www().join("other.tmp");
    std::fs::write(&other, "return 'two'").unwrap();
    std::fs::File::options().write(true).open(&other).unwrap().set_modified(date).unwrap();
    std::fs::rename(&other, &path).unwrap();
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "same.lua", &[], b"").unwrap().body, b"two");
}

/// A number in the answer, and in what print writes, is written as Lua writes it (tostring): one with decimals was
/// refused as "not a text or a number", and print wrote 1e300 with its 301 digits (review of v2.5.0, DX-4).
#[test]
fn numbers_are_written_as_lua_writes_them() {
    let site = Site::new();
    site.script("header.lua", r#"return { headers = { ["X-Ratio"] = 1.5, ["X-List"] = { 2, 0.25 } }, body = "ok" }"#)
        .script("number.lua", "return { body = tonumber(REQUEST.params.n) }")
        .script("nan.lua", "return { body = 0/0 }")
        .script("inf.lua", "return { body = { 1/0, -1/0 } }")
        .script("print.lua", "print(1e300, 2^53, 1/3, 42, -0.5, 1/0, true, nil) print(0/0) return 'printed'");
    let response = site.run("header.lua", &[], b"").unwrap();
    assert_eq!(header(&response, "X-Ratio"), vec![&b"1.5"[..]]);
    assert_eq!(header(&response, "X-List"), vec![&b"2"[..], &b"0.25"[..]]);
    let body = |n: &str| {
        let response = site.run("number.lua", &[("QUERY_STRING", &format!("n={n}"))], b"").unwrap();
        String::from_utf8(response.body).unwrap()
    };
    for (n, text) in [
        ("2.5", "2.5"),
        ("12", "12"),
        ("-7", "-7"),
        ("1e300", "1e+300"),
        ("9007199254740992", "9.007199254741e+15"), // 2^53
        ("100000000000000", "1e+14"),
        ("99999999999999", "99999999999999"),
        ("0.1", "0.1"),
        ("1e-7", "1e-07"),
    ] {
        assert_eq!(body(n), text, "{n}");
    }
    let nan = site.body("nan.lua");
    assert!(nan == "nan" || nan == "-nan", "{nan}");
    assert!(site.run("inf.lua", &[], b"").unwrap_err().contains("isn't a text or a number"), "a table isn't a number");
    let mut engine = LuaEngine::new(Config { print_line: keep_line, ..Config::default() });
    PRINTED.with(|lines| lines.borrow_mut().clear());
    assert_eq!(site.run_with(&mut engine, &Capabilities::none(), "print.lua", &[], b"").unwrap().body, b"printed");
    let lines = PRINTED.with(|lines| lines.borrow().clone());
    let start = "[dx-lua] example.test/print.lua: ";
    assert_eq!(lines[0], format!("{start}1e+300	9.007199254741e+15	0.33333333333333	42	-0.5	inf	true	nil"));
    assert!(lines[1] == format!("{start}nan") || lines[1] == format!("{start}-nan"), "{}", lines[1]);
}

/// A capability for the tests that panics.
struct Panics;

impl Capability for Panics {
    fn name(&self) -> &'static str {
        "panics"
    }
    fn functions(&self) -> &'static [&'static str] {
        &["now"]
    }
    fn call(&mut self, _: usize, _: &Call, args: &[DxValue]) -> Result<DxValue, CapError> {
        Ok(args[3].clone()) // Out of range: a panic
    }
}

/// A panic of Rust inside what a script calls isn't an error that the script catches: it reaches Rust, where it ends
/// the worker. pcall caught it, and the script went on with the text of the panic (review of v2.5.0, DX-2).
#[test]
fn a_panic_isnt_caught_by_a_script() {
    let site = Site::new();
    site.script(
        "panic.lua",
        r#"local ok, e = pcall(turbox.panics.now)
        local ok2, e2 = xpcall(turbox.panics.now, function(e) return e end)
        return "caught: " .. tostring(e) .. tostring(e2)"#,
    );
    let capabilities = Capabilities::none().with(Panics);
    for timeout in ["0", "30000"] {
        // With a time, pcall and xpcall are the wrapped ones (PRELUDE)
        let extra = [("DX_GRANTS", "panics"), ("DX_TIMEOUT_MS", timeout)];
        let run = std::panic::AssertUnwindSafe(|| {
            site.run_with(&mut LuaEngine::new(Config::default()), &capabilities, "panic.lua", &extra, b"")
        });
        let panic = std::panic::catch_unwind(run).expect_err("the script went on after a panic");
        let text = panic.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(text.contains("index out of bounds"), "{text}");
    }
}

/// A pipe with the name of a script isn't a file: answered 404 at once. Opened as a file is, the worker waited for
/// someone to write to it (review of v2.5.0, DX-5).
#[cfg(unix)]
#[test]
fn a_pipe_isnt_opened_as_a_script() {
    let site = Site::new();
    let made = std::process::Command::new("mkfifo").arg(site.www().join("pipe.lua")).status();
    if !made.map(|status| status.success()).unwrap_or(false) {
        return; // Without mkfifo, or where the folder of the tests can't have a pipe
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let pairs = site.pairs("pipe.lua", &[]);
    std::thread::spawn(move || {
        let request = Request::new(pairs, Vec::new());
        let mut response = Response::new();
        let result = LuaEngine::new(Config::default()).handle(&request, &Granted::none(&request), &mut response);
        let _ = sender.send(result.map(|_| response));
    });
    let answer = receiver.recv_timeout(Duration::from_secs(10)).expect("the worker waits for the pipe");
    assert_eq!(answer.unwrap(), Response::empty(404));
}
