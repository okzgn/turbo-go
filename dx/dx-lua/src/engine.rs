//! The engine: a new Lua state for each request, with nothing but the language, the request and the capabilities that
//! Turbo granted to it.

use dx_core::util;
use dx_core::{Engine, Granted, Request, Response, Value as DxValue, MAX_HEAD};
use mlua::chunk::ChunkMode;
use mlua::{HookTriggers, Lua, LuaOptions, LuaString, MultiValue, StdLib, Table, Value, VmState};
use std::cell::Cell;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// The globals a script keeps of those of the libraries loaded; `print` is replaced, and `pcall` and `xpcall` are
/// wrapped (see PRELUDE). Nothing reads a file, the network or the system: no `io`, `os`, `require`, `load`,
/// `loadstring`, `dofile`, `loadfile`, `debug`, `ffi`, `jit`, `package`, `coroutine`, `module`, `newproxy`,
/// `gcinfo`, `setfenv` or `getfenv`.
const ALLOWED_GLOBALS: &[&str] = &[
    "assert",
    "collectgarbage",
    "error",
    "getmetatable",
    "ipairs",
    "next",
    "pairs",
    "pcall",
    "rawequal",
    "rawget",
    "rawset",
    "select",
    "setmetatable",
    "tonumber",
    "tostring",
    "type",
    "unpack",
    "xpcall",
    "_G",
    "_VERSION",
    "table",
    "string",
    "math",
    "bit",
];

/// What runs before each script. When the time of the request is over (`over`, nil without a time), an error caught by
/// `pcall` or `xpcall` is raised again: a script can't catch its own end. The handler of `xpcall` isn't called then:
/// LuaJIT would run it without the hook, since the error comes from the hook, and a handler that doesn't end would hold
/// the worker. And `table.insert` with a position that isn't an integer of 1 to `#t + 1` is an error, as in Lua 5.3:
/// LuaJIT moves the elements up to it in a loop of C, which the hook doesn't stop, and a position of 2^31 (or -2^31)
/// held the worker some 18 s past the time of its request. The originals are kept as upvalues, where no script reaches.
const PRELUDE: &str = r##"
local over, raw_pcall, raw_xpcall, error = ...
if over then
  local function rethrow(ok, ...)
    if not ok and over() then error("the time of the request is over", 0) end
    return ok, ...
  end
  pcall = function(f, ...) return rethrow(raw_pcall(f, ...)) end
  xpcall = function(f, handler, ...)
    local function guarded(...)
      if over() then return "the time of the request is over" end
      return handler(...)
    end
    return rethrow(raw_xpcall(f, guarded, ...))
  end
end
local insert, select, type, tonumber, floor = table.insert, select, type, tonumber, math.floor
table.insert = function(t, ...)
  if select("#", ...) == 2 and type(t) == "table" then
    local position = tonumber((...))
    if position and (position ~= floor(position) or position < 1 or position > #t + 1) then
      error("bad argument #2 to 'insert' (position out of bounds)", 2)
    end
  end
  return insert(t, ...)
end
"##;

/// The limits of a script: the worker's own, which Turbo doesn't set.
pub struct Config {
    /// Bytes of memory of a Lua state.
    pub memory_limit: usize,
    /// Bytes of a request's body: a larger one is read, dropped and answered 413 without being kept (dx_core::run_with).
    /// A script gets the body as a text, and its parts once more: half the memory of a state.
    pub max_body: u64,
    /// Bytes of a script.
    pub max_script: u64,
    /// Instructions between two looks at the time.
    pub hook_every: u32,
    /// Bytes that `print` writes in a request, each line with its start and its end.
    pub max_print: usize,
    /// Where `print` writes each line: the standard error.
    pub print_line: fn(&str),
    /// Scripts kept in memory (by their path, size and date).
    pub cache_entries: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            memory_limit: 16 << 20,
            max_body: 8 << 20,
            max_script: 64 << 10,
            hook_every: 1000,
            max_print: 64 << 10,
            print_line: util::log_line,
            cache_entries: 256,
        }
    }
}

/// A script kept in memory, with what tells whether its file is still the same: its date and size and, on Unix, its
/// inode (another file put in its place, of the same size and within the precision of the date, was taken for it).
struct Cached {
    modified: SystemTime,
    len: u64,
    identity: u64,
    code: Rc<[u8]>,
    used: u64, // When it was last used, by the count of uses of the cache: the least used recently goes first
}

/// The identity of a file: its inode on Unix, where a file put in another's place (written apart and renamed, as most
/// deployments do) has another. Elsewhere 0: on Windows std doesn't give the index of a file, and a file put in another's
/// place keeps its date of creation (tunneling); the date of its last change, to 100 ns, and its size tell it there.
fn file_identity(meta: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// Opens what may be a script without waiting, whatever it is: the caller looks at what was opened, by its handle, and
/// reads it only if it is a file. Looked at by its name first and opened afterwards, a pipe put in the place of the
/// script between the two held the worker until a writer came: a pipe is opened for reading at once only without
/// blocking, and a file is read the same either way.
#[cfg(unix)]
fn open_script(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK, which std doesn't name, as the system has it (libc): it was written by hand for each system
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)
}

/// On Windows no open of what is inside the folder of a site waits (a named pipe isn't a file of a folder); a folder is
/// opened as one (FILE_FLAG_BACKUP_SEMANTICS), so that its handle tells what it is, as on Unix.
#[cfg(windows)]
fn open_script(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_script(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

pub struct LuaEngine {
    config: Config,
    cache: HashMap<PathBuf, Cached>,
    uses: u64,
}

impl LuaEngine {
    pub fn new(config: Config) -> LuaEngine {
        LuaEngine { config, cache: HashMap::new(), uses: 0 }
    }

    /// The limits of a request for dx_core::run_with: a body up to max_body.
    pub fn limits(&self) -> dx_core::Limits {
        dx_core::Limits { body: self.config.max_body, ..dx_core::Limits::default() }
    }

    /// The script of a request, if it is a file inside the folder of the site: `SCRIPT_FILENAME` inside
    /// `DOCUMENT_ROOT`, once both are resolved (a link that leads out of the site isn't followed); and how the log names
    /// it: the site (`SERVER_NAME`) and its path in the site, as two sites may have scripts of the same name.
    fn script(&self, request: &Request) -> Result<Option<(PathBuf, String)>, String> {
        let pair = |name: &str| {
            let value = request.get(name).ok_or_else(|| format!("a request without {name}"))?;
            std::str::from_utf8(value).map(PathBuf::from).map_err(|_| format!("{name} isn't UTF-8"))
        };
        let (script, root) = (pair("SCRIPT_FILENAME")?, pair("DOCUMENT_ROOT")?);
        let root = std::fs::canonicalize(&root).map_err(|e| format!("DOCUMENT_ROOT {}: {e}", root.display()))?;
        let resolved = match std::fs::canonicalize(&script) {
            Ok(resolved) => resolved,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", script.display())),
        };
        let Ok(inside) = resolved.strip_prefix(&root) else {
            let script = util::escape_line(script.to_string_lossy().as_bytes());
            util::log_line(&format!("[dx-lua] {script}: outside the folder of the site, answered 404"));
            return Ok(None);
        };
        let site = request.get("SERVER_NAME").or_else(|| request.get("HTTP_HOST")).unwrap_or_default();
        let name = format!("{}/{}", String::from_utf8_lossy(site), inside.to_string_lossy().replace('\\', "/"));
        Ok(Some((resolved, name)))
    }

    /// The code of a script, from the cache while its size and date don't change. `None` if it isn't a file. What is
    /// read is what was opened, which its handle tells to be a file (see `open_script`), and at most a byte more than a
    /// script may have: a file that grows, or another one put in its place, can't make the worker read more.
    fn load(&mut self, path: &Path) -> Result<Option<Rc<[u8]>>, String> {
        let not_found = |e: std::io::Error| match e.kind() {
            std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(e.to_string()),
        };
        let file = match open_script(path) {
            Ok(file) => file,
            Err(e) => return not_found(e),
        };
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Ok(None); // A folder, a pipe, a device
        }
        let too_large = || format!("a script larger than {} bytes", self.config.max_script);
        if meta.len() > self.config.max_script {
            return Err(too_large());
        }
        let modified = meta.modified().unwrap_or(UNIX_EPOCH);
        let identity = file_identity(&meta);
        self.uses += 1;
        if let Some(cached) = self.cache.get_mut(path) {
            if cached.modified == modified && cached.len == meta.len() && cached.identity == identity {
                cached.used = self.uses;
                return Ok(Some(cached.code.clone()));
            }
        }
        let mut code = Vec::new();
        file.take(self.config.max_script + 1).read_to_end(&mut code).map_err(|e| e.to_string())?;
        if code.len() as u64 > self.config.max_script {
            return Err(too_large());
        }
        let code: Rc<[u8]> = code.into();
        if self.cache.len() >= self.config.cache_entries && !self.cache.contains_key(path) {
            // The one used least recently goes: emptied whole, a site with more scripts than the cache read them all
            // again on every request.
            if let Some(oldest) = self.cache.iter().min_by_key(|(_, cached)| cached.used).map(|(key, _)| key.clone()) {
                self.cache.remove(&oldest);
            }
        }
        let cached = Cached { modified, len: meta.len(), identity, code: code.clone(), used: self.uses };
        self.cache.insert(path.to_path_buf(), cached);
        Ok(Some(code))
    }

    fn run(
        &mut self,
        code: &[u8],
        path: &Path,
        log_name: &str,
        request: &Request,
        granted: &Granted,
    ) -> Result<Response, String> {
        let lua = new_state(self.config.memory_limit)?;
        let deadline = request.deadline();
        if let Some(deadline) = deadline {
            // A hook that can't be set would leave the script without its time: the request answers 500 instead.
            limit_time(&lua, deadline, self.config.hook_every).map_err(|e| format!("the hook of the time: {e}"))?;
        }
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        sandbox(&lua, deadline, log_name, self.config.max_print, self.config.print_line)
            .map_err(|e| format!("the sandbox: {e}"))?;
        // math.random gives another sequence for each request: LuaJIT seeds every new state the same way, and every
        // visitor of every site got the same numbers. The id of the request is random (Turbo's): its 53 high bits, as a
        // number of Lua. It isn't a secure source still: never for tokens or passwords.
        let math: Table = lua.globals().raw_get("math").map_err(|e| format!("the sandbox: {e}"))?;
        math.raw_get::<mlua::Function>("randomseed")
            .and_then(|seed| seed.call::<()>((request.id() >> 11) as f64))
            .map_err(|e| format!("the sandbox: {e}"))?;
        let turbox =
            request_globals(&lua, request, self.config.memory_limit).map_err(|e| format!("the request: {e}"))?;
        lua.scope(|scope| {
            for (capability, functions) in granted.list() {
                if turbox.raw_get::<Value>(capability)? != Value::Nil {
                    return Err(mlua::Error::RuntimeError(format!(
                        "a capability named as a function of turbox: {capability}"
                    )));
                }
                let table = lua.create_table()?;
                for &function in functions {
                    let call = scope.create_function(move |lua, args: MultiValue| {
                        let mut budget = Budget { values: MAX_VALUES, bytes: MAX_BYTES };
                        let args = args.iter().map(|v| from_lua(v, 0, &mut budget)).collect::<Result<Vec<_>, _>>();
                        let args =
                            args.map_err(|e| mlua::Error::RuntimeError(format!("{capability}.{function}: {e}")))?;
                        match granted.call(capability, function, &args) {
                            Ok(value) => to_lua(lua, &value, 0),
                            Err(e) => Err(mlua::Error::RuntimeError(format!("{capability}.{function}: {e}"))),
                        }
                    })?;
                    table.raw_set(function, call)?;
                }
                turbox.raw_set(capability, table)?;
            }
            // call, not eval: eval tries the script as an expression first, and a script that ends in a call
            // would lose its line in the errors (a tail call).
            let value: Value = lua.load(code).set_name(format!("@{name}")).set_mode(ChunkMode::Text).call(())?;
            Ok(to_response(&lua, value))
        })
        .map_err(|e| e.to_string())?
    }
}

impl Engine for LuaEngine {
    fn handle(&mut self, request: &Request, granted: &Granted, response: &mut Response) -> Result<(), String> {
        let Some((path, log_name)) = self.script(request)? else {
            *response = Response::empty(404);
            return Ok(());
        };
        let Some(code) = self.load(&path)? else {
            *response = Response::empty(404);
            return Ok(());
        };
        *response = self.run(&code, &path, &log_name, request, granted)?;
        Ok(())
    }
}

/// A Lua state for a request: the language only, without the JIT, with its memory limited to `memory_limit`. The JIT
/// stays off: only `jit_init`, which `StdLib::JIT` runs, turns it on, and the code it compiles doesn't call the hook that
/// ends a script when its time is over (`while true do end` would never end). A state whose memory can't be limited
/// (mlua falls back to a state without its allocator) runs nothing: the request answers 500.
///
/// A panic of Rust inside what a script calls isn't an error of Lua (`catch_rust_panics` off): `pcall` and `xpcall`
/// don't catch it, so it ends the worker, which Turbo replaces. Caught, a script went on in a worker whose state
/// nobody knows, with the text of the panic in its hands.
pub fn new_state(memory_limit: usize) -> Result<Lua, String> {
    let options = LuaOptions::new().catch_rust_panics(false);
    let lua = Lua::new_with(StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::BIT, options)
        .map_err(|e| format!("a Lua state: {e}"))?;
    lua.set_memory_limit(memory_limit).map_err(|e| format!("a Lua state without a memory limit: {e}"))?;
    Ok(lua)
}

/// Ends what `lua` runs once `deadline` has passed, looked at every `every` instructions. The hook is the state's (a
/// global hook), whatever thread of Lua runs: one set for the main thread alone (`set_hook`) is taken off by mlua the
/// first time it fires in another thread, and in LuaJIT, whose hook is one for the whole state, that takes it off for
/// all of them. No script can make a thread today (`coroutine` isn't among the globals allowed), and the limit doesn't
/// depend on that.
pub(crate) fn limit_time(lua: &Lua, deadline: Instant, every: u32) -> mlua::Result<()> {
    let triggers = HookTriggers { every_nth_instruction: Some(every), ..Default::default() };
    lua.set_global_hook(triggers, move |_, _| {
        if Instant::now() >= deadline {
            Err(mlua::Error::RuntimeError("the time of the request is over".into()))
        } else {
            Ok(VmState::Continue)
        }
    })
}

/// The version of Lua, for `--version`.
pub fn lua_version() -> String {
    let lua = Lua::new();
    lua.load("return jit and jit.version or _VERSION").eval::<String>().unwrap_or_else(|_| "Lua".into())
}

/// Takes out every global but the allowed ones, replaces `print` and wraps `pcall`, `xpcall` and `table.insert`
/// (PRELUDE).
fn sandbox(lua: &Lua, deadline: Option<Instant>, name: &str, max_print: usize, write: fn(&str)) -> mlua::Result<()> {
    let globals = lua.globals();
    let mut remove = Vec::new();
    for pair in globals.clone().pairs::<Value, Value>() {
        let (key, _) = pair?;
        let keep =
            matches!(&key, Value::String(s) if s.to_str().map(|s| ALLOWED_GLOBALS.contains(&&*s)).unwrap_or(false));
        if !keep {
            remove.push(key);
        }
    }
    for key in remove {
        globals.raw_set(key, Value::Nil)?;
    }
    // print: to the standard error, one line each, with what could pass for another line of the log escaped (the name of
    // the script too, which may have a line break). Each line counts with its start and its end: empty ones too.
    let printed = Rc::new(Cell::new(0usize));
    let prefix = format!("[dx-lua] {}: ", util::escape_line(name.as_bytes()));
    let print = lua.create_function(move |lua, args: MultiValue| {
        if printed.get() > max_print {
            return Ok(()); // Over the limit already: nothing is joined nor escaped
        }
        let (room, needed) = (max_print - printed.get(), prefix.len() + 1); // A line takes its start and its end
        let left = room.saturating_sub(needed);
        let (line, total) = print_line(lua, &args, left)?;
        if needed + total <= room {
            write(&format!("{prefix}{}", util::escape_line(&line)));
            printed.set(printed.get() + needed + total);
        } else {
            write(&format!("{prefix}{}", util::log_start(&line, total, left)));
            write(&format!("{prefix}more than {max_print} bytes printed in a request: the rest is dropped"));
            printed.set(max_print + 1);
        }
        Ok(())
    })?;
    globals.raw_set("print", print)?;
    // The PRELUDE: pcall and xpcall wrapped only with a time, table.insert always
    let over = match deadline {
        Some(deadline) => Value::Function(lua.create_function(move |_, ()| Ok(Instant::now() >= deadline))?),
        None => Value::Nil,
    };
    let pcall: Value = globals.raw_get("pcall")?;
    let xpcall: Value = globals.raw_get("xpcall")?;
    let error: Value = globals.raw_get("error")?;
    lua.load(PRELUDE).set_name("=dx-lua").set_mode(ChunkMode::Text).call::<()>((over, pcall, xpcall, error))?;
    Ok(())
}

/// The line that `print` writes of its arguments, joined with tabs, and its length: of the line, only what can be written
/// (`left` bytes, and one more to tell that there is more). A script can pass a large text many times in a call, and
/// each copy of it would be the worker's memory, which the limit of the state doesn't count.
fn print_line(lua: &Lua, args: &MultiValue, left: usize) -> mlua::Result<(Vec<u8>, usize)> {
    let (mut line, mut total) = (Vec::new(), 0usize);
    let mut push = |piece: &[u8]| {
        total = total.saturating_add(piece.len());
        let room = (left + 1).saturating_sub(line.len());
        line.extend_from_slice(&piece[..piece.len().min(room)]);
    };
    for (i, value) in args.iter().enumerate() {
        if i > 0 {
            push(b"\t");
        }
        match value {
            Value::String(s) => push(&s.as_bytes()[..]), // Borrowed from the state: a text isn't copied whole
            other => push(&printable(lua, other)?),
        }
    }
    Ok((line, total))
}

/// What `print` writes of a value that isn't a text: a number as Lua writes it.
fn printable(lua: &Lua, value: &Value) -> mlua::Result<Vec<u8>> {
    Ok(match value {
        Value::Nil => b"nil".to_vec(),
        Value::Boolean(b) => b.to_string().into_bytes(),
        Value::Integer(_) | Value::Number(_) => number_text(lua, value)?,
        other => other.type_name().as_bytes().to_vec(),
    })
}

/// A number as Lua writes it (`tostring`, the `%.14g` of C): 1.5, 1e+300, 9.007199254741e+15 for 2^53, inf, and nan or
/// -nan as LuaJIT gives it. LuaJIT itself writes it, in a text of the state: no metamethod runs, a number has none.
fn number_text(lua: &Lua, value: &Value) -> mlua::Result<Vec<u8>> {
    let number = match *value {
        Value::Integer(i) => Value::Number(i as f64), // A double too: mlua tells apart those without decimals
        Value::Number(n) => Value::Number(n),
        _ => return Ok(Vec::new()),
    };
    Ok(lua.coerce_string(number)?.map(|text| text.as_bytes().to_vec()).unwrap_or_default())
}

/// REQUEST and its short names (METHOD, URI, QUERY, BODY), and turbox with its functions. Returns turbox, where the
/// capabilities granted go. `memory_limit` is the state's: what turbox makes outside it, as an escaped text, is checked
/// against what is left of it before it is made.
fn request_globals(lua: &Lua, request: &Request, memory_limit: usize) -> mlua::Result<Table> {
    let text = |name: &str| request.get(name).unwrap_or_default();
    let r = lua.create_table()?;
    let uri = text("REQUEST_URI");
    let path = &uri[..uri.iter().position(|&c| c == b'?').unwrap_or(uri.len())];
    r.raw_set("method", lua.create_string(text("REQUEST_METHOD"))?)?;
    r.raw_set("uri", lua.create_string(uri)?)?;
    r.raw_set("path", lua.create_string(util::path_decode(path))?)?;
    r.raw_set("query", lua.create_string(text("QUERY_STRING"))?)?;
    r.raw_set("host", lua.create_string(text("HTTP_HOST"))?)?;
    r.raw_set("remote_addr", lua.create_string(text("REMOTE_ADDR"))?)?;
    let vars = lua.create_table()?;
    for (name, value) in request.pairs() {
        vars.raw_set(lua.create_string(name)?, lua.create_string(value)?)?;
    }
    r.raw_set("vars", vars)?;
    let headers = lua.create_table()?;
    for (name, value) in request.headers() {
        headers.raw_set(name, lua.create_string(value)?)?;
    }
    r.raw_set("headers", headers)?;
    r.raw_set("params", first_wins(lua, &util::parse_query(text("QUERY_STRING")))?)?;
    r.raw_set("cookies", first_wins(lua, &util::parse_cookies(text("HTTP_COOKIE")))?)?;
    let mut body = request.body();
    let mut form = Vec::new();
    let files = lua.create_table()?;
    let content_type = text("CONTENT_TYPE");
    let kind = content_type.split(|&c| c == b';').next().unwrap_or_default().trim_ascii();
    if let Some(parts) = util::parse_multipart(content_type, body) {
        body = &[]; // In REQUEST.form and REQUEST.files, not twice
        for part in parts {
            match part.filename {
                None => form.push((part.name, part.data.to_vec())),
                Some(filename) => {
                    let file = lua.create_table()?;
                    file.raw_set("field", lua.create_string(&part.name)?)?;
                    file.raw_set("filename", lua.create_string(&filename)?)?;
                    file.raw_set("content_type", lua.create_string(&part.content_type)?)?;
                    file.raw_set("size", part.data.len())?;
                    file.raw_set("data", lua.create_string(part.data)?)?;
                    files.raw_set(files.raw_len() + 1, file)?;
                }
            }
        }
    } else if kind.eq_ignore_ascii_case(b"application/x-www-form-urlencoded") {
        form = util::parse_query(body);
    }
    r.raw_set("form", first_wins(lua, &form)?)?;
    r.raw_set("files", files)?;
    r.raw_set("body", lua.create_string(body)?)?;
    let globals = lua.globals();
    for (short, long) in [("METHOD", "method"), ("URI", "uri"), ("QUERY", "query"), ("BODY", "body")] {
        globals.raw_set(short, r.raw_get::<Value>(long)?)?;
    }
    globals.raw_set("REQUEST", r)?;
    let turbox = lua.create_table()?;
    turbox.raw_set(
        "urldecode",
        lua.create_function(|lua, s: LuaString| lua.create_string(util::url_decode(&s.as_bytes())))?,
    )?;
    turbox.raw_set(
        "parse_query",
        lua.create_function(|lua, s: LuaString| first_wins(lua, &util::parse_query(&s.as_bytes())))?,
    )?;
    // An escaped text is made in the worker's memory, which the state's limit doesn't count, before it becomes a text of
    // the state: up to six times its length, as often as a script calls it (a pcall catches the error of memory).
    let room = move |lua: &Lua, needed: usize| {
        if needed > memory_limit.saturating_sub(lua.used_memory()) {
            return Err(mlua::Error::MemoryError("not enough memory".into()));
        }
        Ok(())
    };
    turbox.raw_set(
        "html_escape",
        lua.create_function(move |lua, s: LuaString| {
            let text = s.as_bytes();
            room(lua, util::html_escaped_len(&text))?;
            lua.create_string(util::html_escape(&text))
        })?,
    )?;
    turbox.raw_set(
        "json_escape",
        lua.create_function(move |lua, s: LuaString| {
            let text = s.as_bytes();
            room(lua, util::json_escaped_len(&text))?;
            lua.create_string(util::json_escape(&text))
        })?,
    )?;
    turbox.raw_set(
        "now_ms",
        lua.create_function(|_, ()| {
            Ok(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as f64).unwrap_or(0.0))
        })?,
    )?;
    globals.raw_set("turbox", turbox.clone())?;
    Ok(turbox)
}

/// A table of pairs where the first of a name wins.
fn first_wins(lua: &Lua, pairs: &[(Vec<u8>, Vec<u8>)]) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for (name, value) in pairs {
        let key = lua.create_string(name)?;
        if table.raw_get::<Value>(key.clone())? == Value::Nil {
            table.raw_set(key, lua.create_string(value)?)?;
        }
    }
    Ok(table)
}

/// The most values, bytes of texts, and the deepest tables, that cross from a script to a capability in a call: a table
/// may hold the same large text many times, and each one is copied.
const MAX_VALUES: usize = 100_000;
const MAX_BYTES: usize = 16 << 20;
const MAX_DEPTH: usize = 32;

/// What is left of MAX_VALUES and MAX_BYTES in a call.
struct Budget {
    values: usize,
    bytes: usize,
}

fn from_lua(value: &Value, depth: usize, budget: &mut Budget) -> Result<DxValue, String> {
    if budget.values == 0 || depth > MAX_DEPTH {
        return Err("a value too large or too deep".into());
    }
    budget.values -= 1;
    if let Value::String(s) = value {
        budget.bytes = budget.bytes.checked_sub(s.as_bytes().len()).ok_or("texts too large")?;
    }
    Ok(match value {
        Value::Nil => DxValue::Nil,
        Value::Boolean(b) => DxValue::Bool(*b),
        #[allow(clippy::unnecessary_cast)] // mlua's Integer isn't i64 on every target
        Value::Integer(i) => DxValue::Int(*i as i64),
        Value::Number(n) => DxValue::Num(*n),
        Value::String(s) => DxValue::Bytes(s.as_bytes().to_vec()),
        Value::Table(table) => {
            let length = table.raw_len();
            let mut pairs = Vec::new();
            for pair in table.clone().pairs::<Value, Value>() {
                let (k, v) = pair.map_err(|e| e.to_string())?;
                pairs.push((from_lua(&k, depth + 1, budget)?, from_lua(&v, depth + 1, budget)?));
            }
            let is_list = pairs.len() == length
                && pairs.iter().all(|(k, _)| matches!(k.as_int(), Some(i) if i >= 1 && i as usize <= length));
            if is_list {
                pairs.sort_by_key(|(k, _)| k.as_int());
                DxValue::List(pairs.into_iter().map(|(_, v)| v).collect())
            } else {
                DxValue::Map(pairs)
            }
        }
        other => return Err(format!("a {} can't be passed", other.type_name())),
    })
}

fn to_lua(lua: &Lua, value: &DxValue, depth: usize) -> mlua::Result<Value> {
    if depth > MAX_DEPTH {
        return Err(mlua::Error::RuntimeError("a value too deep".into()));
    }
    Ok(match value {
        DxValue::Nil => Value::Nil,
        DxValue::Bool(b) => Value::Boolean(*b),
        DxValue::Int(i) => Value::Number(*i as f64), // LuaJIT's numbers are doubles
        DxValue::Num(n) => Value::Number(*n),
        DxValue::Bytes(b) => Value::String(lua.create_string(b)?),
        DxValue::List(items) => {
            let table = lua.create_table_with_capacity(items.len(), 0)?;
            for (i, item) in items.iter().enumerate() {
                table.raw_set(i + 1, to_lua(lua, item, depth + 1)?)?;
            }
            Value::Table(table)
        }
        DxValue::Map(pairs) => {
            let table = lua.create_table_with_capacity(0, pairs.len())?;
            for (k, v) in pairs {
                table.raw_set(to_lua(lua, k, depth + 1)?, to_lua(lua, v, depth + 1)?)?;
            }
            Value::Table(table)
        }
    })
}

/// How many bytes `lua_bytes` would give of a value, without copying it: a number's are a few.
fn lua_len(value: &Value) -> usize {
    match value {
        Value::String(s) => s.as_bytes().len(),
        _ => 24,
    }
}

/// The bytes of a text, or of a number as Lua writes it (see `number_text`); `None` of anything else.
fn lua_bytes(lua: &Lua, value: &Value) -> Result<Option<Vec<u8>>, String> {
    match value {
        Value::String(s) => Ok(Some(s.as_bytes().to_vec())),
        Value::Integer(_) | Value::Number(_) => number_text(lua, value).map(Some).map_err(|e| e.to_string()),
        _ => Ok(None),
    }
}

fn status(value: &Value) -> Option<u16> {
    let n = match *value {
        Value::Integer(i) => i as f64,
        Value::Number(n) => n,
        _ => return None,
    };
    (n.fract() == 0.0 && (200.0..=599.0).contains(&n)).then_some(n as u16)
}

/// The answer of what a script returns:
/// nil, false or "" → 204 · a text → 200, `text/html` if it starts with `<` (after spaces), else `text/plain` ·
/// a number 200-599 → that status without a body (Turbo answers 400 or more with the site's template) ·
/// a table {status, headers, body}, where a header may have a list of values; a body, or a value of a header, that is
/// a number is written as Lua writes it.
fn to_response(lua: &Lua, value: Value) -> Result<Response, String> {
    match value {
        Value::Nil | Value::Boolean(false) => Ok(Response::empty(204)),
        Value::String(s) => {
            let body = s.as_bytes();
            if body.is_empty() {
                return Ok(Response::empty(204));
            }
            let html = body.iter().find(|c| !c.is_ascii_whitespace()) == Some(&b'<');
            let content_type: &[u8] = if html { b"text/html; charset=utf-8" } else { b"text/plain; charset=utf-8" };
            Ok(Response {
                status: 200,
                headers: vec![(b"Content-Type".to_vec(), content_type.to_vec())],
                body: body.to_vec(),
            })
        }
        Value::Integer(_) | Value::Number(_) => {
            status(&value).map(Response::empty).ok_or_else(|| "a status out of 200-599 returned".to_string())
        }
        Value::Table(table) => {
            let field = |name: &str| table.raw_get::<Value>(name).map_err(|e| e.to_string());
            let status = match field("status")? {
                Value::Nil => 200,
                value => status(&value).ok_or("a status out of 200-599 returned")?,
            };
            let body = match field("body")? {
                Value::Nil => Vec::new(),
                value => lua_bytes(lua, &value)?.ok_or("a body that isn't a text or a number")?,
            };
            let mut headers = Vec::new();
            // What the headers take of the head of the answer, which Turbo takes up to MAX_HEAD: counted before each is
            // copied, so that a list with the same large text many times costs no more than that (each one was copied).
            let too_large = || format!("headers larger than {MAX_HEAD} bytes");
            let mut head = 8usize;
            let mut add = |name: &[u8], value: &Value, headers: &mut Vec<(Vec<u8>, Vec<u8>)>| -> Result<(), String> {
                head = head.saturating_add(8 + name.len() + lua_len(value));
                if head > MAX_HEAD {
                    return Err(too_large());
                }
                let value = lua_bytes(lua, value)?.ok_or("a header whose value isn't a text or a number")?;
                headers.push((name.to_vec(), value));
                Ok(())
            };
            match field("headers")? {
                Value::Nil => {}
                Value::Table(list) => {
                    for pair in list.pairs::<Value, Value>() {
                        let (name, value) = pair.map_err(|e| e.to_string())?;
                        if lua_len(&name) > MAX_HEAD {
                            return Err(too_large());
                        }
                        let name = lua_bytes(lua, &name)?.ok_or("a header without a text for its name")?;
                        if name.eq_ignore_ascii_case(b"Content-Length") {
                            // The worker's: the length of the body. One of the script that wasn't cut the answer, and
                            // the connection was closed
                            continue;
                        }
                        match value {
                            // Raw, as everything read of what a script returns: no metamethod of it runs after it ended.
                            Value::Table(values) => {
                                for i in 1..=values.raw_len() {
                                    let value = values.raw_get::<Value>(i).map_err(|e| e.to_string())?;
                                    add(&name, &value, &mut headers)?;
                                }
                            }
                            value => add(&name, &value, &mut headers)?,
                        }
                    }
                    headers.sort_by(|a, b| a.0.cmp(&b.0)); // The order of a table isn't kept: sorted, so it is the same each time
                }
                _ => return Err("headers that aren't a table".into()),
            }
            Ok(Response { status, headers, body })
        }
        other => Err(format!("a {} returned", other.type_name())),
    }
}

#[cfg(test)]
mod tests;
