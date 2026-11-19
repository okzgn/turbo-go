//! The worker as Turbo runs it: the program itself, with the protocol DX 3 by its standard input and output. What
//! depends on the process (the stack of the thread that runs the scripts) can't be seen in the tests of the engine.

use dx_core::{read_response, write_request, Response, GREETING};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

/// A worker and the folder of a site, with its scripts.
struct Worker {
    child: Child,
    input: ChildStdin,
    answers: Receiver<std::io::Result<(u64, Response)>>,
    root: PathBuf,
    id: u64,
}

impl Worker {
    fn start(scripts: &[(&str, &str)]) -> Worker {
        let root = std::env::temp_dir().join(format!("dx-lua-worker-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        for (name, code) in scripts {
            std::fs::write(root.join(name), code).unwrap();
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_dx-lua"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        // The answers are read in a thread, so that a worker that doesn't answer fails the test instead of holding it.
        let (sender, answers) = channel();
        std::thread::spawn(move || {
            let mut greeting = [0u8; 4];
            if let Err(e) = output.read_exact(&mut greeting) {
                let _ = sender.send(Err(e));
                return;
            }
            assert_eq!(greeting, GREETING);
            loop {
                let answer = read_response(&mut output);
                let ended = answer.is_err();
                if sender.send(answer).is_err() || ended {
                    return;
                }
            }
        });
        Worker { child, input, answers, root, id: 0x1234_5678_9abc_def0 }
    }

    /// The answer of the worker to a request of a script, as Turbo makes it; an error if the worker ends, or writes
    /// what isn't the answer of that request.
    fn request(&mut self, script: &str) -> Result<Response, String> {
        let root = self.root.to_string_lossy().replace('\\', "/");
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = [
            ("REQUEST_METHOD", "GET".to_string()),
            ("REQUEST_URI", format!("/{script}")),
            ("SCRIPT_NAME", format!("/{script}")),
            ("SCRIPT_FILENAME", format!("{root}/{script}")),
            ("DOCUMENT_ROOT", root),
            ("QUERY_STRING", String::new()),
            ("HTTP_HOST", "example.test".to_string()),
            ("SERVER_NAME", "example.test".to_string()),
            ("REMOTE_ADDR", "192.0.2.1".to_string()),
            ("DX_TIMEOUT_MS", "60000".to_string()),
        ]
        .into_iter()
        .map(|(name, value)| (name.as_bytes().to_vec(), value.into_bytes()))
        .collect();
        self.id += 1;
        write_request(&mut self.input, self.id, &pairs, b"").map_err(|e| format!("the request: {e}"))?;
        let answer = self.answers.recv_timeout(Duration::from_secs(120)).map_err(|e| format!("no answer: {e}"))?;
        let (id, response) = answer.map_err(|e| format!("the answer: {e}"))?;
        if id != self.id {
            return Err(format!("the answer of the request {id}, not of {}", self.id));
        }
        Ok(response)
    }

    fn body(&mut self, script: &str) -> String {
        let response = self.request(script).unwrap_or_else(|e| panic!("{script}: {e}"));
        assert_eq!(response.status, 200, "{script}");
        String::from_utf8_lossy(&response.body).into_owned()
    }

    fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A script that recurses through functions of C (string.gsub with a function, table.sort with a comparator,
/// string.format with a __tostring) gets LuaJIT's "stack overflow", an error as any other, and the worker answers the
/// next request. LuaJIT doesn't limit those calls as it limits the calls of Lua, and with the stack of the main
/// thread the process ended, pcall or not: Turbo answered 500 for a worker that "ended without a byte of an answer",
/// and lost a second worker with its retry (review of v2.5.0, DX-1).
#[test]
fn a_recursion_through_c_functions_is_an_error_and_the_worker_goes_on() {
    let mut worker = Worker::start(&[
        (
            "gsub.lua",
            r#"local depth = 0
            local function f()
              depth = depth + 1
              if depth >= 20000 then return "y" end
              return (string.gsub("x", "x", f))
            end
            local ok, e = pcall(f)
            return depth .. " " .. tostring(ok) .. " " .. tostring(e)"#,
        ),
        (
            "sort.lua",
            r#"local function cmp(a, b) table.sort({ 1, 2, 3 }, cmp) return a < b end
            local ok, e = pcall(table.sort, { 1, 2, 3 }, cmp)
            return tostring(ok) .. " " .. tostring(e)"#,
        ),
        (
            "format.lua",
            r#"local mt = {}
            mt.__tostring = function(t) return string.format("%s", t) end
            local ok, e = pcall(string.format, "%s", setmetatable({}, mt))
            return tostring(ok) .. " " .. tostring(e)"#,
        ),
        ("uncaught.lua", r#"local function f() return (string.gsub("x", "x", f)) end return f()"#),
        // As a tail call, string.gsub takes the frame of f: 5 slots of LuaJIT's stack a level instead of 8, so some
        // 13 000 levels, each with its buffer of C, the deepest of all (some 116 MiB on Linux, review of v2.5.1, RS-1).
        // With a stack of 96 or 112 MiB the worker ended here, and the variant above still passed.
        (
            "tail.lua",
            r#"local depth = 0
            local function f()
              depth = depth + 1
              if depth >= 20000 then return "y" end
              return string.gsub("x", "x", f)
            end
            local ok, e = pcall(f)
            return depth .. " " .. tostring(ok) .. " " .. tostring(e)"#,
        ),
        ("uncaught-tail.lua", r#"local g = string.gsub local f f = function() return g("x", "x", f) end return f()"#),
        ("alive.lua", r#"return "alive""#),
    ]);
    assert_eq!(worker.body("alive.lua"), "alive");
    for script in ["gsub.lua", "tail.lua", "sort.lua", "format.lua"] {
        let body = worker.body(script);
        assert!(body.contains("false") && body.contains("stack overflow"), "{script}: {body}");
        assert_eq!(worker.body("alive.lua"), "alive", "the same worker, after {script}");
    }
    for script in ["uncaught.lua", "uncaught-tail.lua"] {
        assert_eq!(worker.request(script), Ok(Response::empty(500)), "{script}: an error as any other");
        assert_eq!(worker.body("alive.lua"), "alive", "the same worker, after an error that nothing caught ({script})");
    }
    assert!(worker.running());
}
