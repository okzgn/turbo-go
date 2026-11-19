//! dx-lua: a worker of Turbo's preprocessor mode dx that runs Lua scripts (LuaJIT) in a sandbox.
//!
//! Turbo starts it (`dx>` followed by the path of this program, in a site's preprocessors) and gives it each request of
//! the extensions it handles. See the guide (`dx-lua/README.md`) for the API of the scripts.

mod engine;

/// The stack reserved for the thread that runs the scripts. Measured with string.gsub nested until LuaJIT's limit, the
/// path that takes the most of it (a buffer of BUFSIZ in each call): 16 MiB are enough on Windows, and on Linux 96 MiB
/// are and 64 MiB aren't.
const STACK: usize = 128 << 20;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!(
            "dx-lua {} (commit {}, protocol DX 3, {})",
            env!("CARGO_PKG_VERSION"),
            env!("DX_LUA_COMMIT"),
            engine::lua_version()
        );
        return;
    }
    if std::env::args().len() > 1 {
        dx_core::util::log_line("dx-lua is started by Turbo, without arguments: \"dx>\" and the path of this program, in the preprocessors of a site");
        std::process::exit(2);
    }
    // The loop runs in a thread of its own, for its stack: LuaJIT doesn't limit the calls of C that a script nests
    // (string.gsub with a function, table.sort with a comparator, string.format with a __tostring), and with the stack
    // of the main thread (1 MiB on Windows, 8 MiB on Linux) a script that recursed through them ended the worker,
    // pcall or not. With this one, LuaJIT's own limit of its stack comes first: a "stack overflow" that is an error as
    // any other, and the worker goes on. The stack is only reserved: what a script doesn't reach is never memory.
    let worker = std::thread::Builder::new().name("worker".into()).stack_size(STACK).spawn(|| {
        let config = engine::Config::default();
        // A worker whose states can't be limited doesn't start: Turbo logs that it doesn't, and doesn't start another
        // for a while, instead of one that would run every script without a limit.
        if let Err(e) = engine::new_state(config.memory_limit) {
            dx_core::util::log_line(&format!("[dx-lua] {e}: it doesn't start"));
            std::process::exit(2);
        }
        // Made here: an engine doesn't go from a thread to another (its scripts are kept in Rc).
        let engine = engine::LuaEngine::new(config);
        let limits = engine.limits();
        dx_core::run_with(engine, dx_core::Capabilities::none(), limits)
    });
    match worker {
        // The loop ends the process by itself: the thread comes back only with a panic, and Turbo replaces the worker.
        Ok(worker) => {
            let _ = worker.join();
            std::process::exit(1)
        }
        Err(e) => {
            dx_core::util::log_line(&format!("[dx-lua] the thread of the worker: {e}: it doesn't start"));
            std::process::exit(2)
        }
    }
}
