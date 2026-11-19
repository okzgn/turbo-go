//! dx-lua: a worker of Turbo's preprocessor mode dx that runs Lua scripts (LuaJIT) in a sandbox.
//!
//! Turbo starts it (`dx>` followed by the path of this program, in a site's preprocessors) and gives it each request of
//! the extensions it handles. See the guide (`dx-lua/README.md`) for the API of the scripts.

mod engine;

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
    let config = engine::Config::default();
    // A worker whose states can't be limited doesn't start: Turbo logs that it doesn't, and doesn't start another for
    // a while, instead of one that would run every script without a limit.
    if let Err(e) = engine::new_state(config.memory_limit) {
        dx_core::util::log_line(&format!("[dx-lua] {e}: it doesn't start"));
        std::process::exit(2);
    }
    let engine = engine::LuaEngine::new(config);
    let limits = engine.limits();
    dx_core::run_with(engine, dx_core::Capabilities::none(), limits)
}
