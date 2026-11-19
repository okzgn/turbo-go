//! Gives `dx-lua --version` the commit it is built from (DX_LUA_COMMIT): a fix of the worker comes as a new build from
//! `dx/`, and the version of the crate doesn't change with every commit. "+modified" follows the commit when `dx/` isn't
//! as that commit has it, and it is "unknown" outside a checkout of Turbo, or where git can't tell.

use std::path::PathBuf;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok().filter(|output| output.status.success())?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn main() {
    // On Windows with MSVC, LuaJIT is built with the static C runtime (/MT), and so must dx-lua be: the options of
    // dx/.cargo/config.toml apply only to a build run from dx/, and RUSTFLAGS replaces them. Built otherwise, the
    // program would mix two runtimes.
    let target = std::env::var("TARGET").unwrap_or_default();
    let features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    if target.ends_with("windows-msvc") && !features.split(',').any(|feature| feature == "crt-static") {
        panic!(
            "dx-lua is built with the static C runtime on Windows: build it from dx/ (where .cargo/config.toml sets it), \
             or add -C target-feature=+crt-static to RUSTFLAGS"
        );
    }
    // The commit of the repository that has this crate: unpacked inside another repository (a source archive), git would
    // give that one's.
    let tracked = Command::new("git").args(["ls-files", "--error-unmatch", "Cargo.toml"]).output();
    let commit = match tracked {
        Ok(output) if output.status.success() => git(&["rev-parse", "--short=12", "HEAD"]),
        _ => None,
    };
    let commit = match commit {
        // What is built isn't what the commit has: a file of dx/ changed, added or removed since
        Some(commit) if git(&["status", "--porcelain", "--", ".."]).is_some() => format!("{commit}+modified"),
        Some(commit) => commit,
        None => "unknown".to_string(),
    };
    println!("cargo:rustc-env=DX_LUA_COMMIT={commit}");
    // Run again when what is built changes (with a rerun-if-changed, cargo runs this again for nothing else): the
    // sources of the two crates and what they depend on
    for path in
        ["build.rs", "src", "Cargo.toml", "../dx-core/src", "../dx-core/Cargo.toml", "../Cargo.toml", "../Cargo.lock"]
    {
        println!("cargo:rerun-if-changed={path}");
    }
    // And when HEAD moves: HEAD itself, and the file of the branch it names (a branch packed by git has none, and
    // then it runs every time, which costs a call to git)
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]).map(PathBuf::from) {
        println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
        if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
            if let Some(reference) = head.trim().strip_prefix("ref: ") {
                println!("cargo:rerun-if-changed={}", git_dir.join(reference).display());
            }
        }
    }
}
