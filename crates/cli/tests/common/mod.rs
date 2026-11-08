//! Helpers shared by the integration tests that run real programs.

use std::path::Path;

/// The programs the tests run through `vahta run` and `vahta delegate`.
const UNIX_TOOLS: [&str; 3] = ["true", "printenv", "sh"];

fn on_path(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let found = |name: String| Path::new(&dir).join(name).is_file();
        found(program.to_string()) || (cfg!(windows) && found(format!("{program}.exe")))
    })
}

/// True, after printing a one-line note, when a test that runs `true`,
/// `printenv` or `sh` cannot run here because one of them is not on `PATH`
/// (on Windows: outside Git Bash). The test then returns without asserting
/// anything:
///
/// ```ignore
/// if common::skip_without_unix_tools() {
///     return;
/// }
/// ```
pub fn skip_without_unix_tools() -> bool {
    let missing: Vec<&str> = UNIX_TOOLS.iter().copied().filter(|p| !on_path(p)).collect();
    if missing.is_empty() {
        return false;
    }
    eprintln!(
        "skipped: {} not on PATH (run from Git Bash to include this test)",
        missing.join(", ")
    );
    true
}
