//! Starting the daemon from the hook, when there is none.
//!
//! A hook that cannot reach the daemon is stricter and blind to what the daemon
//! holds, so it tries to bring one up, within limits that keep it cheap, quiet
//! and safe:
//!
//! * Only when nothing answers on the socket. A daemon that answers (of any
//!   version) is never joined by a second one, and seeing one answer clears the
//!   count of failed starts. The daemon's own lock refuses a second instance
//!   anyway.
//! * Only the `vahta` that lies next to this hook binary, found from the hook's
//!   own executable path: never a lookup through `PATH` or the working
//!   directory, which an agent could plant a program in.
//! * Detached, the way the command line starts it, and waited for only
//!   [`WAIT`]. Late, the call goes on in strict mode and the next call looks at
//!   the socket again.
//! * After [`TRIES`] starts in a row that did not bring a daemon up, no more,
//!   until one is seen answering or the machine restarts. The count is a small
//!   file in the runtime directory (`Paths::hook_starts_file`), written by
//!   rename. A file that cannot be read or makes no sense means "do not start".

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use vahta_ipc::client::Connector;
use vahta_ipc::paths::Paths;

/// How long a call waits for a daemon it has just started.
const WAIT: Duration = Duration::from_millis(1200);
/// Failed starts in a row after which the hook stops trying.
pub const TRIES: u32 = 3;

/// The `vahta` binary next to `hook`, if there is one.
fn sibling(hook: &Path) -> Option<PathBuf> {
    let dir = hook.parent()?;
    let exe = dir.join(format!("vahta{}", std::env::consts::EXE_SUFFIX));
    exe.is_file().then_some(exe)
}

/// The count of failed starts: `Some(n)`, 0 when there is no file yet, `None`
/// when it cannot be trusted.
fn read_count(file: &Path) -> Option<u32> {
    match fs::read_to_string(file) {
        Ok(text) => text.trim().parse().ok(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
        Err(_) => None,
    }
}

fn write_count(file: &Path, n: u32) -> bool {
    let tmp = file.with_extension(format!("tmp{}", std::process::id()));
    let ok = fs::write(&tmp, n.to_string()).is_ok() && fs::rename(&tmp, file).is_ok();
    if !ok {
        let _ = fs::remove_file(&tmp);
    }
    ok
}

/// A daemon was seen answering: the count starts again.
pub fn seen_answering(paths: &Paths) {
    let _ = fs::remove_file(paths.hook_starts_file());
}

/// No daemon answered. Try to start one, within the limits above; `true` when
/// one answers in time. `hook` is this hook binary's path.
pub fn ensure(paths: &Paths, hook: &Path) -> bool {
    // For tests of the hook alone, which must start nothing: setting it can only
    // keep the hook from starting a daemon, never make it start one.
    if std::env::var_os("VAHTA_HOOK_NO_START").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    let Some(vahta) = sibling(hook) else {
        return false;
    };
    let connector = Connector {
        paths: paths.clone(),
        version: vahta_ipc::VERSION.to_string(),
        start: Some(vec![
            OsString::from(vahta),
            OsString::from("daemon"),
            OsString::from("run"),
        ]),
    };
    // Look once more: one may have come up since the caller looked.
    match connector.connect_running() {
        Ok(None) => {}
        Ok(Some(conn)) => {
            if conn.daemon.ok && conn.daemon.version == connector.version {
                seen_answering(paths);
                return true;
            }
            return false;
        }
        Err(_) => return false,
    }
    if paths.ensure_runtime_dir().is_err() {
        return false;
    }
    let file = paths.hook_starts_file();
    let Some(failed) = read_count(&file) else {
        return false;
    };
    if failed >= TRIES {
        return false;
    }
    // Counted before the start: a start that never answers is a failure.
    if !write_count(&file, failed + 1) {
        return false;
    }
    if connector.start_by("hook").is_err() {
        return false;
    }
    if connector.wait_running(WAIT) {
        seen_answering(paths);
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vahta-as-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_count_is_read_with_care() {
        let dir = temp("count");
        let f = dir.join("hook-starts");
        assert_eq!(read_count(&f), Some(0));
        assert!(write_count(&f, 2));
        assert_eq!(read_count(&f), Some(2));
        fs::write(&f, "many").unwrap();
        assert_eq!(read_count(&f), None);
        fs::remove_file(&f).unwrap();
        fs::create_dir(&f).unwrap();
        assert_eq!(read_count(&f), None);
    }

    #[test]
    fn only_a_vahta_beside_the_hook_counts() {
        let dir = temp("sibling");
        let hook = dir.join("vahta-hook");
        assert_eq!(sibling(&hook), None);
        fs::write(
            dir.join(format!("vahta{}", std::env::consts::EXE_SUFFIX)),
            "",
        )
        .unwrap();
        assert!(sibling(&hook).is_some());
    }
}
