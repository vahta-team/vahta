//! Where the daemon keeps its things, and the checks that those places are ours.
//!
//! * the **runtime directory** holds the socket and the single-instance lock:
//!   `$XDG_RUNTIME_DIR/vahta` on Linux (else `<data dir>/run`), `$TMPDIR/vahta`
//!   on macOS, `<data dir>/run` on Windows. Mode 0700, and refused if it is
//!   not owned by us;
//! * the **data directory** is the local store's root (see `vahta-vault`) and
//!   holds the journal;
//! * the **config directory** holds `config.toml`.
//!
//! `VAHTA_RUNTIME_DIR`, `VAHTA_DATA_DIR` and `VAHTA_CONFIG_DIR` replace each
//! one outright; tests set all three to temp directories.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The longest socket path accepted. `sun_path` is 104 bytes on macOS and 108
/// on Linux; the margin keeps the check the same on both.
const MAX_SOCKET_PATH: usize = 100;

#[derive(Debug)]
pub enum PathError {
    /// There is no home or data directory to build a default from.
    NoBase(&'static str),
    /// The runtime directory exists and is not ours, or cannot be made.
    Unsafe(PathBuf, &'static str),
    /// The socket path would not fit in a socket address.
    TooLong(PathBuf),
    Io(PathBuf, io::Error),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::NoBase(what) => write!(
                f,
                "cannot tell where to keep {what} on this machine (set the matching VAHTA_*_DIR)"
            ),
            PathError::Unsafe(p, why) => {
                write!(
                    f,
                    "the runtime directory {} is not safe: {why}",
                    p.display()
                )
            }
            PathError::TooLong(p) => write!(
                f,
                "the socket path {} is too long for a socket address; set VAHTA_RUNTIME_DIR to a shorter directory",
                p.display()
            ),
            PathError::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for PathError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub runtime: PathBuf,
    pub data: PathBuf,
    pub config: PathBuf,
}

fn nonempty(v: Option<OsString>) -> Option<PathBuf> {
    v.filter(|s| !s.is_empty()).map(PathBuf::from)
}

impl Paths {
    /// From the process environment. `data` is the local store root the caller
    /// has already worked out (the `vahta` command does it once for everything).
    pub fn from_env(data: Option<PathBuf>) -> Result<Paths, PathError> {
        Paths::resolve(|k| std::env::var_os(k), data)
    }

    /// The same, from any source of variables, so the rules are tested without
    /// touching the real environment.
    pub fn resolve(
        var: impl Fn(&str) -> Option<OsString>,
        data: Option<PathBuf>,
    ) -> Result<Paths, PathError> {
        let data = data
            .or_else(|| nonempty(var("VAHTA_DATA_DIR")))
            .or_else(|| dirs::data_dir().map(|d| d.join("vahta")))
            .ok_or(PathError::NoBase("its data"))?;
        let config = nonempty(var("VAHTA_CONFIG_DIR"))
            .or_else(|| dirs::config_dir().map(|d| d.join("vahta")))
            .ok_or(PathError::NoBase("its configuration"))?;
        let runtime = match nonempty(var("VAHTA_RUNTIME_DIR")) {
            Some(d) => d,
            None if cfg!(target_os = "macos") => nonempty(var("TMPDIR"))
                .unwrap_or_else(std::env::temp_dir)
                .join("vahta"),
            None if cfg!(target_os = "linux") => match nonempty(var("XDG_RUNTIME_DIR")) {
                Some(x) => x.join("vahta"),
                None => data.join("run"),
            },
            None => data.join("run"),
        };
        Ok(Paths {
            runtime,
            data,
            config,
        })
    }

    pub fn lock_file(&self) -> PathBuf {
        self.runtime.join("daemon.lock")
    }

    /// Held by the hook watchdog (`vahta _guard`) for as long as it runs.
    pub fn guard_lock_file(&self) -> PathBuf {
        self.runtime.join("guard.lock")
    }

    /// Created to ask the watchdog to end (see `guard_cmd.rs`).
    pub fn guard_stop_file(&self) -> PathBuf {
        self.runtime.join("guard.stop")
    }

    /// Whether a watchdog is running: its lock is held.
    pub fn guard_running(&self) -> bool {
        match fs::OpenOptions::new()
            .read(true)
            .open(self.guard_lock_file())
        {
            Ok(f) => matches!(f.try_lock_shared(), Err(fs::TryLockError::WouldBlock)),
            Err(_) => false,
        }
    }

    pub fn journal_file(&self) -> PathBuf {
        self.data.join("journal.jsonl")
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    /// Where the daemon listens, with the length check a Unix socket needs.
    pub fn address(&self) -> Result<vahta_os::ipc::Address, PathError> {
        let addr = vahta_os::ipc::Address::for_runtime_dir(&self.runtime)
            .map_err(|e| PathError::Io(self.runtime.clone(), e))?;
        if let Some(sock) = addr.socket_path()
            && sock.as_os_str().len() > MAX_SOCKET_PATH
        {
            return Err(PathError::TooLong(sock.to_path_buf()));
        }
        Ok(addr)
    }

    /// Create the runtime directory, private to us, and refuse it if it is not.
    pub fn ensure_runtime_dir(&self) -> Result<(), PathError> {
        private_dir(&self.runtime)
    }

    /// Create the data directory (journal, store), private to us.
    pub fn ensure_data_dir(&self) -> Result<(), PathError> {
        private_dir(&self.data)
    }
}

#[cfg(unix)]
fn private_dir(dir: &Path) -> Result<(), PathError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let io = |e| PathError::Io(dir.to_path_buf(), e);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io)?;
    let meta = fs::symlink_metadata(dir).map_err(io)?;
    if !meta.is_dir() {
        return Err(PathError::Unsafe(dir.to_path_buf(), "not a directory"));
    }
    if Some(meta.uid()) != vahta_os::effective_uid() {
        return Err(PathError::Unsafe(
            dir.to_path_buf(),
            "not owned by this user",
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_dir(dir: &Path) -> Result<(), PathError> {
    // Windows: a directory under the user's profile is already private to the
    // user; the pipe, not the directory, is what is guarded.
    fs::create_dir_all(dir).map_err(|e| PathError::Io(dir.to_path_buf(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        let owned: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), OsString::from(*v)))
            .collect();
        move |k| owned.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    #[test]
    fn the_overrides_replace_each_directory() {
        let p = Paths::resolve(
            vars(&[
                ("VAHTA_RUNTIME_DIR", "/r"),
                ("VAHTA_DATA_DIR", "/d"),
                ("VAHTA_CONFIG_DIR", "/c"),
                ("XDG_RUNTIME_DIR", "/x"),
            ]),
            None,
        )
        .unwrap();
        assert_eq!(p.runtime, PathBuf::from("/r"));
        assert_eq!(p.data, PathBuf::from("/d"));
        assert_eq!(p.config, PathBuf::from("/c"));
        assert_eq!(p.lock_file(), PathBuf::from("/r/daemon.lock"));
        assert_eq!(p.journal_file(), PathBuf::from("/d/journal.jsonl"));
        assert_eq!(p.config_file(), PathBuf::from("/c/config.toml"));
    }

    #[test]
    fn an_empty_override_is_no_override() {
        let p = Paths::resolve(
            vars(&[("VAHTA_RUNTIME_DIR", ""), ("VAHTA_CONFIG_DIR", "/c")]),
            Some(PathBuf::from("/d")),
        )
        .unwrap();
        assert_ne!(p.runtime, PathBuf::from(""));
        assert_eq!(p.data, PathBuf::from("/d"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_uses_the_xdg_runtime_dir_else_the_data_dir() {
        let with = Paths::resolve(
            vars(&[
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
                ("VAHTA_CONFIG_DIR", "/c"),
            ]),
            Some(PathBuf::from("/d")),
        )
        .unwrap();
        assert_eq!(with.runtime, PathBuf::from("/run/user/1000/vahta"));
        let without = Paths::resolve(
            vars(&[("VAHTA_CONFIG_DIR", "/c")]),
            Some(PathBuf::from("/d")),
        )
        .unwrap();
        assert_eq!(without.runtime, PathBuf::from("/d/run"));
    }

    #[test]
    fn a_socket_path_too_long_for_an_address_is_refused() {
        let long = format!("/{}", "a".repeat(120));
        let p = Paths {
            runtime: PathBuf::from(long),
            data: PathBuf::from("/d"),
            config: PathBuf::from("/c"),
        };
        if cfg!(unix) {
            assert!(matches!(p.address(), Err(PathError::TooLong(_))));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_directory_is_made_private_and_a_foreign_one_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let p = Paths {
            runtime: dir.clone(),
            data: tmp.path().join("data"),
            config: tmp.path().join("config"),
        };
        p.ensure_runtime_dir().unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // Loosened by someone, tightened again.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        p.ensure_runtime_dir().unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // A file where the directory should be.
        let file = tmp.path().join("file");
        fs::write(&file, "x").unwrap();
        let bad = Paths { runtime: file, ..p };
        assert!(bad.ensure_runtime_dir().is_err());
    }
}
