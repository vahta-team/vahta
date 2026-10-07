//! Finding the file a program name stands for.
//!
//! Shared by the window launcher, the clipboard tools and the command rules.
//! For a rule, "the program" is a file, not a name: a name is resolved once
//! (here) and what runs is the resolved path, so a check that passed on one
//! file cannot be followed by an exec of another through a different PATH.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// `name` as an executable on `path`, or itself if it names a path.
pub fn find_in_path(name: &str, path: Option<&OsString>) -> Option<PathBuf> {
    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        return executable(candidate);
    }
    std::env::split_paths(path?)
        .map(|dir| dir.join(name))
        .find_map(|p| executable(&p))
}

/// `p` if it is an executable file; on Windows also `p` plus a `PATHEXT`
/// extension when `p` has none.
fn executable(p: &Path) -> Option<PathBuf> {
    if is_executable(p) {
        return Some(p.to_path_buf());
    }
    #[cfg(windows)]
    if p.extension().is_none() {
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        for ext in exts.split(';').filter(|e| e.starts_with('.')) {
            let mut name = p.as_os_str().to_os_string();
            name.push(ext);
            let with = PathBuf::from(name);
            if is_executable(&with) {
                return Some(with);
            }
        }
    }
    None
}

fn is_executable(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

/// The canonical absolute path of the program `name`:
///
/// * a bare name is looked up in `path`;
/// * a name with a separator is taken relative to `base` (absolute stays).
///
/// Symlinks are followed (`canonicalize`), so what is compared and what is
/// executed is the file itself. `None` when there is no such executable.
pub fn locate(name: &str, path: Option<&OsString>, base: &Path) -> Option<PathBuf> {
    let found = if name.contains(['/', '\\']) {
        let given = Path::new(name);
        let full = if given.is_absolute() {
            given.to_path_buf()
        } else {
            base.join(given)
        };
        executable(&full)?
    } else {
        find_in_path(name, path)?
    };
    // A PATH entry such as `.` leaves a relative result.
    let absolute = if found.is_absolute() {
        found
    } else {
        base.join(found)
    };
    canonical(&absolute)
}

/// `std::fs::canonicalize`, but on Windows without the verbatim prefix where
/// it can go (`\\?\C:\x` becomes `C:\x`): `cmd.exe`, which runs `.cmd` and
/// `.bat` files, does not accept verbatim paths, and every comparison of
/// resolved paths must use this one form.
pub fn canonical(path: &Path) -> Option<PathBuf> {
    dunce::canonicalize(path).ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn exe(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn a_name_is_found_on_the_path_in_order() {
        let t = tempfile::tempdir().unwrap();
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        exe(&a, "tool");
        exe(&b, "tool");
        let path = std::env::join_paths([&b, &a]).unwrap();
        let got = locate("tool", Some(&path), t.path()).unwrap();
        assert_eq!(got, std::fs::canonicalize(b.join("tool")).unwrap());
        assert!(locate("absent", Some(&path), t.path()).is_none());
        assert!(locate("tool", None, t.path()).is_none());
    }

    #[test]
    fn a_slash_form_is_relative_to_the_base_and_a_symlink_to_its_target() {
        let t = tempfile::tempdir().unwrap();
        let real = exe(t.path(), "real");
        symlink(&real, t.path().join("link")).unwrap();
        let want = std::fs::canonicalize(&real).unwrap();
        assert_eq!(locate("./link", None, t.path()).unwrap(), want);
        assert_eq!(
            locate("link", None, t.path()),
            None,
            "a bare name is not cwd-relative"
        );
        assert_eq!(
            locate(real.to_str().unwrap(), None, Path::new("/")).unwrap(),
            want
        );
        // Not executable: not found.
        std::fs::write(t.path().join("data"), "x").unwrap();
        assert!(locate("./data", None, t.path()).is_none());
    }
}
