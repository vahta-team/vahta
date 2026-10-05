//! Writing a vault without ever leaving half of one on disk, and the lock that
//! makes load, modify and save one step.
//!
//! The write is: a temporary file in the same directory (so the rename cannot
//! cross a file system), `sync_all`, `rename` over the target, then an fsync of
//! the directory so the rename itself survives a power cut. A crash at any
//! point leaves either the old vault or the new one, plus at worst a stray
//! `.vault.vht.tmp-*` that nothing reads.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{Error, crypto, hex_encode};

fn io(op: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.to_path_buf();
    move |source| Error::Io { op, path, source }
}

/// Write `bytes` to `path` atomically, readable only by the owner.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".to_string());
    let suffix = hex_encode(&crypto::random::<8>()?);
    let tmp = dir.join(format!(".{name}.tmp-{suffix}"));

    let result = (|| -> Result<(), Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(io("create", &tmp))?;
        file.write_all(bytes).map_err(io("write", &tmp))?;
        file.sync_all().map_err(io("sync", &tmp))?;
        drop(file);
        fs::rename(&tmp, path).map_err(io("replace", path))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        return result;
    }
    // Make the rename durable. Directories cannot be opened for sync on
    // Windows, where the rename is already as durable as the platform makes it.
    #[cfg(unix)]
    {
        let d = File::open(dir).map_err(io("open directory", dir))?;
        d.sync_all().map_err(io("sync directory", dir))?;
    }
    Ok(())
}

/// An exclusive lock on `<vault dir>/vault.lock`. Hold it around load, modify
/// and save; dropping it releases it.
#[derive(Debug)]
pub struct VaultLock {
    file: File,
}

impl VaultLock {
    /// Wait for the lock next to `vault_path`, creating the file if needed.
    pub fn acquire(vault_path: &Path) -> Result<VaultLock, Error> {
        let lock_path: PathBuf = vault_path.with_file_name("vault.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(io("open", &lock_path))?;
        file.lock().map_err(io("lock", &lock_path))?;
        Ok(VaultLock { file })
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_atomically_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("vault.vht");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["vault.vht".to_string()]);
    }
}
