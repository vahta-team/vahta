//! The hook's spool: where a [`HookReport`](crate::protocol::ClientRequest::HookReport)
//! goes when no daemon is running to hear it.
//!
//! One JSON line per report in `<data dir>/hook-spool.jsonl`, private to the
//! user. The hook appends; the daemon, when it starts, takes the whole file
//! (renaming it first, so a hook appending meanwhile starts a new one) and
//! journals each line. A line holds what the report holds: a category, a rule
//! id, a path, never a value or the text it was found in.
//!
//! The file is capped at [`MAX_SPOOL`]: past it, new reports are dropped, and
//! the daemon notes that the spool was full. An agent cannot fill the disk
//! through it, and an attack loud enough to fill it has already left plenty.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::Paths;
use crate::protocol::Signal;

/// The largest the spool grows before new reports are dropped.
pub const MAX_SPOOL: u64 = 1 << 20;

/// The longest line the daemon reads back; anything longer is not ours.
const MAX_LINE: usize = 4096;

/// One spooled report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolLine {
    /// Seconds since the Unix epoch, when the hook saw it.
    pub time: u64,
    pub session: Option<String>,
    pub harness: String,
    pub cwd: String,
    pub signal: Signal,
}

/// What the daemon took from the spool.
#[derive(Debug, Default)]
pub struct Drained {
    pub lines: Vec<SpoolLine>,
    /// Lines that were not a report (a torn write, or not ours).
    pub unreadable: usize,
    /// The spool had reached [`MAX_SPOOL`], so reports may have been dropped.
    pub full: bool,
}

pub fn spool_file(paths: &Paths) -> PathBuf {
    paths.data.join("hook-spool.jsonl")
}

/// Append `line` to the spool. Creates the data directory, private, if it is
/// not there yet. Past [`MAX_SPOOL`] it writes nothing and says so (`Ok(false)`).
pub fn append(paths: &Paths, line: &SpoolLine) -> io::Result<bool> {
    paths
        .ensure_data_dir()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let file = spool_file(paths);
    if fs::metadata(&file).map(|m| m.len()).unwrap_or(0) >= MAX_SPOOL {
        return Ok(false);
    }
    let mut text = serde_json::to_string(line).map_err(io::Error::other)?;
    text.push('\n');
    let mut f = open_private_append(&file)?;
    // One write per line, so concurrent hooks interleave whole lines.
    f.write_all(text.as_bytes())?;
    Ok(true)
}

#[cfg(unix)]
fn open_private_append(file: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(file)
}

#[cfg(not(unix))]
fn open_private_append(file: &Path) -> io::Result<fs::File> {
    OpenOptions::new().create(true).append(true).open(file)
}

/// Take everything in the spool and remove it. No spool is an empty result.
pub fn drain(paths: &Paths) -> io::Result<Drained> {
    let file = spool_file(paths);
    let taken = paths
        .data
        .join(format!("hook-spool.{}.draining", std::process::id()));
    match fs::rename(&file, &taken) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Drained::default()),
        Err(e) => return Err(e),
    }
    let bytes = fs::read(&taken);
    let _ = fs::remove_file(&taken);
    let bytes = bytes?;
    let mut out = Drained {
        full: bytes.len() as u64 >= MAX_SPOOL,
        ..Drained::default()
    };
    for raw in bytes.split(|b| *b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        match (raw.len() <= MAX_LINE)
            .then(|| serde_json::from_slice::<SpoolLine>(raw).ok())
            .flatten()
        {
            Some(line) => out.lines.push(line),
            None => out.unreadable += 1,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &Path) -> Paths {
        Paths {
            runtime: dir.join("run"),
            data: dir.join("data"),
            config: dir.join("config"),
        }
    }

    fn line(n: u64) -> SpoolLine {
        SpoolLine {
            time: n,
            session: Some("s1".into()),
            harness: "claude".into(),
            cwd: "/p".into(),
            signal: Signal::AgentGuard {
                command: "vahta reveal".into(),
            },
        }
    }

    #[test]
    fn appended_lines_come_back_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert!(append(&p, &line(1)).unwrap());
        assert!(append(&p, &line(2)).unwrap());
        let d = drain(&p).unwrap();
        assert_eq!(d.lines, vec![line(1), line(2)]);
        assert_eq!(d.unreadable, 0);
        assert!(!d.full);
        assert!(drain(&p).unwrap().lines.is_empty());
    }

    #[test]
    fn a_torn_line_is_counted_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        append(&p, &line(1)).unwrap();
        let mut f = open_private_append(&spool_file(&p)).unwrap();
        f.write_all(b"{\"time\":2,\"sess\n").unwrap();
        let d = drain(&p).unwrap();
        assert_eq!(d.lines.len(), 1);
        assert_eq!(d.unreadable, 1);
    }

    #[test]
    fn a_full_spool_takes_no_more() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        p.ensure_data_dir().unwrap();
        fs::write(spool_file(&p), vec![b'\n'; MAX_SPOOL as usize]).unwrap();
        assert!(!append(&p, &line(1)).unwrap());
        assert!(drain(&p).unwrap().full);
    }

    #[cfg(unix)]
    #[test]
    fn the_spool_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        append(&p, &line(1)).unwrap();
        let mode = fs::metadata(spool_file(&p)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
