//! The journal: `<data dir>/journal.jsonl`, one JSON object per line, appended
//! and never rewritten, mode 0600.
//!
//! Each line says what happened and to whom: the time, the event, the session
//! and its parent, the vault, the secret *names*, the peer's executable and
//! pid, the result and the reason, and the use counters. **Never a value and
//! never a password:** there is no field for either, and callers pass names and
//! reasons of their own wording only.
//!
//! A journal that cannot be written does not stop the daemon from working; the
//! failure is remembered and [`Journal::healthy`] says so.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Entry {
    pub time: u64,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// The vault's id in hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uses: Option<u64>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Entry {
    pub fn new(event: &str) -> Entry {
        Entry {
            time: now(),
            event: event.to_string(),
            ..Entry::default()
        }
    }

    pub fn session(mut self, id: &str, parent: Option<&str>) -> Entry {
        self.session = Some(id.to_string());
        self.parent = parent.map(str::to_string);
        self
    }

    pub fn vault(mut self, vault_id: &[u8; 16]) -> Entry {
        self.vault = Some(vahta_vault::hex_encode(vault_id));
        self
    }

    pub fn names(mut self, names: &[String]) -> Entry {
        self.names = names.to_vec();
        self
    }

    pub fn peer(mut self, exe: Option<&str>, pid: u32) -> Entry {
        self.peer_exe = exe.map(str::to_string);
        self.peer_pid = Some(pid);
        self
    }

    pub fn result(mut self, result: &str, reason: Option<&str>) -> Entry {
        self.result = Some(result.to_string());
        self.reason = reason.map(str::to_string);
        self
    }

    pub fn uses(mut self, uses: u64) -> Entry {
        self.uses = Some(uses);
        self
    }
}

#[derive(Debug)]
pub struct Journal {
    file: Mutex<Option<File>>,
    healthy: AtomicBool,
}

impl Journal {
    /// Open (creating) the journal. A failure leaves a journal that discards
    /// its lines and reports itself unhealthy.
    pub fn open(path: &Path) -> Journal {
        let file = Journal::open_file(path).ok();
        Journal {
            healthy: AtomicBool::new(file.is_some()),
            file: Mutex::new(file),
        }
    }

    fn open_file(path: &Path) -> std::io::Result<File> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(0o600);
            let file = options.open(path)?;
            // An older, looser file is tightened.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            Ok(file)
        }
        #[cfg(not(unix))]
        options.open(path)
    }

    /// A journal that writes nowhere, for tests of code that needs one.
    pub fn discard() -> Journal {
        Journal {
            file: Mutex::new(None),
            healthy: AtomicBool::new(true),
        }
    }

    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// Append one line. One `write_all` of the whole line, so concurrent
    /// writers do not interleave inside one.
    pub fn record(&self, entry: Entry) {
        let Ok(mut line) = serde_json::to_string(&entry) else {
            return;
        };
        line.push('\n');
        let Ok(mut guard) = self.file.lock() else {
            return;
        };
        if let Some(file) = guard.as_mut()
            && file.write_all(line.as_bytes()).is_err()
        {
            self.healthy.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_appended_json_and_the_file_is_private() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("data").join("journal.jsonl");
        let j = Journal::open(&path);
        j.record(
            Entry::new("session_start")
                .session("s1", None)
                .names(&["A".to_string()])
                .peer(Some("claude"), 42)
                .result("ok", None),
        );
        j.record(Entry::new("session_end").session("s1", None).uses(3));
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "session_start");
        assert_eq!(lines[0]["names"][0], "A");
        assert_eq!(lines[0]["peer_pid"], 42);
        assert_eq!(lines[1]["uses"], 3);
        assert!(lines[1].get("names").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn an_unwritable_journal_does_not_stop_the_caller() {
        let tmp = tempfile::tempdir().unwrap();
        // A file where the directory should be.
        let file = tmp.path().join("f");
        fs::write(&file, "x").unwrap();
        let j = Journal::open(&file.join("journal.jsonl"));
        assert!(!j.healthy());
        j.record(Entry::new("anything"));
    }
}
