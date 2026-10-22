//! The harnesses' prompt history (`history.jsonl`).
//!
//! Claude Code (`~/.claude/history.jsonl`, under `CLAUDE_CONFIG_DIR` if set)
//! and Codex (`~/.codex/history.jsonl`, under `CODEX_HOME`) keep every prompt
//! the person sent, one JSON document per line, for the arrow-up recall:
//!
//! * Claude: `{"display": TEXT, "pastedContents": {"1": {"content": TEXT, ..}},
//!   "timestamp": MS, "project": DIR, "sessionId": ID}`
//! * Codex: `{"session_id": ID, "ts": SECONDS, "text": TEXT}`
//!
//! The files belong to the person's whole account, not to a project, so
//! `vahta scrub --transcript` cleans them whatever the scope (see
//! `transcript.rs`), with the same cleaner as the transcripts. Nothing here
//! depends on the field names: every string of an entry is looked at.
//!
//! **The blocked prompt.** When the prompt window fired and the person chose to
//! save the value or to do nothing, the message never reached the agent, but the
//! harness may have written it to the history on the way. The daemon then drops
//! the entries that hold it: an entry with a string equal to the message, or
//! with any string that contains one of the secret values found in it. The match
//! is made in memory, against the text the hook sent, which is never logged. It
//! is tried at once and again a few seconds later, because the harness may write
//! the entry after the hook has answered. A line that is not JSON is left
//! alone. A file the harness appends to meanwhile is rewritten only if it did
//! not change during the pass, and what it appended in the instant of the swap
//! is copied from the old file (see `jsonl::drop_lines`).

use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use vahta_ipc::protocol::TranscriptRoots;

use crate::jsonl;

/// A line longer than this is not parsed; it is not a prompt.
const MAX_ENTRY: usize = 4 * 1024 * 1024;
/// How deep and how wide an entry is read.
const MAX_NODES: usize = 100_000;
/// When, after the window, the history is looked at again.
const RETRY_AFTER: [Duration; 3] = [
    Duration::from_millis(700),
    Duration::from_secs(3),
    Duration::from_secs(10),
];

/// The history files of the harnesses `roots` names, whether they exist or not.
pub(crate) fn files(roots: &TranscriptRoots) -> Vec<PathBuf> {
    [&roots.claude, &roots.codex]
        .into_iter()
        .flatten()
        .map(|root| PathBuf::from(root).join("history.jsonl"))
        .collect()
}

/// A blocked prompt, as much of it as is needed to find its history entry.
pub(crate) struct Blocked {
    message: Zeroizing<String>,
    values: Zeroizing<Vec<String>>,
}

impl Blocked {
    /// `values` are the secrets found in `message`; empty ones are ignored.
    pub fn new(message: &str, values: Vec<String>) -> Blocked {
        Blocked {
            message: Zeroizing::new(message.trim().to_string()),
            values: Zeroizing::new(values.into_iter().filter(|v| v.len() >= 8).collect()),
        }
    }

    /// Whether a history line is this prompt.
    fn is_in(&self, line: &str) -> bool {
        if line.len() > MAX_ENTRY {
            return false;
        }
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            return false;
        };
        let mut seen = 0usize;
        let mut stack = vec![&entry];
        while let Some(v) = stack.pop() {
            seen += 1;
            if seen > MAX_NODES {
                return false;
            }
            match v {
                serde_json::Value::String(s) => {
                    if (!self.message.is_empty() && s.trim() == self.message.as_str())
                        || self.values.iter().any(|v| s.contains(v.as_str()))
                    {
                        return true;
                    }
                }
                serde_json::Value::Array(items) => stack.extend(items),
                serde_json::Value::Object(map) => stack.extend(map.values()),
                _ => {}
            }
        }
        false
    }
}

/// Drop the entries of `blocked` from every history file `roots` names. How many
/// entries went.
pub(crate) fn forget(roots: &TranscriptRoots, blocked: &Blocked) -> usize {
    let mut gone = 0;
    for path in files(roots) {
        // Never through a link: the file is the harness's.
        let regular = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
        if regular && let Ok(n) = jsonl::drop_lines(&path, &|line| blocked.is_in(line)) {
            gone += n;
        }
    }
    gone
}

/// [`forget`] now and again shortly after, off the caller's thread, and
/// `journal` the number dropped (never the text).
pub(crate) fn forget_soon(
    roots: TranscriptRoots,
    blocked: Blocked,
    journal: std::sync::Arc<crate::journal::Journal>,
) {
    let _ = std::thread::Builder::new()
        .name("history-forget".to_string())
        .spawn(move || {
            let note = |gone: usize| {
                if gone > 0 {
                    journal.record(crate::journal::Entry::new("history_forget").result(
                        "ok",
                        Some(&format!(
                            "{gone} prompt(s) removed from the harness history"
                        )),
                    ));
                }
            };
            note(forget(&roots, &blocked));
            for wait in RETRY_AFTER {
                std::thread::sleep(wait);
                note(forget(&roots, &blocked));
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> String {
        ["tok", "en-", "abcdef", "123456"].concat()
    }

    #[test]
    fn an_entry_is_the_prompt_when_a_string_is_it_or_holds_its_secret() {
        let b = Blocked::new(&format!("my key is {}", secret()), vec![secret()]);
        let claude = serde_json::json!({
            "display": format!("my key is {}", secret()), "pastedContents": {},
            "timestamp": 1, "project": "/p", "sessionId": "s"
        });
        let codex = serde_json::json!({"session_id": "s", "ts": 1, "text": format!("  my key is {}\n", secret())});
        let pasted = serde_json::json!({
            "display": "[Pasted text #1 +3 lines]",
            "pastedContents": {"1": {"id": 1, "type": "text", "content": format!("a\n{}\nb", secret())}}
        });
        let other = serde_json::json!({"display": "ls -la", "pastedContents": {}});
        for (entry, want) in [
            (&claude, true),
            (&codex, true),
            (&pasted, true),
            (&other, false),
        ] {
            assert_eq!(b.is_in(&entry.to_string()), want, "{entry}");
        }
        assert!(!b.is_in("not json {"));
        assert!(!b.is_in(""));
        // No secret values (a whole-message find): only the exact message.
        let b = Blocked::new("exactly this", Vec::new());
        assert!(b.is_in(r#"{"display":"exactly this"}"#));
        assert!(!b.is_in(r#"{"display":"exactly this and more"}"#));
    }

    #[test]
    fn only_the_blocked_entries_go_and_the_rest_is_kept_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join("claude");
        std::fs::create_dir_all(&claude).unwrap();
        let path = claude.join("history.jsonl");
        let keep1 = r#"{"display":"first",  "timestamp":1.50}"#;
        let keep2 = "not json at all";
        let bad = serde_json::json!({"display": format!("key {}", secret())}).to_string();
        let keep3 = r#"{"display":"last"}"#;
        // No final newline, a CRLF line and a blocked line between.
        std::fs::write(&path, format!("{keep1}\r\n{keep2}\n{bad}\n{keep3}")).unwrap();
        let roots = TranscriptRoots {
            claude: Some(claude.display().to_string()),
            codex: None,
        };
        let b = Blocked::new(&format!("key {}", secret()), vec![secret()]);
        assert_eq!(forget(&roots, &b), 1);
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, format!("{keep1}\r\n{keep2}\n{keep3}"));
        // Nothing left to drop: the file is not even rewritten.
        let stamp = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(forget(&roots, &b), 0);
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), stamp);
        // A missing file is no error.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(forget(&roots, &b), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        let line = serde_json::json!({"display": secret()}).to_string();
        std::fs::write(&target, format!("{line}\n")).unwrap();
        let root = dir.path().join("codex");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&target, root.join("history.jsonl")).unwrap();
        let roots = TranscriptRoots {
            claude: None,
            codex: Some(root.display().to_string()),
        };
        assert_eq!(forget(&roots, &Blocked::new("x", vec![secret()])), 0);
        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains(&secret())
        );
    }

    #[test]
    fn a_harness_appending_during_the_pass_is_kept_and_the_file_stays_whole() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.jsonl");
        let bad = serde_json::json!({"text": secret()}).to_string();
        std::fs::write(&path, format!("{bad}\n{{\"text\":\"a\"}}\n")).unwrap();
        let written = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = written.clone();
        let appended = path.clone();
        // Appends a line every few ms, as a busy harness would.
        let writer = std::thread::spawn(move || {
            for n in 0..60 {
                use std::io::Write;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&appended)
                    .unwrap();
                writeln!(f, "{{\"text\":\"line {n}\"}}").unwrap();
                counter.store(n + 1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        std::thread::sleep(Duration::from_millis(10));
        let before = written.load(Ordering::SeqCst);
        let dropped = jsonl::drop_lines(&path, &|l| l.contains(&secret()));
        let after = written.load(Ordering::SeqCst);
        writer.join().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        // Every line is whole JSON.
        for l in text.lines() {
            serde_json::from_str::<serde_json::Value>(l).unwrap();
        }
        // What was written before the pass began, and what after it ended, is
        // there. A line written in the instant of the swap is the one thing that
        // can be lost, so lines in between are not asserted.
        for n in (0..before).chain(after + 1..60) {
            assert!(text.contains(&format!("line {n}\"")), "line {n} lost");
        }
        match dropped {
            Ok(1) => assert!(!text.contains(&secret())),
            Ok(n) => panic!("dropped {n}"),
            // It never got a quiet moment: nothing was replaced.
            Err(_) => assert!(text.contains(&secret())),
        }
    }
}
