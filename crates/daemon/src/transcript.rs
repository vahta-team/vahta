//! Secrets in the harnesses' transcripts on disk (`vahta scrub --transcript`).
//!
//! A value that reached an agent's context (the person pasted it, or it slipped
//! past the output redaction) is in the harness's transcript file too, and the
//! next `claude --resume`, a backup or a sync of the home directory carries it
//! on. The live context cannot be cleaned from here; the files can. The agent
//! may ask for it without a window: the request only removes, and the reply
//! names counts and paths, never a value or the text around one.
//!
//! * **What is looked for.** The values this daemon holds for the caller, as an
//!   output is redacted (every form they might be written in, and the
//!   JSON-escaped spelling), and the detector's likely finds. See `jsonl.rs`
//!   for how a line is cleaned and a file rewritten.
//! * **Where.** Claude Code: `projects/<dir>/**.jsonl` under `CLAUDE_CONFIG_DIR`
//!   (default `~/.claude`); `<dir>` is the working directory with every
//!   character that is not a letter or digit written as `-`. By default only
//!   the caller's project, with `--all` every project's. Codex: `sessions/` and
//!   `archived_sessions/` under `CODEX_HOME` (default `~/.codex`), `rollout-*.jsonl`;
//!   by default the ones whose recorded working directory is the caller's.
//!   The client says where (the daemon's own environment may differ).
//!   Cursor keeps chats in a SQLite database and is not touched.
//! * **A running session** is not rewritten while the harness appends to it. A
//!   file is open when it changed in the last minute, or when a hook has said
//!   its session began and not ended and it changed in the last six hours. An
//!   open file is read, its secrets are recorded as exposed, and it is marked;
//!   the session's `SessionEnd` hook then has the daemon clean it.
//! * **Exposed.** A secret found in a transcript is recorded in the machine's
//!   authenticated record of its vault (`vahta_vault::store`: name and time, in
//!   the MAC, so deleting the mark is detected), and `vahta list` and `vahta
//!   check` say to rotate it until it is reset or removed.
//!
//! The values are the sessions' own (the caller must have unlocked); with none,
//! only the detector's finds are taken out.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use vahta_ipc::protocol::{
    ClientReply, TranscriptFile, TranscriptReport, TranscriptRoots, TranscriptState,
};
use vahta_vault::store::StateKey;

use crate::journal::Entry;
use crate::jsonl::{self, Cleaner, Rewrite, Tally};
use crate::ops::{Ctx, Flow};
use crate::output::{anchor_of, known_values};
use crate::server::Shared;

/// A file changed this recently belongs to a running session.
const QUIET: Duration = Duration::from_secs(60);
/// A session a hook announced stays "running" this long after its file last
/// changed (the harness may have been killed with no `SessionEnd`).
const LIVE_FOR: Duration = Duration::from_secs(6 * 3600);
/// At `SessionEnd` the harness may still be flushing; the daemon waits this
/// long before it reads the file.
const FLUSH_WAIT: Duration = Duration::from_secs(1);
/// How deep under a project's folder transcripts are looked for.
const DEPTH: usize = 6;

/// What the daemon remembers about running sessions and marked files.
#[derive(Default)]
pub(crate) struct Marks {
    /// `harness:session` of a session a hook said began, when.
    live: HashMap<String, Instant>,
    /// Files found to hold a secret while their session ran.
    /// Keys of the files (see [`path_key`]).
    deferred: HashSet<String>,
}

fn key(harness: &str, session: &str) -> String {
    format!("{harness}:{session}")
}

/// Claude Code's folder name for a working directory.
pub(crate) fn claude_project_dir(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Harness {
    Claude,
    Codex,
}

impl Harness {
    fn name(self) -> &'static str {
        match self {
            Harness::Claude => "claude",
            Harness::Codex => "codex",
        }
    }
}

struct Found {
    harness: Harness,
    path: PathBuf,
}

/// Regular `.jsonl` files under `dir`, not following links.
fn walk(dir: &Path, depth: usize, keep: &dyn Fn(&str) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(t) = e.file_type() else { continue };
        let path = e.path();
        if t.is_dir() && depth > 0 {
            walk(&path, depth - 1, keep, out);
        } else if t.is_file() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".jsonl") && keep(&name) {
                out.push(path);
            }
        }
    }
}

/// The working directory a Codex rollout records, from its first line.
fn codex_cwd(path: &Path) -> Option<String> {
    use std::io::{BufRead, BufReader, Read};
    let mut line = String::new();
    BufReader::new(std::fs::File::open(path).ok()?)
        .take(1 << 20)
        .read_line(&mut line)
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(line.trim_end()).ok()?;
    v.pointer("/payload/cwd")
        .or_else(|| v.get("cwd"))
        .and_then(|c| c.as_str())
        .map(str::to_string)
}

/// A directory as text for comparing: resolved when it exists (without
/// Windows' verbatim prefix), separators alike, and on Windows case folded.
fn dir_key(p: &Path) -> String {
    let real = dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let text = real.to_string_lossy().replace('\\', "/");
    let text = text.trim_end_matches('/').to_string();
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}

/// A file as a key that is the same however the path was written: the hook and
/// the command may spell the same root differently (separators, case on Windows).
fn path_key(p: &Path) -> String {
    dir_key(p)
}

fn same_dir(a: &str, b: &Path) -> bool {
    dir_key(Path::new(a)) == dir_key(b)
}

/// Every transcript file in scope.
fn discover(cwd: &Path, all: bool, roots: &TranscriptRoots) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    if let Some(claude) = &roots.claude {
        let projects = Path::new(claude).join("projects");
        let mut files = Vec::new();
        if all {
            walk(&projects, DEPTH, &|_| true, &mut files);
        } else {
            let mut dirs = vec![claude_project_dir(cwd)];
            if let Ok(real) = dunce::canonicalize(cwd) {
                dirs.push(claude_project_dir(&real));
            }
            dirs.dedup();
            for d in dirs {
                walk(&projects.join(d), DEPTH, &|_| true, &mut files);
            }
        }
        out.extend(files.into_iter().map(|path| Found {
            harness: Harness::Claude,
            path,
        }));
    }
    if let Some(codex) = &roots.codex {
        let mut files = Vec::new();
        for sub in ["sessions", "archived_sessions"] {
            walk(
                &Path::new(codex).join(sub),
                DEPTH,
                &|n| n.starts_with("rollout-"),
                &mut files,
            );
        }
        out.extend(
            files
                .into_iter()
                .filter(|p| all || codex_cwd(p).is_some_and(|c| same_dir(&c, cwd)))
                .map(|path| Found {
                    harness: Harness::Codex,
                    path,
                }),
        );
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

/// The files of one session: Claude names a transcript after the session id,
/// Codex ends the file name with it.
fn of_session(harness: &str, session: &str, roots: &TranscriptRoots) -> Vec<Found> {
    // An id is a UUID; refuse anything that could be a path or a wildcard.
    if session.len() < 8
        || !session
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    match (harness, &roots.claude, &roots.codex) {
        ("claude", Some(claude), _) => {
            let mut files = Vec::new();
            walk(
                &Path::new(claude).join("projects"),
                DEPTH,
                &|_| true,
                &mut files,
            );
            out.extend(
                files
                    .into_iter()
                    .filter(|p| {
                        p.file_name()
                            .is_some_and(|n| n.to_string_lossy() == format!("{session}.jsonl"))
                            || p.components().any(|c| c.as_os_str() == session)
                    })
                    .map(|path| Found {
                        harness: Harness::Claude,
                        path,
                    }),
            );
        }
        ("codex", _, Some(codex)) => {
            let mut files = Vec::new();
            for sub in ["sessions", "archived_sessions"] {
                walk(
                    &Path::new(codex).join(sub),
                    DEPTH,
                    &|n| n.starts_with("rollout-") && n.ends_with(&format!("{session}.jsonl")),
                    &mut files,
                );
            }
            out.extend(files.into_iter().map(|path| Found {
                harness: Harness::Codex,
                path,
            }));
        }
        _ => {}
    }
    out
}

fn modified_ago(path: &Path) -> Duration {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        // A time in the future, or none: treat the file as just written.
        .unwrap_or_default()
}

/// Whether a session may still be appending to `path`.
fn is_open(marks: &Marks, harness: Harness, path: &Path) -> bool {
    let ago = modified_ago(path);
    if ago < QUIET {
        return true;
    }
    let name = path.to_string_lossy();
    ago < LIVE_FOR
        && marks.live.iter().any(|(k, seen)| {
            k.split_once(':')
                .is_some_and(|(h, s)| h == harness.name() && name.contains(s))
                && seen.elapsed() < LIVE_FOR
        })
}

/// Where a name found in a transcript is recorded as exposed: its vault and the
/// key of this machine's record of that vault.
type Vaults = HashMap<String, ([u8; 16], Arc<StateKey>)>;

/// The held values of the caller, and which vault each name is from.
fn held(ctx: &Ctx<'_>) -> (Vec<jsonl::Value>, Vaults) {
    let chain = vahta_os::ancestor_chain(ctx.pid, vahta_os::MAX_ANCESTORS);
    let anchor = anchor_of(ctx);
    let values = known_values(ctx, &chain, anchor.as_ref().map(|(a, _)| a));
    let mut vaults = HashMap::new();
    if let Ok(sessions) = ctx.shared.sessions.lock() {
        for s in sessions.covering(&chain) {
            let key = Arc::new(s.keys.state_key());
            for name in &s.scope {
                vaults.insert(name.clone(), (s.vault_id, key.clone()));
            }
        }
    }
    (values, vaults)
}

/// Record `names` as exposed, in the machine's authenticated record of each
/// name's vault. Names the caller has no session for have no vault to be
/// recorded under and are left out.
fn mark_exposed(shared: &Shared, names: &[String], vaults: &Vaults) {
    let at = vahta_ipc::state::now();
    let mut groups: Vec<([u8; 16], Arc<StateKey>, Vec<String>)> = Vec::new();
    for name in names {
        let Some((vault, key)) = vaults.get(name) else {
            continue;
        };
        match groups.iter_mut().find(|g| g.0 == *vault) {
            Some(g) => g.2.push(name.clone()),
            None => groups.push((*vault, key.clone(), vec![name.clone()])),
        }
    }
    for (vault, key, mine) in groups {
        let _ = shared.store.mark_exposed(&vault, &key, &mine, at);
    }
}

/// Read one file, and rewrite it when it is closed. `open` files are left
/// alone and put on the deferred list.
fn handle(
    shared: &Shared,
    cleaner: &Cleaner,
    found: &Found,
    force_closed: bool,
) -> Option<(TranscriptFile, Tally)> {
    // Never through a link: the file is the harness's, not whatever it points at.
    let meta = std::fs::symlink_metadata(&found.path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let tally = jsonl::count(&found.path, cleaner).ok()?;
    if tally.total() == 0 {
        return None;
    }
    let open = !force_closed
        && shared
            .marks
            .lock()
            .map(|m| is_open(&m, found.harness, &found.path))
            .unwrap_or(true);
    let (state, tally) = if open {
        if let Ok(mut m) = shared.marks.lock() {
            m.deferred.insert(path_key(&found.path));
        }
        (TranscriptState::Deferred, tally)
    } else {
        match jsonl::rewrite(&found.path, cleaner) {
            Ok(Rewrite::Done(t)) => {
                if let Ok(mut m) = shared.marks.lock() {
                    m.deferred.remove(&path_key(&found.path));
                }
                (TranscriptState::Cleaned, t)
            }
            Ok(Rewrite::Changed) | Err(_) => (TranscriptState::Failed, tally),
        }
    };
    Some((
        TranscriptFile {
            path: found.path.display().to_string(),
            harness: found.harness.name().to_string(),
            values: tally.values,
            patterns: tally.patterns,
            state,
        },
        tally,
    ))
}

/// `vahta scrub --transcript`.
pub(crate) fn scrub(
    ctx: &Ctx<'_>,
    cwd: &str,
    all: bool,
    roots: TranscriptRoots,
) -> Flow<ClientReply> {
    let cwd = ctx.check_cwd(cwd)?;
    let (values, vaults) = held(ctx);
    let cleaner = Cleaner::new(&values);
    drop(values);
    let found = discover(&cwd, all, &roots);
    let mut report = TranscriptReport {
        scanned: found.len(),
        ..TranscriptReport::default()
    };
    let mut all_names: Vec<String> = Vec::new();
    for f in &found {
        if let Some((file, tally)) = handle(ctx.shared, &cleaner, f, false) {
            for n in tally.names {
                if !all_names.contains(&n) {
                    all_names.push(n);
                }
            }
            report.files.push(file);
        }
    }
    mark_exposed(ctx.shared, &all_names, &vaults);
    report.exposed = all_names.clone();
    let values: usize = report.files.iter().map(|f| f.values).sum();
    let patterns: usize = report.files.iter().map(|f| f.patterns).sum();
    ctx.journal(Entry::new("transcript_scrub").names(&all_names).result(
        "ok",
        Some(&format!(
            "{} files read, {} with finds; {values} values, {patterns} patterns",
            report.scanned,
            report.files.len()
        )),
    ));
    Ok(ClientReply::Transcripts(report))
}

/// The hook: a session began or ended. At its end the files marked while it ran
/// are cleaned, a moment later, by a thread of their own, so the hook is not
/// kept waiting.
pub(crate) fn note(
    ctx: &Ctx<'_>,
    harness: &str,
    session: Option<&str>,
    ended: bool,
    roots: TranscriptRoots,
) -> ClientReply {
    let (Some(session), true) = (session, matches!(harness, "claude" | "codex")) else {
        return ClientReply::Ok {};
    };
    if !ended {
        if let Ok(mut m) = ctx.shared.marks.lock() {
            m.live.insert(key(harness, session), Instant::now());
        }
        return ClientReply::Ok {};
    }
    if let Ok(mut m) = ctx.shared.marks.lock() {
        m.live.remove(&key(harness, session));
    }
    let files: Vec<Found> = of_session(harness, session, &roots)
        .into_iter()
        .filter(|f| {
            ctx.shared
                .marks
                .lock()
                .map(|m| m.deferred.contains(&path_key(&f.path)))
                .unwrap_or(false)
        })
        .collect();
    if files.is_empty() {
        return ClientReply::Ok {};
    }
    let (values, vaults) = held(ctx);
    let cleaner = Cleaner::new(&values);
    drop(values);
    let shared: Arc<Shared> = ctx.shared.clone();
    let _ = std::thread::Builder::new()
        .name("transcript-end".to_string())
        .spawn(move || {
            std::thread::sleep(FLUSH_WAIT);
            let mut names: Vec<String> = Vec::new();
            let (mut cleaned, mut failed) = (0usize, 0usize);
            for f in &files {
                match handle(&shared, &cleaner, f, true) {
                    Some((file, tally)) => {
                        if file.state == TranscriptState::Cleaned {
                            cleaned += 1;
                        } else {
                            failed += 1;
                        }
                        names.extend(tally.names);
                    }
                    // Nothing left in it (cleaned by hand, or the file is gone).
                    None => {
                        if let Ok(mut m) = shared.marks.lock() {
                            m.deferred.remove(&path_key(&f.path));
                        }
                    }
                }
            }
            names.sort();
            names.dedup();
            mark_exposed(&shared, &names, &vaults);
            shared
                .journal
                .record(Entry::new("transcript_scrub").names(&names).result(
                    if failed == 0 { "ok" } else { "partial" },
                    Some(&format!("session ended; {cleaned} cleaned, {failed} not")),
                ));
        });
    ClientReply::Ok {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_names_a_project_folder_by_its_path() {
        assert_eq!(
            claude_project_dir(Path::new("/home/ann/Projects/my app.v2")),
            "-home-ann-Projects-my-app-v2"
        );
    }
}
