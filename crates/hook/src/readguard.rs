//! Reading secret files: the file checks behind `before_read` and the
//! best-effort reader-command check inside `before_tool`.
//!
//! The rule is the scanner's, at its default gate: a file is refused when
//! `leak_count(.., "high")` is above zero (certain and likely findings). A path
//! that does not exist, is not a regular file or cannot be read is allowed.
//! Nothing here returns a value from a file, only the file's kind.
//!
//! # Shell reads: what is and is not covered
//!
//! The command is cut into words (single and double quotes and backslashes are
//! honoured) and into commands at `;`, `&&`, `||`, `|`, `&` and newlines. In
//! each command, after leading `VAR=value`, `sudo`, `command`, `exec`, `time`,
//! `nohup` and `builtin`, the program name's basename is compared with a fixed
//! list of readers; every non-flag argument that is an existing regular file
//! is checked, as is the target of any `<` redirection (whatever the program).
//! `~/` is expanded. Not covered: globs (`cat .env*`), `$VARS` and command
//! substitution in paths, directories (`grep -r x .`), here-documents, files
//! named by a script (`python -c`, `node`), `xargs`, and any program not in
//! the list. `env` and `printenv` are out of scope. This is a speed bump for an
//! agent that did not try to hide the read, not a sandbox.

use std::path::{Path, PathBuf};

use vahta_scan::content::{findings_for_content, findings_for_path};
use vahta_scan::finding::{Scope, leak_count};

const READERS: &[&str] = &[
    "cat", "head", "tail", "less", "more", "bat", "nl", "tac", "grep", "rg", "sed", "awk",
    "strings", "xxd", "od", "base64", "sort", "uniq", "cut", "source", ".",
];
const WRAPPERS: &[&str] = &["sudo", "command", "exec", "time", "nohup", "builtin"];

/// The kind of the first finding at the gate, if any.
fn gated_kind(findings: &[vahta_scan::Finding]) -> Option<String> {
    findings
        .iter()
        .find(|f| leak_count(std::slice::from_ref(f), "high") > 0)
        .map(|f| f.kind.clone())
}

/// `given` made absolute against `cwd` (or the process's directory), with a
/// leading `~/` expanded.
fn resolve(given: &str, cwd: Option<&str>) -> PathBuf {
    let p = if let Some(rest) = given.strip_prefix("~/") {
        match std::env::var_os("HOME") {
            Some(h) => Path::new(&h).join(rest),
            None => PathBuf::from(given),
        }
    } else {
        PathBuf::from(given)
    };
    if p.is_absolute() {
        return p;
    }
    match cwd {
        Some(c) if !c.is_empty() => Path::new(c).join(p),
        _ => p,
    }
}

/// The kind of secret in the file at `given`, from disk, or from `content`
/// when the harness supplied it.
pub fn secret_kind_in(given: &str, cwd: Option<&str>, content: Option<&str>) -> Option<String> {
    if given.is_empty() {
        return None;
    }
    let path = resolve(given, cwd);
    match content {
        Some(text) => gated_kind(&findings_for_content(
            &path,
            text.as_bytes(),
            Scope::Project,
        )),
        None => {
            if !std::fs::metadata(&path).ok()?.is_file() {
                return None;
            }
            gated_kind(&findings_for_path(&path, Scope::Project))
        }
    }
}

enum Tok {
    Word(String),
    /// `;`, `&&`, `||`, `|`, `&`, newline.
    Sep,
    /// `<` (not `<<`, not `<(`).
    RedirectIn,
    /// `>`, `>>`, `>|`, `&>`: the next word is a file that is written.
    RedirectOut,
    /// `>&` and `<&`: the next word is a file descriptor, not a file.
    RedirectDup,
}

/// Shell words and separators. Lenient: an unterminated quote runs to the end.
#[allow(unused_assignments)]
fn tokenize(cmd: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut have = false;
    let mut it = cmd.chars().peekable();
    macro_rules! flush {
        () => {
            if have {
                out.push(Tok::Word(std::mem::take(&mut word)));
                have = false;
            }
        };
    }
    while let Some(c) = it.next() {
        match c {
            '\'' => {
                have = true;
                for q in it.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    word.push(q);
                }
            }
            '"' => {
                have = true;
                while let Some(q) = it.next() {
                    match q {
                        '"' => break,
                        '\\' => match it.peek() {
                            Some(&n) if matches!(n, '"' | '\\' | '$' | '`') => {
                                word.push(n);
                                it.next();
                            }
                            _ => word.push('\\'),
                        },
                        _ => word.push(q),
                    }
                }
            }
            '\\' => {
                have = true;
                match it.next() {
                    Some('\n') => {}
                    Some(n) => word.push(n),
                    None => word.push('\\'),
                }
            }
            ' ' | '\t' | '\r' => flush!(),
            '\n' | ';' | '&' | '|' => {
                flush!();
                if matches!(c, '&' | '|') && it.peek() == Some(&c) {
                    it.next();
                }
                out.push(Tok::Sep);
            }
            '<' => {
                flush!();
                match it.peek() {
                    Some('<') | Some('(') => {
                        it.next();
                        out.push(Tok::Sep);
                    }
                    Some('&') => {
                        it.next();
                        out.push(Tok::RedirectDup);
                    }
                    _ => out.push(Tok::RedirectIn),
                }
            }
            '>' => {
                // A file descriptor number just before it (`2>`) is not an
                // argument of the command.
                if have && word.chars().all(|d| d.is_ascii_digit()) {
                    word.clear();
                    have = false;
                } else {
                    flush!();
                }
                if it.peek() == Some(&'>') || it.peek() == Some(&'|') {
                    it.next();
                }
                if it.peek() == Some(&'&') {
                    it.next();
                    out.push(Tok::RedirectDup);
                } else {
                    out.push(Tok::RedirectOut);
                }
            }
            _ => {
                have = true;
                word.push(c);
            }
        }
    }
    flush!();
    out
}

fn is_assignment(w: &str) -> bool {
    match w.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// The paths a shell command may read, as written in it.
fn read_candidates(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut redirect = false;
    // The word after `>`, `>&` or `<&` is a target to write or a descriptor:
    // it is not something being read.
    let mut ignore_next = false;
    let flush = |words: &mut Vec<String>, out: &mut Vec<String>| {
        let mut i = 0;
        while i < words.len() && (is_assignment(&words[i]) || WRAPPERS.contains(&words[i].as_str()))
        {
            i += 1;
        }
        if let Some(prog) = words.get(i) {
            let base = prog.rsplit('/').next().unwrap_or(prog);
            if READERS.contains(&base) {
                let mut only_args = false;
                for w in &words[i + 1..] {
                    if only_args || !w.starts_with('-') {
                        out.push(w.clone());
                    } else if w == "--" {
                        only_args = true;
                    }
                }
            }
        }
        words.clear();
    };
    for t in tokenize(cmd) {
        match t {
            Tok::Word(_) if ignore_next => ignore_next = false,
            Tok::Word(w) if redirect => {
                out.push(w);
                redirect = false;
            }
            Tok::Word(w) => words.push(w),
            Tok::RedirectIn => redirect = true,
            Tok::RedirectOut | Tok::RedirectDup => ignore_next = true,
            Tok::Sep => {
                redirect = false;
                ignore_next = false;
                flush(&mut words, &mut out);
            }
        }
    }
    flush(&mut words, &mut out);
    out
}

/// The first file named in the shell command that holds secrets: its path as
/// written, and its kind.
pub fn secret_file_in_command(cmd: &str, cwd: Option<&str>) -> Option<(String, String)> {
    read_candidates(cmd)
        .into_iter()
        .find_map(|given| secret_kind_in(&given, cwd, None).map(|k| (given, k)))
}

// --- Vahta's own files ---------------------------------------------------------------

/// Programs that change files, besides the readers: `rm`, `mv`, `cp` and the
/// like. Their arguments are checked against Vahta's own files.
const MUTATORS: &[&str] = &[
    "rm", "mv", "cp", "ln", "tee", "dd", "truncate", "shred", "install", "rsync", "touch", "chmod",
    "chown", "unlink", "rmdir", "scp", "ed", "ex", "vi", "vim", "nano", "emacs",
];

/// The name of the directory that holds a project's vault, its lock and its
/// backups.
const VAULT_DIR: &str = ".vahta";

/// `<data dir>/vahta`: `VAHTA_DATA_DIR` if set, else the platform's data
/// directory plus `vahta` (the store, the state files and the journal).
fn data_root() -> Option<PathBuf> {
    match std::env::var_os("VAHTA_DATA_DIR") {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => dirs::data_dir().map(|d| d.join("vahta")),
    }
}

/// `path` without `.` and `..`, made lexically (no file system), so a path that
/// does not exist can still be placed.
fn normalise(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `path` with the part that exists resolved through symlinks, so a link into a
/// protected place is seen for what it points at.
fn resolved(path: &Path) -> PathBuf {
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut base = path.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&base) {
            let mut out = real;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (base.file_name().map(|n| n.to_os_string()), base.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                base = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn component_is_vault_dir(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(VAULT_DIR))
    })
}

fn inside(path: &Path, root: &Path) -> bool {
    let (a, b) = (normalise(path), normalise(root));
    a.starts_with(&b)
        || a.to_string_lossy()
            .to_lowercase()
            .starts_with(&b.to_string_lossy().to_lowercase())
            && cfg!(any(windows, target_os = "macos"))
}

/// Whether `given` is one of Vahta's own files: anything in a `.vahta/`
/// directory (the vault, its lock, its backups, whatever else lives there) or in
/// `<data dir>/vahta/` (the local store of what this machine has seen of each
/// vault, and the journal). The file need not exist, and a symlink into either
/// place counts. Says nothing of a file's content: only where it is.
pub fn is_vahta_path(given: &str, cwd: Option<&str>) -> bool {
    if given.is_empty() {
        return false;
    }
    let path = resolve(given, cwd);
    let lexical = normalise(&path);
    let real = resolved(&lexical);
    for p in [&lexical, &real] {
        if component_is_vault_dir(p) {
            return true;
        }
    }
    if let Some(root) = data_root() {
        let real_root = resolved(&normalise(&root));
        for p in [&lexical, &real] {
            if inside(p, &root) || inside(p, &real_root) {
                return true;
            }
        }
    }
    false
}

/// The first of `candidates` that is one of Vahta's own files, as written.
fn first_vahta_path(candidates: Vec<String>, cwd: Option<&str>) -> Option<String> {
    candidates.into_iter().find(|c| is_vahta_path(c, cwd))
}

/// Every word of a shell command that names something a reader or a mutator
/// acts on, and every redirection target. A word with `=` (`of=file`,
/// `--target-directory=dir`) also counts for what follows the `=`.
fn touched_candidates(cmd: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut redirect = false; // the next word is a file to read or write
    let mut ignore_next = false; // the next word is a descriptor
    let flush = |words: &mut Vec<String>, out: &mut Vec<String>| {
        let mut i = 0;
        while i < words.len() && (is_assignment(&words[i]) || WRAPPERS.contains(&words[i].as_str()))
        {
            i += 1;
        }
        if let Some(prog) = words.get(i) {
            let base = prog.rsplit(['/', '\\']).next().unwrap_or(prog);
            if READERS.contains(&base) || MUTATORS.contains(&base) {
                for w in &words[i + 1..] {
                    match w.split_once('=') {
                        Some((_, value)) if !value.is_empty() => out.push(value.to_string()),
                        _ => {}
                    }
                    if !w.starts_with('-') {
                        out.push(w.clone());
                    }
                }
            }
        }
        words.clear();
    };
    for t in tokenize(cmd) {
        match t {
            Tok::Word(_) if ignore_next => ignore_next = false,
            Tok::Word(w) if redirect => {
                out.push(w);
                redirect = false;
            }
            Tok::Word(w) => words.push(w),
            Tok::RedirectIn | Tok::RedirectOut => redirect = true,
            Tok::RedirectDup => ignore_next = true,
            Tok::Sep => {
                redirect = false;
                ignore_next = false;
                flush(&mut words, &mut out);
            }
        }
    }
    flush(&mut words, &mut out);
    out
}

/// The first of Vahta's own files a shell command reads, writes, removes,
/// moves or copies, as written. Best effort in the same way as
/// [`secret_file_in_command`]: not covered are globs, `$VARS`, command
/// substitution, a path built by a script or an interpreter, and a directory
/// whose contents include a vault.
pub fn vahta_file_in_command(cmd: &str, cwd: Option<&str>) -> Option<String> {
    first_vahta_path(touched_candidates(cmd), cwd)
}

/// The paths a Codex `apply_patch` patch adds, updates, deletes or moves to.
pub fn patch_paths(text: &str) -> Vec<String> {
    const HEADERS: &[&str] = &[
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    text.lines()
        .filter_map(|l| {
            let l = l.trim_start();
            HEADERS
                .iter()
                .find_map(|h| l.strip_prefix(h))
                .map(|p| p.trim().to_string())
        })
        .filter(|p| !p.is_empty())
        .collect()
}

/// The first of Vahta's own files a patch touches.
pub fn vahta_file_in_patch(text: &str, cwd: Option<&str>) -> Option<String> {
    first_vahta_path(patch_paths(text), cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(cmd: &str) -> Vec<String> {
        read_candidates(cmd)
    }

    #[test]
    fn output_redirections_are_not_read_candidates_and_descriptors_are_not_files() {
        assert_eq!(c("cat .env > out.txt"), [".env"]);
        assert_eq!(c("cat .env 2>&1 | head"), [".env"]);
        assert_eq!(c("cat 2>/dev/null .env"), [".env"]);
        assert_eq!(c("cat .env >> out.txt"), [".env"]);
        assert_eq!(c("cat .env &> out.txt"), [".env"]);
        assert_eq!(c("base64 < .env > out"), [".env"]);
    }

    fn t(cmd: &str) -> Vec<String> {
        touched_candidates(cmd)
    }

    #[test]
    fn what_a_reader_or_a_mutator_or_a_redirection_touches() {
        assert_eq!(t("rm -rf .vahta"), [".vahta"]);
        assert_eq!(
            t("cp .vahta/vault.vht /tmp/x"),
            [".vahta/vault.vht", "/tmp/x"]
        );
        assert_eq!(t("echo hi > .vahta/vault.vht"), [".vahta/vault.vht"]);
        assert_eq!(t("echo hi >> .vahta/vault.vht"), [".vahta/vault.vht"]);
        assert_eq!(t("echo hi 2> .vahta/lock"), [".vahta/lock"]);
        assert_eq!(
            t("dd if=a of=.vahta/vault.vht"),
            ["a", "if=a", ".vahta/vault.vht", "of=.vahta/vault.vht"]
        );
        assert_eq!(t("cp --target-directory=.vahta x"), [".vahta", "x"]);
        assert_eq!(t("sudo cat .vahta/vault.vht | wc -c"), [".vahta/vault.vht"]);
        assert_eq!(t("FOO=1 mv a b; ls .vahta"), ["a", "b"]);
        assert!(t("echo .vahta").is_empty());
        assert!(t("vahta list").is_empty());
        assert_eq!(t("cat 2>&1 .vahta/vault.vht"), [".vahta/vault.vht"]);
    }

    #[test]
    fn a_patch_names_the_files_it_touches() {
        let patch = "*** Begin Patch\n*** Update File: .vahta/vault.vht\n+x\n*** Add File: new.txt\n*** Move to: .vahta/b\n*** End Patch";
        assert_eq!(
            patch_paths(patch),
            [".vahta/vault.vht", "new.txt", ".vahta/b"]
        );
        assert_eq!(
            vahta_file_in_patch(patch, None).as_deref(),
            Some(".vahta/vault.vht")
        );
        assert_eq!(
            vahta_file_in_patch("*** Update File: src/main.rs\n", None),
            None
        );
    }

    #[test]
    fn vahta_paths_are_recognised_by_where_they_are() {
        let tmp = std::env::temp_dir().join(format!("vahta-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("proj/.vahta")).unwrap();
        std::fs::create_dir_all(tmp.join("proj/src")).unwrap();
        std::fs::write(tmp.join("proj/.vahta/vault.vht"), "x").unwrap();
        let cwd = tmp.join("proj");
        let cwd = cwd.to_str().unwrap();
        // The vault, its lock and a backup, with or without existing, however
        // the path is spelled.
        for p in [
            ".vahta",
            ".vahta/",
            ".vahta/vault.vht",
            "./.vahta/vault.lock",
            "src/../.vahta/vault.vht.v1-backup",
            ".vahta/not/yet/there",
            ".VAHTA/vault.vht",
        ] {
            assert!(is_vahta_path(p, Some(cwd)), "{p}");
        }
        assert!(is_vahta_path(&format!("{cwd}/.vahta/vault.vht"), None));
        // Not Vahta's: the manifest, look-alikes, ordinary files.
        for p in [
            "vahta.toml",
            "src/main.rs",
            ".vahta-notes/x",
            "vahta/vault.vht",
            "",
            ".vaht",
        ] {
            assert!(!is_vahta_path(p, Some(cwd)), "{p:?}");
        }
        // A symlink into the vault directory is the vault directory.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(tmp.join("proj/.vahta"), tmp.join("proj/src/link")).unwrap();
            assert!(is_vahta_path("src/link/vault.vht", Some(cwd)));
            assert!(is_vahta_path("src/link", Some(cwd)));
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn readers_and_their_file_arguments() {
        assert_eq!(c("cat .env"), [".env"]);
        assert_eq!(c("grep -r x .env"), ["x", ".env"]);
        assert_eq!(c("echo hi && cat 'a b.txt' | head -n 3"), ["a b.txt", "3"]);
        assert_eq!(c("FOO=1 sudo /bin/cat \"my .env\""), ["my .env"]);
        assert_eq!(c("base64 < .env"), [".env"]);
        assert_eq!(c("cat -- -x"), ["-x"]);
        assert!(c("echo .env; ls .env").is_empty());
        assert_eq!(c("true;cat .env"), [".env"]);
    }
}
