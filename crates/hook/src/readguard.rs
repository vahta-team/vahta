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
                    _ => out.push(Tok::RedirectIn),
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
            Tok::Word(w) if redirect => {
                out.push(w);
                redirect = false;
            }
            Tok::Word(w) => words.push(w),
            Tok::RedirectIn => redirect = true,
            Tok::Sep => {
                redirect = false;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn c(cmd: &str) -> Vec<String> {
        read_candidates(cmd)
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
