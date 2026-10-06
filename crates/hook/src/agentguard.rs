//! Vahta commands an agent must never run.
//!
//! `vahta reveal` shows a value in a window on the screen, and an agent can
//! take a screenshot. `vahta copy` puts a value on the clipboard, and an agent
//! can read the clipboard. `vahta _surface` is the prompt window itself: run by
//! an agent, it could answer a window meant for the person. Each one asks for
//! the password, but an agent asking the person to approve them is exactly the
//! approval fatigue Vahta exists to remove, and none of them has an agent use.
//! Every other `vahta` command may be run by an agent: outside `vahta run` in a
//! session, each asks for the password or an approval in the window anyway.
//!
//! The command is cut into words and commands as the read guard does. A command
//! is ours when its program, after `VAR=value`, the wrappers and `env`, has the
//! base name `vahta` or `vh` (`.exe` allowed, either slash). The first word
//! after it that is not a flag is the subcommand. `sh -c`, `bash -c` and the
//! like are looked into, as is `eval`. A Windows path the tokenizer has eaten
//! the backslashes of still ends in `vahta.exe`. Text that only mentions the
//! words (`git commit -m "vahta reveal"`) is not a command and is allowed. Not
//! covered: `$VARS`, aliases, functions and scripts that run the command.

use crate::readguard::{Tok, WRAPPERS, is_assignment, tokenize};

/// Subcommands an agent may not run.
const FORBIDDEN: &[&str] = &["reveal", "copy", "_surface"];

/// Shells whose `-c` argument is a command line of its own.
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "pwsh",
    "powershell",
];

/// How deep `bash -c 'sh -c "..."'` is followed.
const MAX_NESTING: usize = 4;

/// The program name without directories and a trailing `.exe`.
fn base_name(word: &str) -> &str {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    base.strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base)
}

fn is_vahta(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    matches!(base_name(word), "vahta" | "vh")
        || lower.ends_with("\\vahta.exe")
        || lower.ends_with("\\vh.exe")
        // `C:\bin\vahta.exe` unquoted reaches us as `C:binvahta.exe`.
        || (lower.contains(':') && (lower.ends_with("vahta.exe") || lower.ends_with("vh.exe")))
}

/// The forbidden invocation in one command's words, as `vahta reveal`.
fn in_words(words: &[String], depth: usize) -> Option<String> {
    let mut i = 0;
    loop {
        let w = words.get(i)?;
        if is_assignment(w) || WRAPPERS.contains(&w.as_str()) {
            i += 1;
        } else if base_name(w) == "env" {
            // `env [-i] [-u NAME] [VAR=value]... program`
            i += 1;
            while let Some(a) = words.get(i) {
                if a == "-u" || a == "--unset" {
                    i += 2;
                } else if a.starts_with('-') || is_assignment(a) {
                    i += 1;
                } else {
                    break;
                }
            }
        } else {
            break;
        }
    }
    let prog = words.get(i)?;
    let rest = &words[i + 1..];
    if is_vahta(prog) {
        let sub = rest.iter().find(|a| !a.starts_with('-'))?;
        return FORBIDDEN
            .contains(&sub.as_str())
            .then(|| format!("{} {sub}", base_name(prog)));
    }
    if depth >= MAX_NESTING {
        return None;
    }
    let base = base_name(prog);
    if base == "eval" {
        return forbidden_in(&rest.join(" "), depth + 1);
    }
    if SHELLS.contains(&base) {
        // The argument after `-c` (or `-Command` for PowerShell), possibly
        // after other flags: `bash -lc '...'` included.
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            let is_c = a.starts_with('-')
                && !a.starts_with("--")
                && (a.ends_with('c') || a.eq_ignore_ascii_case("-command"));
            if is_c {
                return it.next().and_then(|cmd| forbidden_in(cmd, depth + 1));
            }
        }
    }
    None
}

fn forbidden_in(cmd: &str, depth: usize) -> Option<String> {
    let mut words: Vec<String> = Vec::new();
    for t in tokenize(cmd) {
        match t {
            Tok::Word(w) => words.push(w),
            _ => {
                if let Some(hit) = in_words(&words, depth) {
                    return Some(hit);
                }
                words.clear();
            }
        }
    }
    in_words(&words, depth)
}

/// The first forbidden Vahta command in a shell command line, as
/// `vahta reveal`, if any.
pub fn forbidden_command(cmd: &str) -> Option<String> {
    forbidden_in(cmd, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forbidden_subcommands_are_caught_however_they_are_spelled() {
        for cmd in [
            "vahta reveal API_KEY",
            "vh copy API_KEY",
            "vahta _surface",
            "/home/u/.local/bin/vahta reveal X",
            "~/.local/bin/vh copy X",
            "FOO=1 vahta reveal X",
            "sudo vahta copy X",
            "env -i PATH=/usr/bin vahta reveal X",
            "env -u HOME vahta copy X",
            "cd proj && vahta reveal X",
            "true; vahta copy X | cat",
            "bash -c 'vahta reveal X'",
            "bash -lc \"cd p && vh copy X\"",
            "sh -c 'bash -c \"vahta reveal X\"'",
            "eval vahta reveal X",
            "vahta --quiet reveal X",
            "\"C:\\Program Files\\Vahta\\vahta.exe\" reveal X",
            "C:\\bin\\vahta.exe copy X",
            "vahta.EXE reveal X",
            "pwsh -Command 'vahta copy X'",
        ] {
            assert!(forbidden_command(cmd).is_some(), "{cmd}");
        }
    }

    #[test]
    fn other_commands_and_mere_mentions_are_allowed() {
        for cmd in [
            "vahta run -- echo reveal",
            "vahta unlock --secret A",
            "vahta list",
            "vahta set copy",
            "vahta",
            "git commit -m 'vahta reveal is blocked for agents'",
            "echo vahta copy",
            "grep -r 'vahta reveal' docs",
            "myvahta reveal X",
            "vahtax copy X",
            "cargo run -p vahta-cli -- list",
            "bash script.sh",
            "bash -c 'vahta list'",
        ] {
            assert_eq!(forbidden_command(cmd), None, "{cmd}");
        }
    }

    #[test]
    fn the_answer_names_the_invocation() {
        assert_eq!(forbidden_command("vh copy X").as_deref(), Some("vh copy"));
        assert_eq!(
            forbidden_command("/x/vahta.exe reveal X").as_deref(),
            Some("vahta reveal")
        );
    }

    #[test]
    fn nesting_is_bounded() {
        let mut cmd = "vahta reveal X".to_string();
        for _ in 0..10 {
            cmd = format!("sh -c {}", shell_quote(&cmd));
        }
        // Too deep to follow: not caught, and no stack trouble.
        assert_eq!(forbidden_command(&cmd), None);
    }

    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
