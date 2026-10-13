//! A `vahta run` the hook may approve out loud.
//!
//! Claude Code, Codex and Cursor stop an unattended `vahta run` with their own
//! permission prompts or their auto-review. A blanket allow rule for `vahta
//! run` would also allow `vahta run -- rm -rf ~`: the harness matches a prefix
//! and cannot see the rules of the secret. So the hook says "allow" only for a
//! command it can read completely, and only after the daemon has checked the
//! inner command against the secret's own rules (`ClientRequest::CheckRun`).
//!
//! What is read: exactly one command, `vahta run [options] -- INNER...` (or
//! `vh`), spelled as a bare word so the shell finds the real one on its PATH.
//! Anything that makes the shell do more than split words (a second command,
//! a pipe, a redirection, a subshell, an expansion, a glob, a backslash, an
//! assignment before the program) is no opinion, because the words the hook
//! sees would not be the words that run. So are options it does not know, a
//! missing `--`, and an inner command that is itself `vahta`.

use crate::readguard::{Tok, tokenize};

/// A `vahta run` read in full.
#[derive(Debug, PartialEq, Eq)]
pub struct RunCall {
    /// The `--secret` names, in order; empty means the project's `vahta.toml`.
    pub names: Vec<String>,
    /// The command after `--`.
    pub argv: Vec<String>,
}

/// Characters after which the shell no longer just splits words, or the quotes
/// do not mean what the tokenizer thinks. Checked on the raw text, quoted or
/// not: a command that needs them quoted is left to the harness.
fn shell_special(c: char) -> bool {
    matches!(
        c,
        '$' | '`'
            | '*'
            | '?'
            | '['
            | ']'
            | '{'
            | '}'
            | '~'
            | '!'
            | '\\'
            | '#'
            | '<'
            | '>'
            | '('
            | ')'
            | '&'
            | ';'
            | '|'
    ) || (c.is_control() && c != '\t')
}

/// Whether every quote is closed (the tokenizer is lenient about that).
fn quotes_closed(cmd: &str) -> bool {
    let mut open: Option<char> = None;
    for c in cmd.chars() {
        match open {
            Some(q) if c == q => open = None,
            Some(_) => {}
            None if c == '\'' || c == '"' => open = Some(c),
            None => {}
        }
    }
    open.is_none()
}

/// `vahta` or `vh`, as a bare word.
fn is_vahta_word(w: &str) -> bool {
    w == "vahta" || w == "vh"
}

/// Read `cmd` as one `vahta run`, or `None`.
pub fn parse(cmd: &str) -> Option<RunCall> {
    if cmd.chars().any(shell_special) || !quotes_closed(cmd) {
        return None;
    }
    let mut words: Vec<String> = Vec::new();
    for t in tokenize(cmd) {
        match t {
            Tok::Word(w) => words.push(w),
            _ => return None,
        }
    }
    let mut it = words.into_iter();
    if !is_vahta_word(&it.next()?) || it.next()? != "run" {
        return None;
    }
    let rest: Vec<String> = it.collect();
    let mut names = Vec::new();
    let mut ask = false;
    let mut reason = false;
    let mut i = 0;
    let mut separated = false;
    // The options `vahta run` knows, read as it reads them (`run_cmd.rs`).
    while let Some(a) = rest.get(i) {
        i += 1;
        match a.as_str() {
            "--" => {
                separated = true;
                break;
            }
            "--ask" => ask = true,
            "--secret" => {
                names.push(rest.get(i)?.clone());
                i += 1;
            }
            "--label" => {
                rest.get(i)?;
                i += 1;
            }
            "--reason" => {
                reason = true;
                rest.get(i)?;
                i += 1;
            }
            "--as" => {
                let (n, var) = rest.get(i)?.split_once('=')?;
                if n.is_empty() || var.is_empty() {
                    return None;
                }
                i += 1;
            }
            _ => return None,
        }
    }
    if !separated {
        return None;
    }
    if reason && !ask {
        return None;
    }
    let argv: Vec<String> = rest[i..].to_vec();
    let program = argv.first()?;
    // `vahta run -- vahta reveal X` would pass the person-only guard (it sees
    // the first `vahta`); a rule set never names `vahta`, and neither do we.
    if program.is_empty() || is_vahta_word(program.rsplit('/').next().unwrap_or(program)) {
        return None;
    }
    Some(RunCall { names, argv })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(names: &[&str], argv: &[&str]) -> Option<RunCall> {
        Some(RunCall {
            names: names.iter().map(|s| s.to_string()).collect(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn a_plain_run_is_read() {
        assert_eq!(
            parse("vahta run --secret A -- cargo test"),
            call(&["A"], &["cargo", "test"])
        );
        assert_eq!(parse("vh run -- echo hi"), call(&[], &["echo", "hi"]));
    }

    #[test]
    fn options_before_the_double_dash_are_read() {
        assert_eq!(
            parse(
                "vahta run --secret A --as A=TOKEN --secret B --label 'deploy it' --ask \
                 --reason 'needs the key' -- curl -s https://example.com/x"
            ),
            call(&["A", "B"], &["curl", "-s", "https://example.com/x"])
        );
    }

    #[test]
    fn quoted_arguments_stay_whole() {
        assert_eq!(
            parse("vahta run --secret A -- sh -c 'echo one two'"),
            call(&["A"], &["sh", "-c", "echo one two"])
        );
        assert_eq!(
            parse("vahta run --secret 'A' -- echo \"a  b\" ''"),
            call(&["A"], &["echo", "a  b", ""])
        );
        // The program may be quoted too.
        assert_eq!(parse("vahta run -- 'ls' -l"), call(&[], &["ls", "-l"]));
    }

    #[test]
    fn no_double_dash_no_opinion() {
        for cmd in [
            "vahta run --secret A echo hi",
            "vahta run --secret A",
            "vahta run",
            "vahta run --secret A --",
            "vahta run --",
            "vahta run --secret",
        ] {
            assert_eq!(parse(cmd), None, "{cmd}");
        }
    }

    #[test]
    fn unknown_or_misused_options_are_no_opinion() {
        for cmd in [
            "vahta run --secret=A -- true",
            "vahta run -s A -- true",
            "vahta run --cwd /tmp -- true",
            "vahta run --help -- true",
            "vahta run --as A -- true",
            "vahta run --as =X -- true",
            "vahta run --reason why -- true",
            "vahta run --secret A --ask --reason -- true",
        ] {
            assert_eq!(parse(cmd), None, "{cmd}");
        }
    }

    #[test]
    fn anything_the_shell_would_do_more_with_is_no_opinion() {
        for cmd in [
            "vahta run --secret A -- true && rm -rf x",
            "vahta run --secret A -- true; rm -rf x",
            "vahta run --secret A -- true | tee out",
            "vahta run --secret A -- true & ",
            "vahta run --secret A -- true > out",
            "vahta run --secret A -- cat < in",
            "vahta run --secret A -- true\nrm x",
            "(vahta run --secret A -- true)",
            "vahta run --secret A -- echo $(id)",
            "vahta run --secret A -- echo `id`",
            "vahta run --secret A -- echo $HOME",
            "vahta run --secret A -- ls *.txt",
            "vahta run --secret A -- ls ~/x",
            "vahta run --secret A -- echo {a,b}",
            "vahta run --secret A -- echo a\\ b",
            "vahta run --secret A -- echo 'it''s'; id",
            "FOO=1 vahta run --secret A -- true",
            "env vahta run --secret A -- true",
            "sudo vahta run --secret A -- true",
            "cd x && vahta run --secret A -- true",
            "vahta run --secret A -- echo 'unterminated",
            "vahta run --secret A -- echo \"unterminated",
        ] {
            assert_eq!(parse(cmd), None, "{cmd:?}");
        }
    }

    #[test]
    fn only_the_bare_vahta_is_trusted_and_not_as_its_own_inner_command() {
        for cmd in [
            "/tmp/x/vahta run --secret A -- true",
            "./vahta run --secret A -- true",
            "vahta.exe run --secret A -- true",
            "vahta list",
            "vahta runx --secret A -- true",
            "echo vahta run --secret A -- true",
            "vahta run --secret A -- vahta reveal A",
            "vahta run --secret A -- /usr/bin/vh copy A",
        ] {
            assert_eq!(parse(cmd), None, "{cmd}");
        }
    }
}
