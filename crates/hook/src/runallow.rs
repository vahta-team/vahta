//! A `vahta run` or `vahta http` the hook may approve out loud.
//!
//! Claude Code, Codex and Cursor stop an unattended `vahta run` with their own
//! permission prompts or their auto-review. A blanket allow rule for `vahta
//! run` would also allow `vahta run -- rm -rf ~`: the harness matches a prefix
//! and cannot see the rules of the secret. So the hook says "allow" only for a
//! command it can read completely, and only after the daemon has checked it
//! against the secret's own rules (`CheckRun` for the inner command of a run,
//! `CheckHttp` for the host of a request).
//!
//! What is read: exactly one command, `vahta run [options] -- INNER...` or
//! `vahta http [options] URL` (or `vh`), spelled as a bare word so the shell
//! finds the real one on its PATH. Anything that makes the shell do more than
//! split words is no opinion, because the words the hook sees would not be the
//! words that run: a second command, a pipe, a redirection, a subshell, an
//! expansion (`$`, backticks), a glob, a `~`, a backslash, brace expansion, an
//! assignment before the program. Inside single quotes everything is literal,
//! so only a newline or control character is refused there; inside double
//! quotes `$`, backtick, `\` and `!` are. Also no opinion: options the command
//! does not know, a run without `--`, an inner command that is itself `vahta`.

use crate::readguard::{Tok, tokenize};

/// A `vahta run` read in full.
#[derive(Debug, PartialEq, Eq)]
pub struct RunCall {
    /// The `--secret` names, in order; empty means the project's `vahta.toml`.
    pub names: Vec<String>,
    /// The command after `--`.
    pub argv: Vec<String>,
}

/// A `vahta http` read in full: the secrets and where the request goes.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpCall {
    pub names: Vec<String>,
    pub url: String,
}

/// What the hook understood the command to be.
#[derive(Debug, PartialEq, Eq)]
pub enum Call {
    Run(RunCall),
    Http(HttpCall),
}

/// Whether the shell does only word splitting and quote removal on `cmd`.
fn plain_shell(cmd: &str) -> bool {
    #[derive(PartialEq)]
    enum Q {
        None,
        Single,
        Double,
    }
    let mut q = Q::None;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_control() && c != '\t' {
            return false;
        }
        match q {
            Q::Single => {
                if c == '\'' {
                    q = Q::None;
                }
            }
            Q::Double => match c {
                '"' => q = Q::None,
                '$' | '`' | '\\' | '!' => return false,
                _ => {}
            },
            Q::None => match c {
                '\'' => q = Q::Single,
                '"' => q = Q::Double,
                // `{NAME}` is a placeholder; any other brace is expansion.
                '{' => {
                    let mut ok = false;
                    for (n, d) in chars.by_ref().enumerate() {
                        if d == '}' {
                            ok = n > 0;
                            break;
                        }
                        if !(d.is_ascii_alphanumeric() || d == '_') {
                            break;
                        }
                    }
                    if !ok {
                        return false;
                    }
                }
                '$' | '`' | '*' | '?' | '[' | ']' | '}' | '~' | '!' | '\\' | '#' | '<' | '>'
                | '(' | ')' | '&' | ';' | '|' => return false,
                _ => {}
            },
        }
    }
    q == Q::None
}

/// `vahta` or `vh`, as a bare word.
fn is_vahta_word(w: &str) -> bool {
    w == "vahta" || w == "vh"
}

/// Read `cmd` as one `vahta run` or `vahta http`, or `None`.
pub fn parse(cmd: &str) -> Option<Call> {
    if !plain_shell(cmd) {
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
    if !is_vahta_word(&it.next()?) {
        return None;
    }
    let sub = it.next()?;
    let rest: Vec<String> = it.collect();
    match sub.as_str() {
        "run" => parse_run(&rest).map(Call::Run),
        "http" => parse_http(&rest).map(Call::Http),
        _ => None,
    }
}

/// The options of `vahta http`, read as it reads them (`http_cmd.rs`).
fn parse_http(rest: &[String]) -> Option<HttpCall> {
    let mut names = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    let mut i = 0;
    while let Some(a) = rest.get(i) {
        i += 1;
        match a.as_str() {
            "--" => {
                urls.extend(rest[i..].iter().cloned());
                break;
            }
            "--json" => {}
            "--secret" => {
                names.push(rest.get(i)?.clone());
                i += 1;
            }
            "-H" | "--header" | "--query" | "-X" | "--request" | "-d" | "--data" | "--timeout"
            | "--max-bytes" | "--label" => {
                rest.get(i)?;
                i += 1;
            }
            other if !other.starts_with('-') => urls.push(other.to_string()),
            _ => return None,
        }
    }
    if names.is_empty() || urls.len() != 1 {
        return None;
    }
    Some(HttpCall {
        names,
        url: urls.remove(0),
    })
}

fn parse_run(rest: &[String]) -> Option<RunCall> {
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

    fn parse_run(cmd: &str) -> Option<RunCall> {
        match parse(cmd) {
            Some(Call::Run(c)) => Some(c),
            _ => None,
        }
    }

    fn parse_http(cmd: &str) -> Option<HttpCall> {
        match parse(cmd) {
            Some(Call::Http(c)) => Some(c),
            _ => None,
        }
    }

    fn call(names: &[&str], argv: &[&str]) -> Option<RunCall> {
        Some(RunCall {
            names: names.iter().map(|s| s.to_string()).collect(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
        })
    }

    #[test]
    fn a_plain_run_is_read() {
        assert_eq!(
            parse_run("vahta run --secret A -- cargo test"),
            call(&["A"], &["cargo", "test"])
        );
        assert_eq!(parse_run("vh run -- echo hi"), call(&[], &["echo", "hi"]));
    }

    #[test]
    fn options_before_the_double_dash_are_read() {
        assert_eq!(
            parse_run(
                "vahta run --secret A --as A=TOKEN --secret B --label 'deploy it' --ask \
                 --reason 'needs the key' -- curl -s https://example.com/x"
            ),
            call(&["A", "B"], &["curl", "-s", "https://example.com/x"])
        );
    }

    #[test]
    fn quoted_arguments_stay_whole() {
        assert_eq!(
            parse_run("vahta run --secret A -- sh -c 'echo one two'"),
            call(&["A"], &["sh", "-c", "echo one two"])
        );
        assert_eq!(
            parse_run("vahta run --secret 'A' -- echo \"a  b\" ''"),
            call(&["A"], &["echo", "a  b", ""])
        );
        // The program may be quoted too.
        assert_eq!(parse_run("vahta run -- 'ls' -l"), call(&[], &["ls", "-l"]));
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
            assert_eq!(parse_run(cmd), None, "{cmd}");
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
            assert_eq!(parse_run(cmd), None, "{cmd}");
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
            assert_eq!(parse_run(cmd), None, "{cmd:?}");
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
            assert_eq!(parse_run(cmd), None, "{cmd}");
        }
    }

    #[test]
    fn single_quotes_make_everything_literal_and_double_quotes_most() {
        assert_eq!(
            parse_run("vahta run --secret A -- sh -c 'echo $HOME; ls *'"),
            call(&["A"], &["sh", "-c", "echo $HOME; ls *"])
        );
        assert_eq!(
            parse_run("vahta run -- echo \"a; b | c\""),
            call(&[], &["echo", "a; b | c"])
        );
        for cmd in [
            "vahta run -- echo \"$HOME\"",
            "vahta run -- echo \"`id`\"",
            "vahta run -- echo 'a\nb'",
        ] {
            assert_eq!(parse_run(cmd), None, "{cmd:?}");
        }
    }

    fn http(names: &[&str], url: &str) -> Option<HttpCall> {
        Some(HttpCall {
            names: names.iter().map(|s| s.to_string()).collect(),
            url: url.to_string(),
        })
    }

    #[test]
    fn a_plain_http_request_is_read_with_its_placeholders() {
        assert_eq!(
            parse_http(
                "vahta http --secret API_KEY -H 'Authorization: Bearer {API_KEY}' \
                 --query key={API_KEY} -X POST -d '{\"a\": 1}' --json https://api.example.com/v1/x"
            ),
            http(&["API_KEY"], "https://api.example.com/v1/x")
        );
        assert_eq!(
            parse_http("vh http --secret A --query k={A} -d @body.json -- https://h.example/"),
            http(&["A"], "https://h.example/")
        );
        assert_eq!(
            parse_http("vahta http --secret A -H 'X: {A}' 'https://h.example/p?q=1&r=2'"),
            http(&["A"], "https://h.example/p?q=1&r=2")
        );
    }

    #[test]
    fn an_http_request_the_hook_cannot_read_whole_is_no_opinion() {
        for cmd in [
            "vahta http -H 'X: y' https://h.example/",
            "vahta http --secret A",
            "vahta http --secret A https://a.example/ https://b.example/",
            "vahta http --secret A --proxy x https://h.example/",
            "vahta http --secret A -H",
            "vahta http --secret A --query k={A,B} https://h.example/",
            "vahta http --secret A --query k={A https://h.example/",
            "vahta http --secret A --query k={a..b} https://h.example/",
            "vahta http --secret A https://h.example/?q=1",
            "vahta http --secret A https://h.example/ && id",
            "vahta http --secret A -H 'X: {A}' https://h.example/ | tee out",
            "vahta http --secret A -d $(cat f) https://h.example/",
            "vahta http --secret A -d @$F https://h.example/",
            "cd x; vahta http --secret A https://h.example/",
        ] {
            assert_eq!(parse_http(cmd), None, "{cmd:?}");
        }
    }
}
