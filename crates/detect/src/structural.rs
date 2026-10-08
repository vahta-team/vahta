//! Rules that need parsing, so they are code and not data: a password inside a
//! connection string, a password given to a program on its command line, an
//! AWS secret handed to `aws configure set`, a private-key header.
//!
//! Each one looks at the shape around the value and then asks
//! [`classify_value`] about the value itself, so a `${VAR}`, a placeholder or a
//! marked test value (`fake-plain-value-1`) is let through exactly as it is
//! for an assignment.
//!
//! Never returns or logs values.

use crate::classify::{
    Confidence, classify_value, is_marked_test_value, is_placeholder, starts_with_reference,
};

/// What a structural rule found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Structural {
    /// Shown to the agent, with its article.
    pub category: &'static str,
    /// Shown to the person.
    pub rule: &'static str,
    pub description: &'static str,
    pub confidence: Confidence,
}

const CONN: Structural = Structural {
    category: "a password in a connection string",
    rule: "vahta.connection-string",
    description: "A password inside a connection string (scheme://user:password@host)",
    confidence: Confidence::Likely,
};

const PEM: Structural = Structural {
    category: "a private key block",
    rule: "vahta.pem-private-key",
    description: "A PEM or PGP private-key header",
    confidence: Confidence::Likely,
};

const CLI_PASSWORD: Structural = Structural {
    category: "a password passed on the command line",
    rule: "vahta.cli-password",
    description: "A password given to a program as an argument (mysql -p, docker login -p, sshpass -p, curl -u, ...)",
    confidence: Confidence::Likely,
};

const ENV_PASSWORD: Structural = Structural {
    category: "a password set in the environment",
    rule: "vahta.env-password",
    description: "A password in a conventional environment variable (PGPASSWORD, MYSQL_PWD, ...)",
    confidence: Confidence::Likely,
};

const AWS_CONFIGURE: Structural = Structural {
    category: "an AWS secret key",
    rule: "vahta.aws-configure-set",
    description: "An AWS secret access key or session token given to `aws configure set`",
    confidence: Confidence::Likely,
};

/// Schemes whose URL carries a login.
const CONNECTION_SCHEMES: &[&str] = &[
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "redis",
    "rediss",
    "mongodb",
    "mongodb+srv",
    "amqp",
    "amqps",
    "mssql",
    "sqlserver",
    "clickhouse",
    "ftp",
    "ftps",
];

/// Environment variables that hold a password by convention, though their
/// names do not end in one of the generic keywords.
const ENV_PASSWORDS: &[&str] = &["PGPASSWORD", "MYSQL_PWD", "REDISCLI_AUTH", "SSHPASS"];

/// Words in a text that make it worth tokenising it as shell commands.
const PROGRAMS: &[&str] = &[
    "mysql",
    "mariadb",
    "docker",
    "podman",
    "nerdctl",
    "sshpass",
    "htpasswd",
    "smbclient",
    "curl",
    "wget",
    "aws",
    "redis-cli",
    "mongo",
    "openssl",
    "gpg",
];

/// A text longer than this is not tokenised as shell.
const MAX_SHELL_BYTES: usize = 1 << 20;
/// Tokens kept per text; a longer command line is read to this point.
const MAX_TOKENS: usize = 20_000;
/// A token is cut here; no password is longer.
const MAX_TOKEN_LEN: usize = 2048;

pub fn find_structural(text: &str) -> Option<Structural> {
    if text.contains("-----BEGIN") && has_private_key_header(text) {
        return Some(PEM);
    }
    if text.contains("://") && has_connection_password(text) {
        return Some(CONN);
    }
    shell_password(text)
}

// --- PEM --------------------------------------------------------------------

/// `-----BEGIN <label>PRIVATE KEY<suffix>-----` with a closing run of dashes,
/// even with no body: the header alone is the sign that a key is being written.
fn has_private_key_header(text: &str) -> bool {
    let mut rest = text;
    while let Some(at) = rest.find("-----BEGIN") {
        let after = &rest[at + "-----BEGIN".len()..];
        // The label is capitals, digits and spaces, and short.
        let label_end = after
            .bytes()
            .take(110)
            .position(|b| !(b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' '));
        if let Some(end) = label_end
            && after[end..].starts_with("-----")
        {
            let label = after[..end].trim();
            if label.ends_with("PRIVATE KEY") || label.ends_with("PRIVATE KEY BLOCK") {
                return true;
            }
        }
        rest = after;
    }
    false
}

// --- connection strings -----------------------------------------------------

fn has_connection_password(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(i) = text[from..].find("://") {
        let at = from + i;
        from = at + 3;
        // The scheme is the run of scheme characters just before `://`.
        let start = bytes[..at]
            .iter()
            .rposition(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')))
            .map_or(0, |p| p + 1);
        let scheme = text[start..at].to_ascii_lowercase();
        if !CONNECTION_SCHEMES.contains(&scheme.as_str()) {
            continue;
        }
        // The authority runs to the first `/ ? #`, whitespace or quote; a
        // password may hold an unescaped `@`, so the login ends at the last one.
        let rest = &text[from..];
        let end = rest
            .bytes()
            .position(|b| {
                b.is_ascii_whitespace() || matches!(b, b'/' | b'?' | b'#' | b'\'' | b'"' | b'`')
            })
            .unwrap_or(rest.len());
        let authority = &rest[..end.min(MAX_TOKEN_LEN)];
        let Some(at_sign) = authority.rfind('@') else {
            continue;
        };
        let login = &authority[..at_sign];
        let Some((_, password)) = login.split_once(':') else {
            continue;
        };
        if password_value(password, false) != Confidence::None {
            return true;
        }
    }
    false
}

// --- passwords given to programs --------------------------------------------

/// How sure we are that `value` is a password. `short_ok` is for an argument
/// that cannot be anything else (`docker login -p`, `sshpass -p`): then a
/// 6-or-7-character mixed value counts as well.
fn password_value(value: &str, short_ok: bool) -> Confidence {
    let v = value.trim_matches(|c| c == '\'' || c == '"');
    if v.is_empty() || starts_with_reference(v) || is_placeholder(v) || is_marked_test_value(v) {
        return Confidence::None;
    }
    if is_angle_or_bracket_placeholder(v) {
        return Confidence::None;
    }
    let (tier, _) = classify_value(v);
    if tier != Confidence::None || !short_ok {
        return tier;
    }
    let n = v.chars().count();
    let classes = [
        v.chars().any(|c| c.is_ascii_lowercase()),
        v.chars().any(|c| c.is_ascii_uppercase()),
        v.chars().any(|c| c.is_ascii_digit()),
        v.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|x| **x)
    .count();
    if (6..8).contains(&n) && classes >= 2 {
        Confidence::Possible
    } else {
        Confidence::None
    }
}

/// `<password>`, `[password]`, `{password}`: a template slot.
fn is_angle_or_bracket_placeholder(v: &str) -> bool {
    let b = v.as_bytes();
    matches!(
        (b.first(), b.last()),
        (Some(b'<'), Some(b'>')) | (Some(b'['), Some(b']')) | (Some(b'{'), Some(b'}'))
    )
}

/// The simple commands of a shell text, as words (quotes removed). A rough
/// reading: it splits on `; & | ( ) \`` and newlines outside quotes, honours
/// `'..'`, `".."` and backslashes, and skips `#` comments. It does not expand
/// anything.
fn commands(text: &str) -> Vec<Vec<String>> {
    let mut cmds: Vec<Vec<String>> = Vec::new();
    let mut cmd: Vec<String> = Vec::new();
    let mut tok = String::new();
    let mut in_tok = false;
    let mut total = 0usize;
    let mut chars = text.chars().peekable();
    macro_rules! end_tok {
        () => {
            if in_tok {
                cmd.push(std::mem::take(&mut tok));
                in_tok = false;
                total += 1;
            }
        };
    }
    macro_rules! end_cmd {
        () => {
            end_tok!();
            if !cmd.is_empty() {
                cmds.push(std::mem::take(&mut cmd));
            }
        };
    }
    while let Some(c) = chars.next() {
        if total > MAX_TOKENS {
            break;
        }
        match c {
            '\n' | ';' | '&' | '|' | '(' | ')' | '`' => {
                end_cmd!();
            }
            ' ' | '\t' | '\r' => {
                end_tok!();
            }
            '#' if !in_tok => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        break;
                    }
                }
                end_cmd!();
            }
            '\\' => match chars.next() {
                Some('\n') => {
                    end_tok!();
                }
                Some(n) => {
                    in_tok = true;
                    push_capped(&mut tok, n);
                }
                None => {}
            },
            '\'' => {
                in_tok = true;
                for n in chars.by_ref() {
                    if n == '\'' {
                        break;
                    }
                    push_capped(&mut tok, n);
                }
            }
            '"' => {
                in_tok = true;
                while let Some(n) = chars.next() {
                    match n {
                        '"' => break,
                        '\\' => {
                            if let Some(e) = chars.next() {
                                if !matches!(e, '"' | '\\' | '$' | '`') {
                                    push_capped(&mut tok, '\\');
                                }
                                push_capped(&mut tok, e);
                            }
                        }
                        n => push_capped(&mut tok, n),
                    }
                }
            }
            c => {
                in_tok = true;
                push_capped(&mut tok, c);
            }
        }
    }
    if in_tok {
        cmd.push(tok);
    }
    if !cmd.is_empty() {
        cmds.push(cmd);
    }
    cmds
}

fn push_capped(tok: &mut String, c: char) {
    if tok.len() < MAX_TOKEN_LEN {
        tok.push(c);
    }
}

fn basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

/// `NAME=value` where NAME is a plain identifier.
fn env_assignment(tok: &str) -> Option<(&str, &str)> {
    let (name, value) = tok.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    (first.is_ascii_alphabetic() || first == '_')
        .then_some(())
        .filter(|_| chars.all(|c| c.is_ascii_alphanumeric() || c == '_'))?;
    Some((name, value))
}

fn is_known_program(name: &str) -> bool {
    PROGRAMS.contains(&name)
        || name.starts_with("mysql")
        || name.starts_with("mariadb")
        || name == "mongosh"
}

const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "nohup", "time", "exec", "command", "export", "xargs", "nice", "stdbuf",
    "timeout", "setsid", "bash", "sh", "zsh", "dash",
];

fn shell_password(text: &str) -> Option<Structural> {
    if text.len() > MAX_SHELL_BYTES {
        return None;
    }
    let mentions_program = PROGRAMS.iter().any(|p| text.contains(p));
    let mentions_env = ENV_PASSWORDS.iter().any(|p| text.contains(p));
    if !mentions_program && !mentions_env {
        return None;
    }
    for cmd in commands(text) {
        if let Some(found) = check_command(&cmd, mentions_program) {
            return Some(found);
        }
        // `sh -c '...'`: read the script too, one level.
        if let Some(pos) = cmd.iter().position(|t| t == "-c")
            && cmd
                .iter()
                .take(pos)
                .any(|t| matches!(basename(t), "sh" | "bash" | "zsh" | "dash"))
            && let Some(script) = cmd.get(pos + 1)
        {
            for inner in commands(script) {
                if let Some(found) = check_command(&inner, mentions_program) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn check_command(cmd: &[String], mentions_program: bool) -> Option<Structural> {
    for tok in cmd {
        if let Some((name, value)) = env_assignment(tok)
            && ENV_PASSWORDS.contains(&name)
            && password_value(value, true) != Confidence::None
        {
            return Some(ENV_PASSWORD);
        }
    }
    if !mentions_program {
        return None;
    }
    let mut after_wrapper = false;
    let mut index = None;
    for (i, tok) in cmd.iter().enumerate().take(10) {
        if env_assignment(tok).is_some() {
            continue;
        }
        let name = basename(tok);
        if is_known_program(name) {
            index = Some(i);
            break;
        }
        if WRAPPERS.contains(&name) {
            after_wrapper = true;
            continue;
        }
        if after_wrapper {
            continue;
        }
        break;
    }
    let i = index?;
    let program = basename(&cmd[i]);
    let args = &cmd[i + 1..];
    program_password(program, args)
}

/// The value after `flag` (`-p VALUE`, `--password VALUE` or `--password=VALUE`).
fn flag_value<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    for (i, a) in args.iter().enumerate() {
        for f in flags {
            if a == f {
                return args.get(i + 1).map(String::as_str);
            }
            if f.starts_with("--")
                && let Some(v) = a.strip_prefix(&format!("{f}="))
            {
                return Some(v);
            }
        }
    }
    None
}

fn program_password(program: &str, args: &[String]) -> Option<Structural> {
    let hit = |c: Confidence| (c != Confidence::None).then_some(CLI_PASSWORD);
    match program {
        // `-pVALUE` attached: `-p VALUE` is a prompt and then a database name.
        p if p.starts_with("mysql") || p.starts_with("mariadb") => args
            .iter()
            .filter(|a| a.starts_with("-p") && !a.starts_with("--"))
            .find_map(|a| hit(password_value(&a[2..], true))),
        "docker" | "podman" | "nerdctl" => {
            if !args.iter().any(|a| a == "login") {
                return None;
            }
            let attached = args
                .iter()
                .filter(|a| a.starts_with("-p") && a.len() > 2 && !a.starts_with("--"))
                .find_map(|a| hit(password_value(&a[2..], true)));
            attached.or_else(|| {
                flag_value(args, &["-p", "--password"]).and_then(|v| hit(password_value(v, true)))
            })
        }
        "sshpass" => {
            let attached = args
                .iter()
                .filter(|a| a.starts_with("-p") && a.len() > 2)
                .find_map(|a| hit(password_value(&a[2..], true)));
            attached
                .or_else(|| flag_value(args, &["-p"]).and_then(|v| hit(password_value(v, true))))
        }
        "htpasswd" => htpasswd_password(args).and_then(|v| hit(password_value(v, true))),
        "smbclient" => {
            let login = flag_value(args, &["-U", "--user"]).or_else(|| {
                args.iter()
                    .find(|a| a.starts_with("-U") && a.len() > 2)
                    .map(|a| &a[2..])
            })?;
            let (_, pw) = login.split_once('%')?;
            hit(password_value(pw, true))
        }
        "curl" => {
            let login = flag_value(args, &["-u", "--user"]).or_else(|| {
                args.iter()
                    .find(|a| a.starts_with("-u") && a.len() > 2 && !a.starts_with("--"))
                    .map(|a| &a[2..])
            })?;
            let (_, pw) = login.split_once(':')?;
            hit(password_value(pw, true))
        }
        "wget" => flag_value(
            args,
            &[
                "--password",
                "--http-password",
                "--ftp-password",
                "--proxy-password",
            ],
        )
        .and_then(|v| hit(password_value(v, true))),
        "redis-cli" => {
            flag_value(args, &["-a", "--pass"]).and_then(|v| hit(password_value(v, true)))
        }
        "mongo" | "mongosh" => {
            flag_value(args, &["-p", "--password"]).and_then(|v| hit(password_value(v, true)))
        }
        "openssl" => ["-pass", "-passin", "-passout"]
            .iter()
            .filter_map(|f| flag_value(args, &[f]))
            .filter_map(|v| v.strip_prefix("pass:"))
            .find_map(|v| hit(password_value(v, true))),
        "gpg" => flag_value(args, &["--passphrase"]).and_then(|v| hit(password_value(v, true))),
        "aws" => {
            let pos = args.iter().position(|a| a == "configure")?;
            if args.get(pos + 1).map(String::as_str) != Some("set") {
                return None;
            }
            let name = args.get(pos + 2)?.to_ascii_lowercase();
            if !(name.ends_with("secret_access_key") || name.ends_with("session_token")) {
                return None;
            }
            let value = args.get(pos + 3)?;
            (password_value(value, true) != Confidence::None).then_some(AWS_CONFIGURE)
        }
        _ => None,
    }
}

/// `htpasswd -b [-c] [-n] file user PASSWORD`: with `-n` there is no file.
fn htpasswd_password(args: &[String]) -> Option<&str> {
    let flags: String = args
        .iter()
        .filter(|a| a.starts_with('-') && !a.starts_with("--"))
        .flat_map(|a| a[1..].chars())
        .collect();
    if !flags.contains('b') {
        return None;
    }
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let index = if flags.contains('n') { 1 } else { 2 };
    positional.get(index).map(|s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built from pieces: the hook that guards this repository reads the source.
    fn pw() -> String {
        ["x7Kq", "2NvR", "9pLm", "Wd4z"].concat()
    }

    fn found(text: &str) -> Option<&'static str> {
        find_structural(text).map(|s| s.rule)
    }

    #[test]
    fn connection_strings_with_a_password() {
        for scheme in [
            "postgres",
            "postgresql",
            "mysql",
            "mariadb",
            "redis",
            "rediss",
            "mongodb",
            "mongodb+srv",
            "amqp",
            "amqps",
            "mssql",
            "sqlserver",
            "clickhouse",
            "ftp",
        ] {
            let url = format!("{scheme}://app:{}@db.internal:1234/x", pw());
            assert_eq!(found(&url), Some("vahta.connection-string"), "{scheme}");
        }
        let jdbc = format!("jdbc:postgresql://app:{}@db/x", pw());
        assert_eq!(found(&jdbc), Some("vahta.connection-string"));
    }

    #[test]
    fn connection_strings_without_a_real_password_are_let_through() {
        for url in [
            "postgres://localhost:5432/app".to_string(),
            "postgres://app@localhost/app".to_string(),
            "postgres://admin:${DB_PASSWORD}@db/app".to_string(),
            "postgres://admin:$DB_PASSWORD@db/app".to_string(),
            "postgres://admin:password@db/app".to_string(),
            "postgres://admin:fake-plain-value-1@db/app".to_string(),
            "postgres://user:<password>@db/app".to_string(),
            "https://user:hunter2hunter2@example.com/".to_string(),
            "postgres://postgres:postgres@localhost/app".to_string(),
        ] {
            assert_eq!(found(&url), None, "{url}");
        }
    }

    #[test]
    fn a_private_key_header_blocks_without_a_body() {
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "EC PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ] {
            let header = format!("{}BEGIN {label}{}", "-".repeat(5), "-".repeat(5));
            assert_eq!(found(&header), Some("vahta.pem-private-key"), "{label}");
        }
        for text in [
            "grep -r \"BEGIN PRIVATE KEY\" .",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----",
            "the -----BEGIN marker",
        ] {
            assert_eq!(found(text), None, "{text}");
        }
    }

    #[test]
    fn passwords_on_a_command_line() {
        let p = pw();
        for cmd in [
            format!("mysql -u root -p{p} app"),
            format!("mysqldump -uroot -p{p} app"),
            format!("docker login -u deploy -p {p} registry.internal"),
            format!("docker login --password {p} registry.internal"),
            format!("docker login --password={p}"),
            format!("sshpass -p {p} ssh host"),
            format!("sshpass -p'{p}' ssh host"),
            format!("htpasswd -b .htpasswd alice {p}"),
            format!("htpasswd -nb alice {p}"),
            format!("smbclient //srv/share -U alice%{p}"),
            format!("curl -u alice:{p} https://x.internal"),
            format!("curl --user alice:{p} https://x.internal"),
            format!("wget --password {p} https://x.internal"),
            format!("redis-cli -a {p} ping"),
            format!("sudo -u root mysql -p{p}"),
            format!("cd /x && PGPASSWORD={p} psql -h db"),
            format!("export MYSQL_PWD={p}"),
            format!("bash -c 'mysql -u root -p{p}'"),
            format!("aws configure set aws_secret_access_key {p}{p}"),
            format!("openssl enc -aes-256-cbc -pass pass:{p} -in a"),
        ] {
            assert!(found(&cmd).is_some(), "{cmd}");
        }
    }

    #[test]
    fn prompts_and_indirection_on_a_command_line_are_let_through() {
        for cmd in [
            "mysql -u root -p app",
            "mysql -p",
            "docker login -u deploy --password-stdin registry.internal",
            "docker login -u deploy -p \"$REGISTRY_PASSWORD\" registry.internal",
            "docker ps -p 12345678",
            "sshpass -p \"${SSH_PASS}\" ssh host",
            "curl -u alice:$API_PASSWORD https://x.internal",
            "curl -u alice https://x.internal",
            "htpasswd .htpasswd alice",
            "PGPASSWORD=\"$PGPASSWORD\" psql -h db",
            "echo mysql -pfoo",
            "docker login -u deploy -p changeme registry.internal",
        ] {
            assert_eq!(found(cmd), None, "{cmd}");
        }
    }

    #[test]
    fn the_shell_reading_honours_quotes_and_separators() {
        let c = commands("a 'b c' \"d \\\" e\" f\\ g; h && i | j\n# comment\nk");
        assert_eq!(
            c,
            vec![
                vec!["a", "b c", "d \" e", "f g"],
                vec!["h"],
                vec!["i"],
                vec!["j"],
                vec!["k"],
            ]
        );
    }
}
