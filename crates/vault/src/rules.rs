//! Command rules for a secret: the text syntax, the deny groups and the
//! program-name normalisation. Pure; nothing here touches the file system.
//!
//! A rule is one string. The first word is the program, any further words are
//! an argv prefix the command must start with:
//!
//! ```text
//! stripe              a program found in PATH
//! ./scripts/deploy.sh a path, relative to the project root
//! git push            program `git`, argv[1..] begins with ["push"]
//! @network            a deny group (deny only)
//! ```
//!
//! Words are split on whitespace and quoting is not supported: a rule with a
//! quote is refused. There are no regexes.
//!
//! The groups are constants in this file and documented in `docs/daemon.md`.
//! They make a deny list a speed bump, not a wall: a program that is in no
//! group, or a copy under another name, is not caught. `allow` is the guard.

use crate::format::current::{ApprovedRule, Program};

/// `@network`: programs whose job is to move bytes to another machine.
pub const NETWORK: &[&str] = &[
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "http",
    "https",
    "xh",
    "httpie",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ftp",
    "telnet",
    "aria2c",
    "invoke-webrequest",
];

/// `@shells`: programs that run other commands from a string.
pub const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "cmd",
    "nu",
];

/// `@interpreters`: language runtimes that run code from an argument or stdin.
pub const INTERPRETERS: &[&str] = &[
    "python",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "osascript",
];

/// Programs that run another program named in their arguments (`env curl …`,
/// `sudo curl …`). Not a deny group: allowing one of them allows whatever it
/// starts, so the windows warn, and deny matching looks past them to the
/// program they run.
pub const LAUNCHERS: &[&str] = &[
    "env", "sudo", "doas", "xargs", "nohup", "timeout", "nice", "ionice", "time", "exec",
    "command", "setsid", "stdbuf", "chrt", "taskset", "unbuffer", "watch", "flock", "npx", "pnpx",
    "bunx", "uvx", "pipx", "runuser", "su",
];

/// Whether a normalised program name runs other programs: a shell, an
/// interpreter or a launcher. Allowing one gives the secret to anything.
pub fn runs_anything(name: &str) -> bool {
    SHELLS.contains(&name) || INTERPRETERS.contains(&name) || LAUNCHERS.contains(&name)
}

/// The program names of a group (`@network`), or `None` for an unknown group.
pub fn group_members(group: &str) -> Option<&'static [&'static str]> {
    match group {
        "@network" => Some(NETWORK),
        "@shells" => Some(SHELLS),
        "@interpreters" => Some(INTERPRETERS),
        _ => None,
    }
}

/// The names of all groups, for messages.
pub const GROUPS: &[&str] = &["@network", "@shells", "@interpreters"];

/// A program's file name as deny matching sees it: lower case, without
/// `.exe`/`.cmd`/`.bat`, and without a trailing version (`python3.12` becomes
/// `python`). A name that would end up empty stays as it was.
pub fn normalize_program_name(file_name: &str) -> String {
    let mut s = file_name.to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat"] {
        if let Some(stem) = s.strip_suffix(ext) {
            s = stem.to_string();
            break;
        }
    }
    let trimmed = s.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let trimmed = trimmed.trim_end_matches(['-', '_']);
    if trimmed.is_empty() {
        s
    } else {
        trimmed.to_string()
    }
}

/// Whether the normalised `name` is in the group.
pub fn in_group(group: &str, name: &str) -> bool {
    group_members(group).is_some_and(|m| m.contains(&name))
}

/// How the program word of a rule is to be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramSpec {
    /// A bare name: looked up in PATH.
    Bare(String),
    /// Contains a slash: relative to the project root (or absolute).
    Path(String),
    /// `@group`.
    Group(String),
}

/// A rule as written, before a program is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    pub text: String,
    pub program: ProgramSpec,
    pub args: Vec<String>,
}

const MAX_RULE_LEN: usize = 512;

/// Parse one rule. `allow` is whether it is an `allow` rule (a group there is
/// refused). The error is a short sentence for the person.
pub fn parse_rule(text: &str, allow: bool) -> Result<ParsedRule, String> {
    let shown = text.trim();
    if shown.is_empty() {
        return Err("a rule must not be empty".to_string());
    }
    if shown.len() > MAX_RULE_LEN {
        return Err("a rule is too long".to_string());
    }
    if shown.chars().any(char::is_control) {
        return Err(format!(
            "rule `{}` has a control character",
            shown.escape_debug()
        ));
    }
    if shown.contains(['"', '\'', '`']) {
        return Err(format!(
            "rule `{shown}` has a quote; quoting is not supported, split it into plain words"
        ));
    }
    let mut words = shown.split_whitespace();
    let first = words.next().unwrap_or_default();
    let args: Vec<String> = words.map(str::to_string).collect();
    let program = if first.starts_with('@') {
        if allow {
            return Err(format!(
                "`{first}` is a group; groups are only for `deny`, `allow` names programs"
            ));
        }
        if group_members(first).is_none() {
            return Err(format!(
                "unknown group `{first}` (known: {})",
                GROUPS.join(", ")
            ));
        }
        if !args.is_empty() {
            return Err(format!("group `{first}` takes no arguments"));
        }
        ProgramSpec::Group(first.to_string())
    } else if first.contains(['/', '\\']) {
        ProgramSpec::Path(first.to_string())
    } else {
        ProgramSpec::Bare(first.to_string())
    };
    Ok(ParsedRule {
        text: shown.split_whitespace().collect::<Vec<_>>().join(" "),
        program,
        args,
    })
}

impl ParsedRule {
    /// A `deny` rule needs no resolution: it matches by name. The program of a
    /// slash form is reduced to its file name, so a copy elsewhere is caught.
    pub fn to_deny(&self) -> ApprovedRule {
        let program = match &self.program {
            ProgramSpec::Group(g) => Program::Group(g.clone()),
            ProgramSpec::Bare(n) => Program::Name(normalize_program_name(n)),
            ProgramSpec::Path(p) => {
                let file = p.rsplit(['/', '\\']).next().unwrap_or(p);
                Program::Name(normalize_program_name(file))
            }
        };
        ApprovedRule {
            text: self.text.clone(),
            program,
            args: self.args.clone(),
        }
    }

    /// An `allow` rule once its program is resolved to a canonical path.
    pub fn to_allow(&self, canonical: String) -> ApprovedRule {
        ApprovedRule {
            text: self.text.clone(),
            program: Program::Path(canonical),
            args: self.args.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_forms() {
        let r = parse_rule("stripe", true).unwrap();
        assert_eq!(r.program, ProgramSpec::Bare("stripe".into()));
        assert!(r.args.is_empty());
        let r = parse_rule("  git   push ", true).unwrap();
        assert_eq!(r.program, ProgramSpec::Bare("git".into()));
        assert_eq!(r.args, vec!["push"]);
        assert_eq!(r.text, "git push");
        let r = parse_rule("./scripts/deploy.sh", true).unwrap();
        assert_eq!(r.program, ProgramSpec::Path("./scripts/deploy.sh".into()));
        let r = parse_rule("@shells", false).unwrap();
        assert_eq!(r.program, ProgramSpec::Group("@shells".into()));
    }

    #[test]
    fn refuses_what_it_cannot_honour() {
        for (rule, allow) in [
            ("", true),
            ("   ", false),
            ("git \"push now\"", true),
            ("echo 'a'", true),
            ("@bogus", false),
            ("@network", true),
            ("@network extra", false),
            ("a\u{7}b", true),
        ] {
            assert!(parse_rule(rule, allow).is_err(), "{rule:?}");
        }
    }

    #[test]
    fn names_are_normalised() {
        assert_eq!(normalize_program_name("python3.12"), "python");
        assert_eq!(normalize_program_name("Python3"), "python");
        assert_eq!(normalize_program_name("CURL.EXE"), "curl");
        assert_eq!(normalize_program_name("bash-5.1"), "bash");
        assert_eq!(normalize_program_name("pwsh.cmd"), "pwsh");
        assert_eq!(normalize_program_name("stripe"), "stripe");
        assert_eq!(normalize_program_name("3.12"), "3.12");
    }

    #[test]
    fn deny_reduces_a_path_to_its_name() {
        let r = parse_rule("/opt/tools/Curl3", false).unwrap().to_deny();
        assert_eq!(r.program, Program::Name("curl".into()));
        let g = parse_rule("@network", false).unwrap().to_deny();
        assert!(in_group("@network", "curl"));
        assert_eq!(g.program, Program::Group("@network".into()));
    }
}
