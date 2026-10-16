//! Command rules for a secret: the text syntax, the deny groups, the
//! program-name normalisation and project-relative paths. Pure; nothing here
//! touches the file system.
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

use std::borrow::Cow;
use std::path::{Component, Path};

use crate::format::current::{ApprovedRule, HostRule, Program, RuleSet};

// --- Paths inside the project ----------------------------------------------------------------

/// What stands for the project root in a stored path: `$PROJECT` alone, or
/// `$PROJECT/lib/x.py`. A rule that names a place inside the project is stored
/// this way, so the vault says the same thing on every machine and does not
/// carry the folder layout of the person who approved it; whoever evaluates the
/// rules expands it from their own project root. An absolute path in a rule
/// (every vault made before this) still works as it is.
pub const PROJECT_ROOT: &str = "$PROJECT";

/// Whether `p` is `$PROJECT` or `$PROJECT/…`.
pub fn is_project_path(p: &str) -> bool {
    p == PROJECT_ROOT
        || p.strip_prefix(PROJECT_ROOT)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The stored form of the absolute `path` if it is at or below `root`, with
/// normal components only; `None` otherwise.
pub fn to_project_path(path: &str, root: &Path) -> Option<String> {
    let rel = strip_root(Path::new(path), root)?;
    let mut out = PROJECT_ROOT.to_string();
    for c in rel.components() {
        match c {
            Component::Normal(part) => {
                out.push('/');
                out.push_str(part.to_str()?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// `path` below `root`. On Windows the names are compared without regard to
/// case, as the file system does; the rest keeps the spelling it has.
fn strip_root<'a>(path: &'a Path, root: &Path) -> Option<&'a Path> {
    if let Ok(rel) = path.strip_prefix(root) {
        return Some(rel);
    }
    #[cfg(windows)]
    {
        let mut rest = path.components();
        for r in root.components() {
            let p = rest.next()?;
            if !p
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&r.as_os_str().to_string_lossy())
            {
                return None;
            }
        }
        Some(rest.as_path())
    }
    #[cfg(not(windows))]
    None
}

/// `stored` as a path on this machine: `$PROJECT` forms are expanded from
/// `root`, anything else is returned as it is.
pub fn expand_project_path<'a>(stored: &'a str, root: &Path) -> Cow<'a, str> {
    if !is_project_path(stored) {
        return Cow::Borrowed(stored);
    }
    // Stored with `/`; joined part by part so the result has this machine's
    // separators.
    let mut path = root.to_path_buf();
    path.extend(
        stored[PROJECT_ROOT.len()..]
            .split('/')
            .filter(|p| !p.is_empty()),
    );
    Cow::Owned(path.to_string_lossy().into_owned())
}

/// `word` in its stored form if it is an absolute path inside one of `roots`.
fn relative_word(word: &str, roots: &[&Path]) -> String {
    if !Path::new(word).is_absolute() {
        return word.to_string();
    }
    roots
        .iter()
        .find_map(|r| to_project_path(word, r))
        .unwrap_or_else(|| word.to_string())
}

fn relative_words(text: &str, roots: &[&Path]) -> String {
    text.split(' ')
        .map(|w| relative_word(w, roots))
        .collect::<Vec<_>>()
        .join(" ")
}

fn relative_rule(rule: &mut ApprovedRule, roots: &[&Path]) {
    if let Program::Path(p) = &mut rule.program {
        *p = relative_word(p, roots);
    }
    for a in &mut rule.args {
        *a = relative_word(a, roots);
    }
    rule.text = relative_words(&rule.text, roots);
}

/// Store the places of `rules` that are inside the project (one of `roots`:
/// the project root as given and as the file system resolves it) in the
/// project-relative form. Places elsewhere are left as they are.
pub fn relativize(rules: &mut RuleSet, roots: &[&Path]) {
    for r in rules.allow.iter_mut().chain(rules.deny.iter_mut()) {
        relative_rule(r, roots);
    }
    for d in &mut rules.dirs {
        d.path = relative_word(&d.path, roots);
        // `PATH`, `PATH:ro` or `PATH:rw` as the person wrote it.
        let (path, mode) = match d.text.rfind(':') {
            Some(i) if matches!(&d.text[i..], ":ro" | ":rw") => d.text.split_at(i),
            _ => (d.text.as_str(), ""),
        };
        d.text = format!("{}{mode}", relative_word(path, roots));
    }
}

/// The absolute places in `rules` that are not in the project-relative form:
/// the programs and folders a package carries from one machine to another,
/// where they may not exist. Each once, in order.
pub fn absolute_places(rules: &RuleSet) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut note = |p: &str| {
        if Path::new(p).is_absolute() && !out.iter().any(|o| o == p) {
            out.push(p.to_string());
        }
    };
    for r in &rules.allow {
        if let Program::Path(p) = &r.program {
            note(p);
        }
        r.args.iter().for_each(|a| note(a));
    }
    for r in &rules.deny {
        r.args.iter().for_each(|a| note(a));
    }
    rules.dirs.iter().for_each(|d| note(&d.path));
    out
}

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

/// One network destination as written: `host`, `*.host` (every name beneath
/// it, not the host itself), either with an optional `:port`. The host is a DNS
/// name or an IPv4 literal, case-insensitive; no scheme, no path, no wildcard
/// anywhere but a leading `*.`. The error is a short sentence for the person.
pub fn parse_host(text: &str) -> Result<HostRule, String> {
    let shown = text.trim();
    let bad = |why: &str| Err(format!("host `{shown}`: {why}"));
    if shown.is_empty() || shown.len() > 300 {
        return bad("a host must be 1 to 300 characters");
    }
    if shown.contains("://") || shown.contains('/') {
        return bad("write only the host name, with no scheme or path");
    }
    let (name, port) = match shown.rsplit_once(':') {
        Some((name, port)) => match port.parse::<u16>() {
            Ok(p) if p != 0 => (name, Some(p)),
            _ => return bad("the port is a number from 1 to 65535"),
        },
        None => (shown, None),
    };
    let (name, subdomains) = match name.strip_prefix("*.") {
        Some(rest) => (rest, true),
        None => (name, false),
    };
    let host = name.to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if host.is_empty() || host.len() > 253 || !host.split('.').all(label_ok) {
        return bad("not a DNS name or IPv4 address (IPv6 and other wildcards are not supported)");
    }
    Ok(HostRule {
        text: shown.to_string(),
        host,
        subdomains,
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_paths_round_trip_with_this_machines_separators() {
        let root = std::env::temp_dir().join("vahta-rules-root");
        let inside = root.join("lib").join("x.py");
        let inside_text = inside.to_string_lossy().into_owned();
        let stored = to_project_path(&inside_text, &root).unwrap();
        assert_eq!(stored, "$PROJECT/lib/x.py");
        assert_eq!(
            Path::new(expand_project_path(&stored, &root).as_ref()),
            inside.as_path()
        );
        assert_eq!(
            to_project_path(&root.to_string_lossy(), &root).unwrap(),
            "$PROJECT"
        );
        assert_eq!(
            Path::new(expand_project_path("$PROJECT", &root).as_ref()),
            root.as_path()
        );
        // A sibling that merely shares a prefix is not inside.
        let sibling = root.with_file_name("vahta-rules-root2").join("x");
        assert!(to_project_path(&sibling.to_string_lossy(), &root).is_none());
        // Windows names differ in case only.
        #[cfg(windows)]
        assert_eq!(
            to_project_path(&inside_text.to_uppercase(), &root).unwrap(),
            "$PROJECT/LIB/X.PY"
        );
    }

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
    fn hosts_parse_with_wildcards_and_ports() {
        let h = parse_host(" API.Stripe.com ").unwrap();
        assert_eq!(
            (h.host.as_str(), h.subdomains, h.port),
            ("api.stripe.com", false, None)
        );
        let h = parse_host("*.example.org:8443").unwrap();
        assert_eq!(
            (h.host.as_str(), h.subdomains, h.port),
            ("example.org", true, Some(8443))
        );
        assert!(parse_host("10.0.0.5:80").is_ok());
        for bad in [
            "",
            "https://a.com",
            "a.com/x",
            "a..com",
            "*a.com",
            "a.com:0",
            "a.com:x",
            "[::1]",
            "-a.com",
            "a_b.com",
        ] {
            assert!(parse_host(bad).is_err(), "{bad}");
        }
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
