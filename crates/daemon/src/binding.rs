//! Binding a secret to commands: the check that runs before a command gets a
//! secret that has approved rules.
//!
//! Matching is pure; only resolution (see [`crate::pathfind`]) reads the file
//! system. The rules checked are the **approved copy in the signed vault**
//! (`Peek::bindings`), never `vahta.toml`.
//!
//! * `allow`, when it is not empty, names the programs (by canonical path,
//!   fixed when the person approved the rule) and an optional argv prefix.
//!   The command's resolved program must match one of them.
//! * `deny` matches by the program's *file name*, normalised (no `.exe`, no
//!   trailing version) and by the name the caller typed, so a copy of `curl`
//!   under another directory is still caught. **Deny wins.**
//! * No rules at all: the secret is unbound and any command is allowed. That
//!   case never reaches this module.
//!
//! `deny` is a speed bump (a program in no group, or a renamed copy of one that
//! is, gets past it). `allow` is the guard.

use std::path::Path;

use vahta_vault::rules::{in_group, normalize_program_name};
use vahta_vault::{ApprovedRule, Binding, Program};

/// What the rules say about one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allowed,
    /// There is an allow list and nothing on it matches.
    NotAllowed {
        why: String,
    },
    /// A deny rule matches (the rule's text).
    Denied {
        rule: String,
    },
}

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn args_match(rule: &ApprovedRule, argv: &[String]) -> bool {
    argv.get(1..).is_some_and(|a| a.starts_with(&rule.args))
}

/// The names deny matching looks at: what the caller typed and what it
/// resolved to.
fn names_of(resolved: Option<&Path>, argv: &[String]) -> Vec<String> {
    let mut names = vec![normalize_program_name(base_name(&argv[0]))];
    if let Some(name) = resolved.and_then(|p| p.file_name()) {
        let n = normalize_program_name(&name.to_string_lossy());
        if !names.contains(&n) {
            names.push(n);
        }
    }
    names
}

/// Check `argv` (whose program resolved to `resolved`, `None` when it could not
/// be found) against one secret's approved rules.
pub(crate) fn check(binding: &Binding, resolved: Option<&Path>, argv: &[String]) -> Verdict {
    if argv.is_empty() {
        return Verdict::NotAllowed {
            why: "there is no command".to_string(),
        };
    }
    let names = names_of(resolved, argv);
    for rule in &binding.deny {
        let hit = match &rule.program {
            Program::Group(g) => names.iter().any(|n| in_group(g, n)),
            Program::Name(n) => names.contains(n),
            Program::Path(_) => false,
        };
        // A group has no arguments; a named rule may have an argv prefix.
        if hit && (matches!(rule.program, Program::Group(_)) || args_match(rule, argv)) {
            return Verdict::Denied {
                rule: rule.text.clone(),
            };
        }
    }
    if binding.allow.is_empty() {
        return Verdict::Allowed;
    }
    let Some(resolved) = resolved else {
        return Verdict::NotAllowed {
            why: "the program could not be found".to_string(),
        };
    };
    let ok = binding.allow.iter().any(|rule| match &rule.program {
        Program::Path(p) => Path::new(p) == resolved && args_match(rule, argv),
        _ => false,
    });
    if ok {
        Verdict::Allowed
    } else {
        Verdict::NotAllowed {
            why: "it is not on the allowed list".to_string(),
        }
    }
}

/// The rules as the person reads them: `allow: a, b; deny: c`.
pub(crate) fn rules_text(binding: &Binding) -> String {
    let list = |rules: &[ApprovedRule]| {
        rules
            .iter()
            .map(|r| r.text.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut parts = Vec::new();
    if !binding.allow.is_empty() {
        parts.push(format!("allow: {}", list(&binding.allow)));
    }
    if !binding.deny.is_empty() {
        parts.push(format!("deny: {}", list(&binding.deny)));
    }
    parts.join("; ")
}

/// Why the agent could change the file at `resolved`: it is inside the project
/// or in a temp directory. `None` for anywhere else.
pub(crate) fn agent_writable(resolved: &Path, project_root: &Path) -> Option<&'static str> {
    let root = std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    if resolved.starts_with(&root) {
        return Some("this file is inside the project, so the agent can change it");
    }
    #[cfg(unix)]
    let temps = vec![
        std::env::temp_dir(),
        "/tmp".into(),
        "/var/tmp".into(),
        "/dev/shm".into(),
    ];
    #[cfg(not(unix))]
    let temps = vec![std::env::temp_dir()];
    for t in temps {
        let t = std::fs::canonicalize(&t).unwrap_or(t);
        if resolved.starts_with(&t) {
            return Some("this file is in a temporary directory, so the agent can change it");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use vahta_vault::rules::parse_rule;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| (*s).to_string()).collect()
    }

    fn allow(rule: &str, path: &str) -> ApprovedRule {
        parse_rule(rule, true).unwrap().to_allow(path.to_string())
    }

    fn deny(rule: &str) -> ApprovedRule {
        parse_rule(rule, false).unwrap().to_deny()
    }

    fn binding(allow: Vec<ApprovedRule>, deny: Vec<ApprovedRule>) -> Binding {
        Binding {
            name: "K".into(),
            allow,
            deny,
        }
    }

    #[test]
    fn allow_matches_the_resolved_path() {
        let b = binding(vec![allow("stripe", "/usr/bin/stripe")], vec![]);
        let ok = Path::new("/usr/bin/stripe");
        assert_eq!(
            check(&b, Some(ok), &argv(&["stripe", "x"])),
            Verdict::Allowed
        );
        // The same name, another file: refused.
        let other = Path::new("/proj/bin/stripe");
        assert!(matches!(
            check(&b, Some(other), &argv(&["stripe"])),
            Verdict::NotAllowed { .. }
        ));
        assert!(matches!(
            check(&b, None, &argv(&["stripe"])),
            Verdict::NotAllowed { .. }
        ));
    }

    #[test]
    fn an_argument_rule_is_a_prefix() {
        let b = binding(vec![allow("git push", "/usr/bin/git")], vec![]);
        let git = Path::new("/usr/bin/git");
        assert_eq!(
            check(&b, Some(git), &argv(&["git", "push", "origin"])),
            Verdict::Allowed
        );
        assert!(matches!(
            check(&b, Some(git), &argv(&["git", "pull"])),
            Verdict::NotAllowed { .. }
        ));
        assert!(matches!(
            check(&b, Some(git), &argv(&["git"])),
            Verdict::NotAllowed { .. }
        ));
    }

    #[test]
    fn deny_wins_over_allow_and_catches_a_copy_by_name() {
        let b = binding(vec![allow("curl", "/usr/bin/curl")], vec![deny("@network")]);
        assert!(matches!(
            check(&b, Some(Path::new("/usr/bin/curl")), &argv(&["curl"])),
            Verdict::Denied { .. }
        ));
        // A copy elsewhere, with a version and extension.
        assert!(matches!(
            check(&b, Some(Path::new("/tmp/x/Curl7.EXE")), &argv(&["./x"])),
            Verdict::Denied { .. }
        ));
        // Renamed on disk but typed by its name.
        assert!(matches!(
            check(&b, Some(Path::new("/tmp/renamed")), &argv(&["curl"])),
            Verdict::Denied { .. }
        ));
        let py = binding(vec![], vec![deny("@interpreters")]);
        assert!(matches!(
            check(
                &py,
                Some(Path::new("/usr/bin/python3.12")),
                &argv(&["python3.12"])
            ),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn a_named_deny_may_carry_arguments() {
        let b = binding(vec![], vec![deny("git push")]);
        let git = Path::new("/usr/bin/git");
        assert!(matches!(
            check(&b, Some(git), &argv(&["git", "push"])),
            Verdict::Denied { .. }
        ));
        assert_eq!(
            check(&b, Some(git), &argv(&["git", "log"])),
            Verdict::Allowed
        );
    }

    #[test]
    fn deny_only_allows_everything_else() {
        let b = binding(vec![], vec![deny("@shells")]);
        assert_eq!(
            check(&b, Some(Path::new("/usr/bin/env")), &argv(&["env"])),
            Verdict::Allowed
        );
        assert!(matches!(
            check(&b, Some(Path::new("/bin/sh")), &argv(&["sh", "-c", "x"])),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn the_rules_read_back() {
        let b = binding(vec![allow("git push", "/g")], vec![deny("@network")]);
        assert_eq!(rules_text(&b), "allow: git push; deny: @network");
    }
}
