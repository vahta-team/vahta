//! The rule form "program + package" for the package runners.
//!
//! A rule is an argv prefix: `npx -y @pkg/server@1.2.3` matches exactly that
//! start of a command. A runner's flags make that brittle (`npx -y` or
//! `npx --yes`, a harness that adds one), and a person thinks of the rule as
//! "run this package". So for a rule whose program is `npx`, `bunx`, `uvx` or
//! `pipx run`, a rule that names the package first also matches a command that
//! has known flags of that runner before the package:
//!
//! * `npx @pkg/server@1.2.3` matches `npx -y @pkg/server@1.2.3`: a **pinned**
//!   rule (it has a version) needs that exact word.
//! * `npx @pkg/server` matches `npx -y @pkg/server@1.2.3` and
//!   `npx @pkg/server@latest`: an **unpinned** rule takes any version of that
//!   package, but only a plain one (letters, digits, `.`, `_`, `+`, `-`). A
//!   source in the version (`@pkg/server@npm:other`, `@git+https://...`, a
//!   path) is not a version and does not match.
//! * Only the flags listed in [`Runner::skips`] are skipped, and only before
//!   the package. A flag that changes what the next word means (`npx -p`,
//!   `uvx --from`, `pipx run --spec`) is not skipped, so the command does not
//!   match. Words after the package are the package's own arguments: as with
//!   any prefix rule they are allowed, and reported as extra (`extra_args`).
//! * The package name must be the whole word: `@pkg/server-evil` and
//!   `pkg[extra]` (Python extras) are other packages.
//!
//! The pinned form is the safer one to recommend: an unpinned rule trusts
//! whatever the package's maintainers publish next. A rule that does not start
//! with the package (`npx -y @pkg/server@1.2.3`) is an ordinary prefix rule.

use vahta_vault::ApprovedRule;
use vahta_vault::rules::normalize_program_name;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runner {
    Npx,
    Bunx,
    Uvx,
    PipxRun,
}

impl Runner {
    /// The runner a rule's first word names: what the person typed, since the
    /// resolved path of `npx` is often a script with another name.
    fn of(rule: &ApprovedRule) -> Option<Runner> {
        let first = rule.text.split_whitespace().next()?;
        let file = first.rsplit(['/', '\\']).next().unwrap_or(first);
        match normalize_program_name(file).as_str() {
            "npx" => Some(Runner::Npx),
            "bunx" => Some(Runner::Bunx),
            "uvx" => Some(Runner::Uvx),
            "pipx" => Some(Runner::PipxRun),
            _ => None,
        }
    }

    /// Flags that change nothing about which package runs.
    fn skips(self, word: &str) -> bool {
        match self {
            Runner::Npx => matches!(word, "-y" | "--yes" | "-q" | "--quiet"),
            Runner::Bunx => matches!(word, "--bun" | "-b"),
            Runner::Uvx => matches!(word, "-q" | "--quiet"),
            Runner::PipxRun => matches!(word, "--no-cache"),
        }
    }

    fn is_python(self) -> bool {
        matches!(self, Runner::Uvx | Runner::PipxRun)
    }

    /// `(name, version)` of a package word, or `None` for a word that is not a
    /// plain `name`, `name@version` (`name==version` for Python).
    fn split(self, word: &str) -> Option<(&str, Option<&str>)> {
        let (name, version) = if self.is_python() {
            match word.split_once("==") {
                Some((n, v)) => (n, Some(v)),
                None => match word.get(1..).and_then(|t| t.find('@')) {
                    Some(i) => (&word[..i + 1], Some(&word[i + 2..])),
                    None => (word, None),
                },
            }
        } else {
            match word.get(1..).and_then(|t| t.rfind('@')) {
                Some(i) => (&word[..i + 1], Some(&word[i + 2..])),
                None => (word, None),
            }
        };
        let name_ok = !name.is_empty()
            && name.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, '.' | '_' | '-')
                    || (!self.is_python() && matches!(c, '@' | '/' | '~'))
            });
        name_ok.then_some((name, version))
    }
}

/// A version that is only a version.
fn plain_version(v: &str) -> bool {
    !v.is_empty()
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// How many words of `rest` (the argv after the program) the rule consumes, or
/// `None` when it does not match: the rule's own words as a prefix, or the
/// runner form described at the top.
pub(crate) fn rule_match(rule: &ApprovedRule, rest: &[String]) -> Option<usize> {
    if rest.starts_with(&rule.args) {
        return Some(rule.args.len());
    }
    let runner = Runner::of(rule)?;
    let lead = usize::from(runner == Runner::PipxRun);
    if lead == 1 && (rule.args.first()? != "run" || rest.first()? != "run") {
        return None;
    }
    let spec = rule.args.get(lead)?;
    if spec.starts_with('-') {
        return None;
    }
    let tail = &rule.args[lead + 1..];
    let mut i = lead;
    while rest.get(i).is_some_and(|w| runner.skips(w)) {
        i += 1;
    }
    let word = rest.get(i)?;
    let (name, version) = runner.split(spec)?;
    let same = if version.is_some() {
        word == spec
    } else {
        let (n, v) = runner.split(word)?;
        n == name && v.is_none_or(plain_version)
    };
    (same && rest[i + 1..].starts_with(tail)).then_some(i + 1 + tail.len())
}

#[cfg(test)]
mod tests {
    use super::rule_match;
    use vahta_vault::rules::parse_rule;

    fn m(rule: &str, cmd: &str) -> Option<usize> {
        let rule = parse_rule(rule, true)
            .unwrap()
            .to_allow("/bin/x".to_string());
        let words: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
        rule_match(&rule, &words[1..])
    }

    #[test]
    fn a_package_rule_skips_the_runners_known_flags() {
        assert_eq!(m("npx @pkg/server", "npx -y @pkg/server@1.2.3"), Some(2));
        assert_eq!(m("npx @pkg/server", "npx --yes -q @pkg/server"), Some(3));
        assert_eq!(m("npx @pkg/server", "npx @pkg/server@latest"), Some(1));
        assert_eq!(m("npx srv", "npx -y srv@2.0.0-beta.1"), Some(2));
        assert_eq!(m("bunx srv", "bunx --bun srv@1.0.0"), Some(2));
        assert_eq!(
            m("uvx mcp-server-git", "uvx mcp-server-git==0.6.2"),
            Some(1)
        );
        assert_eq!(
            m("uvx mcp-server-git", "uvx -q mcp-server-git@0.6.2"),
            Some(2)
        );
        assert_eq!(m("pipx run srv", "pipx run srv==1.0"), Some(2));
        assert_eq!(m("pipx run srv", "pipx run --no-cache srv"), Some(3));
    }

    #[test]
    fn a_pinned_rule_needs_that_version() {
        assert_eq!(
            m("npx @pkg/server@1.2.3", "npx -y @pkg/server@1.2.3"),
            Some(2)
        );
        assert_eq!(m("npx @pkg/server@1.2.3", "npx -y @pkg/server@1.2.4"), None);
        assert_eq!(m("npx @pkg/server@1.2.3", "npx -y @pkg/server"), None);
        assert_eq!(m("uvx srv==1.0", "uvx srv==1.1"), None);
        assert_eq!(m("uvx srv==1.0", "uvx srv==1.0"), Some(1));
    }

    #[test]
    fn near_misses_do_not_match() {
        // Another package whose name starts the same.
        assert_eq!(m("npx @pkg/server", "npx -y @pkg/server-evil"), None);
        assert_eq!(m("npx @pkg/server", "npx -y @pkg/server-evil@1.0.0"), None);
        assert_eq!(m("npx @pkg/server", "npx -y @pkg/serve"), None);
        assert_eq!(m("npx @pkg/server", "npx -y @other/server"), None);
        // The package in a later position, or after an unknown word.
        assert_eq!(m("npx @pkg/server", "npx -y evil @pkg/server"), None);
        assert_eq!(m("npx @pkg/server", "npx evil -y @pkg/server"), None);
        assert_eq!(m("npx @pkg/server", "npx --foo @pkg/server"), None);
        // Flags that change what the next word means are not skipped.
        assert_eq!(m("npx @pkg/server", "npx -p evil @pkg/server"), None);
        assert_eq!(m("npx @pkg/server", "npx --package=evil @pkg/server"), None);
        assert_eq!(m("uvx srv", "uvx --from evil srv"), None);
        // A source is not a version.
        assert_eq!(m("npx @pkg/server", "npx @pkg/server@npm:evil"), None);
        assert_eq!(
            m("npx @pkg/server", "npx @pkg/server@git+https://x/y"),
            None
        );
        assert_eq!(m("npx @pkg/server", "npx @pkg/server@../evil"), None);
        assert_eq!(m("uvx srv", "uvx srv[extra]"), None);
        assert_eq!(m("uvx srv", "uvx srv>=1"), None);
        // pipx needs `run` first.
        assert_eq!(m("pipx run srv", "pipx --quiet run srv"), None);
        assert_eq!(m("pipx run srv", "pipx install srv"), None);
        // Nothing to run.
        assert_eq!(m("npx @pkg/server", "npx -y"), None);
        assert_eq!(m("npx @pkg/server", "npx"), None);
        // Not a runner: an ordinary prefix rule.
        assert_eq!(m("git push", "git -c x=y push"), None);
        assert_eq!(m("node srv.js", "node -r evil srv.js"), None);
    }

    #[test]
    fn words_after_the_package_are_its_own_arguments() {
        // Allowed as with any prefix rule; the caller reports them as extra.
        assert_eq!(
            m("npx @pkg/server", "npx -y @pkg/server@1 --token x"),
            Some(2)
        );
        assert_eq!(
            m("npx @pkg/server --stdio", "npx -y @pkg/server --stdio"),
            Some(3)
        );
        assert_eq!(
            m("npx @pkg/server --stdio", "npx -y @pkg/server --other"),
            None
        );
    }

    #[test]
    fn a_rule_that_starts_with_flags_is_a_plain_prefix() {
        assert_eq!(
            m("npx -y @pkg/server@1.2.3", "npx -y @pkg/server@1.2.3"),
            Some(2)
        );
        assert_eq!(m("npx -y @pkg/server", "npx -y @pkg/server@1.2.3"), None);
        assert_eq!(m("npx -y @pkg/server@1.2.3", "npx @pkg/server@1.2.3"), None);
    }
}
