//! One command against one secret's approved rules.
//!
//! The rules checked are the **approved copy in the signed vault**
//! (`Peek::bindings`), never `vahta.toml`. In this order:
//!
//! 1. **deny** matches by the program's *file name*, normalised (no `.exe`, no
//!    trailing version) and by the name the caller typed, so a copy of `curl`
//!    under another directory is still caught; a launcher (`env curl …`,
//!    `timeout 5 curl …`) is looked through. **Deny wins** over everything.
//! 2. **no isolation** (see below): where the network cannot be cut, a program
//!    in `@network`, `@shells` or `@interpreters` is refused for a secret that
//!    is meant to have no free network.
//! 3. **directories**, when the rule set has any (`dirs`): the working
//!    directory must be inside one of them. Without that the command is
//!    refused. Paths are compared as given, so the caller passes canonical ones
//!    (the daemon does; the directories were canonical when approved).
//! 4. **programs**:
//!    * `allow` and `dirs` both empty: any program passes ("open"; a category
//!      decides whether that is acceptable, see [`crate::Category::check`]).
//!    * `allow` not empty: the resolved program must match an allow rule (its
//!      canonical path, then the argv prefix) **or**, when `dirs` is not empty,
//!      be a file inside one of the directories. A new script in an approved
//!      folder needs no new approval; that is what the folder is for.
//!    * `allow` empty, `dirs` not empty: the program must be inside a
//!      directory.
//! 5. **network**: `Network::None` and `Network::Hosts` ask for a run with no
//!    network ([`Verdict::Allowed::isolate_network`]); hosts are then reachable
//!    only through `vahta http`. `Network::App` does not.
//!
//! `write` on a directory is informational for now: nothing enforces read-only.
//!
//! **Where isolation is unavailable** ([`Ctx::network_isolation`] false: macOS,
//! Windows, or Linux with user namespaces off) a run cannot be cut off, so for
//! a rule set that wants it the run is allowed only if the program is in none
//! of the three groups, and `isolate_network` is false with a `note` that says
//! the network was not cut. A program in a group is [`Verdict::Refused`] with
//! the reason in words. This is still a speed bump (a renamed copy gets past
//! it); the message and the docs say so.
//!
//! `deny` is a speed bump (a program in no group, or a renamed copy of one,
//! gets past it). `allow` is the guard.

use std::path::{Component, Path, PathBuf};

use vahta_vault::rules::{GROUPS, LAUNCHERS, in_group, normalize_program_name};
use vahta_vault::{ApprovedRule, Network, Program, RuleSet};

/// What is being run.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    /// The command's program, canonical, `None` when it could not be found.
    pub program: Option<&'a Path>,
    /// The whole argv, the program word first.
    pub argv: &'a [String],
    /// The working directory, canonical.
    pub cwd: &'a Path,
    /// The project's root (for messages).
    pub project_root: &'a Path,
    /// Whether a run can be started with no network here
    /// (`vahta_os::network_isolation_available()`).
    pub network_isolation: bool,
}

/// What the rules say about one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The command may use the secret.
    Allowed {
        /// Start it with no network at all. Set by `Network::None` and
        /// `Network::Hosts`, and only where that can be done.
        isolate_network: bool,
        /// Something the person or the journal should know: the rules ask for
        /// no network and this system cannot give it.
        note: Option<String>,
    },
    /// The program is not on the allow list. Adding it to the list fixes this.
    NotAllowed { why: String },
    /// A deny rule matches (the rule's text). Never added to a list.
    Denied { rule: String },
    /// The rules cannot be met by adding a program: the working directory is
    /// outside the directories, or the network cannot be cut here.
    Refused { why: String },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allowed { .. })
    }
}

fn base_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn args_match(rule: &ApprovedRule, argv: &[String]) -> bool {
    argv.get(1..).is_some_and(|a| a.starts_with(&rule.args))
}

/// The names deny matching looks at: what the caller typed and what it
/// resolved to. When that is a launcher (`env curl …`, `timeout 5 curl …`),
/// also every later word that is not an option or a `NAME=value`, since one of
/// them is the program it starts. That can deny on an argument that only
/// looks like a program name, which is the safe side for a deny list.
fn names_of(resolved: Option<&Path>, argv: &[String]) -> Vec<String> {
    let mut names = vec![normalize_program_name(base_name(&argv[0]))];
    if let Some(name) = resolved.and_then(|p| p.file_name()) {
        let n = normalize_program_name(&name.to_string_lossy());
        if !names.contains(&n) {
            names.push(n);
        }
    }
    if names.iter().any(|n| LAUNCHERS.contains(&n.as_str())) {
        for word in &argv[1..] {
            if word.starts_with('-') || word.contains('=') || word.is_empty() {
                continue;
            }
            let n = normalize_program_name(base_name(word));
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    names
}

/// Whether `path` is `dir` or below it. Compares whole components, and a path
/// with `..` in it never matches.
fn inside(path: &Path, dir: &Path) -> bool {
    !path.components().any(|c| c == Component::ParentDir) && path.starts_with(dir)
}

fn shown(path: &Path, root: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
        Ok(rel) => format!("./{}", rel.display()),
        Err(_) => path.display().to_string(),
    }
}

/// The arguments of `argv` beyond the allowed prefix: the words after the
/// program that the `allow` rule matching the resolved `program` does not
/// itself name. `None` when no allow rule matched (a directory, or no list):
/// there is no prefix to go beyond. Of several matching rules, the one that
/// names the most arguments.
pub fn extra_args<'a>(
    rules: &RuleSet,
    program: Option<&Path>,
    argv: &'a [String],
) -> Option<&'a [String]> {
    let resolved = program?;
    rules
        .allow
        .iter()
        .filter(|r| matches!(&r.program, Program::Path(p) if Path::new(p) == resolved))
        .filter(|r| args_match(r, argv))
        .map(|r| r.args.len())
        .max()
        .map(|n| &argv[1 + n..])
}

/// Check the command in `ctx` against `rules`.
pub fn evaluate(rules: &RuleSet, ctx: &Ctx<'_>) -> Verdict {
    let argv = ctx.argv;
    if argv.is_empty() {
        return Verdict::NotAllowed {
            why: "there is no command".to_string(),
        };
    }
    let names = names_of(ctx.program, argv);
    for rule in &rules.deny {
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

    let wants_isolation = !matches!(rules.network, Network::App);
    let isolate_network = wants_isolation && ctx.network_isolation;
    let mut note = None;
    if wants_isolation && !ctx.network_isolation {
        if let Some(g) = GROUPS.iter().find(|g| names.iter().any(|n| in_group(g, n))) {
            return Verdict::Refused {
                why: format!(
                    "this secret is meant to have no free network access, and this system cannot \
                     cut the network for a command (no unprivileged user namespaces, or not \
                     Linux), so programs in {g} are refused for it"
                ),
            };
        }
        note = Some(
            "the rules ask for a run with no network, and this system cannot do that: the \
             command ran with the network on"
                .to_string(),
        );
    }

    if !rules.dirs.is_empty()
        && !rules
            .dirs
            .iter()
            .any(|d| inside(ctx.cwd, Path::new(&d.path)))
    {
        let list: Vec<&str> = rules.dirs.iter().map(|d| d.text.as_str()).collect();
        return Verdict::Refused {
            why: format!(
                "the working directory {} is outside the directories this secret is for ({})",
                shown(ctx.cwd, ctx.project_root),
                list.join(", ")
            ),
        };
    }

    if !rules.allow.is_empty() || !rules.dirs.is_empty() {
        let Some(resolved) = ctx.program else {
            return Verdict::NotAllowed {
                why: "the program could not be found".to_string(),
            };
        };
        let by_rule = rules.allow.iter().any(|rule| match &rule.program {
            Program::Path(p) => Path::new(p) == resolved && args_match(rule, argv),
            _ => false,
        });
        let by_dir = rules
            .dirs
            .iter()
            .any(|d| inside(resolved, &PathBuf::from(&d.path)));
        if !by_rule && !by_dir {
            return Verdict::NotAllowed {
                why: if rules.allow.is_empty() {
                    "it is not a program inside the allowed directories".to_string()
                } else {
                    "it is not on the allowed list".to_string()
                },
            };
        }
    }
    Verdict::Allowed {
        isolate_network,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vahta_vault::rules::parse_rule;
    use vahta_vault::{DirRule, HostRule};

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| (*s).to_string()).collect()
    }

    fn allow(rule: &str, path: &str) -> ApprovedRule {
        parse_rule(rule, true).unwrap().to_allow(path.to_string())
    }

    fn deny(rule: &str) -> ApprovedRule {
        parse_rule(rule, false).unwrap().to_deny()
    }

    fn binding(allow: Vec<ApprovedRule>, deny: Vec<ApprovedRule>) -> RuleSet {
        RuleSet {
            name: "K".into(),
            allow,
            deny,
            network: Network::App,
            ..RuleSet::default()
        }
    }

    fn dir(path: &str) -> DirRule {
        DirRule {
            text: path.into(),
            path: path.into(),
            write: true,
        }
    }

    fn eval_in(
        b: &RuleSet,
        resolved: Option<&Path>,
        words: &[&str],
        cwd: &str,
        iso: bool,
    ) -> Verdict {
        let a = argv(words);
        evaluate(
            b,
            &Ctx {
                program: resolved,
                argv: &a,
                cwd: Path::new(cwd),
                project_root: Path::new("/proj"),
                network_isolation: iso,
            },
        )
    }

    fn check(b: &RuleSet, resolved: Option<&Path>, words: &[&str]) -> Verdict {
        eval_in(b, resolved, words, "/proj", true)
    }

    fn allowed() -> Verdict {
        Verdict::Allowed {
            isolate_network: false,
            note: None,
        }
    }

    #[test]
    fn allow_matches_the_resolved_path() {
        let b = binding(vec![allow("stripe", "/usr/bin/stripe")], vec![]);
        let ok = Path::new("/usr/bin/stripe");
        assert_eq!(check(&b, Some(ok), &["stripe", "x"]), allowed());
        // The same name, another file: refused.
        let other = Path::new("/proj/bin/stripe");
        assert!(matches!(
            check(&b, Some(other), &["stripe"]),
            Verdict::NotAllowed { .. }
        ));
        assert!(matches!(
            check(&b, None, &["stripe"]),
            Verdict::NotAllowed { .. }
        ));
    }

    #[test]
    fn extra_arguments_are_those_beyond_the_allowed_prefix() {
        let git = Path::new("/usr/bin/git");
        let b = binding(vec![allow("git push", "/usr/bin/git")], vec![]);
        let a = argv(&["git", "push", "--force", "origin"]);
        assert_eq!(extra_args(&b, Some(git), &a), Some(&a[2..]));
        let exact = argv(&["git", "push"]);
        assert_eq!(extra_args(&b, Some(git), &exact), Some(&exact[2..]));
        // A bare rule allows any arguments: all of them are extra.
        let bare = binding(vec![allow("git", "/usr/bin/git")], vec![]);
        assert_eq!(extra_args(&bare, Some(git), &a), Some(&a[1..]));
        // The rule that names more arguments wins.
        let both = binding(
            vec![
                allow("git", "/usr/bin/git"),
                allow("git push", "/usr/bin/git"),
            ],
            vec![],
        );
        assert_eq!(extra_args(&both, Some(git), &a), Some(&a[2..]));
        // No rule matched (another program, or arguments that differ).
        assert_eq!(extra_args(&b, Some(Path::new("/bin/git")), &a), None);
        assert_eq!(extra_args(&b, Some(git), &argv(&["git", "pull"])), None);
        assert_eq!(extra_args(&b, None, &a), None);
    }

    #[test]
    fn an_argument_rule_is_a_prefix() {
        let b = binding(vec![allow("git push", "/usr/bin/git")], vec![]);
        let git = Path::new("/usr/bin/git");
        assert_eq!(check(&b, Some(git), &["git", "push", "origin"]), allowed());
        assert!(matches!(
            check(&b, Some(git), &["git", "pull"]),
            Verdict::NotAllowed { .. }
        ));
        assert!(matches!(
            check(&b, Some(git), &["git"]),
            Verdict::NotAllowed { .. }
        ));
    }

    #[test]
    fn deny_wins_over_allow_and_catches_a_copy_by_name() {
        let b = binding(vec![allow("curl", "/usr/bin/curl")], vec![deny("@network")]);
        assert!(matches!(
            check(&b, Some(Path::new("/usr/bin/curl")), &["curl"]),
            Verdict::Denied { .. }
        ));
        // A copy elsewhere, with a version and extension.
        assert!(matches!(
            check(&b, Some(Path::new("/tmp/x/Curl7.EXE")), &["./x"]),
            Verdict::Denied { .. }
        ));
        // Renamed on disk but typed by its name.
        assert!(matches!(
            check(&b, Some(Path::new("/tmp/renamed")), &["curl"]),
            Verdict::Denied { .. }
        ));
        let py = binding(vec![], vec![deny("@interpreters")]);
        assert!(matches!(
            check(&py, Some(Path::new("/usr/bin/python3.12")), &["python3.12"]),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn a_named_deny_may_carry_arguments() {
        let b = binding(vec![], vec![deny("git push")]);
        let git = Path::new("/usr/bin/git");
        assert!(matches!(
            check(&b, Some(git), &["git", "push"]),
            Verdict::Denied { .. }
        ));
        assert_eq!(check(&b, Some(git), &["git", "log"]), allowed());
    }

    #[test]
    fn deny_only_allows_everything_else() {
        let b = binding(vec![], vec![deny("@shells")]);
        assert_eq!(
            check(&b, Some(Path::new("/usr/bin/env")), &["env"]),
            allowed()
        );
        assert!(matches!(
            check(&b, Some(Path::new("/bin/sh")), &["sh", "-c", "x"]),
            Verdict::Denied { .. }
        ));
    }

    #[test]
    fn deny_looks_past_a_launcher_to_the_program_it_starts() {
        let b = binding(
            vec![
                allow("env", "/usr/bin/env"),
                allow("timeout", "/usr/bin/timeout"),
            ],
            vec![deny("@network")],
        );
        let env = Path::new("/usr/bin/env");
        for words in [
            &["env", "curl", "-d", "x", "http://h"][..],
            &["env", "-i", "A=1", "/usr/bin/curl", "http://h"][..],
            &["env", "env", "wget", "http://h"][..],
        ] {
            assert!(
                matches!(check(&b, Some(env), words), Verdict::Denied { .. }),
                "{words:?}"
            );
        }
        assert!(matches!(
            check(
                &b,
                Some(Path::new("/usr/bin/timeout")),
                &["timeout", "5", "nc", "h", "1"]
            ),
            Verdict::Denied { .. }
        ));
        // A launcher running an allowed, undenied program still runs.
        assert_eq!(
            check(&b, Some(env), &["env", "A=1", "printenv", "A"]),
            allowed()
        );
        // Not a launcher: its arguments are only arguments.
        let p = binding(
            vec![allow("printenv", "/usr/bin/printenv")],
            vec![deny("@network")],
        );
        assert_eq!(
            check(
                &p,
                Some(Path::new("/usr/bin/printenv")),
                &["printenv", "curl"]
            ),
            allowed()
        );
    }

    #[test]
    fn directories_bound_the_working_directory_and_let_scripts_in() {
        let mut b = binding(vec![allow("psql", "/usr/bin/psql")], vec![]);
        b.dirs = vec![dir("/proj/scripts")];
        let psql = Path::new("/usr/bin/psql");
        // Allowed program, working directory inside.
        assert_eq!(
            eval_in(&b, Some(psql), &["psql"], "/proj/scripts/sub", true),
            allowed()
        );
        // Working directory outside: refused, and adding a program cannot help.
        assert!(matches!(
            eval_in(&b, Some(psql), &["psql"], "/proj", true),
            Verdict::Refused { .. }
        ));
        assert!(matches!(
            eval_in(&b, Some(psql), &["psql"], "/proj/scripts-evil", true),
            Verdict::Refused { .. }
        ));
        // A program inside a directory needs no allow rule.
        let script = Path::new("/proj/scripts/migrate.sh");
        assert_eq!(
            eval_in(&b, Some(script), &["./migrate.sh"], "/proj/scripts", true),
            allowed()
        );
        // A program outside both is not allowed.
        assert!(matches!(
            eval_in(
                &b,
                Some(Path::new("/usr/bin/cat")),
                &["cat"],
                "/proj/scripts",
                true
            ),
            Verdict::NotAllowed { .. }
        ));
        // No allow rules but directories: programs must be inside them.
        b.allow.clear();
        assert_eq!(
            eval_in(&b, Some(script), &["./migrate.sh"], "/proj/scripts", true),
            allowed()
        );
        assert!(matches!(
            eval_in(&b, Some(psql), &["psql"], "/proj/scripts", true),
            Verdict::NotAllowed { .. }
        ));
        // Deny still wins inside a directory.
        b.deny = vec![deny("migrate.sh")];
        assert!(matches!(
            eval_in(&b, Some(script), &["migrate.sh"], "/proj/scripts", true),
            Verdict::Denied { .. }
        ));
        // `..` never counts as inside.
        let b2 = RuleSet {
            dirs: vec![dir("/proj/scripts")],
            ..binding(vec![], vec![])
        };
        assert!(matches!(
            eval_in(
                &b2,
                Some(Path::new("/proj/scripts/../bin/x")),
                &["x"],
                "/proj/scripts",
                true
            ),
            Verdict::NotAllowed { .. }
        ));
    }

    fn net(n: Network) -> RuleSet {
        RuleSet {
            network: n,
            ..binding(vec![], vec![])
        }
    }

    fn hosts() -> Network {
        Network::Hosts(vec![HostRule {
            text: "api.example.com".into(),
            host: "api.example.com".into(),
            subdomains: false,
            port: None,
        }])
    }

    #[test]
    fn none_and_hosts_ask_for_an_isolated_run_and_app_does_not() {
        let cat = Path::new("/usr/bin/cat");
        for (n, want) in [
            (Network::None, true),
            (hosts(), true),
            (Network::App, false),
        ] {
            assert_eq!(
                eval_in(&net(n), Some(cat), &["cat"], "/proj", true),
                Verdict::Allowed {
                    isolate_network: want,
                    note: None
                }
            );
        }
    }

    #[test]
    fn where_the_network_cannot_be_cut_the_groups_are_refused_and_the_rest_say_so() {
        for n in [Network::None, hosts()] {
            let rs = net(n);
            for (path, words) in [
                ("/usr/bin/curl", &["curl"][..]),
                ("/bin/sh", &["sh", "-c", "x"][..]),
                ("/usr/bin/python3", &["python3"][..]),
                ("/usr/bin/env", &["env", "nc", "h", "1"][..]),
            ] {
                match eval_in(&rs, Some(Path::new(path)), words, "/proj", false) {
                    Verdict::Refused { why } => assert!(why.contains("cannot"), "{why}"),
                    other => panic!("{words:?}: {other:?}"),
                }
            }
            match eval_in(
                &rs,
                Some(Path::new("/usr/bin/cat")),
                &["cat"],
                "/proj",
                false,
            ) {
                Verdict::Allowed {
                    isolate_network: false,
                    note: Some(n),
                } => assert!(n.contains("network"), "{n}"),
                other => panic!("{other:?}"),
            }
        }
        // `app` asked for nothing, so nothing is refused or noted.
        assert_eq!(
            eval_in(
                &net(Network::App),
                Some(Path::new("/usr/bin/curl")),
                &["curl"],
                "/proj",
                false
            ),
            allowed()
        );
    }

    #[test]
    fn the_empty_command_is_not_allowed() {
        let b = binding(vec![], vec![]);
        assert!(matches!(check(&b, None, &[]), Verdict::NotAllowed { .. }));
    }
}
