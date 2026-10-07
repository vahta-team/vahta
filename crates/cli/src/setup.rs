//! `vahta setup`: put `vahta-hook` into the config of the coding agents found
//! on this machine, and say whether what is there is current.
//!
//! The logic lives in `vahta-setup`; this file parses the command line, picks
//! the harnesses, prints the status table and the `--dry-run` diffs, and makes
//! the writes. Everything is planned before anything is written, so one
//! harness's refusal (say, a config that is not valid JSON) leaves every file
//! as it was.
//!
//! Setup never touches a harness's config unless asked: bare `vahta setup`
//! only reads. The hook binary is the `vahta-hook` next to the running
//! `vahta`; there is no way to point setup at another one.

use std::io::Write;

use vahta_harness::{HARNESSES, Manifest};
use vahta_setup::{Action, Env as SetupEnv, HookProblem, Placement, Plan, State, Status};

use crate::{EXIT_CLEAN, EXIT_USAGE};

/// A refusal or a failed write. Not a usage error, so not 2.
const EXIT_FAILED: i32 = 1;

pub const USAGE: &str = "\
usage: vahta setup
       vahta setup --claude|--codex|--cursor [--force] [--dry-run] [--last] [--uninstall]
       vahta setup --all [--dry-run] [--last] [--uninstall]
       vahta setup --refresh [--dry-run] [--last]

Register vahta-hook with the coding agents on this machine.

Bare `vahta setup` installs nothing: it prints which harnesses are found, whether
vahta is set up in each, and where their config lives.

options:
  --claude, --codex, --cursor
                         act on that harness; several may be given. Refused when
                         the harness is not found, unless --force
  --all                  act on every harness that was found (with --uninstall:
                         every harness that has entries of ours)
  --force                install even though the harness was not found
  --dry-run              print what would change as a unified diff; write nothing
  --last                 move our entries behind every other hook of the same
                         event (by default ours stay where they are). For when
                         another hook also rewrites tool output: which rewrite
                         wins is not defined by Claude Code (see docs/hooks.md)
  --uninstall            remove our entries and leave everything else alone
  --refresh              reinstall in every harness that already has entries of
                         ours, whatever their state (current, outdated, or pointing
                         at another vahta-hook), and leave the others alone. Writes
                         nothing when nothing of ours is installed. Takes only
                         --dry-run and --last; run it after moving or
                         reinstalling vahta
  -h, --help             show this help

Setup adds one hook entry per event to the harness's user-level config, after
the entries already there, and never touches an entry that is not ours. An
entry of ours that is already there is updated where it stands. A file
that is not valid JSON is refused. The file as it was before vahta first
changed it is kept as <file>.vahta-backup; later runs leave that copy alone.
";

struct Args {
    harnesses: Vec<String>,
    all: bool,
    force: bool,
    dry_run: bool,
    uninstall: bool,
    refresh: bool,
    last: bool,
}

enum Parsed {
    Run(Args),
    Help,
    Error(String),
}

fn parse(args: &[String]) -> Parsed {
    let mut out = Args {
        harnesses: Vec::new(),
        all: false,
        force: false,
        dry_run: false,
        uninstall: false,
        refresh: false,
        last: false,
    };
    for a in args {
        match a.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "--all" => out.all = true,
            "--force" => out.force = true,
            "--dry-run" => out.dry_run = true,
            "--uninstall" => out.uninstall = true,
            "--refresh" => out.refresh = true,
            "--last" => out.last = true,
            other => match other.strip_prefix("--").filter(|n| HARNESSES.contains(n)) {
                Some(name) => {
                    if !out.harnesses.iter().any(|h| h == name) {
                        out.harnesses.push(name.to_string());
                    }
                }
                None => return Parsed::Error(format!("unrecognised argument: {other}")),
            },
        }
    }
    let named = !out.harnesses.is_empty();
    if out.last && out.uninstall {
        return Parsed::Error("--last goes with an install, not --uninstall".into());
    }
    if out.refresh {
        if out.uninstall || out.all || named || out.force {
            return Parsed::Error(
                "--refresh goes with --dry-run and --last only, not --uninstall, --all, --force or a harness flag".into(),
            );
        }
        return Parsed::Run(out);
    }
    if out.all && named {
        return Parsed::Error("--all and a harness flag cannot be combined".into());
    }
    if out.all && out.force {
        return Parsed::Error("--force goes with a harness flag, not --all".into());
    }
    if !out.all && !named && (out.force || out.dry_run || out.uninstall || out.last) {
        return Parsed::Error("name a harness (--claude, --codex, --cursor) or --all".into());
    }
    Parsed::Run(out)
}

fn manifests() -> Vec<Manifest> {
    HARNESSES
        .iter()
        .filter_map(|h| vahta_harness::manifest(h).and_then(Result::ok))
        .collect()
}

/// The stale notice. One line per harness that has entries of ours which are no
/// longer what this binary would write. Silent when nothing is set up. Reads
/// three config files and nothing else. Always stderr, so JSON on stdout stays
/// clean.
pub fn stale_notice(env: &SetupEnv, stderr: &mut dyn Write) {
    let mut affected: Vec<(Manifest, bool)> = Vec::new();
    for m in manifests() {
        let i = vahta_setup::inspect(&m, env);
        let missing = i
            .problems
            .iter()
            .any(|p| matches!(p, HookProblem::Missing(_)));
        if missing || i.state == State::Outdated {
            affected.push((m, missing));
        }
    }
    // One harness: name it. Several: one command fixes them all.
    let many = affected.len() > 1;
    for (m, missing) in &affected {
        let fix = if many {
            "vahta setup --refresh".to_string()
        } else {
            format!("vahta setup --{}", m.name)
        };
        if *missing {
            // The harness runs a hook that is gone: no protection, and no error.
            let _ = writeln!(
                stderr,
                "vahta: the hook set up for {} no longer exists; run `{fix}`",
                m.title
            );
        } else {
            let _ = writeln!(
                stderr,
                "vahta: setup for {} is outdated; run `{fix}`",
                m.title
            );
        }
    }
}

/// The manifest's after-setup notice for a harness, by name.
fn notice_of(name: &str) -> Option<String> {
    manifests()
        .into_iter()
        .find(|m| m.name == name)?
        .setup_notice
}

fn state_word(s: &State) -> &'static str {
    match s {
        State::None => "none",
        State::Current => "current",
        State::Outdated => "outdated",
        State::Unreadable(_) => "unreadable",
    }
}

fn print_table(statuses: &[Status], stdout: &mut dyn Write) {
    let rows: Vec<[String; 4]> = statuses
        .iter()
        .map(|s| {
            [
                s.title.clone(),
                if s.detection.found { "yes" } else { "no" }.to_string(),
                state_word(&s.inspect.state).to_string(),
                s.inspect
                    .config_path
                    .as_ref()
                    .map_or("-".into(), |p| p.display().to_string()),
            ]
        })
        .collect();
    let head = ["harness", "found", "set up", "config"];
    let mut width = [0; 3];
    for (i, w) in width.iter_mut().enumerate() {
        *w = rows
            .iter()
            .map(|r| r[i].chars().count())
            .chain([head[i].len()])
            .max()
            .unwrap_or(0);
    }
    let line = |r: &[String; 4]| {
        format!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {}",
            r[0],
            r[1],
            r[2],
            r[3],
            w0 = width[0],
            w1 = width[1],
            w2 = width[2]
        )
    };
    let _ = writeln!(stdout, "{}", line(&head.map(String::from)));
    for r in &rows {
        let _ = writeln!(stdout, "{}", line(r));
    }
    let mut notes = Vec::new();
    for s in statuses {
        if !s.detection.found {
            notes.push(format!("{}: not found ({})", s.title, s.detection.why));
        }
        if matches!(s.inspect.state, State::Current | State::Outdated)
            && let Some(n) = notice_of(&s.name)
        {
            notes.push(format!("{}: {n}", s.title));
        }
        if let State::Unreadable(why) = &s.inspect.state {
            notes.push(format!("{}: config {why}", s.title));
        }
        for p in &s.inspect.problems {
            notes.push(match p {
                HookProblem::Missing(w) => {
                    format!("{}: the installed hook {w} does not exist", s.title)
                }
                HookProblem::Elsewhere(w) => {
                    format!(
                        "{}: the installed hook {w} is not the vahta-hook next to this vahta",
                        s.title
                    )
                }
            });
        }
    }
    if !notes.is_empty() {
        let _ = writeln!(stdout);
        for n in notes {
            let _ = writeln!(stdout, "  {n}");
        }
    }
    let _ = writeln!(stdout);
    let _ = writeln!(
        stdout,
        "Nothing was changed. `vahta setup --all` sets up every harness that was found;\n\
         `vahta setup --claude` (or --codex, --cursor) picks one. See `vahta setup --help`."
    );
}

pub fn run(
    args: &[String],
    env: Option<&SetupEnv>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let parsed = match parse(args) {
        Parsed::Help => {
            let _ = stdout.write_all(USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Parsed::Error(msg) => {
            let _ = write!(stderr, "vahta setup: error: {msg}\n\n{USAGE}");
            return EXIT_USAGE;
        }
        Parsed::Run(a) => a,
    };
    let Some(env) = env else {
        let _ = writeln!(
            stderr,
            "vahta setup: error: could not determine the home directory"
        );
        return EXIT_FAILED;
    };
    let ms = manifests();

    if parsed.harnesses.is_empty() && !parsed.all && !parsed.refresh {
        let statuses: Vec<Status> = ms.iter().map(|m| vahta_setup::status(m, env)).collect();
        print_table(&statuses, stdout);
        return EXIT_CLEAN;
    }

    let action = if parsed.uninstall {
        Action::Uninstall
    } else {
        Action::Install
    };
    // A refresh with nothing to repoint has no use for the hook, so it checks later.
    if action == Action::Install && !parsed.refresh && !env.hook.is_file() {
        let _ = writeln!(
            stderr,
            "vahta setup: error: vahta-hook not found at {}; it must sit next to vahta",
            env.hook.display()
        );
        return EXIT_FAILED;
    }

    // Choose the harnesses.
    let mut chosen: Vec<&Manifest> = Vec::new();
    let mut refused = false;
    if parsed.refresh {
        // Whatever the state, as long as there is something of ours to repoint.
        for m in &ms {
            match vahta_setup::inspect(m, env).state {
                State::Current | State::Outdated => chosen.push(m),
                State::None => {}
                State::Unreadable(why) => {
                    let _ = writeln!(stdout, "{}: skipped, config {why}", m.title);
                }
            }
        }
        if chosen.is_empty() {
            let _ = writeln!(
                stdout,
                "nothing of ours is installed in any harness; nothing to refresh"
            );
            return EXIT_CLEAN;
        }
        if !env.hook.is_file() {
            let _ = writeln!(
                stderr,
                "vahta setup: error: vahta-hook not found at {}; it must sit next to vahta",
                env.hook.display()
            );
            return EXIT_FAILED;
        }
    } else if parsed.all {
        for m in &ms {
            let found = vahta_setup::detect(m, env);
            let has_ours = matches!(
                vahta_setup::inspect(m, env).state,
                State::Current | State::Outdated
            );
            let take = if action == Action::Install {
                found.found
            } else {
                has_ours
            };
            if take {
                chosen.push(m);
            } else if action == Action::Install {
                let _ = writeln!(stdout, "{}: skipped, not found ({})", m.title, found.why);
            } else {
                let _ = writeln!(
                    stdout,
                    "{}: skipped, nothing of ours in its config",
                    m.title
                );
            }
        }
    } else {
        for name in &parsed.harnesses {
            let Some(m) = ms.iter().find(|m| &m.name == name) else {
                continue;
            };
            let found = vahta_setup::detect(m, env);
            if action == Action::Install && !found.found && !parsed.force {
                let _ = writeln!(
                    stderr,
                    "vahta setup: {} not found ({}); use --{name} --force to install anyway",
                    m.title, found.why
                );
                refused = true;
            } else {
                chosen.push(m);
            }
        }
    }
    if refused {
        return EXIT_FAILED;
    }

    // Plan everything before writing anything.
    let mut plans: Vec<(&Manifest, Plan)> = Vec::new();
    for m in chosen {
        let placement = if parsed.last {
            Placement::Last
        } else {
            Placement::Keep
        };
        match vahta_setup::plan_placed(m, env, action, placement) {
            Ok(p) => plans.push((m, p)),
            Err(e) => {
                let file = vahta_setup::config_path(m, env)
                    .map_or(String::new(), |p| format!(" {}", p.display()));
                let _ = writeln!(
                    stderr,
                    "vahta setup: {}:{file} {e}; nothing was written",
                    m.title
                );
                refused = true;
            }
        }
    }
    if refused {
        return EXIT_FAILED;
    }

    let mut failed = false;
    for (m, p) in &plans {
        let path = p.path.display();
        let Some(after) = &p.after else {
            let _ = match action {
                Action::Install => writeln!(
                    stdout,
                    "{}: already current, nothing to do ({path})",
                    m.title
                ),
                Action::Uninstall => writeln!(stdout, "{}: nothing of ours in {path}", m.title),
            };
            continue;
        };
        if parsed.dry_run {
            let _ = writeln!(stdout, "{}: would change {path}", m.title);
            let _ = write!(
                stdout,
                "{}",
                vahta_setup::unified_diff(&p.path, p.before.as_deref(), after)
            );
            continue;
        }
        match vahta_setup::commit(p) {
            Ok(backup) => {
                let verb = match action {
                    Action::Install => format!("installed {} hooks into", m.events.len()),
                    Action::Uninstall => "removed our hooks from".to_string(),
                };
                let kept = backup.map_or(String::new(), |b| {
                    format!(" (old file kept as {})", b.display())
                });
                let _ = writeln!(stdout, "{}: {verb} {path}{kept}", m.title);
                if let (Action::Install, Some(n)) = (action, &m.setup_notice) {
                    let _ = writeln!(stdout, "  {n}");
                }
            }
            Err(e) => {
                let _ = writeln!(stderr, "vahta setup: {}: cannot write {path}: {e}", m.title);
                failed = true;
            }
        }
    }
    if failed { EXIT_FAILED } else { EXIT_CLEAN }
}
