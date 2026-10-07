//! `vahta` — the command line.
//!
//! `vahta setup` registers the hook with the coding agents (see `setup.rs`).
//! `vahta list` and `vahta check` read the project's vault without a password
//! (see `vault_cmds.rs`). Everything that opens a vault, runs a command with its
//! secrets or holds a session goes through the daemon, which is the vault's only
//! owner: `vahta daemon` (see `daemon_cmd.rs`), `init`, `add`, `reset`,
//! `remove`, `import`, `reveal` and `copy` (`vault_ops.rs`), `unlock`, `lock` and
//! `sessions` (`session_cmds.rs`), `run` and `delegate` (`run_cmd.rs`),
//! `output allow` (`output_cmd.rs`), and the
//! hidden `_surface`, the prompt window the daemon opens (`surface_cmd.rs`).
//! These commands take no secret and no password as an argument: the person
//! types them in the window. `vahta scan [PATH]` is the project path of `ka scan`, and
//! with `--deep` the home dotfiles, MCP configs and agent session transcripts
//! as well. The scan's flags, output and exit codes match the
//! Python command's, and `src/key_amnesia/scan_py.py` remains the
//! specification.
//!
//! What it does **not** do, deliberately: the interactive import into a vault
//! (`--yes`), whose format is not settled. It stays in the Python `ka scan`;
//! asking for it here is a usage error rather than a silent half-scan.
//!
//! `--deep` reads the real home directory (`$HOME`, as Python's `Path.home()`
//! does) and every agent transcript under it. Progress goes to stderr, as in
//! Python, unless `--quiet`.
//!
//! Where Python's deep scan *crashes* — a transcript line nested past its
//! recursion limit, or an integer of more than 4300 digits — this scans the
//! line like any other, on purpose: such a line may hold a real key, and one
//! hostile line must not hide every other finding.
//!
//! Prints names, paths and counts. Never a secret value: the scanner does not
//! hold one.

mod bind_cmd;
mod daemon_cmd;
mod output_cmd;
mod run_cmd;
mod session_cmds;
mod setup;
mod surface_cmd;
mod vault_cmds;
mod vault_ops;

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use vahta_scan::deep::{DeepError, scan_deep_with_threads};
use vahta_scan::finding::leak_count;
use vahta_scan::report::{findings_to_json, format_human_report};
use vahta_scan::walk::scan_project_with_threads;

/// Exit codes, as `ka scan` has them: 0 clean, 1 leaks at the gate, 2 usage.
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_LEAKS: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
/// A command that ran and found a failure (`vahta check` with a name missing,
/// a vault operation that went wrong).
pub const EXIT_FAILED: i32 = 1;
/// The daemon commands add: a structured refusal, a prompt window that was
/// cancelled or timed out, and a daemon that is not available.
pub const EXIT_REFUSED: i32 = 3;
pub const EXIT_CANCELLED: i32 = 4;
pub const EXIT_DAEMON: i32 = 5;

const USAGE: &str = "\
usage: vahta scan [PATH] [--deep] [--json] [--strict {certain,high,paranoid}]
                  [--include-excluded | --wide] [--no-import] [--quiet]

Find plaintext secrets an agent can read under PATH (default: the current
directory). Reports names, paths and counts; never values.

options:
  --deep                 also scan your home directory: dotfiles, shell
                         history, ssh keys, MCP configs, and the session
                         transcripts of Claude Code, Codex and Copilot CLI
  --json                 machine-readable JSON instead of text
  --strict LEVEL         exit 1 when findings at this gate are present:
                         certain, high (default) or paranoid
  --include-excluded     also walk node_modules, .venv, build dirs, .git
  --wide                 alias for --include-excluded
  --quiet                with --deep, do not print progress on stderr
  --no-import            accepted for compatibility with `ka scan`; no effect
  -h, --help             show this help

--deep reads transcript lines and reports line numbers and names, never
values. A line nested very deeply, or holding an integer of more than 4300
digits, is scanned like any other (`ka scan --deep` stops on such a line).

Not available here: --yes (import into a vault). Use the Python `ka scan`.
";

const TOP_USAGE: &str = "\
usage: vahta <command> [options]
       vh <command> [options]     (`vh` is the short name)

commands:
  scan    find plaintext secrets an agent can read in a project
  setup   register vahta-hook with Claude Code, Codex and Cursor
  list    list the secrets in this project's vault (names only)
  check   compare vahta.toml with the vault; for CI
  run     run a command with secrets in its environment, output scrubbed
  bind    say which commands may use a secret (the person approves)
  delegate  narrow your session for a sub-agent and run it
  unlock  open a session: one password, then `vahta run` needs no window
  lock    end this project's sessions (no password)
  sessions  list sessions, or `kill ID` one (no password)
  output  `output allow REF`: ask to see what was cut from a tool's output
  init    create this project's vault
  add     store a new secret (typed in a window, never on the command line)
  reset   replace the value of a secret the vault has
  remove  remove a secret
  import  add the secrets of a ka vault or a .env file
  reveal  show a secret in a window
  copy    put a secret on the clipboard for 30 seconds
  daemon  run, inspect, stop or restart the daemon that owns the vault

Run `vahta <command> --help` for the options.
";

struct ScanArgs {
    path: Option<String>,
    json: bool,
    strict: String,
    include_excluded: bool,
    deep: bool,
    quiet: bool,
    /// Worker threads; `None` is the default (available parallelism, capped).
    /// Undocumented in `USAGE` on purpose: Python's `ka scan` has no such flag.
    jobs: Option<usize>,
}

enum Parsed {
    Run(ScanArgs),
    Help,
    Error(String),
}

fn parse_scan(args: &[String]) -> Parsed {
    let mut out = ScanArgs {
        path: None,
        json: false,
        strict: "high".to_string(),
        include_excluded: false,
        deep: false,
        quiet: false,
        jobs: None,
    };
    let mut only_paths = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if only_paths || !a.starts_with('-') || a == "-" {
            if out.path.is_some() {
                return Parsed::Error(format!("unexpected extra argument: {a}"));
            }
            out.path = Some(a.to_string());
            continue;
        }
        match a {
            "--" => only_paths = true,
            "-h" | "--help" => return Parsed::Help,
            "--json" => out.json = true,
            "--include-excluded" | "--wide" => out.include_excluded = true,
            "--no-import" => {}
            "--quiet" => out.quiet = true,
            "--deep" => out.deep = true,
            "--yes" => {
                return Parsed::Error(
                    "--yes (import into a vault) is only available in the Python `ka scan`"
                        .to_string(),
                );
            }
            "--jobs" => match args.get(i).and_then(|v| v.parse::<usize>().ok()) {
                Some(n) if n >= 1 => {
                    i += 1;
                    out.jobs = Some(n);
                }
                _ => return Parsed::Error("--jobs expects a positive integer".to_string()),
            },
            "--strict" => match args.get(i) {
                Some(v) => {
                    i += 1;
                    out.strict = v.clone();
                }
                None => return Parsed::Error("--strict expects a value".to_string()),
            },
            _ => {
                if let Some(v) = a.strip_prefix("--strict=") {
                    out.strict = v.to_string();
                } else {
                    return Parsed::Error(format!("unrecognised option: {a}"));
                }
            }
        }
    }
    if !matches!(out.strict.as_str(), "certain" | "high" | "paranoid") {
        return Parsed::Error(format!(
            "invalid --strict value: {:?} (choose from certain, high, paranoid)",
            out.strict
        ));
    }
    Parsed::Run(out)
}

/// What the program takes from its surroundings, gathered once in `main` so
/// the rest can be driven without a process.
pub struct Env {
    pub cwd: PathBuf,
    /// `Path.home()`: `$HOME`, else the passwd entry. `None` when neither.
    pub home: Option<PathBuf>,
    /// `os.environ.get("APPDATA")`.
    pub appdata: Option<OsString>,
    /// `sys.stderr.isatty()`: decides whether progress rewrites one line.
    pub stderr_is_tty: bool,
    /// What `vahta setup` needs; `None` without a home directory.
    pub setup: Option<vahta_setup::Env>,
    /// Where Vahta keeps what this machine remembers about each vault.
    /// `VAHTA_DATA_DIR` if set (tests and unusual setups), else the platform
    /// data directory plus `vahta`. `None` where there is neither.
    pub data_dir: Option<PathBuf>,
}

/// `_scan_progress_printer`: stage and counts on stderr, never contents.
struct Progress<'a> {
    out: &'a mut dyn Write,
    tty: bool,
    last_len: usize,
}

impl<'a> Progress<'a> {
    fn new(out: &'a mut dyn Write, tty: bool) -> Self {
        Progress {
            out,
            tty,
            last_len: 0,
        }
    }

    fn tick(&mut self, stage: &str, done: usize, total: usize) {
        let msg = if total > 0 {
            format!("{stage} {done}/{total}")
        } else {
            format!("{stage} {done}")
        };
        let len = msg.chars().count();
        if self.tty {
            let pad = self.last_len.saturating_sub(len);
            let _ = write!(self.out, "\r{msg}{}", " ".repeat(pad));
            self.last_len = len;
        } else {
            let _ = writeln!(self.out, "{msg}");
        }
        let _ = self.out.flush();
    }

    fn finish(&mut self) {
        if self.tty && self.last_len > 0 {
            let _ = write!(self.out, "\r{}\r", " ".repeat(self.last_len));
            let _ = self.out.flush();
            self.last_len = 0;
        }
    }
}

/// `cmd_scan`'s deep branch. `Err` is the exit status after the message.
fn deep_findings(
    env: &Env,
    quiet: bool,
    jobs: usize,
    stderr: &mut dyn Write,
) -> Result<Vec<vahta_scan::Finding>, i32> {
    let Some(home) = &env.home else {
        let _ = writeln!(
            stderr,
            "vahta scan: error: could not determine the home directory"
        );
        return Err(EXIT_LEAKS);
    };
    let appdata = env.appdata.as_deref();
    let result = {
        let mut printer = (!quiet).then(|| Progress::new(&mut *stderr, env.stderr_is_tty));
        let result = match printer.as_mut() {
            Some(p) => {
                let mut tick = |stage: &str, done: usize, total: usize| {
                    p.tick(stage, done, total);
                    Ok::<(), std::convert::Infallible>(())
                };
                scan_deep_with_threads(home, appdata, Some(&mut tick), jobs)
            }
            None => scan_deep_with_threads::<std::convert::Infallible>(home, appdata, None, jobs),
        };
        // Python's `finally: finish_progress()`.
        if let Some(p) = printer.as_mut() {
            p.finish();
        }
        result
    };
    match result {
        Ok(found) => Ok(found),
        Err(DeepError::Progress(never)) => match never {},
    }
}

fn run_scan(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let cwd = env.cwd.as_path();
    let parsed = match parse_scan(args) {
        Parsed::Help => {
            let _ = stdout.write_all(USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Parsed::Error(msg) => {
            let _ = write!(stderr, "vahta scan: error: {msg}\n\n{USAGE}");
            return EXIT_USAGE;
        }
        Parsed::Run(a) => a,
    };

    let target: PathBuf = match &parsed.path {
        Some(p) => cwd.join(p),
        None => cwd.to_path_buf(),
    };
    let root = match dunce::canonicalize(&target) {
        Ok(r) if r.is_dir() => r,
        Ok(_) => {
            let _ = writeln!(
                stderr,
                "vahta scan: error: not a directory: {}",
                target.display()
            );
            return EXIT_USAGE;
        }
        Err(e) => {
            let _ = writeln!(
                stderr,
                "vahta scan: error: cannot read {}: {e}",
                target.display()
            );
            return EXIT_USAGE;
        }
    };
    let root_str = root.to_string_lossy().into_owned();

    let jobs = parsed.jobs.unwrap_or_else(vahta_scan::par::default_threads);
    let mut findings = scan_project_with_threads(&root, parsed.include_excluded, jobs);

    if parsed.deep {
        // Avoid double-counting files already seen under the project tree when
        // the project is inside the home directory. Project findings stay
        // first and are not re-sorted against the deep ones, as in Python.
        let deep = match deep_findings(env, parsed.quiet, jobs, stderr) {
            Ok(d) => d,
            Err(code) => return code,
        };
        // Compared as resolved paths: the project's are under the
        // canonicalized root, the deep ones under the home directory as given,
        // so the strings can differ for one file.
        let key = |p: &str| dunce::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
        let mut seen: std::collections::HashSet<PathBuf> =
            findings.iter().map(|f| key(&f.path)).collect();
        for f in deep {
            if seen.insert(key(&f.path)) {
                findings.push(f);
            }
        }
    }

    if parsed.json {
        // Python: `theme.out(json.dumps(obj, indent=2))` — the document and
        // exactly one newline, no trailing blank line.
        let text = findings_to_json(&findings, &root_str, &parsed.strict);
        let _ = writeln!(stdout, "{text}");
    } else {
        // Python: `theme.out(report)` then `theme.out("")`.
        let text = format_human_report(&findings, &root_str, &parsed.strict);
        let _ = writeln!(stdout, "{text}");
        let _ = writeln!(stdout);
    }

    if leak_count(&findings, &parsed.strict) > 0 {
        EXIT_LEAKS
    } else {
        EXIT_CLEAN
    }
}

/// The whole program, parameterised so it can be driven without a process.
pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    // Say on stderr, never stdout, when a setup we made has gone stale.
    if args.first().map(String::as_str) != Some("setup")
        && let Some(setup_env) = &env.setup
    {
        setup::stale_notice(setup_env, stderr);
    }
    match args.first().map(String::as_str) {
        Some("setup") => setup::run(&args[1..], env.setup.as_ref(), stdout, stderr),
        Some("scan") => run_scan(&args[1..], env, stdout, stderr),
        Some("list") => vault_cmds::run_list(&args[1..], env, stdout, stderr),
        Some("check") => vault_cmds::run_check(&args[1..], env, stdout, stderr),
        Some("daemon") => daemon_cmd::run(&args[1..], env, stdout, stderr),
        Some(cmd @ ("init" | "add" | "reset" | "remove" | "import" | "reveal" | "copy")) => {
            vault_ops::run(cmd, &args[1..], env, stdout, stderr)
        }
        // `set` did either, and so could overwrite a secret by a mistyped name;
        // it was split in two, and whoever still types it is told which to use.
        Some("set") => {
            let _ = writeln!(
                stderr,
                "vahta: error: unknown command: set — use `vahta add` (new) or `vahta reset` (overwrite)"
            );
            EXIT_USAGE
        }
        Some("bind") => bind_cmd::run(&args[1..], env, stdout, stderr),
        Some("run") => run_cmd::run_run(&args[1..], env, stdout, stderr),
        Some("delegate") => run_cmd::run_delegate(&args[1..], env, stdout, stderr),
        Some("unlock") => session_cmds::run_unlock(&args[1..], env, stdout, stderr),
        Some("lock") => session_cmds::run_lock(&args[1..], env, stdout, stderr),
        Some("sessions") => session_cmds::run_sessions(&args[1..], env, stdout, stderr),
        Some("output") => output_cmd::run(&args[1..], env, stdout, stderr),
        // The prompt window, started by the daemon; not listed in the help.
        Some("_surface") => surface_cmd::run(&args[1..]),
        Some("-h") | Some("--help") => {
            let _ = stdout.write_all(TOP_USAGE.as_bytes());
            EXIT_CLEAN
        }
        Some("--version") | Some("-V") => {
            let _ = writeln!(stdout, "vahta {}", env!("CARGO_PKG_VERSION"));
            EXIT_CLEAN
        }
        Some(other) => {
            let _ = write!(
                stderr,
                "vahta: error: unknown command: {other}\n\n{TOP_USAGE}"
            );
            EXIT_USAGE
        }
        None => {
            let _ = write!(stderr, "{TOP_USAGE}");
            EXIT_USAGE
        }
    }
}

/// Python's `Path.home()`: on POSIX `$HOME` (an empty or all-slash value is
/// the root), else the passwd entry's directory; on Windows the profile
/// directory, as `std::env::home_dir` gives it.
fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    if let Some(h) = std::env::var_os("HOME") {
        use std::os::unix::ffi::OsStrExt;
        let bytes = h.as_bytes();
        let end = bytes.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
        return if end == 0 {
            Some(PathBuf::from("/"))
        } else {
            Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end])))
        };
    }
    #[allow(deprecated)]
    std::env::home_dir()
}

/// The setup environment of this process. The hook is the `vahta-hook` next to
/// the running executable, whether or not it exists.
fn setup_env(home: Option<PathBuf>) -> Option<vahta_setup::Env> {
    let hook_name = format!("vahta-hook{}", std::env::consts::EXE_SUFFIX);
    let hook = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join(&hook_name)))
        .unwrap_or_else(|| PathBuf::from(hook_name));
    Some(vahta_setup::Env {
        home: home?,
        vars: std::env::vars().collect(),
        path: std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default(),
        os: vahta_setup::Os::current(),
        hook,
    })
}

/// `VAHTA_DATA_DIR`, else `<platform data dir>/vahta`.
fn data_dir() -> Option<PathBuf> {
    match std::env::var_os("VAHTA_DATA_DIR") {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => vahta_vault::store::LocalStore::platform_default().map(|s| s.root().to_path_buf()),
    }
}

/// The program: what `vahta` and `vh` run (`src/main.rs`, `src/bin/vh.rs`).
pub fn main() {
    // Non-UTF-8 arguments are lossily converted rather than panicking.
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("vahta: error: cannot determine the current directory: {e}");
            std::process::exit(EXIT_USAGE);
        }
    };
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let home = home_dir();
    let env = Env {
        cwd,
        setup: setup_env(home.clone()),
        home,
        appdata: std::env::var_os("APPDATA"),
        stderr_is_tty: stderr.is_terminal(),
        data_dir: data_dir(),
    };
    let code = run(&args, &env, &mut stdout.lock(), &mut stderr.lock());
    std::process::exit(code);
}
