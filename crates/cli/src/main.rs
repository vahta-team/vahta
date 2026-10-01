//! `vahta` — the command line.
//!
//! One subcommand so far: `vahta scan [PATH]`, the project path of
//! `ka scan`, and with `--deep` the home dotfiles, MCP configs and agent
//! session transcripts as well. Its flags, output and exit codes match the
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
//! recursion limit, or an integer of more than 4300 digits — this reports the
//! error on stderr and exits 1, the status an uncaught Python exception has.
//! It does not skip the line: that would hide a divergence rather than reproduce
//! one, and a scanner that quietly stops looking is the wrong way to fail.
//!
//! Prints names, paths and counts. Never a secret value: the scanner does not
//! hold one.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use vahta_scan::deep::{scan_deep, DeepError};
use vahta_scan::finding::leak_count;
use vahta_scan::report::{findings_to_json, format_human_report};
use vahta_scan::walk::scan_project;

/// Exit codes, as `ka scan` has them: 0 clean, 1 leaks at the gate, 2 usage.
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_LEAKS: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

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
values. A transcript nested deeper than about 990 levels, or holding an
integer of more than 4300 digits, stops the scan with an error and exit
status 1, as `ka scan --deep` does.

Not available here: --yes (import into a vault). Use the Python `ka scan`.
";

const TOP_USAGE: &str = "\
usage: vahta <command> [options]

commands:
  scan    find plaintext secrets an agent can read in a project

Run `vahta scan --help` for the options.
";

struct ScanArgs {
    path: Option<String>,
    json: bool,
    strict: String,
    include_excluded: bool,
    deep: bool,
    quiet: bool,
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
}

/// `_scan_progress_printer`: stage and counts on stderr, never contents.
struct Progress<'a> {
    out: &'a mut dyn Write,
    tty: bool,
    last_len: usize,
}

impl<'a> Progress<'a> {
    fn new(out: &'a mut dyn Write, tty: bool) -> Self {
        Progress { out, tty, last_len: 0 }
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
    stderr: &mut dyn Write,
) -> Result<Vec<vahta_scan::Finding>, i32> {
    let Some(home) = &env.home else {
        let _ = writeln!(stderr, "vahta scan: error: could not determine the home directory");
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
                scan_deep(home, appdata, Some(&mut tick))
            }
            None => scan_deep::<std::convert::Infallible>(home, appdata, None),
        };
        // Python's `finally: finish_progress()`.
        if let Some(p) = printer.as_mut() {
            p.finish();
        }
        result
    };
    match result {
        Ok(found) => Ok(found),
        Err(DeepError::Recursion) => {
            let _ = writeln!(
                stderr,
                "vahta scan: error: a transcript line is nested too deeply to scan \
                 (Python: RecursionError); the --deep scan stopped"
            );
            Err(EXIT_LEAKS)
        }
        Err(DeepError::IntLimit) => {
            let _ = writeln!(
                stderr,
                "vahta scan: error: a transcript line holds an integer of more than 4300 \
                 digits (Python: ValueError); the --deep scan stopped"
            );
            Err(EXIT_LEAKS)
        }
        Err(DeepError::Progress(never)) => match never {},
    }
}

fn run_scan(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
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
    let root = match std::fs::canonicalize(&target) {
        Ok(r) if r.is_dir() => r,
        Ok(_) => {
            let _ = writeln!(stderr, "vahta scan: error: not a directory: {}", target.display());
            return EXIT_USAGE;
        }
        Err(e) => {
            let _ = writeln!(stderr, "vahta scan: error: cannot read {}: {e}", target.display());
            return EXIT_USAGE;
        }
    };
    let root_str = root.to_string_lossy().into_owned();

    let mut findings = scan_project(&root, parsed.include_excluded);

    if parsed.deep {
        // Avoid double-counting files already seen under the project tree when
        // the project is inside the home directory. Project findings stay
        // first and are not re-sorted against the deep ones, as in Python.
        let deep = match deep_findings(env, parsed.quiet, stderr) {
            Ok(d) => d,
            Err(code) => return code,
        };
        let mut seen: std::collections::HashSet<String> =
            findings.iter().map(|f| f.path.clone()).collect();
        for f in deep {
            if !seen.contains(&f.path) {
                seen.insert(f.path.clone());
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
pub fn run(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match args.first().map(String::as_str) {
        Some("scan") => run_scan(&args[1..], env, stdout, stderr),
        Some("-h") | Some("--help") => {
            let _ = stdout.write_all(TOP_USAGE.as_bytes());
            EXIT_CLEAN
        }
        Some("--version") | Some("-V") => {
            let _ = writeln!(stdout, "vahta {}", env!("CARGO_PKG_VERSION"));
            EXIT_CLEAN
        }
        Some(other) => {
            let _ = write!(stderr, "vahta: error: unknown command: {other}\n\n{TOP_USAGE}");
            EXIT_USAGE
        }
        None => {
            let _ = write!(stderr, "{TOP_USAGE}");
            EXIT_USAGE
        }
    }
}

/// Python's `Path.home()` on POSIX: `$HOME` (an empty or all-slash value is the
/// root), else the passwd entry's directory.
fn home_dir() -> Option<PathBuf> {
    match std::env::var_os("HOME") {
        Some(h) => {
            use std::os::unix::ffi::OsStrExt;
            let bytes = h.as_bytes();
            let end = bytes.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
            if end == 0 {
                Some(PathBuf::from("/"))
            } else {
                Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end])))
            }
        }
        #[allow(deprecated)]
        None => std::env::home_dir(),
    }
}

fn main() {
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
    let env = Env {
        cwd,
        home: home_dir(),
        appdata: std::env::var_os("APPDATA"),
        stderr_is_tty: stderr.is_terminal(),
    };
    let code = run(&args, &env, &mut stdout.lock(), &mut stderr.lock());
    std::process::exit(code);
}
