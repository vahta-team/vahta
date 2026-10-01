//! `vahta` — the command line.
//!
//! One subcommand so far: `vahta scan [PATH]`, the project path of
//! `ka scan`. Its flags, output and exit codes match the Python command's, and
//! `src/key_amnesia/scan_py.py` remains the specification.
//!
//! What it does **not** do, deliberately: `--deep` (home dotfiles and agent
//! transcripts) and the interactive import into a vault. Both stay in the
//! Python `ka scan`; asking for them here is a usage error rather than a
//! silent half-scan.
//!
//! Prints names, paths and counts. Never a secret value: the scanner does not
//! hold one.

use std::io::Write;
use std::path::{Path, PathBuf};

use vahta_scan::finding::leak_count;
use vahta_scan::report::{findings_to_json, format_human_report};
use vahta_scan::walk::scan_project;

/// Exit codes, as `ka scan` has them: 0 clean, 1 leaks at the gate, 2 usage.
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_LEAKS: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

const USAGE: &str = "\
usage: vahta scan [PATH] [--json] [--strict {certain,high,paranoid}]
                  [--include-excluded | --wide] [--no-import] [--quiet]

Find plaintext secrets an agent can read under PATH (default: the current
directory). Reports names, paths and counts; never values.

options:
  --json                 machine-readable JSON instead of text
  --strict LEVEL         exit 1 when findings at this gate are present:
                         certain, high (default) or paranoid
  --include-excluded     also walk node_modules, .venv, build dirs, .git
  --wide                 alias for --include-excluded
  --no-import, --quiet   accepted for compatibility with `ka scan`; no effect
  -h, --help             show this help

Not available here: --deep and --yes. Use the Python `ka scan` for those.
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
            "--no-import" | "--quiet" => {}
            "--deep" => {
                return Parsed::Error(
                    "--deep is only available in the Python `ka scan`; \
                     vahta scan covers the project tree"
                        .to_string(),
                );
            }
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

fn run_scan(
    args: &[String],
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
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

    let findings = scan_project(&root, parsed.include_excluded);

    if parsed.json {
        // Python: `theme.out(json.dumps(obj, indent=2) + "\n")`, and
        // `theme.out` appends a newline of its own, so stdout ends in a blank
        // line. Reproduced so the two commands' output is byte-identical.
        let text = findings_to_json(&findings, &root_str, &parsed.strict);
        let _ = writeln!(stdout, "{text}");
        let _ = writeln!(stdout);
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
    cwd: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match args.first().map(String::as_str) {
        Some("scan") => run_scan(&args[1..], cwd, stdout, stderr),
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
    let code = run(&args, &cwd, &mut stdout.lock(), &mut stderr.lock());
    std::process::exit(code);
}
