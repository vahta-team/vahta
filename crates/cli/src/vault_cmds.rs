//! `vahta list` and `vahta check`: the two commands that read a project's
//! vault without a password and without a daemon.
//!
//! Both read only what the vault file shows in the clear: its signed name
//! index. They verify the file's signatures, and compare the owner key and
//! generation with what this machine has seen (see `vahta-vault`'s store), so a
//! swapped owner or a rolled-back file is a hard error here, not a quiet
//! success. They never print a value, because they never have one.
//!
//! `vahta check` is built for CI, where there is a `vahta.toml` and no vault:
//! with no vault it validates the contract alone. Its output follows `ka
//! check`.

use std::io::Write;
use std::path::Path;

use serde_json::json;
use vahta_vault::manifest::{self, CheckResult};
use vahta_vault::project::Project;
use vahta_vault::store::LocalStore;
use vahta_vault::{Entry, Kind, Peek, Tier, Vault, Verification};

use crate::{EXIT_CLEAN, EXIT_FAILED, EXIT_USAGE, Env};

pub const LIST_USAGE: &str = "\
usage: vahta list [--json]

List the secrets in this project's vault: name, kind and tier. Reads the
vault's signed name index; needs no password and prints no values.

options:
  --json                 machine-readable JSON instead of text
  -h, --help             show this help
";

pub const CHECK_USAGE: &str = "\
usage: vahta check [--json]

Compare the project's vahta.toml with its vault. Exit 1 when a required name is
missing from the vault. With no vault (a CI run) only vahta.toml is validated.
Optional names that are absent are listed, never a failure.

options:
  --json                 machine-readable JSON instead of text
  -h, --help             show this help
";

enum Args {
    Run { json: bool },
    Help,
    Error(String),
}

fn parse(args: &[String]) -> Args {
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Args::Help,
            other => return Args::Error(format!("unrecognised argument: {other}")),
        }
    }
    Args::Run { json }
}

fn store(env: &Env) -> Option<LocalStore> {
    env.data_dir.as_ref().map(LocalStore::new)
}

const NO_STORE: &str =
    "cannot tell where Vahta keeps its local state on this machine (set VAHTA_DATA_DIR)";

fn kind_text(k: &Kind) -> String {
    match k {
        Kind::Env => "env".to_string(),
        Kind::File { file_name } => format!("file:{file_name}"),
    }
}

fn tier_text(t: Tier) -> &'static str {
    match t {
        Tier::Session => "session",
        Tier::EachUse => "each_use",
    }
}

fn sorted(entries: &[Entry]) -> Vec<&Entry> {
    let mut v: Vec<&Entry> = entries.iter().collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// Peek the vault and compare it with this machine's store. `Err` is the
/// message to print after `vahta <command>: error: `.
fn peek_verified(vault: &Path, store: &LocalStore) -> Result<(Peek, Verification), String> {
    let peek = Vault::peek(vault).map_err(|e| e.to_string())?;
    // A swapped owner and a rolled-back file are different events and the
    // library's messages say which; they are hard errors, not warnings.
    let verified = peek.verified(store).map_err(|e| e.to_string())?.status;
    Ok((peek, verified))
}

pub fn run_list(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let json = match parse(args) {
        Args::Help => {
            let _ = stdout.write_all(LIST_USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta list: error: {msg}\n\n{LIST_USAGE}");
            return EXIT_USAGE;
        }
        Args::Run { json } => json,
    };
    let Some(project) = Project::find(&env.cwd) else {
        let _ = writeln!(
            stderr,
            "vahta list: no Vahta project here (no .vahta/ in this directory or above)"
        );
        return EXIT_FAILED;
    };
    let vault = project.vault_path();
    if !vault.exists() {
        let _ = writeln!(stderr, "vahta list: this project has no vault yet");
        return EXIT_FAILED;
    }
    let Some(store) = store(env) else {
        let _ = writeln!(stderr, "vahta list: error: {NO_STORE}");
        return EXIT_FAILED;
    };
    let (peek, verified) = match peek_verified(&vault, &store) {
        Ok(ok) => ok,
        Err(msg) => {
            let _ = writeln!(stderr, "vahta list: error: {msg}");
            return EXIT_FAILED;
        }
    };
    let entries = sorted(&peek.entries);

    if json {
        let secrets: Vec<_> = entries
            .iter()
            .map(|e| {
                let mut o = json!({"name": e.name, "kind": "env", "tier": tier_text(e.tier)});
                if let Kind::File { file_name } = &e.kind {
                    o["kind"] = json!("file");
                    o["file_name"] = json!(file_name);
                }
                o
            })
            .collect();
        let doc = json!({
            "vault": vault.display().to_string(),
            "format": peek.format,
            "generation": peek.generation,
            "verified": verified == Verification::Pinned,
            "upgrade_pending": peek.upgrade_pending,
            "secrets": secrets,
        });
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&doc).unwrap_or_default()
        );
    } else {
        if entries.is_empty() {
            let _ = writeln!(stdout, "No secrets in the vault.");
        } else {
            let width = entries.iter().map(|e| e.name.len()).max().unwrap_or(0);
            let kinds: Vec<String> = entries.iter().map(|e| kind_text(&e.kind)).collect();
            let kind_width = kinds.iter().map(String::len).max().unwrap_or(0);
            for (e, kind) in entries.iter().zip(&kinds) {
                let _ = writeln!(
                    stdout,
                    "{:<width$}  {:<kind_width$}  {}",
                    e.name,
                    kind,
                    tier_text(e.tier)
                );
            }
        }
        if verified == Verification::Unpinned {
            let _ = writeln!(
                stderr,
                "unverified: this vault has not been unlocked on this machine yet"
            );
        }
        if peek.upgrade_pending {
            let _ = writeln!(
                stderr,
                "note: this vault is in an older format and will be upgraded the next time it is unlocked"
            );
        }
    }
    EXIT_CLEAN
}

/// The JSON shape of `ka check`, with `vault` where ka has `names_path`.
fn check_json(
    manifest_path: Option<&Path>,
    vault: Option<&Path>,
    r: &CheckResult,
    error: Option<&str>,
) -> String {
    let doc = json!({
        "ok": r.ok && error.is_none(),
        "manifest": manifest_path.map(|p| p.display().to_string()),
        "vault": vault.map(|p| p.display().to_string()),
        "required": r.required,
        "present": r.present,
        "missing": r.missing,
        "optional_absent": r.optional_absent,
        "error": error,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

fn empty_result() -> CheckResult {
    CheckResult {
        ok: true,
        required: vec![],
        present: vec![],
        missing: vec![],
        optional_absent: vec![],
    }
}

pub fn run_check(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let json = match parse(args) {
        Args::Help => {
            let _ = stdout.write_all(CHECK_USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Args::Error(msg) => {
            let _ = write!(stderr, "vahta check: error: {msg}\n\n{CHECK_USAGE}");
            return EXIT_USAGE;
        }
        Args::Run { json } => json,
    };

    // One place for every failure: ka's shape in JSON, a line on stderr in text.
    let fail = |stdout: &mut dyn Write,
                stderr: &mut dyn Write,
                manifest_path: Option<&Path>,
                vault: Option<&Path>,
                msg: &str|
     -> i32 {
        if json {
            let _ = writeln!(
                stdout,
                "{}",
                check_json(manifest_path, vault, &empty_result(), Some(msg))
            );
        } else {
            let _ = writeln!(stderr, "vahta check: error: {msg}");
        }
        EXIT_FAILED
    };

    let Some(project) = Project::find_contract(&env.cwd) else {
        return fail(
            stdout,
            stderr,
            None,
            None,
            "no Vahta project here (no .vahta/ or vahta.toml in this directory or above)",
        );
    };
    let manifest_path = project.manifest_path();
    if !manifest_path.is_file() {
        // ka: "No amnesia.toml found - nothing to check."
        if json {
            let _ = writeln!(stdout, "{}", check_json(None, None, &empty_result(), None));
        } else {
            let _ = writeln!(stdout, "No vahta.toml found - nothing to check.");
        }
        return EXIT_CLEAN;
    }
    let manifest = match manifest::load(&manifest_path) {
        Ok(m) => m,
        Err(e) => return fail(stdout, stderr, Some(&manifest_path), None, &e.to_string()),
    };

    let vault_path = project.vault_path();
    let has_vault = vault_path.is_file();
    let (names, vault_shown): (Option<Vec<String>>, Option<&Path>) = if has_vault {
        let Some(store) = store(env) else {
            return fail(
                stdout,
                stderr,
                Some(&manifest_path),
                Some(&vault_path),
                NO_STORE,
            );
        };
        match peek_verified(&vault_path, &store) {
            Ok((peek, verified)) => {
                if verified == Verification::Unpinned && !json {
                    let _ = writeln!(
                        stderr,
                        "unverified: this vault has not been unlocked on this machine yet"
                    );
                }
                (
                    Some(peek.entries.iter().map(|e| e.name.clone()).collect()),
                    Some(vault_path.as_path()),
                )
            }
            Err(msg) => {
                return fail(
                    stdout,
                    stderr,
                    Some(&manifest_path),
                    Some(&vault_path),
                    &msg,
                );
            }
        }
    } else {
        (None, None)
    };

    // No vault: the contract alone, which is all CI has. The names it
    // declares are listed as required or optional, none are "missing".
    let result = match &names {
        Some(names) => manifest::check_against_names(&manifest, names),
        None => {
            let mut r = manifest::check_against_names(&manifest, &[]);
            r.present.clear();
            r.missing.clear();
            r.optional_absent.clear();
            r.ok = true;
            r
        }
    };

    if json {
        let _ = writeln!(
            stdout,
            "{}",
            check_json(Some(&manifest_path), vault_shown, &result, None)
        );
    } else {
        let mut lines = vec![format!("Manifest: {}", manifest_path.display())];
        match vault_shown {
            Some(v) => lines.push(format!("Vault: {}", v.display())),
            None => lines.push("Vault: none here; checked vahta.toml only".to_string()),
        }
        if result.required.is_empty() {
            lines.push("No required secrets declared.".to_string());
            lines.push("OK".to_string());
        } else if names.is_none() {
            lines.push(format!("Required: {}", result.required.len()));
            lines.push("OK".to_string());
        } else {
            lines.push(format!("Required: {}", result.required.len()));
            lines.push(format!("Present:  {}", result.present.len()));
            if result.missing.is_empty() {
                lines.push("Missing:  (none)".to_string());
                lines.push("OK".to_string());
            } else {
                lines.push(format!("Missing:  {}", result.missing.join(", ")));
                lines.push("FAIL".to_string());
            }
            if !result.optional_absent.is_empty() {
                lines.push(format!(
                    "Optional absent (informational): {}",
                    result.optional_absent.join(", ")
                ));
            }
        }
        let text = lines.join("\n");
        if result.ok {
            let _ = writeln!(stdout, "{text}");
        } else {
            let _ = writeln!(stderr, "{text}");
        }
    }
    if result.ok { EXIT_CLEAN } else { EXIT_FAILED }
}
