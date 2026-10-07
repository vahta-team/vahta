//! `vahta run --ask`: a command that a secret's approved rules do not allow,
//! put to the person.
//!
//! The window shows what would run and with which secrets, the program as it
//! resolved, the rules in force and, marked as unverified, the agent's reason.
//! The person chooses:
//!
//! * **Allow once**: the run goes on; nothing is stored;
//! * **No** (or closing the window): nothing runs, exit 4;
//! * **Add to the list**: with the password again, the program is added to the
//!   secret's `allow` rules, in `vahta.toml` first (so the file the repository
//!   reviews shows it) and then in the vault. Not offered for a denied
//!   command, or when the ask comes from a delegated session.
//!
//! A denied command can be allowed once and never added: a deny rule is a
//! decision the person made earlier, and removing one is `vahta bind`.

use std::path::{Path, PathBuf};

use vahta_vault::project::Project;
use vahta_vault::rules::parse_rule;
use vahta_vault::{ApprovedRule, Binding, Peek, manifest};

use crate::binding::{self, Verdict};
use crate::journal::Entry;
use crate::ops::{Ctx, Flow, error, from_surface, from_vault, lines_for, unlock};
use crate::protocol::ClientReply;
use crate::surface::sanitize_label;

const ALLOW_ONCE: usize = 0;
const NO: usize = 1;
const ADD: usize = 2;

/// What the person decided, when it was not "no".
pub(crate) enum Decision {
    Once,
    Added,
}

/// The rule that would let `argv0` run: the name as typed for a bare name, and
/// for a path the canonical program relative to the project (or absolute). The
/// text must be a rule the parser accepts, and must not repeat a rule the
/// secret already has under another file.
fn proposed_rule(
    argv0: &str,
    program: &Path,
    project_root: &Path,
    failures: &[(&Binding, Verdict)],
) -> Option<(String, ApprovedRule)> {
    let text = if argv0.contains(['/', '\\']) {
        let root =
            std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
        match program.strip_prefix(&root) {
            Ok(rel) => {
                let rel: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                format!("./{}", rel.join("/"))
            }
            Err(_) => program.to_string_lossy().into_owned(),
        }
    } else {
        argv0.to_string()
    };
    let parsed = parse_rule(&text, true).ok()?;
    if !parsed.args.is_empty() || parsed.text != text {
        return None;
    }
    let clash = failures
        .iter()
        .any(|(b, _)| b.allow.iter().any(|r| r.text == parsed.text));
    if clash {
        return None;
    }
    let approved = parsed.to_allow(program.to_string_lossy().into_owned());
    Some((text, approved))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ask(
    ctx: &Ctx<'_>,
    project: &Project,
    vault_path: &Path,
    peek: &Peek,
    argv: &[String],
    program: Option<&Path>,
    failures: &[(&Binding, Verdict)],
    secrets_line: String,
    command_line: String,
    reason: Option<&str>,
    delegated: bool,
) -> Flow<Decision> {
    let title = "Run a command that is not on the list";
    let denied = failures
        .iter()
        .any(|(_, v)| matches!(v, Verdict::Denied { .. }));
    let proposal = match program {
        Some(p) if !denied && !delegated => proposed_rule(&argv[0], p, &project.root, failures),
        _ => None,
    };
    let names: Vec<String> = failures.iter().map(|(b, _)| b.name.clone()).collect();

    let mut lines = lines_for(project, vault_path);
    lines.push(secrets_line);
    lines.push(command_line);
    lines.push(match program {
        Some(p) => format!("Program: {}", p.display()),
        None => "Program: not found".to_string(),
    });
    for (b, v) in failures {
        let why = match v {
            Verdict::Denied { rule } => format!("denied by `{rule}`"),
            Verdict::NotAllowed { why } => why.clone(),
            Verdict::Allowed => String::new(),
        };
        lines.push(format!("{}: {} ({why})", b.name, binding::rules_text(b)));
    }
    let mut panel = ctx.panel(title, lines);
    panel.agent_note = reason.and_then(sanitize_label);
    let mut warnings: Vec<&str> = Vec::new();
    if denied {
        warnings.push("This command is on the deny list.");
    }
    if let Some(p) = program
        && let Some(w) = binding::agent_writable(p, &project.root)
    {
        warnings.push(w);
    }
    if !warnings.is_empty() {
        panel.warning = Some(warnings.join(" "));
    }

    let mut options = vec!["Allow once".to_string(), "No".to_string()];
    if let Some((text, _)) = &proposal {
        options.push(format!("Add `{text}` to the list"));
    }
    let mut window = ctx.window(title)?;
    let choice = window
        .choose(&panel, "Let this command use the secret?", &options)
        .map_err(from_surface)?;
    let journal = |event: &str, result: &str| {
        let shown = program
            .map(|p| format!("program {}", p.display()))
            .unwrap_or_else(|| "program not found".to_string());
        ctx.journal(
            Entry::new(event)
                .vault(&peek.vault_id)
                .names(&names)
                .result(result, Some(&shown)),
        );
    };
    match choice {
        Some(ALLOW_ONCE) => {
            journal("run_allowed_once", "ok");
            window.close(None);
            Ok(Decision::Once)
        }
        Some(ADD) if proposal.is_some() => {
            let Some((text, approved)) = proposal else {
                return Err(error("nothing to add"));
            };
            add_to_list(
                ctx,
                &mut *window,
                &mut panel,
                project,
                vault_path,
                peek,
                failures,
                &text,
                &approved,
            )?;
            journal("binding_added", "ok");
            window.close(Some(&format!("Added `{text}`.")));
            Ok(Decision::Added)
        }
        Some(NO) | Some(_) | None => {
            journal("run_refused", "declined");
            window.close(None);
            Err(ClientReply::Cancelled {
                message: "the person did not agree; nothing was run".to_string(),
            })
        }
    }
}

/// Write `approved` into every failing secret's rules: `vahta.toml` first,
/// then the vault, after a fresh password and a check that the vault is the
/// one the window was opened on.
#[allow(clippy::too_many_arguments)]
fn add_to_list(
    ctx: &Ctx<'_>,
    window: &mut dyn crate::surface::Window,
    panel: &mut crate::protocol::Panel,
    project: &Project,
    vault_path: &Path,
    peek: &Peek,
    failures: &[(&Binding, Verdict)],
    text: &str,
    approved: &ApprovedRule,
) -> Flow<()> {
    panel.lines.push(format!("Adding the rule: {text}"));
    panel.warning = None;
    let mut vault = unlock(ctx, window, vault_path, panel)?;
    if vault.vault_id() != peek.vault_id || vault.generation() != peek.generation {
        return Err(error(
            "the vault changed while the window was open; nothing was done",
        ));
    }
    let manifest_path: PathBuf = project.manifest_path();
    let current = match std::fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(error(format!(
                "cannot read {}: {e}; nothing was done",
                manifest_path.display()
            )));
        }
    };
    let mut updated = current;
    for (b, _) in failures {
        updated = manifest::add_rule(&updated, &b.name, true, text).map_err(from_vault)?;
    }
    manifest::write_text(&manifest_path, &updated).map_err(from_vault)?;
    for (b, _) in failures {
        let mut next = (*b).clone();
        next.allow.push(approved.clone());
        vault
            .set_bindings(&b.name, Some(next))
            .map_err(from_vault)?;
    }
    vault.save(vault_path, ctx.store()).map_err(|e| {
        error(format!(
            "{e}; vahta.toml now proposes the rule but the vault did not take it (`vahta bind` \
             approves the file)"
        ))
    })?;
    Ok(())
}
