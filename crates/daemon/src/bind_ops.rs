//! `vahta bind`: the agent proposes command rules for a secret, the person
//! approves them.
//!
//! * `bind NAME --allow RULE... --deny RULE...` replaces NAME's rules (or, with
//!   `--clear`, removes them). The window shows the old rules, the new ones,
//!   each allowed program as it resolved and the agent's reason (marked
//!   unverified).
//! * `bind` with no name approves `vahta.toml` as written: for every name whose
//!   proposed rules differ from the vault's, the window shows both.
//!
//! Either way nothing changes without the person choosing "Approve" and typing
//! the password. On approval the file is written first (so the repository
//! shows what is enforced), then the signed vault copy, which is the one the
//! daemon checks at run time.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use vahta_vault::project::Project;
use vahta_vault::rules::{self, ParsedRule, ProgramSpec};
use vahta_vault::{ApprovedRule, Binding, Peek, Vault, manifest};

use crate::binding;
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, check_name, error, find_vault, from_surface, from_vault, lines_for, refused,
    unknown_name, unlock,
};
use crate::pathfind;
use crate::protocol::{ClientReply, RefusalKind};
use crate::surface::sanitize_label;

const APPROVE: usize = 0;

pub(crate) struct BindArgs {
    pub cwd: String,
    pub name: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub clear: bool,
    pub reason: Option<String>,
    pub path: Option<String>,
}

/// One secret's change: what it has, what it would have, and (for the window)
/// the program each allow rule resolved to.
struct Change {
    name: String,
    old: Option<Binding>,
    new: Option<Binding>,
    resolved: Vec<(String, PathBuf)>,
    /// The proposed texts, to write into `vahta.toml` (not used when the file
    /// is the source).
    allow_texts: Vec<String>,
    deny_texts: Vec<String>,
}

fn rules_or_any(b: &Option<Binding>) -> String {
    match b {
        Some(b) => binding::rules_text(b),
        None => "any command".to_string(),
    }
}

/// The rules of one secret and the programs they resolved to.
type Built = (Option<Binding>, Vec<(String, PathBuf)>);

/// Resolve `rules` into a binding for `name`; `None` when there are none.
fn build(
    name: &str,
    allow: &[ParsedRule],
    deny: &[ParsedRule],
    path: Option<&OsString>,
    root: &Path,
) -> Result<Built, String> {
    let mut resolved = Vec::new();
    let mut approved: Vec<ApprovedRule> = Vec::new();
    for rule in allow {
        let word = match &rule.program {
            ProgramSpec::Bare(w) | ProgramSpec::Path(w) => w,
            ProgramSpec::Group(g) => return Err(format!("`{g}` is a group; groups are for deny")),
        };
        let Some(found) = pathfind::locate(word, path, root) else {
            return Err(format!(
                "cannot find the program of the rule `{}` (bare names are looked up in your PATH, \
                 paths are relative to the project root)",
                rule.text
            ));
        };
        resolved.push((rule.text.clone(), found.clone()));
        approved.push(rule.to_allow(found.to_string_lossy().into_owned()));
    }
    let denied: Vec<ApprovedRule> = deny.iter().map(ParsedRule::to_deny).collect();
    if approved.is_empty() && denied.is_empty() {
        return Ok((None, resolved));
    }
    Ok((
        Some(Binding {
            name: name.to_string(),
            allow: approved,
            deny: denied,
        }),
        resolved,
    ))
}

fn parse_all(texts: &[String], allow: bool) -> Result<Vec<ParsedRule>, String> {
    if texts.len() > 64 {
        return Err("too many rules".to_string());
    }
    texts.iter().map(|t| rules::parse_rule(t, allow)).collect()
}

fn texts(rules: &[ParsedRule]) -> Vec<String> {
    rules.iter().map(|r| r.text.clone()).collect()
}

pub(crate) fn bind(ctx: &Ctx<'_>, args: BindArgs) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(&args.cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    peek.verified(ctx.store()).map_err(from_vault)?;
    let path: Option<OsString> = args.path.as_deref().map(OsString::from);
    let changes = match &args.name {
        Some(name) => vec![change_for(&args, name, &peek, &project, path.as_ref())?],
        None => changes_from_file(&peek, &project, path.as_ref())?,
    };
    if changes.is_empty() {
        return Ok(ClientReply::Done {
            message: "nothing to approve: vahta.toml and the vault have the same rules".to_string(),
        });
    }
    let from_file = args.name.is_none();

    let title = if from_file {
        "Approve the rules in vahta.toml"
    } else {
        "Bind a secret to commands"
    };
    let mut lines = lines_for(&project, &vault_path);
    let mut warnings: Vec<String> = Vec::new();
    for c in &changes {
        lines.push(format!("{}:", c.name));
        lines.push(format!("  now:  {}", rules_or_any(&c.old)));
        lines.push(format!("  new:  {}", rules_or_any(&c.new)));
        for (text, program) in &c.resolved {
            lines.push(format!("  `{text}` is {}", program.display()));
            if let Some(w) = binding::agent_writable(program, &project.root) {
                let w = format!("{}: {w}", program.display());
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
            let file = program
                .file_name()
                .map(|n| rules::normalize_program_name(&n.to_string_lossy()))
                .unwrap_or_default();
            if ["@shells", "@interpreters"]
                .iter()
                .any(|g| rules::in_group(g, &file))
            {
                warnings.push(format!(
                    "`{text}` is a shell or interpreter: allowing it lets the agent run anything \
                     with this secret"
                ));
            }
        }
        if c.new.is_none() {
            lines.push("  (any command may use it again)".to_string());
        }
    }
    let mut panel = ctx.panel(title, lines);
    panel.agent_note = args.reason.as_deref().and_then(sanitize_label);
    if !warnings.is_empty() {
        panel.warning = Some(warnings.join(" "));
    }
    let names: Vec<String> = changes.iter().map(|c| c.name.clone()).collect();

    let mut window = ctx.window(title)?;
    let options = vec!["Approve".to_string(), "No".to_string()];
    let choice = window
        .choose(&panel, "Make these the rules?", &options)
        .map_err(from_surface)?;
    if choice != Some(APPROVE) {
        ctx.journal(
            Entry::new("bind")
                .vault(&peek.vault_id)
                .names(&names)
                .result("declined", None),
        );
        window.close(None);
        return Err(ClientReply::Cancelled {
            message: "the person did not agree; the rules are unchanged".to_string(),
        });
    }
    panel.warning = None;
    let mut vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
    if vault.vault_id() != peek.vault_id || vault.generation() != peek.generation {
        return Err(error(
            "the vault changed while the window was open; nothing was done",
        ));
    }
    if !from_file {
        write_file(&project, &changes)?;
    }
    for c in &changes {
        vault
            .set_bindings(&c.name, c.new.clone())
            .map_err(from_vault)?;
    }
    vault.save(&vault_path, ctx.store()).map_err(|e| {
        error(format!(
            "{e}; vahta.toml may now propose rules that the vault did not take (`vahta bind` \
             approves the file)"
        ))
    })?;
    let summary: Vec<String> = changes
        .iter()
        .map(|c| match &c.new {
            Some(b) => format!("{}: {}", c.name, binding::rules_text(b)),
            None => format!("{}: any command", c.name),
        })
        .collect();
    ctx.journal(
        Entry::new("bind")
            .vault(&peek.vault_id)
            .names(&names)
            .result(
                "approved",
                Some(if from_file {
                    "from vahta.toml"
                } else {
                    "proposed"
                }),
            ),
    );
    window.close(Some("Rules saved."));
    Ok(ClientReply::Done {
        message: format!("approved. {}", summary.join("; ")),
    })
}

fn change_for(
    args: &BindArgs,
    name: &str,
    peek: &Peek,
    project: &Project,
    path: Option<&OsString>,
) -> Flow<Change> {
    check_name(name)?;
    if !peek.entries.iter().any(|e| e.name == name) {
        return Err(unknown_name(name));
    }
    if args.clear && (!args.allow.is_empty() || !args.deny.is_empty()) {
        return Err(error("--clear takes no --allow or --deny"));
    }
    if !args.clear && args.allow.is_empty() && args.deny.is_empty() {
        return Err(error(
            "nothing to bind: give --allow RULE, --deny RULE, or --clear",
        ));
    }
    let allow = parse_all(&args.allow, true).map_err(error)?;
    let deny = parse_all(&args.deny, false).map_err(error)?;
    let (new, resolved) = build(name, &allow, &deny, path, &project.root).map_err(error)?;
    Ok(Change {
        name: name.to_string(),
        old: peek.bindings.iter().find(|b| b.name == name).cloned(),
        new,
        resolved,
        allow_texts: texts(&allow),
        deny_texts: texts(&deny),
    })
}

/// Every name whose `vahta.toml` rules differ from the vault's.
fn changes_from_file(peek: &Peek, project: &Project, path: Option<&OsString>) -> Flow<Vec<Change>> {
    let manifest_path = project.manifest_path();
    if !manifest_path.is_file() {
        return Err(refused(
            RefusalKind::NothingToDo,
            "there is no vahta.toml here to approve; propose rules with `vahta bind NAME --allow \
             PROGRAM`",
        ));
    }
    let manifest = manifest::load(&manifest_path).map_err(from_vault)?;
    let mut changes = Vec::new();
    for entry in &peek.entries {
        let proposed = manifest.secrets.get(&entry.name);
        let approved = peek.bindings.iter().find(|b| b.name == entry.name);
        if manifest::rules_in_sync(proposed, approved) {
            continue;
        }
        let (allow, deny) = proposed
            .map(|e| (e.allow.clone(), e.deny.clone()))
            .unwrap_or_default();
        let (new, resolved) = build(&entry.name, &allow, &deny, path, &project.root)
            .map_err(|e| error(format!("{}: {e}", entry.name)))?;
        changes.push(Change {
            name: entry.name.clone(),
            old: approved.cloned(),
            new,
            resolved,
            allow_texts: texts(&allow),
            deny_texts: texts(&deny),
        });
    }
    Ok(changes)
}

/// Write the new rules into `vahta.toml`, in memory first so a failure on the
/// second name leaves the file alone.
fn write_file(project: &Project, changes: &[Change]) -> Flow<()> {
    let manifest_path = project.manifest_path();
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
    let mut updated = current.clone();
    for c in changes {
        updated = manifest::set_rules(&updated, &c.name, &c.allow_texts, &c.deny_texts)
            .map_err(from_vault)?;
    }
    if updated != current {
        manifest::write_text(&manifest_path, &updated).map_err(from_vault)?;
    }
    Ok(())
}
