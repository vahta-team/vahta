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
use std::path::PathBuf;

use vahta_vault::manifest;
use vahta_vault::project::Project;
use vahta_vault::{Network, Peek, RuleSet, Vault};

use crate::binding;
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, check_name, class_by_name, error, find_vault, from_surface, from_vault, lines_for,
    refused, unknown_name, unlock_expecting,
};
use crate::proposal::{self, Args, Built};
use crate::protocol::{ClientReply, RefusalKind};
use crate::surface::sanitize_label;
use vahta_auth::Action;

const APPROVE: usize = 0;

pub(crate) struct BindArgs {
    pub cwd: String,
    pub name: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub category: Option<String>,
    pub dirs: Vec<String>,
    pub net: Option<String>,
    pub clear: bool,
    pub reason: Option<String>,
    pub path: Option<String>,
}

/// One secret's change: what it has, what it would have, and (for the window)
/// the program each allow rule resolved to.
struct Change {
    name: String,
    old: Option<RuleSet>,
    new: Option<RuleSet>,
    resolved: Vec<(String, PathBuf)>,
    warnings: Vec<String>,
    /// The loud line when the category is below the detected one.
    downgrade: Option<String>,
}

fn rules_or_none(b: &Option<RuleSet>) -> String {
    match b {
        Some(b) => match binding::rules_text(b) {
            t if t.is_empty() => "no restrictions".to_string(),
            t => t,
        },
        None => "no rules (nothing may use it)".to_string(),
    }
}

/// The detected category of a secret: the class its value showed when it was
/// stored, else the one its name suggests.
fn detected_for(peek: &Peek, name: &str) -> &'static vahta_policy::Category {
    let class = peek
        .entries
        .iter()
        .find(|e| e.name == name)
        .and_then(|e| e.class)
        .unwrap_or_else(|| class_by_name(name));
    vahta_policy::suggest(Some(class), name)
}

/// A change for `name` from a built proposal, with the downgrade marked.
fn change_of(name: &str, peek: &Peek, built: Option<Built>, who: &str) -> Change {
    let old = peek.bindings.iter().find(|b| b.name == name).cloned();
    let Some(mut built) = built else {
        return Change {
            name: name.to_string(),
            old,
            new: None,
            resolved: Vec::new(),
            warnings: Vec::new(),
            downgrade: None,
        };
    };
    let detected = detected_for(peek, name);
    let mut downgrade = None;
    if let Some(chosen) = built
        .rule_set
        .category
        .as_deref()
        .and_then(vahta_policy::category)
        && vahta_policy::is_downgrade(chosen, detected)
    {
        built.rule_set.downgraded_from = Some(detected.id.to_string());
        downgrade = Some(proposal::downgrade_line(
            chosen,
            detected,
            who,
            "this secret",
        ));
    }
    Change {
        name: name.to_string(),
        old,
        new: Some(built.rule_set),
        resolved: built.resolved,
        warnings: built.warnings,
        downgrade,
    }
}

pub(crate) fn bind(ctx: &Ctx<'_>, args: BindArgs) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(&args.cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    peek.verified_for_unlock(ctx.store()).map_err(from_vault)?;
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
        lines.push(format!("  now:  {}", rules_or_none(&c.old)));
        lines.push(format!("  new:  {}", rules_or_none(&c.new)));
        for (text, program) in &c.resolved {
            lines.push(format!("  `{text}` is {}", program.display()));
        }
        if c.new.is_none() {
            lines.push("  (no command may use it until rules are approved)".to_string());
        }
        // Loud first.
        if let Some(d) = &c.downgrade {
            warnings.insert(0, d.clone());
        }
        for w in &c.warnings {
            if !warnings.contains(w) {
                warnings.push(w.clone());
            }
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
    let action = Action::Bind {
        names: names.clone(),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
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
            None => format!("{}: no rules", c.name),
        })
        .collect();
    for c in changes.iter().filter(|c| c.downgrade.is_some()) {
        let detail = c.new.as_ref().map(|n| {
            format!(
                "{} -> {}",
                n.downgraded_from.as_deref().unwrap_or("?"),
                n.category.as_deref().unwrap_or("?")
            )
        });
        ctx.journal(
            Entry::new("category_downgraded")
                .vault(&peek.vault_id)
                .names(std::slice::from_ref(&c.name))
                .result("accepted", detail.as_deref()),
        );
    }
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

fn net_text(n: &Network) -> String {
    match n {
        Network::None => "none".to_string(),
        Network::App => "app".to_string(),
        Network::Hosts(h) => format!(
            "hosts:{}",
            h.iter()
                .map(|h| h.text.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
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
    let any_rule = !args.allow.is_empty()
        || !args.deny.is_empty()
        || args.category.is_some()
        || !args.dirs.is_empty()
        || args.net.is_some();
    if args.clear && any_rule {
        return Err(error("--clear takes no rule options"));
    }
    if !args.clear && !any_rule {
        return Err(error(
            "nothing to bind: give --category, --allow, --deny, --dir, --net or --clear",
        ));
    }
    if args.clear {
        return Ok(change_of(name, peek, None, "the agent"));
    }
    let old = peek.bindings.iter().find(|b| b.name == name);
    let only_commands = args.category.is_none() && args.dirs.is_empty() && args.net.is_none();
    let mut a = Args {
        category: args.category.clone(),
        allow: args.allow.clone(),
        deny: args.deny.clone(),
        dirs: args.dirs.clone(),
        net: args.net.clone(),
        path: path.cloned(),
    };
    let category = match (&args.category, old) {
        (Some(c), _) => Some(proposal::find_category(c).map_err(error)?),
        // Only commands given: the rest of the approved rules stays.
        (None, Some(o)) if only_commands => {
            a.dirs = o.dirs.iter().map(|d| d.text.clone()).collect();
            a.net = Some(net_text(&o.network));
            o.category.as_deref().and_then(vahta_policy::category)
        }
        (None, _) => Some(detected_for(peek, name)),
    };
    let built = proposal::build(name, category, &a, &project.root).map_err(error)?;
    Ok(change_of(name, peek, Some(built), "the agent"))
}

/// Every name whose `vahta.toml` rules differ from the vault's. A name the
/// file proposes nothing for is left alone.
fn changes_from_file(peek: &Peek, project: &Project, path: Option<&OsString>) -> Flow<Vec<Change>> {
    let manifest_path = project.manifest_path();
    if !manifest_path.is_file() {
        return Err(refused(
            RefusalKind::NothingToDo,
            "there is no vahta.toml here to approve; propose rules with `vahta bind NAME \
             --category CATEGORY --allow PROGRAM`",
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
        let fail = |e: String| error(format!("{}: {e}", entry.name));
        let built = match proposed {
            Some(e)
                if !(e.allow.is_empty()
                    && e.deny.is_empty()
                    && e.category.is_none()
                    && e.dirs.is_empty()
                    && e.network.is_none()) =>
            {
                let category = match &e.category {
                    Some(c) => Some(proposal::find_category(c).map_err(fail)?),
                    None => None,
                };
                let a = Args {
                    category: e.category.clone(),
                    allow: e.allow.iter().map(|r| r.text.clone()).collect(),
                    deny: e.deny.iter().map(|r| r.text.clone()).collect(),
                    dirs: e.dirs.clone(),
                    net: match e.network.as_deref() {
                        Some("hosts") => Some(format!(
                            "hosts:{}",
                            e.hosts
                                .iter()
                                .map(|h| h.text.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        )),
                        other => other.map(str::to_string),
                    },
                    path: path.cloned(),
                };
                Some(proposal::build(&entry.name, category, &a, &project.root).map_err(fail)?)
            }
            _ => None,
        };
        changes.push(change_of(&entry.name, peek, built, "vahta.toml"));
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
        let texts = c.new.as_ref().map(proposal::texts_of).unwrap_or_default();
        updated = manifest::set_rules(&updated, &c.name, &texts).map_err(from_vault)?;
    }
    if updated != current {
        manifest::write_text(&manifest_path, &updated).map_err(from_vault)?;
    }
    Ok(())
}

/// Write one secret's rules into `vahta.toml` (see [`write_file`]); used by
/// `add`, which stores the rules with the secret.
pub(crate) fn write_rules(project: &Project, name: &str, rules: &RuleSet) -> Flow<()> {
    let change = Change {
        name: name.to_string(),
        old: None,
        new: Some(rules.clone()),
        resolved: Vec::new(),
        warnings: Vec::new(),
        downgrade: None,
    };
    write_file(project, &[change])
}
