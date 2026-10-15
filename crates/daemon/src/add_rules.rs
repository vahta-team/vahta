//! The rules offered in the window of `vahta add`, after the value: the
//! agent's proposal (or the suggested category's default set) in plain words,
//! with a choice. One window, one password; the rules are stored in the same
//! save as the secret.
//!
//! * **Accept** stores the proposal.
//! * **Use the default set for CATEGORY** stores the category's own rules
//!   instead (see `proposal::default_set`). When the agent proposed a category
//!   below the one the value and name point at, CATEGORY is the detected one:
//!   the person's way of overruling a downgrade in one click.
//! * **Cancel** stores nothing.
//!
//! A category below the detected one is allowed, but the panel's first warning
//! says so, and the caller journals `category_downgraded`.

use std::path::Path;

use vahta_policy::{Category, describe, is_downgrade, suggest};
use vahta_vault::{Class, RuleSet, Tier};

use crate::ops::{Flow, cancelled, error, from_surface};
use crate::proposal::{self, Args, DefaultErr};
use crate::protocol::Panel;
use crate::surface::{Window, sanitize_label};

/// What the person agreed to.
pub(crate) struct Offer {
    pub rule_set: RuleSet,
    pub tier: Tier,
}

pub(crate) struct Inputs<'a> {
    pub name: &'a str,
    pub class: Class,
    pub tier: Option<Tier>,
    pub args: &'a Args,
    pub reason: Option<&'a str>,
    pub root: &'a Path,
    /// The harnesses of a connector (empty for a project secret).
    pub harnesses: &'a [String],
}

pub(crate) fn offer(window: &mut dyn Window, panel: &Panel, i: &Inputs<'_>) -> Flow<Offer> {
    let detected = suggest(Some(i.class), i.name);
    let chosen: &'static Category = match &i.args.category {
        Some(id) => proposal::find_category(id).map_err(error)?,
        None => detected,
    };
    let down = is_downgrade(chosen, detected);

    // The proposal: the agent's rules, or the default set when it gave none.
    let mut built = if i.args.is_bare() {
        match proposal::default_set(i.name, chosen, i.args, None, i.root) {
            Ok(b) => b,
            Err(DefaultErr::NeedHosts) => {
                let hosts = ask_hosts(window, panel, chosen)?;
                proposal::default_set(i.name, chosen, i.args, Some(hosts), i.root)
                    .map_err(|e| error(default_err(e)))?
            }
            Err(DefaultErr::Other(e)) => return Err(error(e)),
        }
    } else {
        proposal::build(i.name, Some(chosen), i.args, i.root).map_err(|e| {
            error(format!(
                "{e} (the value looks like a {}; category {} was used)",
                detected.name.to_lowercase(),
                chosen.id
            ))
        })?
    };
    if down {
        built.rule_set.downgraded_from = Some(detected.id.to_string());
    }
    built.rule_set.harnesses = i.harnesses.to_vec();

    // The alternative: the category's defaults, the detected one on a downgrade.
    let target = if down { detected } else { chosen };
    let alt_wanted = !(i.args.is_bare() && !down);
    let alt_ok = alt_wanted
        && match proposal::default_set(i.name, target, i.args, None, i.root) {
            Ok(_) | Err(DefaultErr::NeedHosts) => true,
            Err(DefaultErr::Other(_)) => false,
        };

    let tier = i.tier.unwrap_or(chosen.tier);
    let mut warnings: Vec<String> = Vec::new();
    if down {
        warnings.push(proposal::downgrade_line(
            chosen,
            detected,
            "the agent",
            "the value",
        ));
    }
    if i.tier == Some(Tier::Session) && chosen.tier == Tier::EachUse {
        warnings.push(format!(
            "The agent asks for a session tier; the default for {} is each-use.",
            chosen.id
        ));
    }
    warnings.extend(built.warnings.iter().cloned());

    let mut shown = panel.clone();
    shown.lines.push(describe(&built.rule_set, tier));
    shown.lines.push(format!("Category: {}", chosen.id));
    if !i.harnesses.is_empty() {
        shown
            .lines
            .push(format!("Only for: {}", i.harnesses.join(", ")));
    }
    for (text, program) in &built.resolved {
        shown
            .lines
            .push(format!("`{text}` is {}", program.display()));
    }
    shown.agent_note = i.reason.and_then(sanitize_label);
    if !warnings.is_empty() {
        shown.warning = Some(warnings.join(" "));
    }
    let mut options = vec!["Accept".to_string()];
    if alt_ok {
        options.push(format!("Use the default set for {}", target.id));
    }
    options.push("Cancel".to_string());
    let picked = window
        .choose(
            &shown,
            &format!("Store {} with these rules?", i.name),
            &options,
        )
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    if picked == 0 {
        return Ok(Offer {
            rule_set: built.rule_set,
            tier,
        });
    }
    if !(alt_ok && picked == 1) {
        return Err(cancelled());
    }
    let hosts = match proposal::default_set(i.name, target, i.args, None, i.root) {
        Err(DefaultErr::NeedHosts) => Some(ask_hosts(window, &shown, target)?),
        _ => None,
    };
    let mut alt = proposal::default_set(i.name, target, i.args, hosts, i.root)
        .map_err(|e| error(default_err(e)))?;
    alt.rule_set.harnesses = i.harnesses.to_vec();
    Ok(Offer {
        rule_set: alt.rule_set,
        tier: target.tier,
    })
}

fn default_err(e: DefaultErr) -> String {
    match e {
        DefaultErr::NeedHosts => "no hosts were given".to_string(),
        DefaultErr::Other(s) => s,
    }
}

fn ask_hosts(
    window: &mut dyn Window,
    panel: &Panel,
    cat: &Category,
) -> Flow<Vec<vahta_vault::HostRule>> {
    let mut p = panel.clone();
    p.lines.push(format!(
        "A {} may reach only the hosts you name, through Vahta.",
        cat.name.to_lowercase()
    ));
    let text = window
        .ask_text(
            &p,
            "Hosts it may reach, comma-separated (e.g. api.stripe.com)",
        )
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    proposal::parse_hosts(text.split(',')).map_err(|e| error(format!("{e}; nothing was done")))
}
