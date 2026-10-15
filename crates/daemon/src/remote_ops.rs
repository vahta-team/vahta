//! `vahta remote on|off`: the vault's opt-in to be used from other projects.
//!
//! Off by default. The flag lives in the signed vault, so only a change the
//! person approves can set it: a window shows the vault and what the flag
//! allows, and the master password writes it. Both directions need the person;
//! turning it off is not cheaper, so an agent cannot talk the person into one
//! and slip in the other. `vahta remote` alone only says which way it is.
//!
//! The flag opens nothing by itself: a secret is usable from another project
//! only where its own `from` list names that project (`vahta bind NAME --from`).

use vahta_auth::Action;
use vahta_vault::Vault;

use crate::journal::Entry;
use crate::ops::{Ctx, Flow, find_vault, from_surface, from_vault, lines_for, unlock_expecting};
use crate::protocol::ClientReply;

const APPROVE: usize = 0;

fn state(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

pub(crate) fn remote(ctx: &Ctx<'_>, cwd: &str, on: Option<bool>) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    peek.verified_for_unlock(ctx.store()).map_err(from_vault)?;
    let Some(want) = on else {
        let using: Vec<String> = peek
            .bindings
            .iter()
            .filter(|b| !b.from.is_empty())
            .map(|b| b.name.clone())
            .collect();
        let tail = if using.is_empty() {
            "no secret names another project in its `from` list".to_string()
        } else {
            format!("secrets with a `from` list: {}", using.join(", "))
        };
        return Ok(ClientReply::Done {
            message: format!("remote use is {} ({tail})", state(peek.remote)),
        });
    };
    if peek.remote == want {
        return Ok(ClientReply::Done {
            message: format!("remote use is already {}; nothing changed", state(want)),
        });
    }

    let title = if want {
        "Let other projects use this vault"
    } else {
        "Stop other projects using this vault"
    };
    let mut lines = lines_for(&project, &vault_path);
    if want {
        lines.push(
            "Turning on: a command run in ANOTHER project (`vahta run --vault ...`) may use a \
             secret of this vault, but only a secret whose `from` list names that project."
                .to_string(),
        );
        let named: Vec<String> = peek
            .bindings
            .iter()
            .filter(|b| !b.from.is_empty())
            .map(|b| format!("{}: {}", b.name, b.from.join(", ")))
            .collect();
        if named.is_empty() {
            lines.push("No secret has a `from` list yet, so nothing is reachable.".to_string());
        } else {
            lines.push("Secrets that name other projects:".to_string());
            lines.extend(named.iter().map(|n| format!("  {n}")));
        }
        lines.push(
            "Each use still follows the secret's own rules (programs, folders, network)."
                .to_string(),
        );
    } else {
        lines.push(
            "Turning off: this vault answers only to commands run inside its own project. \
             Sessions opened from other projects stop working."
                .to_string(),
        );
    }
    let panel = ctx.panel(title, lines);
    let mut window = ctx.window(title)?;
    let options = vec![
        if want { "Turn on" } else { "Turn off" }.to_string(),
        "No".to_string(),
    ];
    let choice = window
        .choose(&panel, "Make this change?", &options)
        .map_err(from_surface)?;
    if choice != Some(APPROVE) {
        ctx.journal(
            Entry::new("remote_set")
                .vault(&peek.vault_id)
                .result("declined", Some(state(want))),
        );
        window.close(None);
        return Err(ClientReply::Cancelled {
            message: "the person did not agree; remote use is unchanged".to_string(),
        });
    }
    let action = Action::Remote { on: want };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    vault.set_remote(want).map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    if !want {
        // Sessions opened from other projects end now, not at their next use.
        let ended = ctx
            .shared
            .sessions
            .lock()
            .map(|mut s| {
                s.end_where(
                    |s| s.vault_id == peek.vault_id && s.used_from.is_some(),
                    "remote_off",
                )
            })
            .unwrap_or_default();
        ctx.shared.record_ended(ended);
    }
    ctx.journal(
        Entry::new("remote_set")
            .vault(&peek.vault_id)
            .result("ok", Some(state(want))),
    );
    window.close(Some("Saved."));
    Ok(ClientReply::Done {
        message: format!("remote use is now {}", state(want)),
    })
}
