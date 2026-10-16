//! The team commands: `vahta id`, `members`, `grant`, `revoke`, `share` and
//! `join`, and opening a vault as a member.
//!
//! A vault is shared by sending a file through a chat. The owner adds a member
//! by the key string the member sent, **after typing the verification digits
//! the member read out over another channel**; a package (see
//! `vahta_vault::member`) then goes to that member alone. Everything that
//! changes membership asks the owner's password in the window, like the device
//! commands (`password_only`: a phone cannot add a person). A member's own key
//! is `identity.vht` in the data directory, sealed with their password, which
//! is asked in the window whenever the package is opened.
//!
//! The journal records `identity_created`, `member_added`, `member_add_refused`,
//! `member_extended`, `member_removed`, `member_granted`, `member_revoked`,
//! `package_made`, `member_joined`, `transfer_made` and `transfer_imported`, with
//! names, roles, expiries and a twelve-digit fingerprint of the member's key;
//! never key material, a value or a password.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use vahta_auth::{Action, Factor, UnlockedBy};
use vahta_ipc::duration::{human, ymd};
use vahta_ipc::members::{MemberInfo, MemberOp, ProposedRules};
use vahta_vault::member::{self, FileInfo};
use vahta_vault::project::Project;
use vahta_vault::store::StateKey;
use vahta_vault::write::{VaultLock, write_atomic};
use vahta_vault::{
    Error, Peek, Recipient, RecipientKind, RecipientPublic, RecipientSecret, Role, Vault, identity,
};

use crate::authn::{MAX_PASSWORD_TRIES, Opened};
use crate::journal::Entry;
use crate::ops::{
    Ctx, Flow, cancelled, error, find_vault, from_surface, from_vault, lines_for, refused,
    unlock_expecting,
};
use crate::proposal;
use crate::protocol::{ClientReply, Panel, RefusalKind};
use crate::surface::Window;

/// A membership lasts from a minute to ten years.
const MIN_SPAN_SECS: u64 = 60;
const MAX_SPAN_SECS: u64 = 3650 * 86_400;
/// How many times the digits may be typed before the add is refused.
const WORD_TRIES: usize = 3;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn handle(ctx: &Ctx<'_>, cwd: &str, op: MemberOp) -> Flow<ClientReply> {
    match op {
        MemberOp::Id {} => id_create(ctx),
        MemberOp::Add {
            name,
            role,
            key,
            secs,
        } => add(ctx, cwd, &name, &role, &key, secs),
        MemberOp::List {} => list(cwd),
        MemberOp::Extend { name, secs } => extend(ctx, cwd, &name, secs),
        MemberOp::Remove { name } => remove(ctx, cwd, &name),
        MemberOp::Grant { name, member } => grant(ctx, cwd, &name, &member, true),
        MemberOp::Revoke { name, member } => grant(ctx, cwd, &name, &member, false),
        MemberOp::Share { member, out } => share(ctx, cwd, &member, &out),
        MemberOp::SendToOwner { name, out, rules } => send_to_owner(ctx, cwd, &name, &out, rules),
        MemberOp::Join { file, path } => join(ctx, cwd, &file, path),
    }
}

// --- Small things -------------------------------------------------------------------------------

fn role_text(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Editor => "editor",
        Role::Runner => "runner",
    }
}

fn parse_role(text: &str) -> Flow<Role> {
    match text.to_ascii_lowercase().as_str() {
        "admin" => Ok(Role::Admin),
        "editor" => Ok(Role::Editor),
        "runner" => Ok(Role::Runner),
        _ => Err(error("a role is runner, editor or admin")),
    }
}

fn check_span(secs: u64) -> Flow<()> {
    if (MIN_SPAN_SECS..=MAX_SPAN_SECS).contains(&secs) {
        Ok(())
    } else {
        Err(refused(
            RefusalKind::NothingToDo,
            "a membership lasts from 1 minute to 10 years; nothing was changed",
        ))
    }
}

fn check_member_name(name: &str) -> Flow<()> {
    if name.is_empty()
        || name.chars().count() > 64
        || name.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(error(
            "a member's name is one word of up to 64 characters (no spaces)",
        ));
    }
    Ok(())
}

fn identity_path(ctx: &Ctx<'_>) -> PathBuf {
    ctx.shared.options.paths.data.join("identity.vht")
}

fn state_text(r: &Recipient) -> &'static str {
    if r.expires_at.is_some_and(|t| t <= now()) {
        "expired"
    } else {
        "active"
    }
}

fn access_text(expires_at: Option<u64>) -> String {
    match expires_at {
        Some(t) if t <= now() => format!("ended {}", ymd(t)),
        Some(t) => format!("until {} (in {})", ymd(t), human(t - now())),
        None => "no end".to_string(),
    }
}

/// The member the person means, by name (case does not matter).
fn resolve<'a>(info: &'a FileInfo, text: &str) -> Flow<&'a Recipient> {
    let text = text.trim();
    info.recipients
        .iter()
        .find(|r| r.name.eq_ignore_ascii_case(text))
        .ok_or_else(|| {
            refused(
                RefusalKind::UnknownName,
                "no member has that name; see `vahta members list`",
            )
        })
}

/// An owner's vault: the project, the file, what a peek shows and the members.
/// A member's package is refused, since a member manages no one.
fn owner_vault(ctx: &Ctx<'_>, cwd: &str) -> Flow<(Project, PathBuf, Peek, FileInfo)> {
    let (project, path) = find_vault(cwd)?;
    let bytes = vahta_vault::read_file(&path).map_err(from_vault)?;
    let peek = Vault::peek_bytes(&bytes).map_err(from_vault)?;
    if peek.package {
        return Err(error(
            "this directory holds a member's package, not a vault: only the vault's owner (or an \
             admin with the full vault) manages members",
        ));
    }
    peek.verified_for_unlock(ctx.store()).map_err(from_vault)?;
    let info = member::file_info(&bytes).map_err(from_vault)?;
    Ok((project, path, peek, info))
}

/// A new file for `bytes`, readable by the person only, never over another.
fn write_new(path: &Path, bytes: &[u8]) -> Flow<()> {
    if !path.is_absolute() {
        return Err(error("the output path must be absolute"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut f) => f
            .write_all(bytes)
            .and_then(|()| f.sync_all())
            .map_err(|e| error(format!("cannot write {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(refused(
            RefusalKind::Exists,
            format!(
                "{} already exists; choose another name (nothing was overwritten)",
                path.display()
            ),
        )),
        Err(e) => Err(error(format!("cannot create {}: {e}", path.display()))),
    }
}

/// An output path is refused before any window if it is taken or has no
/// directory to go in.
fn check_out(out: &str) -> Flow<PathBuf> {
    let path = PathBuf::from(out);
    if !path.is_absolute() {
        return Err(error("the output path must be absolute"));
    }
    if path.exists() {
        return Err(refused(
            RefusalKind::Exists,
            format!(
                "{} already exists; choose another name (nothing was overwritten)",
                path.display()
            ),
        ));
    }
    if !path.parent().is_some_and(Path::is_dir) {
        return Err(error("the folder for the output file does not exist"));
    }
    Ok(path)
}

fn ask_identity(
    window: &mut dyn Window,
    panel: &Panel,
    identity_file: &Path,
) -> Flow<RecipientSecret> {
    let mut shown = panel.clone();
    for _ in 0..MAX_PASSWORD_TRIES {
        let typed = window
            .ask_password(&shown, "Your identity password", false)
            .map_err(from_surface)?
            .ok_or_else(cancelled)?;
        match identity::open(identity_file, typed.expose().as_bytes()) {
            Ok(keys) => return Ok(keys),
            Err(Error::Unlock) => {
                shown.warning = Some("Wrong password. Try again.".to_string());
            }
            Err(e) => return Err(from_vault(e)),
        }
    }
    Err(error("too many wrong passwords; nothing was done"))
}

// --- vahta id ----------------------------------------------------------------------------------

/// What `vahta id` and `vahta id --show` tell: the key to send and the words to
/// read out. Public information only.
pub fn id_text(public: &RecipientPublic) -> String {
    format!(
        "your key (send this in the chat):\n  {}\nyour verification digits (read these out over \
         a call or in person, never in the chat):\n  {}",
        member::public_key_string(public),
        member::digits_line(public)
    )
}

fn id_create(ctx: &Ctx<'_>) -> Flow<ClientReply> {
    let path = identity_path(ctx);
    if identity::exists(&path) {
        return Err(refused(
            RefusalKind::Exists,
            "this machine already has an identity; `vahta id --show` shows its key and digits",
        ));
    }
    let title = "Create your Vahta identity";
    let mut window = ctx.window(title)?;
    let mut panel = ctx.panel(
        title,
        vec![
            "Your identity is the key a vault owner adds you with.".to_string(),
            format!("It is kept in {}", path.display()),
            "Choose the password that protects it on this machine. The owner never sees it; \
             without it the packages sent to you cannot be opened."
                .to_string(),
        ],
    );
    panel.warning =
        Some("If you forget this password, ask the owner to add a new identity.".into());
    let pw = window
        .ask_password(&panel, "New identity password", true)
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    if pw.expose().is_empty() {
        return Err(error("the password cannot be empty; nothing was done"));
    }
    let public = identity::create(&path, pw.expose().as_bytes(), ctx.shared.options.kdf)
        .map_err(from_vault)?;
    ctx.journal(
        Entry::new("identity_created")
            .result("ok", Some(&format!("key {}", member::fingerprint(&public)))),
    );
    window.close(Some("Identity created."));
    Ok(ClientReply::Done {
        message: format!("created {}\n{}", path.display(), id_text(&public)),
    })
}

// --- members add / list / extend / remove ---------------------------------------------------

fn add(
    ctx: &Ctx<'_>,
    cwd: &str,
    name: &str,
    role: &str,
    key: &str,
    secs: Option<u64>,
) -> Flow<ClientReply> {
    check_member_name(name)?;
    let role = parse_role(role)?;
    let public = member::parse_public_key(key).map_err(|e| error(e.to_string()))?;
    if let Some(s) = secs {
        check_span(s)?;
    }
    let (project, vault_path, peek, info) = owner_vault(ctx, cwd)?;
    if info
        .recipients
        .iter()
        .any(|r| r.name.eq_ignore_ascii_case(name))
    {
        return Err(refused(
            RefusalKind::Exists,
            format!("a member called {name} already exists"),
        ));
    }
    if let Some(r) = info.member_with(&public) {
        return Err(refused(
            RefusalKind::Exists,
            format!("this key is already a member, as {}", r.name),
        ));
    }
    if public.sign_pk == info.owner.sign_pk || public.enc_pk == info.owner.enc_pk {
        return Err(error("this key is the vault owner's own"));
    }
    let expires_at = secs.map(|s| now() + s);
    let fingerprint = member::fingerprint(&public);

    let title = "Add a member";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Member: {name}"));
    lines.push(format!(
        "Role: {}",
        match role {
            Role::Runner => "runner (runs commands with the secrets it is given)",
            Role::Editor => "editor (also adds and changes its own secrets)",
            Role::Admin => "admin (also adds and removes runners and editors)",
        }
    ));
    lines.push(format!("Access: {}", access_text(expires_at)));
    lines.push(format!("Key fingerprint: {fingerprint}"));
    lines.push(format!(
        "Ask {name} to read you the digits from `vahta id --show` over a call or in person, \
         not in the chat the key came through, and type them below."
    ));
    let mut panel = ctx.panel(title, lines);
    if expires_at.is_none() {
        panel.warning = Some(
            "This membership never ends. A short one limits what an old package opens.".into(),
        );
    }
    let mut matched = false;
    for _ in 0..WORD_TRIES {
        let typed = window
            .ask_text(&panel, &format!("The digits {name} read to you"))
            .map_err(from_surface)?
            .ok_or_else(cancelled)?;
        if member::digits_match(&public, &typed) {
            matched = true;
            break;
        }
        panel.warning = Some(
            "Those are not the digits of this key. Ask again; if they still differ, the key was \
             changed on its way to you."
                .to_string(),
        );
    }
    if !matched {
        ctx.journal(
            Entry::new("member_add_refused")
                .vault(&peek.vault_id)
                .names(&[name.to_string()])
                .result(
                    "refused",
                    Some(&format!("verification digits differ; key {fingerprint}")),
                ),
        );
        window.close(Some("Refused."));
        return Err(error(
            "refused: the digits do not match this key; nothing was written",
        ));
    }
    let action = Action::Devices {
        what: format!("add member {name}"),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    let id = vault
        .add_recipient(name, RecipientKind::Person, role, &public)
        .map_err(from_vault)?;
    if expires_at.is_some() {
        vault
            .set_recipient_expiry(&id, expires_at)
            .map_err(from_vault)?;
    }
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("member_added")
            .vault(&peek.vault_id)
            .names(&[name.to_string()])
            .result(
                "ok",
                Some(&format!(
                    "role {}; access {}; key {fingerprint}",
                    role_text(role),
                    access_text(expires_at)
                )),
            ),
    );
    window.close(Some("Member added."));
    Ok(ClientReply::Done {
        message: format!(
            "added {name} as {} (access {}). Next: `vahta grant SECRET {name}` for each secret \
             they need, then `vahta share {name} -o {name}.vhp`",
            role_text(role),
            access_text(expires_at)
        ),
    })
}

fn list(cwd: &str) -> Flow<ClientReply> {
    let (_, path) = find_vault(cwd)?;
    let bytes = vahta_vault::read_file(&path).map_err(from_vault)?;
    let info = member::file_info(&bytes).map_err(from_vault)?;
    let members = info
        .recipients
        .iter()
        .map(|r| MemberInfo {
            name: r.name.clone(),
            role: role_text(r.role).to_string(),
            expires_at: r.expires_at,
            state: state_text(r).to_string(),
            secrets: info.held_by(&r.id).to_vec(),
            fingerprint: member::fingerprint(&RecipientPublic {
                enc_pk: r.enc_pk,
                sign_pk: r.sign_pk,
            }),
        })
        .collect();
    Ok(ClientReply::Members {
        owner_digits: member::digits_line(&info.owner),
        members,
    })
}

fn extend(ctx: &Ctx<'_>, cwd: &str, name: &str, secs: u64) -> Flow<ClientReply> {
    check_span(secs)?;
    let (project, vault_path, peek, info) = owner_vault(ctx, cwd)?;
    let target = resolve(&info, name)?.clone();
    let expires_at = now() + secs;
    let title = "Extend a membership";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!(
        "Member: {} ({})",
        target.name,
        role_text(target.role)
    ));
    lines.push(format!("Now: {}", access_text(target.expires_at)));
    lines.push(format!("New: {}", access_text(Some(expires_at))));
    lines.push("They need a new package (`vahta share`) to see the new date.".to_string());
    let panel = ctx.panel(title, lines);
    let action = Action::Devices {
        what: format!("extend member {}", target.name),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    vault
        .set_recipient_expiry(&target.id, Some(expires_at))
        .map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("member_extended")
            .vault(&peek.vault_id)
            .names(std::slice::from_ref(&target.name))
            .result(
                "ok",
                Some(&format!("access {}", access_text(Some(expires_at)))),
            ),
    );
    window.close(Some("Saved."));
    Ok(ClientReply::Done {
        message: format!(
            "{} now has access {}. Send them a new package: `vahta share {} -o FILE`",
            target.name,
            access_text(Some(expires_at)),
            target.name
        ),
    })
}

fn remove(ctx: &Ctx<'_>, cwd: &str, name: &str) -> Flow<ClientReply> {
    let (project, vault_path, peek, info) = owner_vault(ctx, cwd)?;
    let target = resolve(&info, name)?.clone();
    let held = info.held_by(&target.id).to_vec();
    let title = "Remove a member";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!(
        "Member: {} ({})",
        target.name,
        role_text(target.role)
    ));
    if held.is_empty() {
        lines.push("They hold no secrets.".to_string());
    } else {
        lines.push(format!("They hold: {}", held.join(", ")));
        lines.push(
            "Those secrets are re-keyed in the vault. A package they already have still opens \
             the old values: rotate them in the real services."
                .to_string(),
        );
    }
    let panel = ctx.panel(title, lines);
    let action = Action::Devices {
        what: format!("remove member {}", target.name),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    let mut rotate = vault.remove_recipient(&target.id).map_err(from_vault)?;
    rotate.sort();
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("member_removed")
            .vault(&peek.vault_id)
            .names(&rotate)
            .result(
                "ok",
                Some(&format!("{} ({})", target.name, role_text(target.role))),
            ),
    );
    window.close(Some("Removed."));
    let message = if rotate.is_empty() {
        format!("removed {}; they held no secrets", target.name)
    } else {
        format!(
            "removed {}. Rotate these in the real services, since they could read them: {}",
            target.name,
            rotate.join(", ")
        )
    };
    Ok(ClientReply::Done { message })
}

// --- grant / revoke ------------------------------------------------------------------------------

fn grant(ctx: &Ctx<'_>, cwd: &str, name: &str, member: &str, give: bool) -> Flow<ClientReply> {
    crate::ops::check_name(name)?;
    let (project, vault_path, peek, info) = owner_vault(ctx, cwd)?;
    let target = resolve(&info, member)?.clone();
    if !peek.entries.iter().any(|e| e.name == name) {
        return Err(crate::ops::unknown_name(name));
    }
    let holds = info.held_by(&target.id).iter().any(|n| n == name);
    if give == holds {
        return Ok(ClientReply::Done {
            message: if give {
                format!("{} already holds {name}; nothing changed", target.name)
            } else {
                format!("{} does not hold {name}; nothing changed", target.name)
            },
        });
    }
    let title = if give {
        "Give a member a secret"
    } else {
        "Take a secret from a member"
    };
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Secret: {name}"));
    lines.push(format!(
        "Member: {} ({}, access {})",
        target.name,
        role_text(target.role),
        access_text(target.expires_at)
    ));
    if give {
        lines.push(format!(
            "{} will be able to read {name} with their own key, from the next package you \
             send them.",
            target.name
        ));
    } else {
        lines.push(format!(
            "{name} is re-keyed in the vault. {} could already read it: rotate it in the real \
             service.",
            target.name
        ));
    }
    let panel = ctx.panel(title, lines);
    if give {
        let options = vec!["Give it".to_string(), "No".to_string()];
        let choice = window
            .choose(&panel, "Give this secret to this member?", &options)
            .map_err(from_surface)?;
        if choice != Some(0) {
            window.close(None);
            return Err(cancelled());
        }
    }
    let action = Action::Devices {
        what: format!(
            "{} {name} {} {}",
            if give { "grant" } else { "revoke" },
            if give { "to" } else { "from" },
            target.name
        ),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    if give {
        vault.grant(name, &target.id).map_err(from_vault)?;
    } else {
        vault.revoke(name, &target.id).map_err(from_vault)?;
    }
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new(if give {
            "member_granted"
        } else {
            "member_revoked"
        })
        .vault(&peek.vault_id)
        .names(&[name.to_string()])
        .result("ok", Some(&format!("member {}", target.name))),
    );
    window.close(Some("Saved."));
    Ok(ClientReply::Done {
        message: if give {
            format!(
                "{} can now read {name}. Send a new package: `vahta share {} -o FILE`",
                target.name, target.name
            )
        } else {
            format!(
                "{} no longer holds {name}. Rotate {name} in the real service: they could read \
                 it. Their old package still opens the old value.",
                target.name
            )
        },
    })
}

// --- share ---------------------------------------------------------------------------------------------

fn share(ctx: &Ctx<'_>, cwd: &str, member: &str, out: &str) -> Flow<ClientReply> {
    let out = check_out(out)?;
    let (project, vault_path, peek, info) = owner_vault(ctx, cwd)?;
    let target = resolve(&info, member)?.clone();
    let held = info.held_by(&target.id).to_vec();
    if held.is_empty() {
        return Err(refused(
            RefusalKind::NothingToDo,
            format!(
                "{} holds no secrets; give some first with `vahta grant SECRET {}`",
                target.name, target.name
            ),
        ));
    }
    if target.expires_at.is_some_and(|t| t <= now()) {
        return Err(refused(
            RefusalKind::NothingToDo,
            format!(
                "{}'s access has ended; `vahta members extend {} --for 30d` first",
                target.name, target.name
            ),
        ));
    }
    let title = "Make a package for a member";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!(
        "Member: {} ({}, access {})",
        target.name,
        role_text(target.role),
        access_text(target.expires_at)
    ));
    lines.push(format!("Secrets in it: {}", held.join(", ")));
    lines.push(format!("Writes: {}", out.display()));
    lines.push(
        "It holds only these secrets, sealed for this member's key. Other secrets, other members \
         and devices are not in it."
            .to_string(),
    );
    let panel = ctx.panel(title, lines);
    let action = Action::Other {
        what: format!("package for {}", target.name),
    };
    let vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    let canon = std::fs::canonicalize(&project.root).ok();
    let roots: Vec<&Path> = canon
        .iter()
        .map(PathBuf::as_path)
        .chain([project.root.as_path()])
        .collect();
    let bytes = vault.package_for(&target.id, &roots).map_err(from_vault)?;
    // Places outside the project stay as the owner approved them; they may not
    // exist on the member's machine, so say which secrets carry them.
    let outside: Vec<String> = Vault::peek_bytes(&bytes)
        .map(|p| p.bindings)
        .unwrap_or_default()
        .iter()
        .filter_map(|b| {
            let places = vahta_vault::rules::absolute_places(b);
            (!places.is_empty()).then(|| format!("{}: {}", b.name, places.join(", ")))
        })
        .collect();
    write_new(&out, &bytes)?;
    ctx.journal(
        Entry::new("package_made")
            .vault(&peek.vault_id)
            .names(&held)
            .result(
                "ok",
                Some(&format!(
                    "for {}; generation {}",
                    target.name,
                    vault.generation()
                )),
            ),
    );
    window.close(Some("Package written."));
    let warning = if outside.is_empty() {
        String::new()
    } else {
        format!(
            "warning: these rules name places outside the project, which may not exist on {}'s \
             machine (rules inside the project are relative and travel fine): {}\n",
            target.name,
            outside.join("; ")
        )
    };
    Ok(ClientReply::Done {
        message: format!(
            "{warning}wrote {} for {} ({} secret(s)). Send the file to {} in the chat, and read them these \
             digits over a call or in person, so they can check the file came from you when \
             they run `vahta join`:\n  {}",
            out.display(),
            target.name,
            held.len(),
            target.name,
            member::digits_line(&info.owner)
        ),
    })
}

/// When this machine's membership in the package at `path` ends, if it does:
/// what caps a session a member opens. A package not addressed to this
/// identity, or an ended membership, is an error.
pub(crate) fn membership_end(ctx: &Ctx<'_>, path: &Path) -> Flow<Option<u64>> {
    let bytes = vahta_vault::read_file(path).map_err(from_vault)?;
    let info = member::file_info(&bytes).map_err(from_vault)?;
    let idp = identity_path(ctx);
    if !identity::exists(&idp) {
        return Err(error(
            "this vault is a member's package and this machine has no identity: run `vahta id`",
        ));
    }
    let public = identity::read_public(&idp).map_err(from_vault)?;
    let me = info
        .member_with(&public)
        .ok_or_else(|| error("this package is not addressed to this machine's identity"))?;
    if me.expires_at.is_some_and(|t| t <= now()) {
        return Err(error(Error::MembershipExpired.to_string()));
    }
    Ok(me.expires_at)
}

// --- Opening as a member ---------------------------------------------------------------------------

/// What a member of `role` may ask of a package, by the action's row.
fn role_allows(role: Role, action: &Action) -> Result<(), String> {
    let name = role_text(role);
    match action {
        Action::RunEachUse { .. } | Action::RunAsk { .. } | Action::Http { .. } => Ok(()),
        Action::Add { .. } | Action::Reset { .. } if role != Role::Runner => Ok(()),
        Action::Add { .. } | Action::Reset { .. } => Err(
            "you are a runner in this vault: you can run commands with its secrets, not add or \
             change them; nothing was done"
                .to_string(),
        ),
        // A session runs commands, which every role may; the daemon ends it
        // no later than the membership.
        Action::Unlock { .. } => Ok(()),
        _ => Err(format!(
            "you are {} {name} in this vault: a member can run commands with the secrets it \
             holds{}; the owner manages the rest; nothing was done",
            if name == "admin" { "an" } else { "a" },
            if role == Role::Runner {
                ""
            } else {
                " and add or change its own"
            }
        )),
    }
}

/// Open the package at `path` as the member this machine's identity is.
/// `allow` decides, before any password is asked, whether this member's role
/// may do what is being asked.
fn open_member_with(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
    allow: &dyn Fn(Role) -> Result<(), String>,
) -> Flow<Vault> {
    let bytes = vahta_vault::read_file(path).map_err(from_vault)?;
    let info = member::file_info(&bytes).map_err(from_vault)?;
    let idp = identity_path(ctx);
    if !identity::exists(&idp) {
        return Err(error(
            "this vault is a member's package and this machine has no identity: run `vahta id`",
        ));
    }
    let public = identity::read_public(&idp).map_err(from_vault)?;
    let Some(me) = info.member_with(&public) else {
        return Err(error(
            "this package is not addressed to this machine's identity",
        ));
    };
    allow(me.role).map_err(error)?;
    if me.expires_at.is_some_and(|t| t <= now()) {
        return Err(error(Error::MembershipExpired.to_string()));
    }
    let id = me.id;
    let keys = ask_identity(window, panel, &idp)?;
    // A package this machine never joined has had no owner digits confirmed:
    // `vahta join` is the only way in, so the owner's key is never taken on
    // trust from a file that merely appeared in the folder.
    let state_key = StateKey::recipient(id, keys.sign_sk());
    let checked = ctx
        .store()
        .check(
            &info.vault_id,
            &state_key,
            &info.owner.sign_pk,
            info.owner_generation,
        )
        .map_err(from_vault)?;
    if checked.first_open {
        return Err(error(
            "this package was never joined on this machine: run `vahta join FILE` with the file              the owner sent, which shows the owner's digits to confirm",
        ));
    }
    Vault::open_as_recipient(path, &id, &keys, ctx.store()).map_err(from_vault)
}

/// [`crate::authn::unlock_keeping_password`] for a package: the identity
/// password instead of the master password, and the role's limits.
pub(crate) fn open_member(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
    action: &Action,
) -> Flow<Opened> {
    let vault = open_member_with(ctx, window, path, panel, &|role| role_allows(role, action))?;
    if let Some(root) = path.parent().and_then(Path::parent) {
        crate::guard_ops::note_project(ctx, root);
    }
    let by = UnlockedBy {
        kind: u16::MAX,
        slot_id: [0; 16],
        label: "member identity".to_string(),
        factor: Factor::Knowledge,
        device_id: None,
        rewrapped: false,
    };
    Ok((vault, by, None))
}

// --- Sending one secret to the owner -------------------------------------------------------------

fn send_to_owner(
    ctx: &Ctx<'_>,
    cwd: &str,
    name: &str,
    out: &str,
    rules: ProposedRules,
) -> Flow<ClientReply> {
    crate::ops::check_name(name)?;
    let proposed = (rules != ProposedRules::default()).then(|| member::ProposedRules {
        category: rules.category.clone(),
        allow: rules.allow.clone(),
        deny: rules.deny.clone(),
        dirs: rules.dirs.clone(),
        net: rules.net.clone(),
    });
    if proposed.as_ref().is_some_and(|p| !p.is_well_formed()) {
        return Err(error(
            "the proposed rules are too many or too long, or have a control character; nothing \
             was written",
        ));
    }
    let out = check_out(out)?;
    let (project, vault_path) = find_vault(cwd)?;
    let peek = Vault::peek(&vault_path).map_err(from_vault)?;
    if !peek.package {
        return Err(error(
            "this vault is yours: only a member sends a secret to the owner",
        ));
    }
    if !peek.entries.iter().any(|e| e.name == name) {
        return Err(crate::ops::unknown_name(name));
    }
    let title = "Send a secret to the owner";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Secret: {name}"));
    lines.push(format!("Writes: {}", out.display()));
    lines.push(
        "The file holds only this secret, sealed so that only the owner can read it, and signed \
         by you."
            .to_string(),
    );
    if let Some(p) = &proposed {
        lines.push(format!(
            "Rules you propose for it (the owner reads and approves them; they change nothing \
             of a secret the owner already has): {}",
            proposed_text(p)
        ));
    }
    let panel = ctx.panel(title, lines);
    let vault = open_member_with(ctx, window.as_mut(), &vault_path, &panel, &|role| {
        if role == Role::Runner {
            Err("you are a runner in this vault: it only runs commands; nothing was sent".into())
        } else {
            Ok(())
        }
    })?;
    let me = vault
        .membership()
        .map(|m| m.id)
        .ok_or_else(|| error("this vault is not opened as a member"))?;
    let counter = ctx
        .store()
        .next_transfer_counter(&peek.vault_id, &me)
        .map_err(from_vault)?;
    let bytes = vault
        .make_transfer(name, counter, proposed)
        .map_err(from_vault)?;
    write_new(&out, &bytes)?;
    ctx.journal(
        Entry::new("transfer_made")
            .vault(&peek.vault_id)
            .names(&[name.to_string()])
            .result("ok", None),
    );
    window.close(Some("Written."));
    Ok(ClientReply::Done {
        message: format!(
            "wrote {} with {name} for the owner. Send it in the chat; the owner runs `vahta join \
             {}` in the project.",
            out.display(),
            out.file_name()
                .map_or_else(String::new, |f| f.to_string_lossy().into_owned())
        ),
    })
}

/// A proposal as one line: `category: c; allow: a, b; ...`.
fn proposed_text(p: &member::ProposedRules) -> String {
    let mut parts = Vec::new();
    if let Some(c) = &p.category {
        parts.push(format!("category: {c}"));
    }
    for (label, list) in [("allow", &p.allow), ("deny", &p.deny), ("dirs", &p.dirs)] {
        if !list.is_empty() {
            parts.push(format!("{label}: {}", list.join(", ")));
        }
    }
    if let Some(n) = &p.net {
        parts.push(format!("network: {n}"));
    }
    parts.join("; ")
}

// --- join ----------------------------------------------------------------------------------------------

fn join(ctx: &Ctx<'_>, cwd: &str, file: &str, path: Option<String>) -> Flow<ClientReply> {
    let file = PathBuf::from(file);
    let bytes = vahta_vault::read_file(&file).map_err(from_vault)?;
    if member::is_transfer(&bytes) {
        join_transfer(ctx, cwd, &bytes, path)
    } else {
        join_package(ctx, cwd, &bytes)
    }
}

fn join_transfer(
    ctx: &Ctx<'_>,
    cwd: &str,
    bytes: &[u8],
    path: Option<String>,
) -> Flow<ClientReply> {
    let (project, vault_path, peek, info) = owner_vault(ctx, cwd)?;
    let title = "Import a secret a member sent";
    let mut window = ctx.window(title)?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push("A member sent a secret file. Nothing is imported until you agree.".to_string());
    let panel = ctx.panel(title, lines);
    let action = Action::Import {
        source: "a member's file".to_string(),
    };
    let mut vault = unlock_expecting(ctx, window.as_mut(), &vault_path, &panel, action, &peek)?;
    let t = vault
        .read_transfer(bytes)
        .map_err(|e| error(format!("{e}; nothing was imported")))?;
    let role = info
        .recipients
        .iter()
        .find(|r| r.id == t.from.id)
        .map_or("member", |r| role_text(r.role));
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Secret: {}", t.name));
    lines.push(format!("From: {} ({role})", t.from.name));
    // The rules an editor proposes count only for a secret the vault does not
    // have; they are built here, on the owner's machine, like any `vahta bind`.
    let mut offered: Option<proposal::Built> = None;
    if t.replaces {
        lines.push(format!(
            "The vault already has {}: this REPLACES its value. Its kind, tier and rules stay as \
             they are.",
            t.name
        ));
        if t.proposed.is_some() {
            lines.push(
                "The sender also proposed rules; they are ignored, since only you change the \
                 rules of a secret you have (`vahta bind`)."
                    .to_string(),
            );
        }
    } else {
        match &t.proposed {
            None => lines.push(
                "New to the vault. It has no approved rules until you add them with `vahta bind`; \
                 the sender keeps access to it."
                    .to_string(),
            ),
            Some(p) => {
                lines.push(format!(
                    "New to the vault. {} PROPOSES these rules (not approved yet): {}",
                    t.from.name,
                    proposed_text(p)
                ));
                match build_proposed(&t.name, p, path, &project) {
                    Ok(built) => {
                        lines.push(format!(
                            "In effect, if you approve them: {}",
                            crate::binding::rules_text(&built.rule_set)
                        ));
                        for (text, program) in &built.resolved {
                            lines.push(format!("`{text}` runs {}", program.display()));
                        }
                        for w in &built.warnings {
                            lines.push(format!("Warning: {w}"));
                        }
                        offered = Some(built);
                    }
                    Err(e) => lines.push(format!(
                        "These rules cannot be built here ({e}); the secret can still be \
                         imported without rules."
                    )),
                }
            }
        }
    }
    lines.push("The value is not shown.".to_string());
    let panel = ctx.panel(title, lines);
    let options = if offered.is_some() {
        vec![
            "Import with these rules".to_string(),
            "Import without rules".to_string(),
            "Cancel".to_string(),
        ]
    } else {
        vec!["Import".to_string(), "Cancel".to_string()]
    };
    let choice = window
        .choose(&panel, "Import this secret?", &options)
        .map_err(from_surface)?;
    let cancel = options.len() - 1;
    let with_rules = offered.is_some() && choice == Some(0);
    if choice.is_none_or(|c| c >= cancel) {
        ctx.journal(
            Entry::new("transfer_imported")
                .vault(&peek.vault_id)
                .names(std::slice::from_ref(&t.name))
                .result("declined", Some(&format!("from {}", t.from.name))),
        );
        window.close(None);
        return Err(cancelled());
    }
    vault.apply_transfer(&t).map_err(from_vault)?;
    if let (true, Some(built)) = (with_rules, &offered) {
        // The file first, so the repository shows what is enforced.
        crate::bind_ops::write_rules(&project, &t.name, &built.rule_set)?;
        vault
            .set_bindings(&t.name, Some(built.rule_set.clone()))
            .map_err(from_vault)?;
    }
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("transfer_imported")
            .vault(&peek.vault_id)
            .names(std::slice::from_ref(&t.name))
            .result(
                "ok",
                Some(&format!(
                    "from {}{}",
                    t.from.name,
                    if with_rules {
                        "; with the rules it proposed"
                    } else {
                        ""
                    }
                )),
            ),
    );
    window.close(Some("Imported."));
    Ok(ClientReply::Done {
        message: format!(
            "imported {} from {}{}",
            t.name,
            t.from.name,
            if t.replaces {
                " (replaced the old value)"
            } else if with_rules {
                "; the rules it proposed are approved; `vahta share` a new package"
            } else {
                "; set its rules with `vahta bind`, then `vahta share` a new package"
            }
        ),
    })
}

/// The proposal as a rule set for `name`, built like `vahta bind` would.
fn build_proposed(
    name: &str,
    p: &member::ProposedRules,
    path: Option<String>,
    project: &Project,
) -> Result<proposal::Built, String> {
    let category = match &p.category {
        Some(c) => Some(proposal::find_category(c)?),
        None => None,
    };
    let args = proposal::Args {
        category: p.category.clone(),
        allow: p.allow.clone(),
        deny: p.deny.clone(),
        dirs: p.dirs.clone(),
        net: p.net.clone(),
        path: path.map(std::ffi::OsString::from),
        from: Vec::new(),
    };
    proposal::build(name, category, &args, &project.root)
}

fn join_package(ctx: &Ctx<'_>, cwd: &str, bytes: &[u8]) -> Flow<ClientReply> {
    let info = member::file_info(bytes).map_err(|e| error(format!("not a usable package: {e}")))?;
    if !info.package || !info.signed_by_owner {
        return Err(error(
            "this file is not a member package signed by a vault's owner; nothing was installed",
        ));
    }
    let idp = identity_path(ctx);
    if !identity::exists(&idp) {
        return Err(error(
            "this machine has no identity yet: run `vahta id`, send the owner your key, then join",
        ));
    }
    let public = identity::read_public(&idp).map_err(from_vault)?;
    let Some(me) = info.member_with(&public).cloned() else {
        return Err(error(
            "this package is not addressed to your identity (its member key is not yours); \
             nothing was installed",
        ));
    };
    if me.expires_at.is_some_and(|t| t <= now()) {
        return Err(error(Error::MembershipExpired.to_string()));
    }
    let root = Project::find(Path::new(cwd)).unwrap_or(Project {
        root: PathBuf::from(cwd),
    });
    let target = root.vault_path();
    // Secrets only the installed file has: installing replaces it.
    let mut local_only: Vec<String> = Vec::new();
    let old = if target.exists() {
        let old = vahta_vault::read_file(&target).map_err(from_vault)?;
        let oi = member::file_info(&old).map_err(|_| {
            error(format!(
                "{} is not a readable package; nothing was changed",
                target.display()
            ))
        })?;
        if !oi.package {
            return Err(error(format!(
                "{} is a vault of its own, not a package: join from another directory",
                target.display()
            )));
        }
        if oi.vault_id != info.vault_id {
            return Err(error(
                "this directory already holds another vault's package; join from another directory",
            ));
        }
        // By the owner's generation: the installed file's own generation runs
        // ahead of it when this member has saved changes locally.
        if info.owner_generation <= oi.owner_generation {
            return Err(error(format!(
                "this package (owner generation {}) is not newer than the one installed (owner \
                 generation {}); an older or repeated package is refused",
                info.owner_generation, oi.owner_generation
            )));
        }
        local_only = oi
            .held_by(&me.id)
            .iter()
            .filter(|n| !info.held_by(&me.id).contains(n))
            .cloned()
            .collect();
        Some(old)
    } else {
        None
    };

    let title = "Join a team vault";
    let mut window = ctx.window(title)?;
    let held = info.held_by(&me.id).to_vec();
    let mut lines = vec![
        format!("Installs: {}", target.display()),
        format!(
            "You: {} ({}, access {})",
            me.name,
            role_text(me.role),
            access_text(me.expires_at)
        ),
        format!("Secrets: {}", held.join(", ")),
    ];
    if !local_only.is_empty() {
        lines.push(format!(
            "Warning: your current file has {}, which this package does not. Installing replaces \
             your file, so they are lost unless you sent them to the owner first \
             (`vahta share --to owner`).",
            local_only.join(", ")
        ));
    }
    let mut panel = ctx.panel(title, lines.clone());
    let keys = ask_identity(window.as_mut(), &panel, &idp)?;
    let state_key = StateKey::recipient(me.id, keys.sign_sk());
    let mut rekeyed = false;
    let checked = match ctx.store().check(
        &info.vault_id,
        &state_key,
        &info.owner.sign_pk,
        info.owner_generation,
    ) {
        Ok(c) => c,
        Err(Error::OwnerChanged) => {
            // The owner re-keyed (a lost device). Accepted only when the
            // package's own chain of successors, each signed by the key before
            // it, leads from the key pinned here to the new one.
            let pinned = ctx
                .store()
                .state(&info.vault_id, &state_key)
                .map_err(from_vault)?
                .ok_or_else(|| error("the owner's key changed; nothing was installed"))?
                .pinned_owner_sign_pk;
            if info.successors_from(&pinned).is_none() {
                return Err(error(
                    "this package is signed by a different owner key than the one pinned on this \
                     machine, and it carries no valid chain from the old key to the new one; \
                     nothing was installed",
                ));
            }
            rekeyed = true;
            vahta_vault::store::Checked { first_open: false }
        }
        Err(e) => return Err(error(format!("{e}; nothing was installed"))),
    };
    if rekeyed {
        lines.push(format!(
            "The owner's key changed (they re-keyed the vault). The chain in the package, signed \
             by the old key, vouches for the new one. The owner's new digits: {}",
            member::digits_line(&info.owner)
        ));
        lines.push(
            "Ask the owner to read you the same digits over a call or in person before you \
             accept."
                .to_string(),
        );
        panel = ctx.panel(title, lines);
        panel.warning =
            Some("If the digits differ, do not install: the file is not from them.".into());
        let options = vec!["The digits match".to_string(), "They differ".to_string()];
        let choice = window
            .choose(
                &panel,
                "Do the digits match what the owner read to you?",
                &options,
            )
            .map_err(from_surface)?;
        if choice != Some(0) {
            window.close(None);
            return Err(error(
                "refused: the owner's new digits were not confirmed; nothing was installed",
            ));
        }
    } else if checked.first_open {
        // The first package of a vault: the owner's key is accepted here for
        // good, so the person compares it with what the owner reads out.
        lines.push(format!(
            "The owner's digits: {}",
            member::digits_line(&info.owner)
        ));
        lines.push(
            "The owner should read you the same digits over a call or in person. They prove \
             this package comes from the person you mean."
                .to_string(),
        );
        panel = ctx.panel(title, lines);
        panel.warning =
            Some("If the digits differ, do not join: the file is not from them.".into());
        let options = vec!["The digits match".to_string(), "They differ".to_string()];
        let choice = window
            .choose(
                &panel,
                "Do the digits match what the owner read to you?",
                &options,
            )
            .map_err(from_surface)?;
        if choice != Some(0) {
            window.close(None);
            return Err(error(
                "refused: the owner's digits were not confirmed; nothing was installed",
            ));
        }
    }
    Project::init(&root.root).map_err(from_vault)?;
    let _lock = VaultLock::acquire(&target).map_err(from_vault)?;
    write_atomic(&target, bytes).map_err(from_vault)?;
    // Opening verifies the file again against this machine's record and writes
    // it (the owner's key pinned, the generation raised).
    if let Err(e) =
        Vault::open_as_recipient_accepting(&target, &me.id, &keys, ctx.store(), &mut |_| rekeyed)
    {
        match &old {
            Some(old) => {
                let _ = write_atomic(&target, old);
            }
            None => {
                let _ = std::fs::remove_file(&target);
            }
        }
        return Err(error(format!("{e}; nothing was installed")));
    }
    crate::guard_ops::note_project(ctx, &root.root);
    ctx.journal(
        Entry::new("member_joined")
            .vault(&info.vault_id)
            .names(&held)
            .result(
                "ok",
                Some(&format!(
                    "{} as {}; owner generation {}{}",
                    me.name,
                    role_text(me.role),
                    info.owner_generation,
                    if rekeyed { "; owner key changed" } else { "" }
                )),
            ),
    );
    window.close(Some("Joined."));
    Ok(ClientReply::Done {
        message: format!(
            "joined as {} ({}), access {}. Secrets: {}. Use them with `vahta run`.",
            me.name,
            role_text(me.role),
            access_text(me.expires_at),
            held.join(", ")
        ),
    })
}
