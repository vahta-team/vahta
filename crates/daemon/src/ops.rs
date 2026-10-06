//! The vault operations a client can ask for: `init`, `set`, `remove`,
//! `import`, `reveal` and `copy`.
//!
//! Every one needs a fresh password, typed in the prompt window, and never
//! enters a session: a session is a runner, and runs only. The window is the
//! only place the password, a typed value or a revealed value exists outside the
//! daemon; a reply to the client says what was done and never has a value.
//!
//! The vault file is only ever written by `Vault::save`, which refuses if the
//! file changed since it was loaded, so two writers cannot clobber each other.

use std::path::{Path, PathBuf};
use std::time::Duration;

use vahta_vault::project::Project;
use vahta_vault::store::LocalStore;
use vahta_vault::{Error, Kind, SecretValue, Tier, Vault, valid_name};
use zeroize::Zeroizing;

use crate::clipboard;
use crate::dotenv;
use crate::journal::Entry;
use crate::protocol::{ClientReply, ImportSource, NameIssue, Panel, Refusal, RefusalKind, Secret};
use crate::server::Shared;
use crate::surface::{SurfaceError, Window};

/// How many wrong attempts one window accepts.
const MAX_TRIES: usize = 3;

/// How long a revealed value stays on screen.
pub const REVEAL_SECONDS: u32 = 60;

/// Who asked: the kernel's account of the peer, for the window and the journal.
pub(crate) struct Ctx<'a> {
    pub shared: &'a Shared,
    pub exe: Option<String>,
    pub pid: u32,
    /// The peer, with its start time, for the session lookups.
    pub peer: vahta_os::ProcessId,
}

/// An early end: the reply to send.
pub(crate) type Flow<T> = Result<T, ClientReply>;

pub(crate) fn error(message: impl Into<String>) -> ClientReply {
    ClientReply::Error {
        message: message.into(),
    }
}

pub(crate) fn refused(kind: RefusalKind, message: impl Into<String>) -> ClientReply {
    ClientReply::Refused(Refusal {
        kind,
        message: message.into(),
        names: Vec::new(),
    })
}

pub(crate) fn refused_names(
    kind: RefusalKind,
    message: impl Into<String>,
    names: Vec<NameIssue>,
) -> ClientReply {
    ClientReply::Refused(Refusal {
        kind,
        message: message.into(),
        names,
    })
}

pub(crate) fn cancelled() -> ClientReply {
    ClientReply::Cancelled {
        message: "cancelled; nothing was done".to_string(),
    }
}

/// A window that did not answer is a cancellation; one that could not open is
/// an error that says nothing was done.
pub(crate) fn from_surface(e: SurfaceError) -> ClientReply {
    match e {
        SurfaceError::Timeout => ClientReply::Cancelled {
            message: "the prompt window was not answered in time; nothing was done".to_string(),
        },
        SurfaceError::Closed => cancelled(),
        other => error(other.to_string()),
    }
}

pub(crate) fn from_vault(e: Error) -> ClientReply {
    error(e.to_string())
}

impl Ctx<'_> {
    pub(crate) fn requested_by(&self) -> String {
        match &self.exe {
            Some(exe) => format!("{exe} (pid {})", self.pid),
            None => format!("pid {}", self.pid),
        }
    }

    pub(crate) fn journal(&self, entry: Entry) {
        self.shared
            .journal
            .record(entry.peer(self.exe.as_deref(), self.pid));
    }

    pub(crate) fn store(&self) -> &LocalStore {
        &self.shared.store
    }

    pub(crate) fn panel(&self, title: &str, mut lines: Vec<String>) -> Panel {
        lines.push(format!("Requested by: {}", self.requested_by()));
        Panel {
            title: title.to_string(),
            lines,
            warning: None,
            agent_note: None,
        }
    }

    /// Open a window, or the reply that says none could be.
    pub(crate) fn window(&self, title: &str) -> Flow<Box<dyn Window>> {
        self.shared.surface.open(title).map_err(from_surface)
    }
}

/// The project that holds `cwd` and its vault file.
pub(crate) fn find_vault(cwd: &str) -> Flow<(Project, PathBuf)> {
    let Some(project) = Project::find(Path::new(cwd)) else {
        return Err(refused(
            RefusalKind::NoVault,
            "no Vahta project here (no .vahta/ in this directory or above); run `vahta init`",
        ));
    };
    let vault = project.vault_path();
    if !vault.is_file() {
        return Err(refused(
            RefusalKind::NoVault,
            "this project has no vault yet; run `vahta init`",
        ));
    }
    Ok((project, vault))
}

/// Ask for the vault's password in `window` and unlock `path` with it. A wrong
/// one is asked again, up to [`MAX_TRIES`] times, in the same window.
pub(crate) fn unlock(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
) -> Flow<Vault> {
    let mut warning = None;
    for _ in 0..MAX_TRIES {
        let mut shown = panel.clone();
        shown.warning = warning.take();
        let typed = window
            .ask_password(&shown, "Vault password", false)
            .map_err(from_surface)?
            .ok_or_else(cancelled)?;
        match Vault::unlock_password(path, typed.expose().as_bytes(), ctx.store()) {
            Ok(vault) => return Ok(vault),
            Err(Error::Unlock) => warning = Some("Wrong password. Try again.".to_string()),
            Err(e) => return Err(from_vault(e)),
        }
    }
    Err(error("too many wrong passwords; nothing was done"))
}

pub(crate) fn lines_for(project: &Project, vault: &Path) -> Vec<String> {
    vec![
        format!("Project: {}", project.root.display()),
        format!("Vault: {}", vault.display()),
    ]
}

pub(crate) fn check_name(name: &str) -> Flow<()> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(error(Error::InvalidName.to_string()))
    }
}

pub(crate) fn unknown_name(name: &str) -> ClientReply {
    refused_names(
        RefusalKind::UnknownName,
        format!("no secret named {name} in this vault"),
        vec![NameIssue {
            name: name.to_string(),
            why: RefusalKind::UnknownName,
        }],
    )
}

// --- init ---------------------------------------------------------------------------

pub(crate) fn init(ctx: &Ctx<'_>, cwd: &str) -> Flow<ClientReply> {
    let root = PathBuf::from(cwd);
    if !root.is_dir() {
        return Err(error("the current directory is not a directory"));
    }
    let project = Project { root: root.clone() };
    let vault_path = project.vault_path();
    if vault_path.exists() {
        return Err(refused(
            RefusalKind::Exists,
            "this directory already has a vault",
        ));
    }
    let mut window = ctx.window("Create a Vahta vault")?;
    let mut panel = ctx.panel("Create a Vahta vault", lines_for(&project, &vault_path));
    panel
        .lines
        .push("Choose the password that will open it.".to_string());
    let chosen = window
        .ask_password(&panel, "New vault password", true)
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    if chosen.expose().is_empty() {
        return Err(error("the password cannot be empty; nothing was done"));
    }
    let (mut vault, recovery) =
        Vault::create(chosen.expose().as_bytes(), ctx.shared.options.kdf).map_err(from_vault)?;
    let paper = Secret::new(recovery.to_paper());
    // The key is shown, and acknowledged, before anything is written: if the
    // window dies first there is no vault whose key was never seen.
    panel.warning = Some(
        "Write this recovery key down and keep it somewhere safe. It opens the vault if the \
         password is lost, it is shown only now, and Vahta cannot show it again."
            .to_string(),
    );
    if !window
        .show_recovery_key(&panel, &paper)
        .map_err(from_surface)?
    {
        return Err(cancelled());
    }
    Project::init(&root).map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("init")
            .vault(&vault.vault_id())
            .result("ok", None),
    );
    window.close(Some("Vault created."));
    Ok(ClientReply::Done {
        message: format!("created {}", vault_path.display()),
    })
}

// --- set / remove ---------------------------------------------------------------------

pub(crate) fn set(
    ctx: &Ctx<'_>,
    cwd: &str,
    name: &str,
    tier: Tier,
    file: Option<&str>,
) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = find_vault(cwd)?;
    let kind = match file {
        Some(f) => Kind::File {
            file_name: f.to_string(),
        },
        None => Kind::Env,
    };
    let tier_text = match tier {
        Tier::Session => "session",
        Tier::EachUse => "each-use",
    };
    let mut window = ctx.window("Store a secret")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Name: {name} (tier {tier_text})"));
    let mut panel = ctx.panel("Store a secret", lines);
    let mut vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
    if vault.entries().iter().any(|e| e.name == name) {
        panel
            .lines
            .push("This replaces the value it has now.".to_string());
    }
    let typed = window
        .ask_value(&panel, &format!("Value of {name}"), true)
        .map_err(from_surface)?
        .ok_or_else(cancelled)?;
    if typed.expose().is_empty() {
        return Err(error("a secret cannot be empty; nothing was done"));
    }
    vault
        .set(name, typed.expose().as_bytes(), kind, tier)
        .map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("set")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", None),
    );
    window.close(Some(&format!("Saved {name}.")));
    Ok(ClientReply::Done {
        message: format!("saved {name}"),
    })
}

/// Refuse a name that is not in the vault. The index is plain, so this needs
/// no password and no window.
fn ensure_known(vault_path: &Path, name: &str) -> Flow<()> {
    let peek = Vault::peek(vault_path).map_err(from_vault)?;
    if peek.entries.iter().any(|e| e.name == name) {
        Ok(())
    } else {
        Err(unknown_name(name))
    }
}

pub(crate) fn remove(ctx: &Ctx<'_>, cwd: &str, name: &str) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = find_vault(cwd)?;
    ensure_known(&vault_path, name)?;
    let mut window = ctx.window("Remove a secret")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Remove: {name}"));
    let panel = ctx.panel("Remove a secret", lines);
    let mut vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
    vault.remove(name).map_err(from_vault)?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("remove")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", None),
    );
    window.close(Some(&format!("Removed {name}.")));
    Ok(ClientReply::Done {
        message: format!("removed {name}"),
    })
}

// --- import ------------------------------------------------------------------------------

/// The largest ka vault read.
const MAX_KA_FILE: u64 = 16 * 1024 * 1024;

pub(crate) fn import(ctx: &Ctx<'_>, cwd: &str, source: &ImportSource) -> Flow<ClientReply> {
    let (project, vault_path) = find_vault(cwd)?;
    // What can be read and parsed without a password is checked before any
    // window opens: a wrong path or a malformed file costs the person nothing.
    let (shown_path, dotenv_items, ka_path) = match source {
        ImportSource::Dotenv { path } => {
            let full = Path::new(cwd).join(path);
            let meta = std::fs::metadata(&full)
                .map_err(|e| error(format!("cannot read {}: {e}", full.display())))?;
            if !meta.is_file() {
                return Err(error(format!("{} is not a file", full.display())));
            }
            if meta.len() > dotenv::MAX_DOTENV {
                return Err(error(format!("{} is too large", full.display())));
            }
            let bytes = Zeroizing::new(
                std::fs::read(&full)
                    .map_err(|e| error(format!("cannot read {}: {e}", full.display())))?,
            );
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| error(format!("{} is not UTF-8 text", full.display())))?;
            let parsed =
                dotenv::parse(text).map_err(|e| error(format!("{}: {e}", full.display())))?;
            if parsed.items.is_empty() {
                return Err(refused(
                    RefusalKind::NothingToDo,
                    format!("{} holds no values to import", full.display()),
                ));
            }
            (full.display().to_string(), Some(parsed), None)
        }
        ImportSource::Ka { path } => {
            let full = Path::new(cwd).join(path);
            let meta = std::fs::metadata(&full)
                .map_err(|e| error(format!("cannot read {}: {e}", full.display())))?;
            if !meta.is_file() || meta.len() > MAX_KA_FILE {
                return Err(error(format!("{} is not a ka vault file", full.display())));
            }
            (full.display().to_string(), None, Some(full))
        }
    };
    let names: Vec<String> = dotenv_items
        .as_ref()
        .map(|p| p.items.iter().map(|(n, _)| n.clone()).collect())
        .unwrap_or_default();
    if !names.is_empty() {
        // Refused before the window, not after the password: a name already
        // in the vault is visible in the plain index.
        let peek = Vault::peek(&vault_path).map_err(from_vault)?;
        let clashes: Vec<NameIssue> = names
            .iter()
            .filter(|n| peek.entries.iter().any(|e| &&e.name == n))
            .map(|n| NameIssue {
                name: n.clone(),
                why: RefusalKind::Exists,
            })
            .collect();
        if !clashes.is_empty() {
            return Err(refused_names(
                RefusalKind::Exists,
                "the vault already has secrets with these names; nothing was imported",
                clashes,
            ));
        }
    }
    let mut window = ctx.window("Import secrets")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Import from: {shown_path}"));
    if !names.is_empty() {
        lines.push(format!("Names: {}", names.join(", ")));
    }
    let panel = ctx.panel("Import secrets", lines);
    let mut vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
    let items: Vec<(String, SecretValue)> = match (dotenv_items, ka_path) {
        (Some(parsed), _) => parsed.into_secrets(),
        (None, Some(path)) => {
            let mut ka_panel = panel.clone();
            ka_panel
                .lines
                .push("Now the password of the ka vault being imported.".to_string());
            let ka_typed = window
                .ask_password(&ka_panel, "ka vault password", false)
                .map_err(from_surface)?
                .ok_or_else(cancelled)?;
            vahta_vault::ka::import_ka(&path, ka_typed.expose().as_bytes()).map_err(from_vault)?
        }
        (None, None) => return Err(error("nothing to import")),
    };
    let imported: Vec<String> = items.iter().map(|(n, _)| n.clone()).collect();
    vault.import(items).map_err(|e| match e {
        Error::ImportCollision(n) => refused_names(
            RefusalKind::Exists,
            "the vault already has a secret with one of these names; nothing was imported",
            vec![NameIssue {
                name: n,
                why: RefusalKind::Exists,
            }],
        ),
        other => from_vault(other),
    })?;
    vault.save(&vault_path, ctx.store()).map_err(from_vault)?;
    ctx.journal(
        Entry::new("import")
            .vault(&vault.vault_id())
            .names(&imported)
            .result("ok", None),
    );
    window.close(Some(&format!("Imported {} secret(s).", imported.len())));
    Ok(ClientReply::Done {
        message: format!(
            "imported {} secret(s): {}",
            imported.len(),
            imported.join(", ")
        ),
    })
}

// --- reveal / copy -----------------------------------------------------------------------------

fn named_value(vault: &Vault, name: &str) -> Flow<SecretValue> {
    vault.get(name).map_err(|e| match e {
        Error::NotFound(_) => unknown_name(name),
        other => from_vault(other),
    })
}

pub(crate) fn reveal(ctx: &Ctx<'_>, cwd: &str, name: &str) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = find_vault(cwd)?;
    ensure_known(&vault_path, name)?;
    let mut window = ctx.window("Reveal a secret")?;
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Reveal: {name}"));
    let mut panel = ctx.panel("Reveal a secret", lines);
    let vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
    let value = named_value(&vault, name)?;
    let text = String::from_utf8_lossy(value.expose()).into_owned();
    let shown = Secret::new(text);
    if std::str::from_utf8(value.expose()).is_err() {
        panel.warning = Some(
            "This value is not valid text; what follows has replacement characters.".to_string(),
        );
    }
    drop(value);
    window
        .show_value(&panel, name, &shown, REVEAL_SECONDS)
        .map_err(from_surface)?;
    ctx.journal(
        Entry::new("reveal")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", None),
    );
    window.close(None);
    Ok(ClientReply::Done {
        message: format!("{name} was shown in the window"),
    })
}

pub(crate) fn copy(ctx: &Ctx<'_>, cwd: &str, name: &str) -> Flow<ClientReply> {
    check_name(name)?;
    let (project, vault_path) = find_vault(cwd)?;
    ensure_known(&vault_path, name)?;
    let Some(tool) = clipboard::detect(&clipboard::Environment::from_process()) else {
        return Err(error(
            "no clipboard tool found (wl-copy, xclip, xsel, pbcopy or clip); nothing was done",
        ));
    };
    let mut window = ctx.window("Copy a secret")?;
    let wait: Duration = ctx.shared.options.clipboard_clear;
    let seconds = wait.as_secs();
    let mut lines = lines_for(&project, &vault_path);
    lines.push(format!("Copy: {name}"));
    lines.push(format!("The clipboard is cleared after {seconds} seconds."));
    let panel = ctx.panel("Copy a secret", lines);
    let vault = unlock(ctx, window.as_mut(), &vault_path, &panel)?;
    let value = named_value(&vault, name)?;
    tool.set(value.expose())
        .map_err(|e| error(format!("cannot use the clipboard: {e}")))?;
    let remembered = Zeroizing::new(value.expose().to_vec());
    drop(value);
    ctx.journal(
        Entry::new("copy")
            .vault(&vault.vault_id())
            .names(&[name.to_string()])
            .result("ok", None),
    );
    window.close(Some(&format!("Copied {name}.")));
    // The clipboard is emptied if nobody has replaced what was put there.
    let journal = ctx.shared.journal.clone();
    let (exe, pid) = (ctx.exe.clone(), ctx.pid);
    let (vault_id, copied_name) = (vault.vault_id(), name.to_string());
    std::thread::spawn(move || {
        std::thread::sleep(wait);
        let (result, reason) = match tool.clear_if_unchanged(&remembered) {
            Ok(true) => ("ok", "cleared"),
            Ok(false) => ("ok", "changed by something else; left alone"),
            Err(_) => ("failed", "could not read or clear the clipboard"),
        };
        journal.record(
            Entry::new("copy_cleared")
                .vault(&vault_id)
                .names(std::slice::from_ref(&copied_name))
                .peer(exe.as_deref(), pid)
                .result(result, Some(reason)),
        );
    });
    Ok(ClientReply::Done {
        message: format!("{name} is on the clipboard for {seconds} seconds"),
    })
}
