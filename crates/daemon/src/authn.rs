//! The daemon's side of `vahta-auth`: how a window becomes an approver, how a
//! vault is unlocked through the registry, and how the devices of a vault are
//! found.
//!
//! The window stays the last word. Whatever a phone does or does not do, the
//! person can type the master password in the window the daemon opened.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use vahta_auth::{
    Action, Approver, AuthError, Cancel, DeviceApprover, Factor, LinkedDevice, Need, Request,
    UnlockCtx, UnlockReply, UnlockedBy, policy,
};
use vahta_vault::{Device, OwnerKeyChange, Peek, RecoveryKey, SlotInfo, Vault};
use zeroize::Zeroizing;

use crate::journal::Entry;
use crate::ops::{Ctx, Flow, cancelled, error, from_surface, from_vault};
use crate::protocol::Panel;
use crate::server::Shared;
use crate::surface::{DeviceWait, SurfaceError, Window};

/// How long a phone is given to answer before the password window is all
/// that is left.
pub(crate) const DEVICE_WAIT: Duration = Duration::from_secs(30);

fn unavailable(e: SurfaceError) -> AuthError {
    match e {
        SurfaceError::Timeout => AuthError::Timeout,
        SurfaceError::Closed => AuthError::Cancelled,
        other => AuthError::Unavailable(other.to_string()),
    }
}

// --- Approving through the window ------------------------------------------------------------

/// A window as an [`Approver`]. With `verify`, it is a Knowledge approver: it
/// asks for the master password first (three tries) and only then puts the
/// question. Without, it is Presence.
/// Checks a typed password against the vault.
pub(crate) type Verify<'a> = Box<dyn Fn(&[u8]) -> bool + Send + Sync + 'a>;

/// What an unlock hands back: the vault, how it was opened and the password
/// typed, when one was.
pub(crate) type Opened = (Vault, UnlockedBy, Option<Zeroizing<Vec<u8>>>);

pub(crate) struct WindowApprover<'a> {
    window: Mutex<&'a mut dyn Window>,
    panel: &'a Panel,
    question: &'a str,
    verify: Option<Verify<'a>>,
}

impl<'a> WindowApprover<'a> {
    pub(crate) fn new(
        window: &'a mut dyn Window,
        panel: &'a Panel,
        question: &'a str,
        verify: Option<Verify<'a>>,
    ) -> WindowApprover<'a> {
        WindowApprover {
            window: Mutex::new(window),
            panel,
            question,
            verify,
        }
    }
}

impl Approver for WindowApprover<'_> {
    fn factor(&self) -> Factor {
        if self.verify.is_some() {
            Factor::Knowledge
        } else {
            Factor::Presence
        }
    }

    fn label(&self) -> String {
        "window".into()
    }

    fn available(&self) -> bool {
        true
    }

    fn decide(
        &self,
        _req: &Request,
        options: &[String],
        timeout: Duration,
        cancel: &Cancel,
    ) -> Result<Option<usize>, AuthError> {
        let mut guard = self
            .window
            .lock()
            .map_err(|_| AuthError::Unavailable("the window is unusable".into()))?;
        let window: &mut dyn Window = &mut **guard;
        if let Some(stop) = window.canceller() {
            cancel.on_cancel(stop);
        }
        if let Some(verify) = &self.verify {
            let mut shown = self.panel.clone();
            let mut ok = false;
            for _ in 0..crate::authn::MAX_PASSWORD_TRIES {
                let typed = match window.ask_password(&shown, "Vault password", false) {
                    Ok(Some(t)) => t,
                    Ok(None) | Err(SurfaceError::Closed | SurfaceError::Timeout) => {
                        return Ok(None);
                    }
                    Err(e) => return Err(unavailable(e)),
                };
                if verify(typed.expose().as_bytes()) {
                    ok = true;
                    break;
                }
                shown.warning = Some("Wrong password. Try again.".to_string());
            }
            if !ok {
                return Ok(None);
            }
        }
        match window.choose_within(self.panel, self.question, options, timeout) {
            Ok(choice) => Ok(choice),
            Err(SurfaceError::Closed | SurfaceError::Timeout) => Ok(None),
            Err(e) => Err(unavailable(e)),
        }
    }
}

pub(crate) const MAX_PASSWORD_TRIES: usize = 3;

/// The devices of the vault at `vault_path` that can be reached.
pub(crate) fn linked_devices(
    shared: &Shared,
    vault_id: &[u8; 16],
    devices: &[Device],
) -> Vec<LinkedDevice> {
    devices
        .iter()
        .filter_map(|d| {
            shared
                .links
                .channel(vault_id, d)
                .map(|channel| LinkedDevice {
                    record: d.clone(),
                    channel,
                })
        })
        .collect()
}

/// Ask for a yes to `request` (its `options`) from the window and every
/// device of the vault that is good enough for `need`, at once. The first
/// answer wins. `Ok(None)` is nobody answering.
#[allow(clippy::too_many_arguments)]
pub(crate) fn approve(
    shared: &Shared,
    window: &mut dyn Window,
    panel: &Panel,
    question: &str,
    vault_path: &Path,
    request: &Request,
    need: Need,
    timeout: Duration,
) -> Result<Option<usize>, AuthError> {
    let devices = Vault::peek(vault_path)
        .map(|p| p.devices)
        .unwrap_or_default();
    let phones: Vec<DeviceApprover> = linked_devices(shared, &request.vault_id, &devices)
        .into_iter()
        .map(|l| DeviceApprover {
            record: l.record,
            channel: l.channel,
        })
        .collect();
    // The window asks the password itself when a presence yes is not enough.
    let verify: Option<Verify<'_>> = if need.satisfied_by(Factor::Presence) {
        None
    } else {
        let (path, store) = (vault_path.to_path_buf(), shared.store.clone());
        Some(Box::new(move |pw| {
            Vault::unlock_password(&path, pw, &store).is_ok()
        }))
    };
    // Say that a phone is being asked too, so the window is not the only
    // place the person looks.
    let mut shown = panel.clone();
    let names: Vec<&str> = phones
        .iter()
        .filter(|p| need.satisfied_by(p.factor()) && p.available())
        .map(|p| p.record.name.as_str())
        .collect();
    if !names.is_empty() {
        shown.lines.push(format!(
            "Also asked on your phone \"{}\". The first answer counts.",
            names.join("\", \"")
        ));
    }
    let win = WindowApprover::new(window, &shown, question, verify);
    let mut all: Vec<&dyn Approver> = vec![&win];
    all.extend(phones.iter().map(|p| p as &dyn Approver));
    let decided = vahta_auth::decide_any(&all, request, &request.options, need, timeout);
    if matches!(decided, Err(AuthError::Denied)) {
        shared.journal.record(
            Entry::new("device_approve")
                .vault(&request.vault_id)
                .names(&request.action.names())
                .result(
                    "refused",
                    Some(&format!("{}: refused on the phone", request.action.key())),
                ),
        );
    }
    let decided = decided?;
    Ok(decided.map(|d| {
        if let Some(id) = d.device_id {
            shared.journal.record(
                Entry::new("device_approve")
                    .device(&id)
                    .vault(&request.vault_id)
                    .names(&request.action.names())
                    .result(
                        "ok",
                        Some(&format!("{}: option {}", request.action.key(), d.choice)),
                    ),
            );
        }
        d.choice
    }))
}

// --- Unlocking through the registry ---------------------------------------------------------------

struct WindowCtx<'a> {
    window: &'a mut dyn Window,
    panel: &'a Panel,
    request: Request,
    devices: Vec<LinkedDevice>,
    surface: Option<SurfaceError>,
    typed: Option<Zeroizing<Vec<u8>>>,
    failures: Vec<(Option<[u8; 16]>, &'static str, String)>,
    /// Owner key changes the person was asked about, and what they said.
    owner_changes: Vec<bool>,
}

impl UnlockCtx for WindowCtx<'_> {
    fn request(&self) -> &Request {
        &self.request
    }

    fn password(&mut self, warning: Option<&str>) -> Result<Option<Zeroizing<Vec<u8>>>, AuthError> {
        let mut shown = self.panel.clone();
        shown.warning = warning.map(str::to_string).or(shown.warning);
        match self.window.ask_password(&shown, "Vault password", false) {
            Ok(Some(s)) => {
                let typed = Zeroizing::new(s.expose().as_bytes().to_vec());
                self.typed = Some(typed.clone());
                Ok(Some(typed))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                self.surface = Some(e);
                Err(AuthError::Cancelled)
            }
        }
    }

    fn recovery_key(&mut self) -> Result<Option<RecoveryKey>, AuthError> {
        let mut warning = None;
        for _ in 0..MAX_PASSWORD_TRIES {
            let mut shown = self.panel.clone();
            shown.warning = warning.take().or(shown.warning);
            match self.window.ask_value(&shown, "Recovery key", false) {
                Ok(Some(s)) => match RecoveryKey::from_paper(s.expose()) {
                    Some(k) => return Ok(Some(k)),
                    None => warning = Some("That is not a recovery key. Try again.".to_string()),
                },
                Ok(None) => return Ok(None),
                Err(e) => {
                    self.surface = Some(e);
                    return Err(AuthError::Cancelled);
                }
            }
        }
        Err(AuthError::TooManyTries)
    }

    fn device(&mut self, slot_id: &[u8; 16]) -> Option<LinkedDevice> {
        self.devices
            .iter()
            .find(|d| &d.record.device_id == slot_id)
            .cloned()
    }

    fn ask_device(
        &mut self,
        slot: &SlotInfo,
        cancel: &Cancel,
        ask: &(dyn Fn(&Cancel) -> Result<UnlockReply, AuthError> + Sync),
    ) -> Result<UnlockReply, AuthError> {
        // A window that cannot show the wait: the phone is asked, nothing said.
        let Some(stop) = self.window.device_wait_stopper() else {
            return ask(cancel);
        };
        let window = &mut *self.window;
        let mut shown = self.panel.clone();
        shown.warning = None;
        let device = slot.label.clone();
        let (result, ended) = std::thread::scope(|scope| {
            // The phone's answer (or its failing) ends the window's wait.
            let worker = scope.spawn(move || {
                let r = ask(cancel);
                stop();
                r
            });
            let ended = window.show_device_wait(&shown, &device, DEVICE_WAIT);
            if !matches!(
                ended,
                Ok(DeviceWait::Over) | Err(SurfaceError::Unavailable(_))
            ) {
                // The person chose the password, closed the window, or the
                // window broke: stop waiting on the phone.
                cancel.cancel();
            }
            let r = worker
                .join()
                .unwrap_or_else(|_| Err(AuthError::Unavailable("the phone link failed".into())));
            (r, ended)
        });
        match ended {
            Ok(DeviceWait::Over) => result,
            // An answer that was already in is honoured.
            Ok(DeviceWait::Password) => match result {
                Ok(reply) => Ok(reply),
                Err(AuthError::Denied) => Err(AuthError::Denied),
                Err(_) => Err(AuthError::Skipped),
            },
            Ok(DeviceWait::Closed) => Err(AuthError::Cancelled),
            // The window could not show it; the phone was asked all the same.
            Err(SurfaceError::Unavailable(_)) => result,
            Err(e) => {
                self.surface = Some(e);
                Err(AuthError::Cancelled)
            }
        }
    }

    fn attempt_failed(&mut self, slot: &SlotInfo, why: &AuthError) {
        let result = if matches!(why, AuthError::Skipped) {
            "skipped"
        } else {
            "refused"
        };
        self.failures
            .push((Some(slot.slot_id), result, why.to_string()));
    }

    fn confirm_owner_change(&mut self, change: &OwnerKeyChange) -> bool {
        let mut shown = self.panel.clone();
        shown.lines.push(format!(
            "This vault's owner key was changed on another machine (re-key after a lost \
             device, {}).",
            vahta_ipc::duration::ymd(change.changed_at)
        ));
        shown.lines.push(
            "It opened here with your own secret. Accept the new key on this machine?".to_string(),
        );
        shown.warning =
            Some("If you did not re-key this vault, or do not know who did, refuse.".to_string());
        let options = ["Accept the new key".to_string(), "Refuse".to_string()];
        let accepted = matches!(
            self.window
                .choose_within(&shown, "Accept the new owner key?", &options, DEVICE_WAIT),
            Ok(Some(0))
        );
        self.owner_changes.push(accepted);
        accepted
    }
}

/// What the client sees when the person refused on their phone.
pub(crate) fn refused_on_phone() -> crate::protocol::ClientReply {
    crate::protocol::ClientReply::Cancelled {
        message: "refused on the phone; nothing was done".to_string(),
    }
}

/// The reply for an authentication that did not open the vault.
pub(crate) fn reply_for(
    e: AuthError,
    surface: Option<SurfaceError>,
) -> crate::protocol::ClientReply {
    if let Some(s) = surface {
        return from_surface(s);
    }
    match e {
        AuthError::Cancelled => cancelled(),
        // The person said no on the phone: the same as saying no in a window.
        AuthError::Denied => refused_on_phone(),
        AuthError::Vault(v) => from_vault(v),
        other => error(other.to_string()),
    }
}

fn categories_of(peek: &Peek, names: &[String]) -> Vec<String> {
    peek.bindings
        .iter()
        .filter(|b| names.contains(&b.name))
        .filter_map(|b| b.category.clone())
        .collect()
}

/// What `action` needs, for the secrets of `peek` it names.
pub(crate) fn need_of(peek: &Peek, action: &Action) -> Need {
    policy::need_for(action.key(), &categories_of(peek, &action.names()))
}

/// The unlock setting for the vault `vault_id`, read from the config file each
/// time (`vahta config unlock` may have changed it since the daemon started):
/// the preference, its text and where it comes from. A config that cannot be
/// read is the default, the last enrolled method; the password still opens.
pub(crate) fn unlock_pref(
    shared: &Shared,
    vault_id: &[u8; 16],
) -> (vahta_auth::UnlockPref, String, String) {
    let cfg =
        vahta_ipc::config::Config::load(&shared.options.paths.config_file()).unwrap_or_default();
    let id = vahta_vault::hex_encode(vault_id);
    let (setting, source) = if cfg.unlock_vault.contains_key(&id) {
        (cfg.unlock_for(&id).clone(), "this vault")
    } else if cfg.unlock != vahta_ipc::config::UnlockSetting::Last {
        (cfg.unlock.clone(), "all vaults")
    } else {
        (cfg.unlock.clone(), "default")
    };
    let text = setting.as_text();
    let pref = vahta_auth::UnlockPref::parse(&text).unwrap_or_default();
    (pref, text, source.to_string())
}

/// Unlock the vault at `path` for `action`: the current method first (by
/// default the last enrolled; see `vahta config unlock`), then the others,
/// the master password in `window` always among them. `peek` is
/// the plain view of the file just read. The returned [`UnlockedBy`] says what
/// opened it.
pub(crate) fn unlock_for(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
    action: Action,
) -> Flow<(Vault, UnlockedBy)> {
    unlock_keeping_password(ctx, window, path, panel, action).map(|(v, by, _)| (v, by))
}

/// [`unlock_for`] that also hands back the password that was typed, for the
/// one caller that needs it again (a re-key wraps the password slot anew).
/// It is zeroed on drop; the caller keeps it no longer than it must.
pub(crate) fn unlock_keeping_password(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
    action: Action,
) -> Flow<Opened> {
    let peek = Vault::peek(path).map_err(from_vault)?;
    // A member's package opens with the member's identity, not a password slot.
    if peek.package {
        return crate::members_ops::open_member(ctx, window, path, panel, &action);
    }
    let need = need_of(&peek, &action);
    let project = path
        .parent()
        .and_then(Path::parent)
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let category = categories_of(&peek, &action.names()).into_iter().next();
    let request = Request::new(action, &project, peek.vault_id, DEVICE_WAIT)
        .map_err(|e| error(e.to_string()))?
        .with_category(category)
        .with_label(panel.agent_note.clone())
        .with_options(&["Allow".to_string()]);
    let mut wctx = WindowCtx {
        window,
        panel,
        devices: linked_devices(ctx.shared, &peek.vault_id, &peek.devices),
        request,
        surface: None,
        typed: None,
        failures: Vec::new(),
        owner_changes: Vec::new(),
    };
    let (pref, _, _) = unlock_pref(ctx.shared, &peek.vault_id);
    let result = ctx
        .shared
        .unlockers
        .unlock_by(path, ctx.store(), need, &pref, &mut wctx);
    for (slot, result, why) in &wctx.failures {
        let mut entry = Entry::new("device_unlock")
            .vault(&peek.vault_id)
            .result(result, Some(why));
        if let Some(id) = slot {
            entry = entry.device(id);
        }
        ctx.journal(entry);
    }
    for accepted in &wctx.owner_changes {
        ctx.journal(Entry::new("owner_key_change").vault(&peek.vault_id).result(
            if *accepted { "ok" } else { "refused" },
            Some(if *accepted {
                "the person accepted the new owner key on this machine"
            } else {
                "the person refused the new owner key"
            }),
        ));
    }
    let surface = wctx.surface.take();
    match result {
        Ok((vault, by)) => {
            if let Some(root) = path.parent().and_then(Path::parent) {
                crate::guard_ops::note_project(ctx, root);
            }
            {
                if let Some(id) = by.device_id {
                    ctx.journal(
                        Entry::new("device_unlock")
                            .device(&id)
                            .vault(&peek.vault_id)
                            .names(&wctx.request.action.names())
                            .result(
                                "ok",
                                Some(if by.rewrapped {
                                    "slot rewrapped"
                                } else {
                                    "slot not rewrapped"
                                }),
                            ),
                    );
                }
            }
            Ok((vault, by, wctx.typed.take()))
        }
        Err(e) => Err(reply_for(e, surface)),
    }
}

/// Ask for the paper key in `window` and open the vault with it.
pub(crate) fn unlock_with_recovery(
    ctx: &Ctx<'_>,
    window: &mut dyn Window,
    path: &Path,
    panel: &Panel,
) -> Flow<Vault> {
    let peek = Vault::peek(path).map_err(from_vault)?;
    let request = Request::new(Action::Recover, "", peek.vault_id, DEVICE_WAIT)
        .map_err(|e| error(e.to_string()))?;
    let mut wctx = WindowCtx {
        window,
        panel,
        devices: Vec::new(),
        request,
        surface: None,
        typed: None,
        failures: Vec::new(),
        owner_changes: Vec::new(),
    };
    let result =
        ctx.shared
            .unlockers
            .unlock_with(vahta_vault::SLOT_RECOVERY, path, ctx.store(), &mut wctx);
    let surface = wctx.surface.take();
    match result {
        Ok((vault, _)) => Ok(vault),
        Err(AuthError::Vault(vahta_vault::Error::Unlock)) => Err(error(
            "that recovery key does not open this vault; nothing was done",
        )),
        Err(e) => Err(reply_for(e, surface)),
    }
}
