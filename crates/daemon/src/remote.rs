//! Using a vault from outside its own project (`--vault DIR`).
//!
//! A tool vault such as `~/Projects/ai-tools/.vahta` should serve `cargo
//! publish` run in another project, but not any project, and not on the word of
//! the client. Three things have to hold, and all three are decided here:
//!
//! * the **vault says yes**: remote use is a signed opt-in of the vault itself
//!   (`vahta remote on`, the person and the master password). While it is off,
//!   a request that names the vault from outside its project fails with the
//!   same refusal as a path with no vault, so nothing is learned from it;
//! * the **secret says yes**: only a secret whose `from` list covers the
//!   calling project can be used (an uncovered secret looks like one the vault
//!   does not have, see [`Target::view`]);
//! * the **daemon knows where the caller is**: the working directory is read
//!   from the kernel for the process on the other end of the socket
//!   (`/proc/PID/cwd`; `proc_pidinfo` on macOS), never taken from the request.
//!   A client whose claimed directory is not its real one is refused and
//!   journaled as suspicious. Where the kernel cannot be asked (Windows) remote
//!   use is refused; use inside the vault's own project works everywhere.
//!
//! Category rules (allow, deny, network, tier) apply in full to a remote use,
//! and a session opened this way belongs to the pair (vault, calling project).
//!
//! The hook's `CheckRun` is a question, not a use: nothing starts and the
//! hook's own directory is not the shell's, so it is asked with the claimed
//! directory ([`Target::for_check`]). The run that follows is checked for real.

use std::path::{Path, PathBuf};

use vahta_vault::Peek;
use vahta_vault::project::{DIR_NAME, Project, calling_project};

use crate::journal::Entry;
use crate::ops::{Ctx, Flow, find_vault, refused};
use crate::pathfind;
use crate::protocol::RefusalKind;

/// What a missing project says. Also what a vault that has not opted in says.
const NO_PROJECT: &str =
    "no Vahta project here (no .vahta/ in this directory or above); run `vahta init`";

fn no_vault() -> crate::protocol::ClientReply {
    refused(RefusalKind::NoVault, NO_PROJECT)
}

/// The vault a request works on, and from where.
pub(crate) struct Target {
    pub project: Project,
    pub vault_path: PathBuf,
    /// The calling project when this is remote use; `None` inside the vault's
    /// own project.
    pub used_from: Option<PathBuf>,
    /// The directory the work happens in: for `--vault`, the one the kernel
    /// says the caller is in; otherwise the one the request named.
    pub cwd: PathBuf,
}

impl Target {
    /// Find the vault for a request that carries `cwd` and maybe `--vault`.
    /// Without `--vault` this is the project holding `cwd`, as ever.
    pub(crate) fn resolve(ctx: &Ctx<'_>, cwd: &str, vault: Option<&str>) -> Flow<Target> {
        Target::find(ctx, cwd, vault, true)
    }

    /// The same for the hook's question: the claimed directory is believed (see
    /// the module notes).
    pub(crate) fn for_check(ctx: &Ctx<'_>, cwd: &str, vault: Option<&str>) -> Flow<Target> {
        Target::find(ctx, cwd, vault, false)
    }

    fn find(ctx: &Ctx<'_>, cwd: &str, vault: Option<&str>, verify: bool) -> Flow<Target> {
        let Some(vault) = vault else {
            let (project, vault_path) = find_vault(cwd)?;
            return Ok(Target {
                project,
                vault_path,
                used_from: None,
                cwd: PathBuf::from(cwd),
            });
        };
        let claimed = pathfind::canonical(Path::new(cwd));
        let root = pathfind::canonical(Path::new(vault)).filter(|r| r.is_dir());
        let inside = |dir: &Path| root.as_ref().is_some_and(|r| dir.starts_with(r));

        // Where the caller is, from the kernel.
        let real = if verify {
            match ctx.peer_cwd() {
                Some(real) => {
                    if claimed.as_deref() != Some(real.as_path()) {
                        ctx.journal(Entry::new("remote_refused").result(
                            "refused",
                            Some(&format!(
                                "suspicious: the client claimed the directory {} but runs in {}",
                                sanitize(cwd),
                                real.display()
                            )),
                        ));
                        return Err(refused(
                            RefusalKind::NotFromHere,
                            "the working directory this request names is not where it runs; \
                             refused and noted",
                        ));
                    }
                    real
                }
                // The kernel cannot say. A claimed directory inside the
                // vault's own project is plain local use; anything else would
                // be remote use that cannot be checked.
                None => match claimed {
                    Some(c) if inside(&c) => c,
                    _ => {
                        return Err(refused(
                            RefusalKind::NotFromHere,
                            "using a vault from another project is not available here: the \
                             daemon cannot tell where the caller runs on this system",
                        ));
                    }
                },
            }
        } else {
            claimed.ok_or_else(no_vault)?
        };

        let root = root.ok_or_else(no_vault)?;
        let project = Project { root: root.clone() };
        let vault_path = project.vault_path();
        if !root.join(DIR_NAME).is_dir() || !vault_path.is_file() {
            return Err(no_vault());
        }
        if real.starts_with(&root) {
            // Inside its own project: no opt-in needed.
            return Ok(Target {
                project,
                vault_path,
                used_from: None,
                cwd: real,
            });
        }

        // Outside it. Every failure from here to the end of the opt-in check
        // is the refusal of a path with no vault.
        let peek = peek_of(&vault_path).ok_or_else(no_vault)?;
        if peek.verified(ctx.store()).is_err() || !peek.remote {
            return Err(no_vault());
        }
        let from = calling_project(&real);
        ctx.set_used_from(from.clone());
        Ok(Target {
            project,
            vault_path,
            used_from: Some(from),
            cwd: real,
        })
    }

    /// The vault as this caller may see it. Inside the vault's own project: all
    /// of it. From another project: only the secrets whose `from` list covers
    /// the calling project, so any other name is simply not in the vault, and
    /// the refusal for it is the one for a name that does not exist.
    pub(crate) fn view(&self, peek: Peek) -> Peek {
        match &self.used_from {
            Some(from) => peek.visible_from(from),
            None => peek,
        }
    }
}

fn peek_of(path: &Path) -> Option<Peek> {
    vahta_vault::Vault::peek(path).ok()
}

/// A client-sent string as a journal line may carry it.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
}
