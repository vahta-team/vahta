//! `vahta config`: the few settings that can be changed from the command line.
//! Today one: `vahta config unlock`, the current unlock method.
//!
//! It needs no password and no daemon. It only decides which of the ways into
//! the vault is tried first; the master password always opens the vault, so
//! the setting can never lock the person out, and nothing that opens the vault
//! is added or removed by it. The daemon reads the setting from `config.toml`
//! each time it unlocks, so a change applies at the next unlock.

use std::io::Write;

use vahta_auth::{Registry, UnlockPref, find_device};
use vahta_ipc::config::{Config, UnlockSetting, set_unlock};
use vahta_vault::project::Project;
use vahta_vault::{Peek, Vault};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_FAILED, EXIT_USAGE, Env};

pub const USAGE: &str = "\
usage: vahta config unlock [--global] [password | device NAME | last | default]

Which way into the vault is tried first. A vault may open with the master
password, the recovery key (its own command) and one or more paired phones.

  (no argument)  show the setting in force and the method it makes current
  last           the method enrolled last (the default): a phone paired after
                 the vault was made, else the password
  password       the master password first; no phone is asked
  device NAME    that phone first (a name, or the start of its id); if it does
                 not answer, the next method, ending with the master password
  default        forget this vault's own setting

The setting is for the vault of this project. --global sets it for every vault
without one of its own. It is stored in config.toml (`unlock`, and per vault
`[unlock_vault]`). Changing it needs no password: it only orders the methods,
and the master password always opens the vault.

options:
  --global      set (or show) the setting for all vaults
  -h, --help    show this help
";

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let usage_error = |stderr: &mut dyn Write, msg: &str| {
        let _ = write!(stderr, "vahta config: error: {msg}\n\n{USAGE}");
        EXIT_USAGE
    };
    match args.first().map(String::as_str) {
        Some("-h" | "--help") => {
            let _ = stdout.write_all(USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        Some("unlock") => {}
        Some(other) => return usage_error(stderr, &format!("unknown setting: {other}")),
        None => return usage_error(stderr, "expected a setting (unlock)"),
    }
    let mut global = false;
    let mut words: Vec<&str> = Vec::new();
    for a in &args[1..] {
        match a.as_str() {
            "-h" | "--help" => {
                let _ = stdout.write_all(USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--global" => global = true,
            other if other.starts_with('-') => {
                return usage_error(stderr, &format!("unrecognised argument: {other}"));
            }
            other => words.push(other),
        }
    }
    // What to do: nothing (show), forget, or set.
    enum Change {
        Show,
        Forget,
        Set(UnlockSetting),
    }
    let change = match words.as_slice() {
        [] => Change::Show,
        ["default"] => Change::Forget,
        ["last"] => Change::Set(UnlockSetting::Last),
        ["password"] => Change::Set(UnlockSetting::Password),
        ["device"] => return usage_error(stderr, "device needs a name"),
        ["device", name @ ..] => {
            match UnlockSetting::parse(&format!("device:{}", name.join(" "))) {
                Some(s) => Change::Set(s),
                None => return usage_error(stderr, "that is not a usable device name"),
            }
        }
        [one] if one.starts_with("device:") => match UnlockSetting::parse(one) {
            Some(s) => Change::Set(s),
            None => return usage_error(stderr, "that is not a usable device name"),
        },
        _ => return usage_error(stderr, "expected password, device NAME, last or default"),
    };

    let paths = match daemon_cmd::paths(env) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "vahta config: error: {e}");
            return EXIT_FAILED;
        }
    };
    let file = paths.config_file();
    let cfg = match Config::load(&file) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "vahta config: error: {e}");
            return EXIT_FAILED;
        }
    };

    // This project's vault, unless the global setting is asked for.
    let vault = if global {
        None
    } else {
        let found = Project::find(&env.cwd).map(|p| p.vault_path());
        match found {
            Some(path) if path.is_file() => match Vault::peek(&path) {
                Ok(peek) => Some(peek),
                Err(e) => {
                    let _ = writeln!(stderr, "vahta config: error: {e}");
                    return EXIT_FAILED;
                }
            },
            _ => {
                if !matches!(change, Change::Show) {
                    let _ = writeln!(
                        stderr,
                        "vahta config: no vault here to set it for (use --global for every vault)"
                    );
                    return EXIT_FAILED;
                }
                None
            }
        }
    };
    let id_hex = vault.as_ref().map(|p| vahta_vault::hex_encode(&p.vault_id));

    let result = match change {
        Change::Show => Ok(()),
        Change::Forget => set_unlock(&file, id_hex.as_deref(), None),
        Change::Set(mut setting) => {
            // A device must be one of this vault's, with a way in; it is
            // stored under its name whatever was typed.
            if let (UnlockSetting::Device(name), Some(peek)) = (&setting, &vault) {
                match find_device(peek, name) {
                    Some(d) => setting = UnlockSetting::Device(d.name.clone()),
                    None => {
                        let _ = writeln!(
                            stderr,
                            "vahta config: error: this vault has no phone called {name} that can \
                             unlock it (see `vahta devices`); nothing was changed"
                        );
                        return EXIT_FAILED;
                    }
                }
            }
            set_unlock(&file, id_hex.as_deref(), Some(&setting))
        }
    };
    if let Err(e) = result {
        let _ = writeln!(
            stderr,
            "vahta config: error: cannot write {}: {e}",
            file.display()
        );
        return EXIT_FAILED;
    }
    let cfg = match Config::load(&file) {
        Ok(c) => c,
        Err(_) => cfg,
    };
    show(&cfg, vault.as_ref(), id_hex.as_deref(), stdout);
    EXIT_CLEAN
}

fn show(cfg: &Config, vault: Option<&Peek>, id_hex: Option<&str>, stdout: &mut dyn Write) {
    let (setting, source) = match id_hex {
        Some(id) if cfg.unlock_vault.contains_key(id) => (cfg.unlock_for(id), "this vault"),
        _ if cfg.unlock != UnlockSetting::Last => (&cfg.unlock, "all vaults"),
        _ => (&cfg.unlock, "default"),
    };
    let _ = writeln!(stdout, "unlock = {} (from {source})", setting.as_text());
    let Some(peek) = vault else {
        return;
    };
    let pref = UnlockPref::parse(&setting.as_text()).unwrap_or_default();
    let order = Registry::standard().order(peek, vahta_auth::Need::Knowledge, &pref);
    let name_of = |slot: &vahta_vault::SlotInfo| {
        peek.devices
            .iter()
            .find(|d| d.device_id == slot.slot_id)
            .map_or_else(|| slot.label.clone(), |d| format!("device {}", d.name))
    };
    let names: Vec<String> = order
        .iter()
        .map(|s| {
            if s.kind == vahta_vault::SLOT_PASSWORD {
                "master password".to_string()
            } else {
                name_of(s)
            }
        })
        .collect();
    if let Some(first) = names.first() {
        let _ = writeln!(stdout, "current: {first}");
        let _ = writeln!(stdout, "order: {}", names.join(", then "));
    }
    let _ = writeln!(stdout, "the master password always works");
}
