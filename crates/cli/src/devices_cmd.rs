//! `vahta devices` and `vahta recover`.
//!
//! Listing reads the signed device list and needs no password. Pairing,
//! extending, revoking and losing a device each open a window for the master
//! password: a paired phone can open the vault but never manages phones.

use std::io::Write;

use serde_json::json;
use vahta_ipc::duration::{human, parse_secs};
use vahta_ipc::protocol::{ClientReply, ClientRequest, DeviceInfo};

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_DAEMON, EXIT_USAGE, Env};

/// How long a phone's access lasts unless `--for` says otherwise.
const DEFAULT_ACCESS: &str = "90d";

pub const USAGE: &str = "\
usage: vahta devices [--json]
       vahta devices pair NAME [--for DURATION]
       vahta devices extend ID [--for DURATION]
       vahta devices revoke ID
       vahta devices lost ID

The phones paired with this project's vault. Each has access for a limited
time, which you can extend, and can be revoked.

  (none)   list them: name, id, when they were paired, when their access ends
           and when they were last used. No password.
  pair     pair a new phone. The window asks for the master password.
  extend   give a device access for DURATION from now (default 90d). Master
           password.
  revoke   remove a device and its way into the vault. Master password. A copy
           of the vault file made earlier still opens with that phone.
  lost     the phone is lost or stolen: remove it AND change the vault's key,
           so such a copy is of no use. Master password. A new recovery key is
           shown once; the old one stops working.

ID is the device's name or the start of its id (four characters or more).

options:
  --for DURATION   30d, 90d, 12h ... (1 minute to 365 days; default 90d)
  --json           machine-readable list
  -h, --help       show this help

The master password always works: if the phone is away or its access has run
out, the window asks for the password.
";

pub const RECOVER_USAGE: &str = "\
usage: vahta recover

The vault password is forgotten. A window asks for the recovery key written
down when the vault was made, then for a new password. The vault's secrets are
untouched. Without the recovery key there is no way back in.
";

fn when(t: Option<u64>) -> String {
    match t {
        Some(t) => ymd(t),
        None => "-".to_string(),
    }
}

/// `YYYY-MM-DD` of a Unix time, UTC.
fn ymd(t: u64) -> String {
    let days = (t / 86_400) as i64;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

fn table(devices: &[DeviceInfo]) -> String {
    let mut rows = vec![vec![
        "NAME".to_string(),
        "ID".to_string(),
        "PAIRED".to_string(),
        "ACCESS UNTIL".to_string(),
        "LAST USED".to_string(),
        "STATE".to_string(),
    ]];
    for d in devices {
        rows.push(vec![
            d.name.clone(),
            d.id.chars().take(8).collect(),
            when(Some(d.paired_at)),
            if d.expires_at.is_some() {
                when(d.expires_at)
            } else {
                "no end".to_string()
            },
            when(d.last_used),
            d.state.clone(),
        ]);
    }
    let widths: Vec<usize> = (0..6)
        .map(|c| rows.iter().map(|r| r[c].chars().count()).max().unwrap_or(0))
        .collect();
    rows.iter()
        .map(|r| {
            r.iter()
                .enumerate()
                .map(|(c, cell)| format!("{cell:<w$}", w = widths[c]))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let usage_error = |stderr: &mut dyn Write, msg: &str| {
        let _ = write!(stderr, "vahta devices: error: {msg}\n\n{USAGE}");
        EXIT_USAGE
    };
    let mut positional: Vec<&str> = Vec::new();
    let mut secs: Option<u64> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        match a {
            "-h" | "--help" => {
                let _ = stdout.write_all(USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--json" => json = true,
            "--for" => {
                let Some(v) = args.get(i) else {
                    return usage_error(stderr, "--for needs a duration");
                };
                i += 1;
                match parse_secs(v) {
                    Some(s) if s > 0 => secs = Some(s),
                    _ => return usage_error(stderr, &format!("not a duration: {v}")),
                }
            }
            other if other.starts_with('-') => {
                return usage_error(stderr, &format!("unrecognised argument: {other}"));
            }
            other => positional.push(other),
        }
    }
    let cwd = env.cwd.to_string_lossy().into_owned();
    let access = secs.unwrap_or_else(|| parse_secs(DEFAULT_ACCESS).unwrap_or(90 * 86_400));
    let (command, request) = match positional.as_slice() {
        [] => ("devices", ClientRequest::DevicesList { cwd }),
        ["pair", name] => (
            "devices pair",
            ClientRequest::DevicesPair {
                cwd,
                name: (*name).to_string(),
                secs: access,
            },
        ),
        ["extend", id] => (
            "devices extend",
            ClientRequest::DevicesExtend {
                cwd,
                id: (*id).to_string(),
                secs: access,
            },
        ),
        ["revoke", id] if secs.is_none() => (
            "devices revoke",
            ClientRequest::DevicesRevoke {
                cwd,
                id: (*id).to_string(),
            },
        ),
        ["lost", id] if secs.is_none() => (
            "devices lost",
            ClientRequest::DevicesLost {
                cwd,
                id: (*id).to_string(),
            },
        ),
        _ => {
            return usage_error(
                stderr,
                "expected pair NAME, extend ID, revoke ID or lost ID",
            );
        }
    };
    if !matches!(request, ClientRequest::DevicesList { .. }) {
        // These need the person at a window; say so before it opens.
        if let ClientRequest::DevicesPair { secs, .. } | ClientRequest::DevicesExtend { secs, .. } =
            &request
        {
            let _ = writeln!(stderr, "(access for {})", human(*secs));
        }
        return daemon_cmd::request(env, command, &request, json, stdout, stderr);
    }
    let mut conn = match daemon_cmd::connect(env, command, stderr) {
        Ok(c) => c,
        Err(code) => return code,
    };
    match conn.request(&request) {
        Ok(ClientReply::Devices { devices }) => {
            if json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&json!({"devices": devices})).unwrap_or_default()
                );
            } else if devices.is_empty() {
                let _ = writeln!(stdout, "no devices are paired with this vault");
            } else {
                let _ = writeln!(stdout, "{}", table(&devices));
            }
            EXIT_CLEAN
        }
        Ok(other) => daemon_cmd::report(command, &other, json, stdout, stderr),
        Err(e) => {
            let _ = writeln!(stderr, "vahta {command}: error: {e}");
            EXIT_DAEMON
        }
    }
}

pub fn run_recover(
    args: &[String],
    env: &Env,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match args {
        [] => {}
        [a] if a == "-h" || a == "--help" => {
            let _ = stdout.write_all(RECOVER_USAGE.as_bytes());
            return EXIT_CLEAN;
        }
        _ => {
            let _ = write!(
                stderr,
                "vahta recover: error: takes no arguments\n\n{RECOVER_USAGE}"
            );
            return EXIT_USAGE;
        }
    }
    let request = ClientRequest::Recover {
        cwd: env.cwd.to_string_lossy().into_owned(),
    };
    daemon_cmd::request(env, "recover", &request, false, stdout, stderr)
}

#[cfg(test)]
mod tests {
    use super::ymd;

    #[test]
    fn dates_are_utc_calendar_days() {
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(951_782_400), "2000-02-29");
        assert_eq!(ymd(1_700_000_000), "2023-11-14");
    }
}
