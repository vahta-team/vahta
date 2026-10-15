//! `vahta remote on|off`: let the secrets of this project's vault be used from
//! other projects, or stop.
//!
//! The switch is a field of the signed vault, and only the person can change it:
//! a window shows what it allows and asks for the master password. Plain
//! `vahta remote` says which way it is (no password). It is the vault's side of
//! remote use; the secret's side is `vahta bind NAME --from PROJECT`.

use std::io::Write;

use vahta_ipc::protocol::ClientRequest;

use crate::daemon_cmd;
use crate::{EXIT_CLEAN, EXIT_USAGE, Env};

pub const REMOTE_USAGE: &str = "\
usage: vahta remote [on|off] [--json]

Say whether this project's vault may be used from OTHER projects, or change it.
Off by default. Turning it on or off needs the person: a window shows the vault
and what the switch allows, and asks for the master password.

On, a command run in another project with `vahta run --vault DIR ...` (also
`http`, `unlock`) can use a secret of this vault, but only a secret whose own
`from` list names that project (`vahta bind NAME --from PROJECT`), and only as
that secret's rules allow. Off, a request that names this vault from another
project fails exactly like a path with no vault. Turning it off also ends the
sessions opened from other projects.

options:
  --json     machine-readable result
  -h, --help show this help
";

pub fn run(args: &[String], env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let mut on: Option<bool> = None;
    let mut json = false;
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                let _ = stdout.write_all(REMOTE_USAGE.as_bytes());
                return EXIT_CLEAN;
            }
            "--json" => json = true,
            "on" | "off" if on.is_none() => on = Some(a == "on"),
            other => {
                let _ = write!(
                    stderr,
                    "vahta remote: error: unrecognised argument: {other}\n\n{REMOTE_USAGE}"
                );
                return EXIT_USAGE;
            }
        }
    }
    let request = ClientRequest::Remote {
        cwd: env.cwd.to_string_lossy().into_owned(),
        on,
    };
    daemon_cmd::request(env, "remote", &request, json, stdout, stderr)
}
