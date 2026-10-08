//! Starting the hook watchdog at login, with the person's consent.
//!
//! What is written and which commands enable it is worked out in
//! `vahta_setup::guard::autostart` over an `Env`; this is the part that runs
//! them. In a test build the commands are never run (see
//! `vahta_daemon::testing::service_log`).

use std::io::Write;
use std::process::{Command, Stdio};

use vahta_setup::Env as SetupEnv;
use vahta_setup::guard::{self, Autostart, Runner};

/// Runs the commands for real, or, in a test build, records them.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, argv: &[String]) -> bool {
        if let Some(sink) = vahta_daemon::testing::service_log() {
            if let Some(path) = sink
                && let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
            {
                let _ = writeln!(f, "{}", argv.join(" "));
            }
            return true;
        }
        let Some((program, args)) = argv.split_first() else {
            return false;
        };
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

fn plan(setup: &SetupEnv) -> Option<Autostart> {
    let exe = std::env::current_exe().ok()?;
    Some(guard::autostart(setup, &exe))
}

/// Write the autostart and enable it.
pub fn enable(setup: &SetupEnv, runner: &dyn Runner) -> Result<(), String> {
    let a = plan(setup).ok_or("cannot find the vahta executable")?;
    guard::enable_autostart(&a, runner)
}

/// Disable the autostart and remove what was written. Safe when there is none.
pub fn disable(setup: &SetupEnv, runner: &dyn Runner) {
    if let Some(a) = plan(setup) {
        guard::disable_autostart(&a, runner);
    }
}
