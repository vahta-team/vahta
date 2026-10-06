//! Ending sessions when the machine sleeps or the screen locks
//! (`lock_on_sleep` in config.toml, on by default).
//!
//! A person who closes the laptop lid has left; a session that outlives that is
//! a window of time for whatever else runs as them. On Linux the daemon listens
//! to logind over the system bus (a local socket, not a network client) for
//! `PrepareForSleep` (true, as the machine is about to suspend) and for `Lock`
//! on a login session (`loginctl lock-session`, and the lock buttons of the
//! desktops that send it), and ends every session. A screen locker that does not
//! tell logind is not heard.
//!
//! macOS and Windows: not in this version. The daemon says so in its journal
//! rather than leaving the person to assume.

use std::sync::Arc;

use crate::journal::Entry;
use crate::server::Shared;

/// Whether a logind signal means "end the sessions": the machine is going to
/// sleep (`PrepareForSleep(true)`), or a session was asked to lock (`Lock`).
/// The other half of the pair, waking up, ends nothing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn means_lock(member: &str, going_to_sleep: Option<bool>) -> bool {
    match member {
        "PrepareForSleep" => going_to_sleep == Some(true),
        "Lock" => true,
        _ => false,
    }
}

/// Start listening, if `lock_on_sleep` is on and this platform can.
pub(crate) fn start(shared: &Arc<Shared>) {
    if !shared.options.config.lock_on_sleep {
        shared
            .journal
            .record(Entry::new("lock_on_sleep").result("disabled", Some("config.toml")));
        return;
    }
    #[cfg(target_os = "linux")]
    logind::start(shared);
    #[cfg(not(target_os = "linux"))]
    shared.journal.record(
        Entry::new("lock_on_sleep").result("unavailable", Some("not implemented on this platform")),
    );
    crate::testing::start_sleep_trigger(shared);
}

/// End every session because the machine slept or locked.
pub(crate) fn lock_now(shared: &Shared, why: &'static str) {
    let n = shared.end_all_sessions("sleep");
    shared.journal.record(
        Entry::new("sleep_lock")
            .result("ok", Some(why))
            .uses(n as u64),
    );
}

#[cfg(target_os = "linux")]
mod logind {
    use super::*;
    use zbus::MatchRule;
    use zbus::blocking::{Connection, MessageIterator};
    use zbus::message::Type;

    fn watch(
        shared: Arc<Shared>,
        connection: Connection,
        interface: &'static str,
        member: &'static str,
    ) {
        let rule = (|| {
            Ok::<_, zbus::Error>(
                MatchRule::builder()
                    .msg_type(Type::Signal)
                    .sender("org.freedesktop.login1")?
                    .interface(interface)?
                    .member(member)?
                    .build(),
            )
        })();
        let Ok(rule) = rule else { return };
        let Ok(stream) = MessageIterator::for_match_rule(rule, &connection, None) else {
            shared
                .journal
                .record(Entry::new("lock_on_sleep").result("unavailable", Some(member)));
            return;
        };
        for message in stream {
            if shared.stopping() {
                return;
            }
            let Ok(message) = message else { continue };
            let body: Option<bool> = message.body().deserialize::<bool>().ok();
            if means_lock(member, body) {
                lock_now(&shared, member);
            }
        }
    }

    pub(super) fn start(shared: &Arc<Shared>) {
        let Ok(connection) = Connection::system() else {
            shared
                .journal
                .record(Entry::new("lock_on_sleep").result("unavailable", Some("no system bus")));
            return;
        };
        for (interface, member) in [
            ("org.freedesktop.login1.Manager", "PrepareForSleep"),
            ("org.freedesktop.login1.Session", "Lock"),
        ] {
            let (shared, connection) = (shared.clone(), connection.clone());
            let _ = std::thread::Builder::new()
                .name("vahta-logind".to_string())
                .spawn(move || watch(shared, connection, interface, member));
        }
        shared
            .journal
            .record(Entry::new("lock_on_sleep").result("listening", Some("logind")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn going_to_sleep_and_locking_end_sessions_waking_does_not() {
        assert!(means_lock("PrepareForSleep", Some(true)));
        assert!(!means_lock("PrepareForSleep", Some(false)));
        assert!(!means_lock("PrepareForSleep", None));
        assert!(means_lock("Lock", None));
        assert!(!means_lock("Unlock", None));
        assert!(!means_lock("SessionNew", Some(true)));
    }
}
