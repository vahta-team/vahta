//! Ending sessions when the machine sleeps or the screen locks
//! (`lock_on_sleep` in config.toml, on by default).
//!
//! A person who closes the laptop lid has left; a session that outlives that is
//! a window of time for whatever else runs as them. On Linux the daemon listens
//! to logind over the system bus (a local socket, not a network client) for
//! `PrepareForSleep` (true, as the machine is about to suspend), for `Lock` on
//! a login session (`loginctl lock-session`, and the lock buttons of the
//! desktops that send it), and for `LockedHint` turning true on one of this
//! user's login sessions (GNOME and KDE set it when their screen locks), and
//! ends every session.
//!
//! Lockers on Hyprland (hyprlock, Omarchy's shell) tell logind nothing. Under
//! Hyprland the daemon therefore also asks the compositor, over its local
//! socket, every two seconds while a session is open, whether a monitor is
//! held by a lock screen. Other screen lockers that tell logind nothing are
//! not heard.
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

/// Whether Hyprland's `j/monitors` answer shows a lock screen: a monitor whose
/// `solitaryBlockedBy` includes `LOCK`. Anything unreadable is "not locked".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn hyprland_locked(monitors_json: &[u8]) -> bool {
    let Ok(serde_json::Value::Array(monitors)) = serde_json::from_slice(monitors_json) else {
        return false;
    };
    monitors.iter().any(|m| {
        m["solitaryBlockedBy"]
            .as_array()
            .is_some_and(|b| b.iter().any(|x| x == "LOCK"))
    })
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
    {
        logind::start(shared);
        hyprland::start(shared);
    }
    #[cfg(not(target_os = "linux"))]
    shared.journal.record(
        Entry::new("lock_on_sleep").result("unavailable", Some("not implemented on this platform")),
    );
    crate::testing::start_sleep_trigger(shared);
}

/// End every session because the machine slept or locked.
#[cfg_attr(
    not(any(target_os = "linux", feature = "test-surface")),
    allow(dead_code)
)]
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
    use std::collections::HashMap;
    use zbus::MatchRule;
    use zbus::blocking::{Connection, MessageIterator, Proxy};
    use zbus::message::Type;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};

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

    /// `PropertiesChanged` on login sessions: end the sessions when
    /// `LockedHint` turns true on a session of this user.
    fn watch_locked_hint(shared: Arc<Shared>, connection: Connection) {
        let rule = (|| {
            Ok::<_, zbus::Error>(
                MatchRule::builder()
                    .msg_type(Type::Signal)
                    .sender("org.freedesktop.login1")?
                    .interface("org.freedesktop.DBus.Properties")?
                    .member("PropertiesChanged")?
                    .arg(0, "org.freedesktop.login1.Session")?
                    .build(),
            )
        })();
        let Ok(rule) = rule else { return };
        let Ok(stream) = MessageIterator::for_match_rule(rule, &connection, None) else {
            shared
                .journal
                .record(Entry::new("lock_on_sleep").result("unavailable", Some("LockedHint")));
            return;
        };
        let me = vahta_os::effective_uid();
        for message in stream {
            if shared.stopping() {
                return;
            }
            let Ok(message) = message else { continue };
            type Changed = (String, HashMap<String, OwnedValue>, Vec<String>);
            let Ok((_, changed, _)) = message.body().deserialize::<Changed>() else {
                continue;
            };
            let locked = changed
                .get("LockedHint")
                .and_then(|v| bool::try_from(v).ok())
                == Some(true);
            if !locked {
                continue;
            }
            // Only this user's sessions: another person locking their screen
            // says nothing about this one.
            let Some(path) = message.header().path().map(|p| p.to_owned()) else {
                continue;
            };
            let user = Proxy::new(
                &connection,
                "org.freedesktop.login1",
                path,
                "org.freedesktop.login1.Session",
            )
            .and_then(|proxy| proxy.get_property::<(u32, OwnedObjectPath)>("User"));
            if user.is_ok_and(|(uid, _)| Some(uid) == me) {
                lock_now(&shared, "LockedHint");
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
        let (hint_shared, hint_connection) = (shared.clone(), connection.clone());
        let _ = std::thread::Builder::new()
            .name("vahta-logind".to_string())
            .spawn(move || watch_locked_hint(hint_shared, hint_connection));
        shared
            .journal
            .record(Entry::new("lock_on_sleep").result("listening", Some("logind")));
    }
}

#[cfg(target_os = "linux")]
mod hyprland {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::Duration;

    const EVERY: Duration = Duration::from_secs(2);

    /// Hyprland's request socket, when this daemon was started inside it.
    fn socket() -> Option<PathBuf> {
        let signature = std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE")?;
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
        let path = PathBuf::from(runtime)
            .join("hypr")
            .join(signature)
            .join(".socket.sock");
        path.exists().then_some(path)
    }

    fn monitors(path: &PathBuf) -> std::io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(EVERY))?;
        stream.set_write_timeout(Some(EVERY))?;
        stream.write_all(b"j/monitors")?;
        let mut out = Vec::new();
        // A monitor list is a few kilobytes; more than a megabyte is not one.
        stream.take(1 << 20).read_to_end(&mut out)?;
        Ok(out)
    }

    pub(super) fn start(shared: &Arc<Shared>) {
        let Some(path) = socket() else { return };
        shared
            .journal
            .record(Entry::new("lock_on_sleep").result("listening", Some("Hyprland")));
        let shared = shared.clone();
        let _ = std::thread::Builder::new()
            .name("vahta-hyprland".to_string())
            .spawn(move || {
                while !shared.stopping() {
                    std::thread::sleep(EVERY);
                    // Only while there is something to end.
                    if shared.live_sessions() == 0 {
                        continue;
                    }
                    if monitors(&path).is_ok_and(|m| hyprland_locked(&m)) {
                        lock_now(&shared, "Hyprland lock screen");
                    }
                }
            });
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

    #[test]
    fn a_hyprland_monitor_held_by_a_lock_screen_is_locked() {
        let locked = br#"[{"name":"eDP-1","solitaryBlockedBy":["LOCK","WINDOWED"]}]"#;
        let open = br#"[{"name":"eDP-1","solitaryBlockedBy":["WINDOWED","CANDIDATE"]},
                        {"name":"HDMI-A-1","solitaryBlockedBy":[]}]"#;
        assert!(hyprland_locked(locked));
        assert!(!hyprland_locked(open));
        // An older Hyprland without the field, or garbage, is not a lock.
        assert!(!hyprland_locked(br#"[{"name":"eDP-1"}]"#));
        assert!(!hyprland_locked(b"not json"));
        assert!(!hyprland_locked(b""));
    }
}
