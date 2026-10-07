//! logind, over the system bus (a local socket, not a network client): the
//! machine is about to suspend (`PrepareForSleep` true), a login session was
//! asked to lock (`Lock`: `loginctl lock-session`, and the lock buttons of the
//! desktops that send it), or `LockedHint` turned true on one of this user's
//! login sessions (GNOME and KDE set it when their screen locks).

use std::collections::HashMap;

use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator, Proxy};
use zbus::message::Type;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use super::{LockSink, LockSource};

pub(super) struct Logind;

/// Whether a logind signal means "end the sessions": the machine is going to
/// sleep (`PrepareForSleep(true)`), or a session was asked to lock (`Lock`).
/// The other half of the pair, waking up, ends nothing.
fn means_lock(member: &str, going_to_sleep: Option<bool>) -> bool {
    match member {
        "PrepareForSleep" => going_to_sleep == Some(true),
        "Lock" => true,
        _ => false,
    }
}

fn watch(sink: LockSink, connection: Connection, interface: &'static str, member: &'static str) {
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
        sink.note("unavailable", member);
        return;
    };
    for message in stream {
        if sink.stopping() {
            return;
        }
        let Ok(message) = message else { continue };
        let body: Option<bool> = message.body().deserialize::<bool>().ok();
        if means_lock(member, body) {
            sink.lock(member);
        }
    }
}

/// `PropertiesChanged` on login sessions: end the sessions when `LockedHint`
/// turns true on a session of this user.
fn watch_locked_hint(sink: LockSink, connection: Connection) {
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
        sink.note("unavailable", "LockedHint");
        return;
    };
    let me = vahta_os::effective_uid();
    for message in stream {
        if sink.stopping() {
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
            sink.lock("LockedHint");
        }
    }
}

impl LockSource for Logind {
    fn name(&self) -> &'static str {
        "logind"
    }

    fn run(self: Box<Self>, sink: LockSink) {
        let Ok(connection) = Connection::system() else {
            sink.note("unavailable", "no system bus");
            return;
        };
        for (interface, member) in [
            ("org.freedesktop.login1.Manager", "PrepareForSleep"),
            ("org.freedesktop.login1.Session", "Lock"),
        ] {
            let (sink, connection) = (sink.clone(), connection.clone());
            let _ = std::thread::Builder::new()
                .name("vahta-lock-logind".to_string())
                .spawn(move || watch(sink, connection, interface, member));
        }
        sink.note("listening", "logind");
        // This thread watches the third signal itself.
        watch_locked_hint(sink, connection);
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
