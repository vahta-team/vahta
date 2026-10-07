//! Lock screens on Hyprland (hyprlock, Omarchy's shell). They tell logind
//! nothing, so under Hyprland the daemon asks the compositor, over its local
//! socket, every two seconds while a session is open, whether a monitor is held
//! by a lock screen.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{LockSink, LockSource};

const EVERY: Duration = Duration::from_secs(2);

pub(super) struct Hyprland;

/// Whether Hyprland's `j/monitors` answer shows a lock screen: a monitor whose
/// `solitaryBlockedBy` includes `LOCK`. Anything unreadable is "not locked".
fn hyprland_locked(monitors_json: &[u8]) -> bool {
    let Ok(serde_json::Value::Array(monitors)) = serde_json::from_slice(monitors_json) else {
        return false;
    };
    monitors.iter().any(|m| {
        m["solitaryBlockedBy"]
            .as_array()
            .is_some_and(|b| b.iter().any(|x| x == "LOCK"))
    })
}

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

fn monitors(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(EVERY))?;
    stream.set_write_timeout(Some(EVERY))?;
    stream.write_all(b"j/monitors")?;
    let mut out = Vec::new();
    // A monitor list is a few kilobytes; more than a megabyte is not one.
    stream.take(1 << 20).read_to_end(&mut out)?;
    Ok(out)
}

impl LockSource for Hyprland {
    fn name(&self) -> &'static str {
        "hyprland"
    }

    fn run(self: Box<Self>, sink: LockSink) {
        let Some(path) = socket() else {
            sink.note("unavailable", "Hyprland: not running inside it");
            return;
        };
        sink.note("listening", "Hyprland");
        while !sink.stopping() {
            std::thread::sleep(EVERY);
            // Only while there is something to end.
            if !sink.sessions_open() {
                continue;
            }
            if monitors(&path).is_ok_and(|m| hyprland_locked(&m)) {
                sink.lock("Hyprland lock screen");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
