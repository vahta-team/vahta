//! Desktop notifications, for the one thing the person must be told while no
//! window of ours is open: a connector's server was refused for want of a
//! connectors session (see `connector_ops.rs`). The harness shows nothing of
//! its server's stderr, so this is the only place the person learns why.
//!
//! No dependency: `notify-send` on Linux, `osascript` on macOS, a PowerShell
//! toast on Windows. A notification that cannot be shown is dropped without a
//! word; it is a convenience, never a gate. The text carries no secret and no
//! name from outside: it is fixed, apart from the harness's own hint.
//!
//! A test build never shows one: it appends `title<TAB>body` to the file
//! `VAHTA_TEST_NOTIFY_LOG` names (see `testing::notify_log`).

use std::time::{Duration, Instant};

/// One notification per harness in this long.
pub(crate) const EVERY: Duration = Duration::from_secs(10 * 60);

/// The notification for a refused launch of a server of `harness`.
pub(crate) fn locked_text(harness: &str) -> (&'static str, String) {
    let hint = match harness {
        "claude" => " (in Claude Code: /mcp)",
        _ => "",
    };
    (
        "Vahta",
        format!(
            "Connectors are locked: run `vahta unlock --connector`, then reconnect the \
             server{hint}"
        ),
    )
}

impl crate::server::Shared {
    /// Tell the person that the connectors are locked, unless `harness` was
    /// told within [`EVERY`].
    pub(crate) fn notify_locked(&self, harness: &str) {
        let due = match self.notified.lock() {
            Ok(mut seen) => {
                let now = Instant::now();
                match seen.get(harness) {
                    Some(at) if now.duration_since(*at) < EVERY => false,
                    _ => {
                        seen.insert(harness.to_string(), now);
                        true
                    }
                }
            }
            Err(_) => false,
        };
        if due {
            let (title, body) = locked_text(harness);
            show(title, &body);
        }
    }
}

/// Show one, or in a test build record it.
fn show(title: &str, body: &str) {
    if let Some(sink) = crate::testing::notify_log() {
        if let Some(path) = sink {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(f, "{title}\t{body}");
            }
        }
        return;
    }
    let (title, body) = (title.to_string(), body.to_string());
    // Off the request's thread: a notifier may take a moment, or hang.
    let _ = std::thread::Builder::new()
        .name("vahta-notify".to_string())
        .spawn(move || run_notifier(&title, &body));
}

#[cfg(target_os = "linux")]
fn run_notifier(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .args(["--app-name=Vahta", "--urgency=critical", "--", title, body])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(target_os = "macos")]
fn run_notifier(title: &str, body: &str) {
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        quote(body),
        quote(title)
    );
    let _ = std::process::Command::new("osascript")
        .args(["-e", &script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(windows)]
fn run_notifier(title: &str, body: &str) {
    // Single-quoted PowerShell strings: only the quote itself is special.
    let q = |s: &str| s.replace('\'', "''");
    let script = format!(
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, \
         ContentType=WindowsRuntime] | Out-Null; \
         $x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(\
         [Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
         $t=$x.GetElementsByTagName('text'); \
         $t.Item(0).AppendChild($x.CreateTextNode('{}')) | Out-Null; \
         $t.Item(1).AppendChild($x.CreateTextNode('{}')) | Out-Null; \
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Vahta')\
         .Show([Windows.UI.Notifications.ToastNotification]::new($x))",
        q(title),
        q(body)
    );
    let mut cmd = std::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    let _ = vahta_os::spawn_detached(&mut cmd);
}

#[cfg(test)]
mod tests {
    use super::locked_text;

    #[test]
    fn the_text_names_the_unlock_and_the_reconnect() {
        let (_, claude) = locked_text("claude");
        assert!(claude.contains("`vahta unlock --connector`"));
        assert!(claude.contains("/mcp"));
        let (_, codex) = locked_text("codex");
        assert!(codex.contains("reconnect"));
        assert!(!codex.contains("/mcp"));
    }
}
