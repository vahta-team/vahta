//! Desktop notifications, for the few things the person must be told while no
//! window of ours is open: something about a connector's MCP server is really
//! off (a process that is not its harness tried to start it, a command outside
//! its rules, its own key in its output, a burst of refusals). Silent when all
//! is well: a normal launch never notifies.
//!
//! The text names the secret and the harness or program in plain words, never a
//! value. A notification is limited to one per (vault, kind, secret) in
//! [`EVERY`] and [`CAP`] in all in that time, so an agent cannot flood the
//! desktop; the event itself is journaled either way, and a notification that
//! was sent is journaled as `notified`.
//!
//! No dependency: `notify-send` on Linux, `osascript` on macOS, a PowerShell
//! toast on Windows. One that cannot be shown is dropped without a word; it is
//! a convenience, never a gate.
//!
//! A test build never shows one: it appends `title<TAB>body` to the file
//! `VAHTA_TEST_NOTIFY_LOG` names (see `testing::notify_log`).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::journal::Entry;

/// One notification per (vault, kind, secret) in this long.
pub(crate) const EVERY: Duration = Duration::from_secs(10 * 60);
/// At most this many notifications in [`EVERY`], whatever they are about.
pub(crate) const CAP: usize = 5;

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    /// A process that is not the bound harness tried to launch a connector.
    NotFromHarness,
    /// A launch outside the secret's allow rules (a substituted package, a
    /// different program).
    CommandNotAllowed,
    /// A connector's value was in its server's output.
    ValueInOutput,
    /// Many refused launches in a short time (the injection alarm's score).
    RefusalBurst,
}

impl Kind {
    fn word(self) -> &'static str {
        match self {
            Kind::NotFromHarness => "not_from_harness",
            Kind::CommandNotAllowed => "command_not_allowed",
            Kind::ValueInOutput => "value_in_output",
            Kind::RefusalBurst => "refusal_burst",
        }
    }
}

/// What the limiter remembers.
#[derive(Default)]
pub(crate) struct Limiter {
    by_key: HashMap<([u8; 16], Kind, String), Instant>,
    recent: VecDeque<Instant>,
}

impl Limiter {
    /// Whether a notification for this key may be sent now; if so it is
    /// counted.
    fn allow(&mut self, key: ([u8; 16], Kind, String), now: Instant) -> bool {
        self.by_key.retain(|_, at| now.duration_since(*at) < EVERY);
        while self
            .recent
            .front()
            .is_some_and(|at| now.duration_since(*at) >= EVERY)
        {
            self.recent.pop_front();
        }
        if self.by_key.contains_key(&key) || self.recent.len() >= CAP {
            return false;
        }
        self.by_key.insert(key, now);
        self.recent.push_back(now);
        true
    }
}

/// How a harness is called.
pub(crate) fn harness_title(kind: &str) -> &'static str {
    match kind {
        "claude" => "Claude Code",
        "codex" => "Codex",
        _ => "Cursor",
    }
}

/// The text of a notification. `who` is the harnesses the connector is bound to
/// (`claude`, ...) or, for a command outside the rules, the program's name;
/// both were cleaned by the caller.
pub(crate) fn text(kind: Kind, names: &[String], who: &str) -> (&'static str, String) {
    let names = names.join(", ");
    let body = match kind {
        Kind::NotFromHarness => format!(
            "A process that is not {who} tried to start the MCP server for {names}. Nothing \
             ran. See `vahta journal --kind suspicious`."
        ),
        Kind::CommandNotAllowed => format!(
            "The MCP server for {names} was asked to run `{who}`, which its rules do not \
             allow. Nothing ran. See `vahta journal --kind suspicious`."
        ),
        Kind::ValueInOutput => format!(
            "The MCP server for {names} printed its own key. Vahta hid it. See \
             `vahta journal --kind suspicious`, and check the server you allowed."
        ),
        Kind::RefusalBurst => format!(
            "Many launches of MCP servers ({names}) were refused in a short time. Nothing \
             ran. See `vahta journal --kind refused`."
        ),
    };
    ("Vahta", body)
}

impl crate::server::Shared {
    /// Tell the person that something is off with the connectors `names`, unless
    /// the limits say not to. The journal gets a `notified` line when one is
    /// sent. `who` is a harness list (`claude,codex`) for `NotFromHarness`,
    /// else a short plain text.
    pub(crate) fn notify_suspicious(
        &self,
        vault: &[u8; 16],
        kind: Kind,
        names: &[String],
        who: &str,
    ) {
        let key = (*vault, kind, names.join(","));
        let due = match self.notices.lock() {
            Ok(mut limiter) => limiter.allow(key, Instant::now()),
            Err(_) => false,
        };
        if !due {
            return;
        }
        let who = if kind == Kind::NotFromHarness {
            who.split(',')
                .map(harness_title)
                .collect::<Vec<_>>()
                .join(" or ")
        } else {
            who.to_string()
        };
        let (title, body) = text(kind, names, &who);
        self.journal.record(
            Entry::new("notified")
                .vault(vault)
                .names(names)
                .result("ok", Some(kind.word())),
        );
        show(title, &body);
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
    use super::*;

    #[test]
    fn one_per_key_in_the_window_and_a_cap_in_all() {
        let mut l = Limiter::default();
        let now = Instant::now();
        let key = |n: &str| ([1; 16], Kind::NotFromHarness, n.to_string());
        assert!(l.allow(key("A"), now));
        assert!(!l.allow(key("A"), now), "the same key is told once");
        assert!(l.allow(([1; 16], Kind::CommandNotAllowed, "A".into()), now));
        for n in ["B", "C", "D"] {
            assert!(l.allow(key(n), now));
        }
        assert!(!l.allow(key("E"), now), "the cap holds");
        let later = now + EVERY;
        assert!(l.allow(key("A"), later), "and lifts after the window");
    }

    #[test]
    fn the_text_names_the_secret_and_the_harness_and_no_value() {
        let (_, t) = text(
            Kind::NotFromHarness,
            &["GITHUB_TOKEN".to_string()],
            "Claude Code",
        );
        assert!(t.contains("not Claude Code") && t.contains("GITHUB_TOKEN"));
        assert!(t.contains("Nothing ran"));
    }
}
