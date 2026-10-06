//! Which process a session belongs to: its anchor.
//!
//! A session belongs to an anchor process (pid and start time) and everything
//! that process starts. The anchor is chosen from the chain of ancestors of the
//! calling `vahta`:
//!
//! * the nearest ancestor that is not a **shell or wrapper** (`sh`, `bash`,
//!   `zsh`, `fish`, `dash`, `ksh`, `nu`, `pwsh`, `powershell`, `cmd`, `env`,
//!   `sudo`, `doas`, `nohup`, `timeout`, `vahta`). Claude Code runs a command as
//!   `bash -c`, so the session lands on `claude`, not on a shell that is gone
//!   when the command ends;
//! * except that a **shell whose parent is a boundary** (a terminal emulator,
//!   `sshd`, `login`, a `tmux` or `screen` server, `systemd`, `init`,
//!   `launchd`, `explorer.exe`) is itself the anchor. That makes a person's
//!   interactive shell anchor to itself, so their own `vahta unlock` covers
//!   the shell they typed it in and nothing else.
//!
//! The anchor must be owned by the same user, have a pid above the platform's
//! minimum, and be more than two levels above init: the last two entries of the
//! chain are never offered, so a session cannot be hung on the login session.
//! Candidates that fail those are skipped and the walk goes on outward.
//!
//! The rules are ka's `classify_admit_tree_levels` and `platform_min_pid`; this
//! is a pure function of the chain so it is tested without a process tree.

use vahta_os::ProcessId;

/// Shells and wrappers: processes that stand between an agent and the command
/// it runs, and are not the agent.
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "nu",
    "pwsh",
    "powershell",
    "cmd",
];
const WRAPPERS: &[&str] = &["env", "sudo", "doas", "nohup", "timeout", "vahta"];

/// Where a process tree stops being an agent's and starts being the machine's:
/// terminal emulators (ka's table, plus the common macOS and Windows ones),
/// remote and login front ends, multiplexer servers, init systems and the
/// desktop shell.
const BOUNDARIES: &[&str] = &[
    // Terminal emulators, from the surface's table.
    "xdg-terminal-exec",
    "ghostty",
    "kitty",
    "foot",
    "footclient",
    "alacritty",
    "wezterm",
    "wezterm-gui",
    "gnome-terminal",
    "gnome-terminal-server",
    "gnome-terminal-",
    "kgx",
    "konsole",
    "xfce4-terminal",
    "mate-terminal",
    "terminator",
    "tilix",
    "lxterminal",
    "qterminal",
    "urxvt",
    "urxvtd",
    "st",
    "x-terminal-emulator",
    "xterm",
    // macOS and Windows terminals.
    "terminal",
    "iterm2",
    "windowsterminal",
    "openconsole",
    "conhost",
    // Remote and login front ends, multiplexers, init.
    "sshd",
    "login",
    "tmux",
    "screen",
    "systemd",
    "init",
    "launchd",
    "explorer",
];

/// One process in the chain, with what the choice needs to know about it.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: ProcessId,
    /// The executable's base name as the system reports it.
    pub exe: String,
    /// Whether it runs as this user.
    pub mine: bool,
}

/// Why no anchor could be chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// Every candidate was foreign, too low or too close to init.
    NoCandidate,
}

/// An executable name reduced to what is compared: lower case, no `.exe`, no
/// login-shell dash (`-bash`).
pub fn normalise(exe: &str) -> String {
    let lower = exe.trim().to_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(&lower);
    lower.trim_start_matches('-').to_string()
}

fn is_shell(name: &str) -> bool {
    SHELLS.contains(&name)
}

fn is_wrapper(name: &str) -> bool {
    WRAPPERS.contains(&name)
}

/// Whether `name` is a boundary. A `tmux: server` shows as `tmux`; anything
/// that begins `gnome-terminal` is one.
pub fn is_boundary(name: &str) -> bool {
    BOUNDARIES.contains(&name) || name.starts_with("gnome-terminal")
}

/// The index in `chain` of the anchor. `chain[0]` is the calling `vahta`, then
/// its parent, and so on outward. `min_pid` is the platform's lowest pid that
/// may be an anchor.
pub fn select(chain: &[Node], min_pid: u32) -> Result<usize, AnchorError> {
    let floor = chain.len().saturating_sub(2);
    for (i, node) in chain.iter().enumerate().skip(1) {
        let name = normalise(&node.exe);
        let candidate = if is_shell(&name) || is_wrapper(&name) {
            // A shell whose parent is a boundary is the anchor itself: it is
            // someone's own interactive shell. A wrapper never is.
            is_shell(&name)
                && chain
                    .get(i + 1)
                    .is_some_and(|parent| is_boundary(&normalise(&parent.exe)))
        } else {
            true
        };
        if !candidate {
            continue;
        }
        // Too close to init, below the minimum or someone else's: skipped.
        if i >= floor || node.id.pid <= min_pid || !node.mine {
            continue;
        }
        return Ok(i);
    }
    Err(AnchorError::NoCandidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain from `(exe, pid, mine)`, innermost first.
    fn chain(entries: &[(&str, u32, bool)]) -> Vec<Node> {
        entries
            .iter()
            .map(|(exe, pid, mine)| Node {
                id: ProcessId {
                    pid: *pid,
                    start_time: u64::from(*pid) * 10,
                },
                exe: (*exe).to_string(),
                mine: *mine,
            })
            .collect()
    }

    fn pid_of(c: &[Node], i: usize) -> u32 {
        c[i].id.pid
    }

    #[test]
    fn claude_codes_bash_anchors_to_claude() {
        let c = chain(&[
            ("vahta", 900, true),
            ("bash", 800, true),
            ("claude", 700, true),
            ("zsh", 600, true),
            ("kitty", 500, true),
            ("Hyprland", 400, true),
            ("systemd", 1, true),
        ]);
        let i = select(&c, 1).unwrap();
        assert_eq!(pid_of(&c, i), 700);
    }

    #[test]
    fn a_persons_own_shell_under_a_terminal_anchors_to_itself() {
        let c = chain(&[
            ("vahta", 900, true),
            ("bash", 800, true),
            ("kitty", 500, true),
            ("Hyprland", 400, true),
            ("systemd", 1, true),
        ]);
        let i = select(&c, 1).unwrap();
        assert_eq!(pid_of(&c, i), 800);
        // Over ssh, under tmux and under a login: the same.
        for parent in ["sshd", "tmux", "login", "screen", "systemd"] {
            let c = chain(&[
                ("vahta", 900, true),
                ("-bash", 800, true),
                (parent, 500, true),
                ("a", 400, true),
                ("b", 300, true),
                ("init", 1, true),
            ]);
            assert_eq!(pid_of(&c, select(&c, 1).unwrap()), 800, "{parent}");
        }
    }

    #[test]
    fn wrappers_and_shells_in_a_row_are_passed_over() {
        let c = chain(&[
            ("vahta", 900, true),
            ("timeout", 880, true),
            ("sudo", 860, true),
            ("env", 840, true),
            ("sh", 820, true),
            ("bash", 800, true),
            ("codex", 700, true),
            ("zsh", 600, true),
            ("alacritty", 500, true),
            ("sway", 400, true),
            ("systemd", 1, true),
        ]);
        assert_eq!(pid_of(&c, select(&c, 1).unwrap()), 700);
        // A wrapper under a boundary is not an anchor, only a shell is.
        let c = chain(&[
            ("vahta", 900, true),
            ("sudo", 800, true),
            ("kitty", 500, true),
            ("a", 400, true),
            ("b", 300, true),
            ("init", 1, true),
        ]);
        // sudo is skipped, kitty is a terminal (not a shell or wrapper) and so
        // is the nearest non-wrapper.
        assert_eq!(pid_of(&c, select(&c, 1).unwrap()), 500);
    }

    #[test]
    fn foreign_low_and_too_close_to_init_are_skipped() {
        // The nearest is another user's: skipped, the next is taken.
        let c = chain(&[
            ("vahta", 900, true),
            ("bash", 800, true),
            ("agent", 700, false),
            ("claude", 650, true),
            ("a", 400, true),
            ("b", 300, true),
            ("systemd", 1, true),
        ]);
        assert_eq!(pid_of(&c, select(&c, 1).unwrap()), 650);
        // At or below the minimum pid.
        let c = chain(&[
            ("vahta", 900, true),
            ("agent", 3, true),
            ("claude", 650, true),
            ("a", 400, true),
            ("b", 300, true),
            ("systemd", 1, true),
        ]);
        assert_eq!(pid_of(&c, select(&c, 4).unwrap()), 650);
        // The last two entries of the chain are never offered.
        let c = chain(&[
            ("vahta", 900, true),
            ("sh", 800, true),
            ("agent", 700, true),
            ("systemd", 1, true),
        ]);
        assert_eq!(select(&c, 1), Err(AnchorError::NoCandidate));
        // Nothing but wrappers and shells.
        let c = chain(&[
            ("vahta", 900, true),
            ("bash", 800, true),
            ("zsh", 700, true),
            ("sudo", 600, true),
            ("env", 500, true),
            ("sh", 400, true),
        ]);
        assert_eq!(select(&c, 1), Err(AnchorError::NoCandidate));
        // A lone vahta has no ancestors to anchor to.
        assert_eq!(
            select(&chain(&[("vahta", 900, true)]), 1),
            Err(AnchorError::NoCandidate)
        );
        assert_eq!(select(&[], 1), Err(AnchorError::NoCandidate));
    }

    #[test]
    fn names_are_compared_without_case_extension_or_login_dash() {
        assert_eq!(normalise("-bash"), "bash");
        assert_eq!(normalise("PowerShell.exe"), "powershell");
        assert_eq!(normalise("Explorer.EXE"), "explorer");
        assert!(is_boundary("explorer"));
        assert!(is_boundary("gnome-terminal-server"));
        assert!(!is_boundary("claude"));
        let c = chain(&[
            ("vahta.exe", 900, true),
            ("pwsh.exe", 800, true),
            ("WindowsTerminal.exe", 500, true),
            ("explorer.exe", 400, true),
            ("a", 300, true),
            ("System", 4, true),
        ]);
        assert_eq!(pid_of(&c, select(&c, 4).unwrap()), 800);
    }
}
