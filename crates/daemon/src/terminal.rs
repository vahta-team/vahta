//! Opening a terminal window for the prompt surface.
//!
//! The daemon has no terminal of its own and the caller's terminal is the one
//! place a prompt must never go (an agent may be reading it), so the window is
//! always a new one running `vahta _surface`. The token and the address travel
//! in its environment, never on its command line.
//!
//! * **Linux** has no standard way to open a terminal, so this carries ka's
//!   table of emulators (`platform.py`'s `_LINUX_EMULATORS`): each with the flag
//!   that makes it run the rest of the command line, in the order to try them,
//!   with the running desktop's own first. The `terminal` config key, the
//!   `VAHTA_TERMINAL` variable and `$TERMINAL` come before the table. A
//!   terminal that opens but never runs our command is closed and the next one
//!   tried; the last one is waited for. No display means failing closed.
//! * **Windows** starts the helper with `CREATE_NEW_CONSOLE`.
//! * **macOS** asks Terminal.app, through `osascript`, to run the helper; the
//!   environment cannot ride along, so it travels in a `0600` file that the
//!   helper reads and deletes.
//!
//! Only the Linux part can be exercised where the tests run; macOS and Windows
//! are written from the platform documentation and ka's behaviour and are
//! checked by compiling in CI and by hand.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::pathfind::find_in_path;

/// How an emulator takes the command to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `term CMD ARGS...`
    Trailing,
    /// `term FLAG... CMD ARGS...`
    Flag,
    /// `term FLAG... "CMD ARGS..."`: one shell-quoted string.
    Joined,
}

/// ka's emulator table, in the order to try. `xdg-terminal-exec` is the
/// freedesktop reference for "launch the user's terminal" and wins when it
/// exists; then the terminals people on Wayland run; then the X11-era ones.
/// `x-terminal-emulator` sits low: it is an alternatives symlink that may land
/// on a terminal whose `-e` is deprecated.
pub const EMULATORS: &[(&str, Style, &[&str])] = &[
    ("xdg-terminal-exec", Style::Trailing, &[]),
    ("ghostty", Style::Flag, &["-e"]),
    ("kitty", Style::Trailing, &[]),
    ("foot", Style::Trailing, &[]),
    ("alacritty", Style::Flag, &["-e"]),
    ("wezterm", Style::Flag, &["start", "--"]),
    ("gnome-terminal", Style::Flag, &["--"]),
    ("kgx", Style::Flag, &["--"]),
    ("konsole", Style::Flag, &["-e"]),
    ("xfce4-terminal", Style::Flag, &["-x"]),
    ("mate-terminal", Style::Flag, &["--"]),
    ("terminator", Style::Flag, &["-x"]),
    ("tilix", Style::Joined, &["-e"]),
    ("lxterminal", Style::Joined, &["-e"]),
    ("qterminal", Style::Joined, &["-e"]),
    ("urxvt", Style::Flag, &["-e"]),
    ("st", Style::Flag, &["-e"]),
    ("x-terminal-emulator", Style::Flag, &["-e"]),
    ("xterm", Style::Flag, &["-e"]),
];

/// A desktop's own terminal, moved to the front when `XDG_CURRENT_DESKTOP`
/// names it: a KDE user gets Konsole even where ghostty is also installed.
const DESKTOP_PREFERENCE: &[(&str, &[&str])] = &[
    ("KDE", &["konsole"]),
    ("GNOME", &["kgx", "gnome-terminal"]),
    ("XFCE", &["xfce4-terminal"]),
    ("MATE", &["mate-terminal"]),
    ("LXQT", &["qterminal"]),
];

/// How long a candidate gets to run our command before the next is tried.
const HELPER_START_TIMEOUT: Duration = Duration::from_secs(8);
/// How long the last candidate is waited for.
const LAST_START_TIMEOUT: Duration = Duration::from_secs(30);
/// A pause after spawning, to catch an emulator that exits at once.
const SETTLE: Duration = Duration::from_millis(150);

/// What the launch needs from the environment, gathered once so the choice of
/// terminal can be tested without touching the process's own.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// Whether there is a display to open a window on (`DISPLAY` or
    /// `WAYLAND_DISPLAY`).
    pub display: bool,
    pub desktop: Option<String>,
    pub path: Option<OsString>,
    /// `VAHTA_TERMINAL`: a command prefix that overrides the config.
    pub terminal_override: Option<String>,
    /// `TERMINAL`: the name of a terminal binary.
    pub terminal_var: Option<String>,
}

impl Environment {
    pub fn from_process() -> Environment {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Environment {
            display: var("DISPLAY").is_some() || var("WAYLAND_DISPLAY").is_some(),
            desktop: var("XDG_CURRENT_DESKTOP"),
            path: std::env::var_os("PATH"),
            terminal_override: var("VAHTA_TERMINAL"),
            terminal_var: var("TERMINAL"),
        }
    }
}

/// What to run in the window.
#[derive(Debug, Clone)]
pub struct Launch {
    /// The helper: this very executable.
    pub program: PathBuf,
    /// Its arguments (`_surface`). Never a token.
    pub args: Vec<String>,
    /// The environment the helper needs; the token is here.
    pub env: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum SpawnError {
    /// No display, so no window: fail closed.
    NoDisplay,
    /// No terminal could be opened; these were tried.
    NoTerminal(Vec<String>),
    /// A terminal opened but our command never ran in it.
    NoWindow(Vec<String>),
    Unsupported,
    Io(String),
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnError::NoDisplay => f.write_str(
                "no interactive display (DISPLAY and WAYLAND_DISPLAY are unset), so the prompt window cannot open; \
                 nothing was done",
            ),
            SpawnError::NoTerminal(tried) => write!(
                f,
                "no terminal emulator could be opened{}; set one in config.toml (`terminal = \"alacritty -e\"`) \
                 or in VAHTA_TERMINAL; nothing was done",
                if tried.is_empty() {
                    String::new()
                } else {
                    format!(" (tried {})", tried.join(", "))
                }
            ),
            SpawnError::NoWindow(tried) => write!(
                f,
                "a terminal opened ({}) but the prompt never started in it; nothing was done",
                tried.join(", ")
            ),
            SpawnError::Unsupported => f.write_str("no prompt window on this platform"),
            SpawnError::Io(e) => write!(f, "cannot open a window: {e}"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// The emulators to try, in order: the running desktop's own first.
pub fn candidates(desktop: Option<&str>) -> Vec<&'static str> {
    let names: Vec<&'static str> = EMULATORS.iter().map(|(n, _, _)| *n).collect();
    let Some(desktop) = desktop.map(str::to_uppercase) else {
        return names;
    };
    for (token, preferred) in DESKTOP_PREFERENCE {
        if desktop.contains(token) {
            let mut front: Vec<&'static str> = preferred
                .iter()
                .copied()
                .filter(|p| names.contains(p))
                .collect();
            let rest: Vec<&'static str> = names
                .iter()
                .copied()
                .filter(|n| !front.contains(n))
                .collect();
            front.extend(rest);
            return front;
        }
    }
    names
}

/// Quote `word` for a POSIX shell.
fn shell_quote(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-=:@%+,".contains(&b))
    {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The command line for a known emulator: its program, its flags, and the
/// helper's.
pub fn emulator_argv(program: &str, name: &str, helper: &[String]) -> Vec<String> {
    let (style, flags) = EMULATORS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, s, f)| (*s, *f))
        .unwrap_or((Style::Trailing, &[][..]));
    let mut argv = vec![program.to_string()];
    argv.extend(flags.iter().map(|f| (*f).to_string()));
    match style {
        Style::Joined => argv.push(
            helper
                .iter()
                .map(|w| shell_quote(w))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        Style::Trailing | Style::Flag => argv.extend(helper.iter().cloned()),
    }
    argv
}

/// Split a command prefix the way a shell would for plain cases: whitespace
/// separates, single and double quotes group, a backslash escapes outside
/// single quotes. `None` for an unterminated quote or an empty command.
pub fn split_command(text: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut have = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if have {
                    words.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            '\'' => {
                have = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        q => cur.push(q),
                    }
                }
            }
            '"' => {
                have = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => cur.push(chars.next()?),
                        q => cur.push(q),
                    }
                }
            }
            '\\' => {
                have = true;
                cur.push(chars.next()?);
            }
            c => {
                have = true;
                cur.push(c);
            }
        }
    }
    if have {
        words.push(cur);
    }
    (!words.is_empty()).then_some(words)
}

/// A configured prefix resolved to an absolute program: `VAHTA_TERMINAL`, then
/// the config's `terminal`, then `$TERMINAL` as a name whose flags come from
/// the table. A configured terminal that is gone resolves to `None`, so the
/// scan gets its turn rather than there being no window at all.
pub fn configured_prefix(config: &str, env: &Environment) -> Option<(String, Vec<String>)> {
    let resolve = |text: &str| {
        let parts = split_command(text)?;
        let program = find_in_path(&parts[0], env.path.as_ref())?;
        let mut argv = vec![program.to_string_lossy().into_owned()];
        argv.extend(parts[1..].iter().cloned());
        let name = Path::new(&parts[0])
            .file_name()?
            .to_string_lossy()
            .into_owned();
        Some((name, argv))
    };
    if let Some(found) = env.terminal_override.as_deref().and_then(resolve) {
        return Some(found);
    }
    if let Some(found) = (!config.trim().is_empty())
        .then(|| resolve(config))
        .flatten()
    {
        return Some(found);
    }
    let named = env.terminal_var.as_deref()?;
    let program = find_in_path(named, env.path.as_ref())?;
    let name = Path::new(named).file_name()?.to_string_lossy().into_owned();
    let (_, flags) = EMULATORS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, s, f)| (*s, *f))
        .unwrap_or((Style::Trailing, &[][..]));
    let mut argv = vec![program.to_string_lossy().into_owned()];
    argv.extend(flags.iter().map(|f| (*f).to_string()));
    Some((name, argv))
}

fn helper_argv(launch: &Launch) -> Vec<String> {
    let mut v = vec![launch.program.to_string_lossy().into_owned()];
    v.extend(launch.args.iter().cloned());
    v
}

/// The full command lines to try, in order, with the name of each.
pub fn plan(launch: &Launch, config: &str, env: &Environment) -> Vec<(String, Vec<String>)> {
    let helper = helper_argv(launch);
    let mut out = Vec::new();
    if let Some((name, mut prefix)) = configured_prefix(config, env) {
        prefix.extend(helper.iter().cloned());
        out.push((name, prefix));
    }
    for name in candidates(env.desktop.as_deref()) {
        if let Some(path) = find_in_path(name, env.path.as_ref()) {
            out.push((
                name.to_string(),
                emulator_argv(&path.to_string_lossy(), name, &helper),
            ));
        }
    }
    out
}

/// Open a window running `launch`. `wait` is called after each attempt with how
/// long to wait for the helper to report in, and returns what it got (the
/// connection) or `None`. Returns the terminal's process, where there is one
/// to keep, and what `wait` returned.
pub fn open<T>(
    launch: &Launch,
    config: &str,
    env: &Environment,
    wait: &mut dyn FnMut(Duration) -> Option<T>,
) -> Result<(Option<Child>, T), SpawnError> {
    #[cfg(target_os = "windows")]
    {
        let _ = (config, env);
        windows::open(launch, wait)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (config, env);
        macos::open(launch, wait)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        linux_open(launch, config, env, wait)
    }
}

#[cfg_attr(any(target_os = "windows", target_os = "macos"), allow(dead_code))]
fn linux_open<T>(
    launch: &Launch,
    config: &str,
    env: &Environment,
    wait: &mut dyn FnMut(Duration) -> Option<T>,
) -> Result<(Option<Child>, T), SpawnError> {
    if !env.display {
        return Err(SpawnError::NoDisplay);
    }
    let attempts = plan(launch, config, env);
    let mut tried = Vec::new();
    let mut opened = Vec::new();
    let last = attempts.len().saturating_sub(1);
    for (i, (name, argv)) in attempts.iter().enumerate() {
        tried.push(name.clone());
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .envs(launch.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => continue,
        };
        std::thread::sleep(SETTLE);
        // A launcher that hands the window to a server (gnome-terminal) exits
        // with success while the window is up; failing at once is a bad
        // invocation or a broken alias.
        if let Ok(Some(status)) = child.try_wait()
            && !status.success()
        {
            continue;
        }
        opened.push(name.clone());
        let timeout = if i == last {
            LAST_START_TIMEOUT
        } else {
            HELPER_START_TIMEOUT
        };
        if let Some(got) = wait(timeout) {
            return Ok((Some(child), got));
        }
        // The window is up but our command never ran in it: close it rather
        // than leave an orphan asking for a password nobody will read.
        let _ = child.kill();
        let _ = child.wait();
    }
    if opened.is_empty() {
        Err(SpawnError::NoTerminal(tried))
    } else {
        Err(SpawnError::NoWindow(opened))
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::os::windows::process::CommandExt;

    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

    pub(super) fn open<T>(
        launch: &Launch,
        wait: &mut dyn FnMut(Duration) -> Option<T>,
    ) -> Result<(Option<Child>, T), SpawnError> {
        let child = Command::new(&launch.program)
            .args(&launch.args)
            .envs(launch.env.iter().map(|(k, v)| (k, v)))
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .map_err(|e| SpawnError::Io(e.to_string()))?;
        match wait(LAST_START_TIMEOUT) {
            Some(got) => Ok((Some(child), got)),
            None => {
                let mut child = child;
                let _ = child.kill();
                Err(SpawnError::NoWindow(vec!["console".to_string()]))
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    /// An AppleScript string literal.
    fn applescript_quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    pub(super) fn open<T>(
        launch: &Launch,
        wait: &mut dyn FnMut(Duration) -> Option<T>,
    ) -> Result<(Option<Child>, T), SpawnError> {
        // The environment cannot ride through Terminal.app, so it goes in a
        // private file the helper reads and removes.
        let dir = std::env::temp_dir();
        let name = format!("vahta-surface-{}-{}.env", std::process::id(), nanos());
        let path = dir.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| SpawnError::Io(e.to_string()))?;
        for (k, v) in &launch.env {
            writeln!(file, "{k}={v}").map_err(|e| SpawnError::Io(e.to_string()))?;
        }
        drop(file);
        let mut helper = super::helper_argv(launch);
        helper.push("--env-file".to_string());
        helper.push(path.to_string_lossy().into_owned());
        let inner = format!(
            "exec {}",
            helper
                .iter()
                .map(|w| shell_quote(w))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let script = format!(
            "tell application \"Terminal\"\n  do script {}\n  activate\nend tell",
            applescript_quote(&inner)
        );
        let status = Command::new("osascript")
            .arg("-e")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| SpawnError::Io(e.to_string()))?;
        if !status.success() {
            let _ = std::fs::remove_file(&path);
            return Err(SpawnError::NoTerminal(vec!["Terminal".to_string()]));
        }
        match wait(LAST_START_TIMEOUT) {
            Some(got) => Ok((None, got)),
            None => {
                let _ = std::fs::remove_file(&path);
                Err(SpawnError::NoWindow(vec!["Terminal".to_string()]))
            }
        }
    }

    fn nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(path: &Path) -> Environment {
        Environment {
            display: true,
            path: Some(path.as_os_str().to_os_string()),
            ..Environment::default()
        }
    }

    #[cfg(unix)]
    fn fake_executable(dir: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn the_table_is_in_ka_order_and_the_desktop_goes_first() {
        let plain = candidates(None);
        assert_eq!(plain[0], "xdg-terminal-exec");
        assert_eq!(plain[1], "ghostty");
        assert_eq!(*plain.last().unwrap(), "xterm");
        assert_eq!(candidates(Some("KDE"))[0], "konsole");
        assert_eq!(
            &candidates(Some("ubuntu:GNOME"))[..2],
            ["kgx", "gnome-terminal"]
        );
        // Nothing is lost or duplicated by the reordering.
        let mut sorted = candidates(Some("KDE"));
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), EMULATORS.len());
    }

    #[test]
    fn each_style_builds_its_command_line() {
        let helper = vec!["/bin/vahta".to_string(), "_surface".to_string()];
        assert_eq!(
            emulator_argv("/usr/bin/kitty", "kitty", &helper),
            ["/usr/bin/kitty", "/bin/vahta", "_surface"]
        );
        assert_eq!(
            emulator_argv("/usr/bin/alacritty", "alacritty", &helper),
            ["/usr/bin/alacritty", "-e", "/bin/vahta", "_surface"]
        );
        assert_eq!(
            emulator_argv("/usr/bin/wezterm", "wezterm", &helper),
            ["/usr/bin/wezterm", "start", "--", "/bin/vahta", "_surface"]
        );
        // One string, quoted, for the terminals that take one.
        let spaced = vec!["/my dir/vahta".to_string(), "_surface".to_string()];
        assert_eq!(
            emulator_argv("/usr/bin/tilix", "tilix", &spaced),
            ["/usr/bin/tilix", "-e", "'/my dir/vahta' _surface"]
        );
        // An unknown terminal gets the modern default: the command, as is.
        assert_eq!(
            emulator_argv("/x/newterm", "newterm", &helper),
            ["/x/newterm", "/bin/vahta", "_surface"]
        );
    }

    #[test]
    fn a_command_prefix_splits_like_a_shell_for_plain_cases() {
        assert_eq!(split_command("alacritty -e").unwrap(), ["alacritty", "-e"]);
        assert_eq!(
            split_command("  my-term --title 'a b' \"c d\" e\\ f ").unwrap(),
            ["my-term", "--title", "a b", "c d", "e f"]
        );
        assert_eq!(split_command("x ''").unwrap(), ["x", ""]);
        assert!(split_command("").is_none());
        assert!(split_command("a 'unterminated").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_configured_terminal_beats_the_table_and_a_missing_one_falls_back() {
        let tmp = tempfile::tempdir().unwrap();
        fake_executable(tmp.path(), "myterm", "true");
        fake_executable(tmp.path(), "kitty", "true");
        let launch = Launch {
            program: PathBuf::from("/bin/vahta"),
            args: vec!["_surface".into()],
            env: vec![],
        };
        let env = env_with(tmp.path());
        let first = &plan(&launch, "myterm -x", &env)[0];
        assert_eq!(first.0, "myterm");
        assert!(first.1[0].ends_with("/myterm"));
        assert_eq!(&first.1[1..], ["-x", "/bin/vahta", "_surface"]);
        // Configured but not installed: the scan still finds kitty.
        let after = plan(&launch, "gone-term -e", &env);
        assert_eq!(after[0].0, "kitty");
        // The override variable wins over the config.
        let mut with_override = env_with(tmp.path());
        with_override.terminal_override = Some("kitty".to_string());
        assert_eq!(plan(&launch, "myterm", &with_override)[0].0, "kitty");
        // $TERMINAL names a binary; its flags come from the table.
        let mut with_var = env_with(tmp.path());
        with_var.terminal_var = Some("kitty".to_string());
        assert_eq!(plan(&launch, "", &with_var)[0].0, "kitty");
    }

    #[test]
    fn no_display_fails_closed_and_no_terminal_is_said() {
        let launch = Launch {
            program: PathBuf::from("/bin/vahta"),
            args: vec![],
            env: vec![],
        };
        let mut none = |_| -> Option<()> { None };
        let headless = Environment::default();
        assert!(matches!(
            linux_open(&launch, "", &headless, &mut none),
            Err(SpawnError::NoDisplay)
        ));
        let tmp = tempfile::tempdir().unwrap();
        let empty_path = env_with(tmp.path());
        let err = linux_open(&launch, "", &empty_path, &mut none).unwrap_err();
        assert!(matches!(err, SpawnError::NoTerminal(_)));
        assert!(err.to_string().contains("nothing was done"));
    }

    #[cfg(unix)]
    #[test]
    fn a_terminal_that_never_runs_our_command_is_closed_and_the_next_one_tried() {
        let tmp = tempfile::tempdir().unwrap();
        let marks = tmp.path().join("marks");
        std::fs::create_dir(&marks).unwrap();
        // The first terminal in the table opens and does nothing; the second
        // runs the command. Both leave a mark so the order is visible.
        let m = marks.display();
        fake_executable(
            tmp.path(),
            "ghostty",
            &format!("echo ghostty >> {m}/order; sleep 30"),
        );
        fake_executable(
            tmp.path(),
            "kitty",
            &format!("echo kitty >> {m}/order; exec \"$@\""),
        );
        fake_executable(tmp.path(), "helper", &format!("echo ran >> {m}/order"));
        let launch = Launch {
            program: tmp.path().join("helper"),
            args: vec![],
            env: vec![("VAHTA_TEST_FLAG".into(), "1".into())],
        };
        let env = env_with(tmp.path());
        let mut calls = 0;
        let mut wait = |_d: Duration| -> Option<&'static str> {
            calls += 1;
            // The helper reports in only for the second terminal.
            if calls == 1 {
                None
            } else {
                // Give the second terminal a moment to run the helper.
                std::thread::sleep(Duration::from_millis(400));
                Some("connected")
            }
        };
        let (child, got) = linux_open(&launch, "", &env, &mut wait).unwrap();
        assert_eq!(got, "connected");
        assert!(child.is_some());
        let order = std::fs::read_to_string(marks.join("order")).unwrap();
        assert_eq!(
            order.lines().collect::<Vec<_>>(),
            ["ghostty", "kitty", "ran"]
        );
    }
}
