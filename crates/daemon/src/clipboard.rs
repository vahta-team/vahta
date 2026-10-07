//! The clipboard, through the tools the platform has, never through argv.
//!
//! `vahta copy` puts a value on the clipboard and takes it back after 30
//! seconds if it is still there. There is no clipboard library in the tree (the
//! ones that exist pull in a graphics stack); the platform's own commands do
//! the job: `wl-copy`/`wl-paste` under Wayland, `xclip` or `xsel` under X11,
//! `pbcopy`/`pbpaste` on macOS, `clip` and PowerShell on Windows. The value goes
//! to the tool's standard input and nowhere else.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use crate::pathfind::find_in_path;

/// The commands for one clipboard.
#[derive(Debug, Clone)]
pub struct Tool {
    /// Reads the new content from stdin.
    copy: Vec<PathBuf>,
    /// Writes the current content to stdout.
    paste: Vec<PathBuf>,
    /// Empties it; `None` means copying nothing does.
    clear: Option<Vec<PathBuf>>,
}

/// What the choice of tool depends on.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    pub path: Option<OsString>,
    pub wayland: bool,
    pub x11: bool,
}

impl Environment {
    pub fn from_process() -> Environment {
        let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
        Environment {
            path: std::env::var_os("PATH"),
            wayland: set("WAYLAND_DISPLAY"),
            x11: set("DISPLAY"),
        }
    }
}

fn argv(env: &Environment, parts: &[&str]) -> Option<Vec<PathBuf>> {
    let program = find_in_path(parts[0], env.path.as_ref())?;
    let mut v = vec![program];
    v.extend(parts[1..].iter().map(PathBuf::from));
    Some(v)
}

/// The tool for this platform, or `None` when there is none installed.
pub fn detect(env: &Environment) -> Option<Tool> {
    if cfg!(target_os = "macos") {
        return Some(Tool {
            copy: argv(env, &["pbcopy"])?,
            paste: argv(env, &["pbpaste"])?,
            clear: None,
        });
    }
    if cfg!(windows) {
        return Some(Tool {
            copy: argv(env, &["clip"])?,
            paste: argv(
                env,
                &["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
            )?,
            clear: argv(
                env,
                &[
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Set-Clipboard -Value $null",
                ],
            ),
        });
    }
    if env.wayland
        && let (Some(mut copy), Some(paste)) = (
            argv(env, &["wl-copy"]),
            argv(env, &["wl-paste", "--no-newline"]),
        )
    {
        // Clipboard history managers (cliphist, Omarchy's, KDE's) skip what
        // is offered as `x-kde-passwordManagerHint`, which `--sensitive` adds
        // (wl-clipboard 2.3). Without it the value lands in their history,
        // often a file on disk, before it is cleared here.
        if wl_copy_knows_sensitive(&copy[0]) {
            copy.push(PathBuf::from("--sensitive"));
        }
        return Some(Tool {
            copy,
            paste,
            clear: argv(env, &["wl-copy", "--clear"]),
        });
    }
    if env.x11 || env.wayland {
        if let (Some(copy), Some(paste)) = (
            argv(env, &["xclip", "-selection", "clipboard", "-in"]),
            argv(env, &["xclip", "-selection", "clipboard", "-out"]),
        ) {
            return Some(Tool {
                copy,
                paste,
                clear: None,
            });
        }
        if let (Some(copy), Some(paste)) = (
            argv(env, &["xsel", "--clipboard", "--input"]),
            argv(env, &["xsel", "--clipboard", "--output"]),
        ) {
            return Some(Tool {
                copy,
                paste,
                clear: argv(env, &["xsel", "--clipboard", "--clear"]),
            });
        }
    }
    None
}

/// Whether this `wl-copy` takes `--sensitive`, from its help.
fn wl_copy_knows_sensitive(wl_copy: &std::path::Path) -> bool {
    Command::new(wl_copy)
        .arg("--help")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|out| {
            out.stdout
                .windows(b"--sensitive".len())
                .any(|w| w == b"--sensitive")
        })
}

fn feed(command: &[PathBuf], input: &[u8]) -> std::io::Result<()> {
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        // The tools fork into the background and keep their output open; a
        // pipe here would never reach end-of-file.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input)?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("the clipboard tool failed"))
    }
}

impl Tool {
    pub fn set(&self, value: &[u8]) -> std::io::Result<()> {
        feed(&self.copy, value)
    }

    /// The current content, wiped when dropped.
    pub fn get(&self) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let mut child = Command::new(&self.paste[0])
            .args(&self.paste[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut out = Zeroizing::new(Vec::new());
        if let Some(mut stdout) = child.stdout.take() {
            stdout.read_to_end(&mut out)?;
        }
        child.wait()?;
        Ok(out)
    }

    pub fn clear(&self) -> std::io::Result<()> {
        match &self.clear {
            Some(command) => feed(command, b""),
            None => feed(&self.copy, b""),
        }
    }

    /// Empty the clipboard if it still holds `value`, and report whether it
    /// did. Something else copied in the meantime is left alone.
    pub fn clear_if_unchanged(&self, value: &[u8]) -> std::io::Result<bool> {
        let current = self.get()?;
        // `pbpaste` and PowerShell may add a trailing newline.
        let same = current.as_slice() == value
            || current
                .strip_suffix(b"\r\n")
                .or_else(|| current.strip_suffix(b"\n"))
                .is_some_and(|c| c == value);
        if same {
            self.clear()?;
        }
        Ok(same)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[cfg(not(target_os = "macos"))]
    use std::os::unix::fs::PermissionsExt;

    /// A directory of fake `wl-copy` and `wl-paste` that keep the clipboard in
    /// a file next to them.
    #[cfg(not(target_os = "macos"))]
    fn fake_wayland(dir: &std::path::Path) {
        let script = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(
                &p,
                format!("#!/bin/sh\nclip=\"$(dirname \"$0\")/clip\"\n{body}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        script(
            "wl-copy",
            "case \"$1\" in\n\
             --help) echo '    --sensitive  Hint that the content is sensitive.' ;;\n\
             --clear) : > \"$clip\" ;;\n\
             *) echo \"$*\" > \"$clip.args\"; cat > \"$clip\" ;;\n\
             esac",
        );
        script("wl-paste", "cat \"$clip\"");
    }

    fn env(dir: &std::path::Path) -> Environment {
        Environment {
            path: Some(dir.as_os_str().to_os_string()),
            wayland: true,
            x11: false,
        }
    }

    // macOS uses pbcopy, whatever the environment says.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn copy_then_clear_only_if_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        fake_wayland(tmp.path());
        let tool = detect(&env(tmp.path())).expect("a tool");
        tool.set(b"fake-one").unwrap();
        assert_eq!(tool.get().unwrap().as_slice(), b"fake-one");
        // Offered as sensitive, so history managers skip it.
        let args = std::fs::read_to_string(tmp.path().join("clip.args")).unwrap();
        assert_eq!(args.trim(), "--sensitive");
        // Still ours: cleared.
        assert!(tool.clear_if_unchanged(b"fake-one").unwrap());
        assert_eq!(tool.get().unwrap().as_slice(), b"");
        // Replaced by someone else: left alone.
        tool.set(b"something else").unwrap();
        assert!(!tool.clear_if_unchanged(b"fake-one").unwrap());
        assert_eq!(tool.get().unwrap().as_slice(), b"something else");
    }

    #[test]
    fn no_tool_is_none_not_a_guess() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(detect(&env(tmp.path())).is_none());
    }
}
