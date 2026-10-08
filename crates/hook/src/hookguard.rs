//! Keeping an agent from switching Vahta's hooks off.
//!
//! An agent that can edit `~/.claude/settings.json` can remove the hook that
//! watches it. This refuses, before the tool runs, what would do that:
//!
//! * **Edits** (Edit, MultiEdit, Write, `apply_patch`) of a file that holds
//!   hooks or the switches that turn them off: each harness's hook config, a
//!   Claude Code settings file (user, project or local), Codex's `config.toml`,
//!   Vahta's own `config.toml` (its `guard` setting) and the administrator
//!   policy paths. The edit is judged by what the file would become: one that
//!   leaves our entries in place (a new permission) is allowed; one that removes
//!   them, leaves the file unreadable, or adds `disableAllHooks` is not.
//! * **Shell commands** that write, remove, move or copy onto such a file
//!   (`sed -i`, `rm`, `mv`, `cp`, `tee`, `truncate`, a `>` redirect, `jq ... >`),
//!   and `python -c` / `node -e` and the like that name one. Reading is fine.
//!
//! Best effort, in the way of `readguard`: a path built by a script, a glob or
//! a command substitution is not followed. The real guard is the watchdog
//! (`vahta _guard`), which notices the change afterwards and asks the person.
//!
//! The agent is told to ask the person with `vahta hooks pause`.

use std::path::{Path, PathBuf};

use vahta_harness::{Event, Group, Manifest};
use vahta_setup::Env;

use crate::readguard::{self, Tok, is_assignment, normalise, resolved};

/// What was found: the file as written, and what the change would do.
pub struct Tampering {
    pub file: String,
    pub what: String,
}

/// Words that make a call worth a closer look. A call with none of them
/// cannot name a file we watch.
const MARKERS: &[&str] = &[
    "settings",
    "hooks",
    "config.toml",
    "managed",
    "requirements",
    ".claude",
    ".codex",
    ".cursor",
    "claude-code",
    "claudecode",
    "vahta",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A harness's hook config (index into the manifests).
    HookConfig(usize),
    /// A Claude Code settings file that is not the user hook config.
    ClaudeSettings,
    CodexToml,
    VahtaConfig,
    Managed,
}

struct Target {
    path: PathBuf,
    kind: Kind,
}

struct Watch {
    manifests: Vec<Manifest>,
    env: Env,
    targets: Vec<Target>,
    home: PathBuf,
}

fn home_dir() -> Option<PathBuf> {
    match std::env::var_os("HOME") {
        Some(h) if !h.is_empty() => Some(PathBuf::from(h)),
        #[allow(deprecated)]
        _ => std::env::home_dir(),
    }
}

impl Watch {
    fn load() -> Option<Watch> {
        let home = home_dir()?;
        let manifests: Vec<Manifest> = vahta_harness::HARNESSES
            .iter()
            .filter_map(|h| vahta_harness::manifest(h).and_then(Result::ok))
            .collect();
        let env = Env::from_process(home.clone(), PathBuf::new());
        let mut targets = Vec::new();
        for (i, m) in manifests.iter().enumerate() {
            for p in vahta_setup::config_paths(m, &env) {
                if m.name == "codex" {
                    targets.push(Target {
                        path: p.with_file_name("config.toml"),
                        kind: Kind::CodexToml,
                    });
                }
                targets.push(Target {
                    path: p,
                    kind: Kind::HookConfig(i),
                });
            }
            if let Some(p) = vahta_setup::guard::managed_path(m, &env, None) {
                targets.push(Target {
                    path: p,
                    kind: Kind::Managed,
                });
            }
        }
        // The `managed-settings.d` directory of Claude Code sits beside its file.
        let drop_ins: Vec<Target> = targets
            .iter()
            .filter(|t| t.kind == Kind::Managed)
            .filter_map(|t| {
                t.path.parent().map(|d| Target {
                    path: d.join("managed-settings.d"),
                    kind: Kind::Managed,
                })
            })
            .collect();
        targets.extend(drop_ins);
        if let Ok(paths) = vahta_ipc::paths::Paths::from_env(None) {
            targets.push(Target {
                path: paths.config_file(),
                kind: Kind::VahtaConfig,
            });
        }
        Some(Watch {
            manifests,
            env,
            targets,
            home,
        })
    }

    /// `given` as an absolute path: `~`, `$HOME` and `${HOME}` expanded at the
    /// start, the rest against `cwd`.
    fn expand(&self, given: &str, cwd: Option<&str>) -> PathBuf {
        let home = self.home.to_string_lossy();
        for prefix in ["~", "$HOME", "${HOME}"] {
            if let Some(rest) = given.strip_prefix(prefix)
                && (rest.is_empty() || rest.starts_with(['/', '\\']))
            {
                return readguard::resolve(&format!("{home}{rest}"), cwd);
            }
        }
        readguard::resolve(given, cwd)
    }

    /// What kind of watched file `path` is, if it is one.
    fn kind_of(&self, path: &Path) -> Option<Kind> {
        let lexical = normalise(path);
        let real = resolved(&lexical);
        let same = |a: &Path, b: &Path| {
            let (a, b) = (normalise(a), normalise(b));
            a == b || (cfg!(any(windows, target_os = "macos")) && lower(&a) == lower(&b))
        };
        for t in &self.targets {
            let tr = resolved(&normalise(&t.path));
            let hit = [&lexical, &real].iter().any(|p| {
                same(p, &t.path)
                    || same(p, &tr)
                    || (t.kind == Kind::Managed && normalise(p).starts_with(normalise(&t.path)))
            });
            if hit {
                return Some(t.kind);
            }
        }
        // A Claude Code project's settings, wherever the project is.
        let parts: Vec<String> = lexical
            .components()
            .rev()
            .take(2)
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();
        if parts.len() == 2
            && parts[1] == ".claude"
            && (parts[0] == "settings.json" || parts[0] == "settings.local.json")
        {
            return Some(Kind::ClaudeSettings);
        }
        if parts.len() == 2 && parts[1] == ".codex" && parts[0] == "config.toml" {
            return Some(Kind::CodexToml);
        }
        None
    }

    /// Whether `path` is a directory above a watched file (so removing or
    /// moving it takes the file along).
    fn above_watched(&self, path: &Path) -> bool {
        let lexical = normalise(path);
        let real = resolved(&lexical);
        self.targets
            .iter()
            .filter(|t| t.kind != Kind::Managed)
            .any(|t| {
                let tp = normalise(&t.path);
                let tr = resolved(&tp);
                [&lexical, &real]
                    .iter()
                    .any(|p| tp.starts_with(p) && tp != **p || tr.starts_with(p) && tr != **p)
            })
    }
}

fn lower(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Whether a Claude Code settings file would turn hooks off.
fn turns_hooks_off(after: &str) -> bool {
    if vahta_setup::guard::disables_all_hooks(after) {
        return true;
    }
    // Not a JSON object we can read: the word alone is enough.
    !matches!(serde_json::from_str::<serde_json::Value>(after), Ok(v) if v.is_object())
        && after.to_lowercase().contains("disableallhooks")
}

/// What a file of `kind` would do if it held `after`, given what it holds now.
fn judge(w: &Watch, kind: Kind, file: &Path, after: &str) -> Option<&'static str> {
    match kind {
        Kind::Managed => Some("would change the administrator policy"),
        Kind::VahtaConfig => after
            .to_lowercase()
            .contains("guard")
            .then_some("would change the watchdog setting in Vahta's config"),
        Kind::CodexToml => vahta_setup::guard::toml_disables_hooks(after)
            .then_some("would switch Codex's hooks off"),
        Kind::ClaudeSettings => {
            turns_hooks_off(after).then_some("would turn every hook off (disableAllHooks)")
        }
        Kind::HookConfig(i) => {
            let m = &w.manifests[i];
            if m.name == "claude" && turns_hooks_off(after) {
                return Some("would turn every hook off (disableAllHooks)");
            }
            let before = read(file)?;
            let had = vahta_setup::ours_in_text(&before, m, w.env.os).unwrap_or(0);
            if had == 0 {
                return None;
            }
            match vahta_setup::ours_in_text(after, m, w.env.os) {
                Err(_) => Some("would leave the hook settings unreadable"),
                Ok(n) if n < had => Some("would remove Vahta's hook entries"),
                Ok(_) => None,
            }
        }
    }
}

/// The text of `file` after the edits, or `None` when they do not apply (the
/// tool would refuse them).
fn after_edits(file: &Path, edits: &[(String, String)]) -> Option<String> {
    let mut text = read(file)?;
    for (old, new) in edits {
        if old.is_empty() || !text.contains(old.as_str()) {
            return None;
        }
        text = text.replacen(old.as_str(), new, 1);
    }
    Some(text)
}

/// A patch's file sections: `(header, path, added lines, removed lines)`.
fn patch_sections(text: &str) -> Vec<(&'static str, String, String, String)> {
    const HEADERS: &[(&str, &str)] = &[
        ("*** Add File: ", "add"),
        ("*** Update File: ", "update"),
        ("*** Delete File: ", "delete"),
        ("*** Move to: ", "move"),
    ];
    let mut out: Vec<(&'static str, String, String, String)> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some((h, path)) = HEADERS.iter().find_map(|(h, kind)| {
            trimmed
                .strip_prefix(h)
                .map(|p| (*kind, p.trim().to_string()))
        }) {
            out.push((h, path, String::new(), String::new()));
        } else if let Some(cur) = out.last_mut() {
            if let Some(added) = line.strip_prefix('+') {
                cur.2.push_str(added);
                cur.2.push('\n');
            } else if let Some(removed) = line.strip_prefix('-') {
                cur.3.push_str(removed);
                cur.3.push('\n');
            }
        }
    }
    out
}

fn judge_patch(w: &Watch, ev: &Event) -> Option<Tampering> {
    let cwd = ev.cwd.as_deref();
    for (op, given, added, removed) in patch_sections(&ev.text) {
        let path = w.expand(&given, cwd);
        let Some(kind) = w.kind_of(&path) else {
            continue;
        };
        let what = match (op, kind) {
            ("delete", _) | ("move", _) => Some("would delete or move a file that holds hooks"),
            ("add", k) => judge(w, k, &path, &added),
            ("update", Kind::HookConfig(_)) => removed
                .contains("vahta-hook")
                .then_some("would remove Vahta's hook entries")
                .or_else(|| {
                    turns_hooks_off(&added).then_some("would turn every hook off (disableAllHooks)")
                }),
            ("update", Kind::ClaudeSettings) => added
                .to_lowercase()
                .contains("disableallhooks")
                .then_some("would turn every hook off (disableAllHooks)"),
            ("update", Kind::CodexToml) => added
                .lines()
                .any(|l| l.replace(' ', "") == "hooks=false")
                .then_some("would switch Codex's hooks off"),
            ("update", Kind::VahtaConfig) => added
                .to_lowercase()
                .contains("guard")
                .then_some("would change the watchdog setting in Vahta's config"),
            ("update", Kind::Managed) => Some("would change the administrator policy"),
            _ => None,
        };
        if let Some(what) = what {
            return Some(Tampering {
                file: given,
                what: what.to_string(),
            });
        }
    }
    None
}

// --- shell ---------------------------------------------------------------------------------

const INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "pwsh",
    "powershell",
];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "fish", "ksh"];
/// Programs whose every path argument is written, removed or moved.
const ANY_ARG: &[&str] = &[
    "rm", "mv", "tee", "truncate", "shred", "unlink", "rmdir", "ed", "ex", "vi", "vim", "nano",
    "emacs", "chmod", "chown", "patch",
];
/// Programs that remove or move what they name, so a directory above counts.
const TAKES_DIR: &[&str] = &["rm", "mv", "shred", "unlink", "rmdir"];
/// Programs whose last path argument (or `-t DIR`) is the destination.
const TO_LAST: &[&str] = &["cp", "install", "rsync", "scp", "ln"];

fn base(prog: &str) -> &str {
    prog.rsplit(['/', '\\']).next().unwrap_or(prog)
}

fn is_interpreter(prog: &str) -> bool {
    let b = base(prog).to_lowercase();
    let b = b.strip_suffix(".exe").unwrap_or(&b);
    INTERPRETERS.iter().any(|i| {
        b == *i
            || (b.starts_with(i) && b[i.len()..].chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// One simple command: its words after assignments and wrappers, and the
/// files redirected into.
struct Simple {
    words: Vec<String>,
    redirects: Vec<String>,
}

fn simple_commands(cmd: &str) -> Vec<Simple> {
    let mut out = Vec::new();
    let mut cur = Simple {
        words: Vec::new(),
        redirects: Vec::new(),
    };
    let (mut redirect, mut skip) = (false, false);
    let push = |cur: &mut Simple, out: &mut Vec<Simple>| {
        let mut i = 0;
        while i < cur.words.len()
            && (is_assignment(&cur.words[i])
                || readguard::WRAPPERS.contains(&cur.words[i].as_str()))
        {
            i += 1;
        }
        let words = cur.words.split_off(i);
        out.push(Simple {
            words,
            redirects: std::mem::take(&mut cur.redirects),
        });
        cur.words.clear();
    };
    for t in readguard::tokenize(cmd) {
        match t {
            Tok::Word(_) if skip => skip = false,
            Tok::Word(w) if redirect => {
                cur.redirects.push(w);
                redirect = false;
            }
            Tok::Word(w) => cur.words.push(w),
            Tok::RedirectOut => redirect = true,
            Tok::RedirectIn => {}
            Tok::RedirectDup => skip = true,
            Tok::Sep => {
                redirect = false;
                skip = false;
                push(&mut cur, &mut out);
            }
        }
    }
    push(&mut cur, &mut out);
    out
}

fn shell_hit(w: &Watch, cmd: &str, cwd: Option<&str>, depth: usize) -> Option<Tampering> {
    let lowered = cmd.to_lowercase();
    let names_file = |text: &str| -> bool { names_watched_file(w, text) };
    for s in simple_commands(cmd) {
        for r in &s.redirects {
            if w.kind_of(&w.expand(r, cwd)).is_some() {
                return Some(Tampering {
                    file: r.clone(),
                    what: "is a shell command that would write to a file that holds hooks".into(),
                });
            }
        }
        let Some(prog) = s.words.first() else {
            continue;
        };
        let b = base(prog).to_lowercase();
        let b = b.strip_suffix(".exe").unwrap_or(&b).to_string();
        let args = &s.words[1..];
        let hit = |file: &str, what: &str| {
            Some(Tampering {
                file: file.to_string(),
                what: format!("is a `{b}` command that {what}"),
            })
        };
        // A shell given a script to run: look inside it.
        if SHELLS.contains(&b.as_str()) && depth < 3 {
            if let Some(i) = args
                .iter()
                .position(|a| a.starts_with('-') && a.contains('c'))
                && let Some(script) = args.get(i + 1)
                && let Some(t) = shell_hit(w, script, cwd, depth + 1)
            {
                return Some(t);
            }
            continue;
        }
        if b == "eval" && depth < 3 {
            if let Some(t) = shell_hit(w, &args.join(" "), cwd, depth + 1) {
                return Some(t);
            }
            continue;
        }
        if is_interpreter(&b) {
            let code = args
                .iter()
                .any(|a| matches!(a.as_str(), "-c" | "-e" | "-p" | "-E" | "--eval" | "-"))
                || cmd.contains("<<");
            if code && names_file(&lowered) {
                return hit(
                    "(named in the script)",
                    "names a file that holds hooks in its script",
                );
            }
            continue;
        }
        let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
        let check = |given: &str| -> Option<Kind> { w.kind_of(&w.expand(given, cwd)) };
        if ANY_ARG.contains(&b.as_str()) {
            for a in &paths {
                if check(a).is_some() {
                    return hit(a, "would change or remove a file that holds hooks");
                }
                if TAKES_DIR.contains(&b.as_str()) && w.above_watched(&w.expand(a, cwd)) {
                    return hit(a, "would remove or move a directory that holds hooks");
                }
            }
        } else if TO_LAST.contains(&b.as_str()) {
            let target_dir = args.iter().enumerate().find_map(|(i, a)| {
                if a == "-t" || a == "--target-directory" {
                    args.get(i + 1).cloned()
                } else {
                    a.strip_prefix("--target-directory=").map(str::to_string)
                }
            });
            let (target, sources): (Option<String>, Vec<String>) = match target_dir {
                Some(d) => (Some(d), paths.iter().map(|p| p.to_string()).collect()),
                None => match paths.split_last() {
                    Some((last, rest)) => (
                        Some(last.to_string()),
                        rest.iter().map(|p| p.to_string()).collect(),
                    ),
                    None => (None, Vec::new()),
                },
            };
            if let Some(t) = target {
                let tp = w.expand(&t, cwd);
                if check(&t).is_some() {
                    return hit(&t, "would overwrite a file that holds hooks");
                }
                if tp.is_dir() {
                    for src in &sources {
                        if let Some(name) = Path::new(src).file_name()
                            && w.kind_of(&tp.join(name)).is_some()
                        {
                            return hit(src, "would overwrite a file that holds hooks");
                        }
                    }
                }
            }
        } else if b == "dd" {
            for a in args {
                if let Some(of) = a.strip_prefix("of=")
                    && check(of).is_some()
                {
                    return hit(of, "would overwrite a file that holds hooks");
                }
            }
        } else if matches!(b.as_str(), "sed" | "perl" | "ruby" | "awk" | "gawk") {
            let in_place = args.iter().any(|a| {
                a == "--in-place"
                    || a.starts_with("--in-place=")
                    || a == "inplace"
                    || (a.starts_with('-') && !a.starts_with("--") && a.contains('i'))
            });
            if in_place {
                for a in &paths {
                    if check(a).is_some() {
                        return hit(a, "would edit a file that holds hooks in place");
                    }
                }
            }
        } else if matches!(b.as_str(), "curl" | "wget") {
            for (i, a) in args.iter().enumerate() {
                if matches!(a.as_str(), "-o" | "-O" | "--output")
                    && let Some(f) = args.get(i + 1)
                    && check(f).is_some()
                {
                    return hit(f, "would overwrite a file that holds hooks");
                }
            }
        }
    }
    None
}

/// Whether raw command text names a watched file by its usual spellings: the
/// absolute path, the `~/` form, or its last two components.
fn names_watched_file(w: &Watch, lowered_text: &str) -> bool {
    let home = w.home.to_string_lossy().to_lowercase().replace('\\', "/");
    let text = lowered_text.replace('\\', "/");
    for t in &w.targets {
        if t.kind == Kind::Managed {
            continue;
        }
        let abs = t.path.to_string_lossy().to_lowercase().replace('\\', "/");
        if text.contains(&abs) {
            return true;
        }
        if let Some(rel) = abs.strip_prefix(&format!("{home}/")) {
            for pre in ["~/", "$home/", "${home}/"] {
                if text.contains(&format!("{pre}{rel}")) {
                    return true;
                }
            }
        }
        let tail: Vec<String> = t
            .path
            .components()
            .rev()
            .take(2)
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();
        if tail.len() == 2 && text.contains(&format!("{}/{}", tail[1], tail[0])) {
            return true;
        }
    }
    // A Claude Code project's settings.
    text.contains(".claude/settings")
}

// --- the check ------------------------------------------------------------------------------------

fn mentions_a_marker(ev: &Event) -> bool {
    let mut hay = ev.text.to_lowercase();
    if let Some(p) = &ev.path {
        hay.push(' ');
        hay.push_str(&p.to_lowercase());
    }
    MARKERS.iter().any(|m| hay.contains(m))
}

/// The first thing in this tool call that would weaken Vahta's hooks.
pub fn tampering(ev: &Event) -> Option<Tampering> {
    match ev.group {
        Some(Group::Write | Group::Shell) => {}
        _ => return None,
    }
    if !mentions_a_marker(ev) {
        return None;
    }
    let w = Watch::load()?;
    let cwd = ev.cwd.as_deref();
    if ev.group == Some(Group::Shell) {
        return shell_hit(&w, &ev.text, cwd, 0);
    }
    if let Some(given) = ev.path.as_deref() {
        let path = w.expand(given, cwd);
        let kind = w.kind_of(&path)?;
        let after = if ev.edits.is_empty() {
            ev.text.clone()
        } else {
            after_edits(&path, &ev.edits)?
        };
        return judge(&w, kind, &path, &after).map(|what| Tampering {
            file: given.to_string(),
            what: what.to_string(),
        });
    }
    judge_patch(&w, ev)
}

/// Whether a shell command names (and so could write) a watched file: used by
/// tests only through [`tampering`].
#[cfg(test)]
mod tests {
    use super::*;
    use vahta_setup::Os;

    fn watch(home: &Path) -> Watch {
        let manifests: Vec<Manifest> = vahta_harness::HARNESSES
            .iter()
            .filter_map(|h| vahta_harness::manifest(h).and_then(Result::ok))
            .collect();
        let mut env = Env::from_process(home.to_path_buf(), PathBuf::new());
        env.os = Os::Linux;
        env.vars.remove("CODEX_HOME");
        let mut targets = Vec::new();
        for (i, m) in manifests.iter().enumerate() {
            for p in vahta_setup::config_paths(m, &env) {
                targets.push(Target {
                    path: p,
                    kind: Kind::HookConfig(i),
                });
            }
        }
        Watch {
            manifests,
            env,
            targets,
            home: home.to_path_buf(),
        }
    }

    fn hit(w: &Watch, cmd: &str) -> bool {
        shell_hit(w, cmd, None, 0).is_some()
    }

    #[test]
    fn shell_mutations_of_hook_files_are_found_and_reads_are_not() {
        let w = watch(Path::new("/h"));
        for cmd in [
            "sed -i 's/vahta//' ~/.claude/settings.json",
            "sed -ni p /h/.claude/settings.json",
            "rm ~/.claude/settings.json",
            "rm -rf ~/.claude",
            "mv /tmp/x /h/.cursor/hooks.json",
            "cp /tmp/x ~/.codex/hooks.json",
            "echo '{}' > ~/.claude/settings.json",
            "jq 'del(.hooks)' ~/.claude/settings.json > /tmp/x && mv /tmp/x ~/.claude/settings.json",
            "cat x | tee $HOME/.claude/settings.json",
            "truncate -s 0 ~/.cursor/hooks.json",
            "bash -c 'rm ~/.claude/settings.json'",
            "python3 -c \"import os; os.remove('/h/.claude/settings.json')\"",
            "node -e \"fs.writeFileSync(os.homedir()+'/.claude/settings.json','')\"",
        ] {
            assert!(hit(&w, cmd), "{cmd}");
        }
        for cmd in [
            "cat ~/.claude/settings.json",
            "jq .hooks ~/.claude/settings.json",
            "grep vahta ~/.cursor/hooks.json | head",
            "sed -n 1,5p ~/.claude/settings.json",
            "cp ~/.claude/settings.json /tmp/backup.json",
            "rm -rf ~/.claude/projects/x",
            "ls ~/.claude",
            "python3 script.py",
            "echo hello > /tmp/out",
        ] {
            assert!(!hit(&w, cmd), "{cmd}");
        }
    }

    #[test]
    fn patch_sections_are_read_by_file() {
        let p = "*** Begin Patch\n*** Update File: a.json\n-  \"x\"\n+  \"y\"\n*** Delete File: b\n*** End Patch";
        let s = patch_sections(p);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].0, "update");
        assert_eq!(s[0].2, "  \"y\"\n");
        assert_eq!(s[0].3, "  \"x\"\n");
        assert_eq!(s[1].0, "delete");
    }

    #[test]
    fn turning_hooks_off_is_found_in_json_and_in_wreckage() {
        assert!(turns_hooks_off("{\"disableAllHooks\": true}"));
        assert!(!turns_hooks_off("{\"disableAllHooks\": false}"));
        assert!(!turns_hooks_off("{\"permissions\": {\"allow\": []}}"));
        assert!(turns_hooks_off("{ disableAllHooks: true "));
    }
}
