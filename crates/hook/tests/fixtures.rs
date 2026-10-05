//! Runs the built `vahta-hook` against every fixture under
//! `crates/harness/harnesses/<harness>/fixtures/`.
//!
//! A fixture is `{event, [args], [env], [files], stdin | stdin_raw, stdout, exit}`.
//! Secret-shaped values are never written in the files: `{{SECRET_ANTHROPIC}}`
//! is replaced here, from pieces. `files` maps a relative path to its content;
//! the test writes them under a fresh temp directory, which `{{TMP}}` names
//! everywhere in the fixture (also inside the file contents).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;

fn secret_anthropic() -> String {
    ["sk-", "ant-", &"a".repeat(25)].concat()
}

fn harnesses_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../harness/harnesses")
}

/// A directory of our own (`tempfile` is not a dependency), removed on drop.
struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vahta-hook-fx-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Tmp(dir)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_fixture(harness: &str, path: &PathBuf) -> Result<(), String> {
    let tmp = Tmp::new();
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let text = text
        .replace("{{SECRET_ANTHROPIC}}", &secret_anthropic())
        .replace("{{TMP}}", &tmp.0.to_string_lossy());
    let fx: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if let Some(files) = fx["files"].as_object() {
        for (rel, content) in files {
            let target = tmp.0.join(rel);
            std::fs::create_dir_all(target.parent().ok_or("no parent")?)
                .map_err(|e| e.to_string())?;
            std::fs::write(&target, content.as_str().unwrap_or("")).map_err(|e| e.to_string())?;
        }
    }
    let stdin = match fx.get("stdin_raw") {
        Some(Value::String(raw)) => raw.clone(),
        _ => fx["stdin"].to_string(),
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vahta-hook"));
    cmd.args([
        "--harness",
        harness,
        "--event",
        fx["event"].as_str().unwrap_or(""),
    ])
    .env_remove("VAHTA_HOOK_DISABLE")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    if let Some(extra) = fx["args"].as_array() {
        cmd.args(extra.iter().filter_map(Value::as_str));
    }
    if let Some(env) = fx["env"].as_object() {
        for (k, v) in env {
            cmd.env(k, v.as_str().unwrap_or(""));
        }
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(stdin.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;

    let want_stdout = match &fx["stdout"] {
        Value::Null => String::new(),
        v => format!("{}\n", serde_json::to_string(v).map_err(|e| e.to_string())?),
    };
    let got = String::from_utf8_lossy(&out.stdout);
    if got != want_stdout {
        return Err(format!("stdout\n  want {want_stdout:?}\n  got  {got:?}"));
    }
    let want_exit = fx["exit"].as_i64().unwrap_or(0) as i32;
    if out.status.code() != Some(want_exit) {
        return Err(format!("exit {:?}, want {want_exit}", out.status.code()));
    }
    Ok(())
}

#[test]
fn every_fixture_matches() {
    let mut failures = Vec::new();
    let mut count = 0;
    for harness in vahta_harness::HARNESSES {
        let dir = harnesses_dir().join(harness).join("fixtures");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        for f in files {
            count += 1;
            if let Err(e) = run_fixture(harness, &f) {
                failures.push(format!(
                    "{harness}/{}: {e}",
                    f.file_name().unwrap().to_string_lossy()
                ));
            }
        }
    }
    assert!(count >= 65, "only {count} fixtures found");
    assert!(
        failures.is_empty(),
        "{} of {count} failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn manifests_parse() {
    for h in vahta_harness::HARNESSES {
        let m = vahta_harness::manifest(h).expect("known").expect("parses");
        assert_eq!(m.name, h);
    }
}

/// Run the hook on a raw stdin string; returns stdout.
fn run_raw(harness: &str, event: &str, stdin: &str) -> String {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_vahta-hook"))
        .args(["--harness", harness, "--event", event])
        .env_remove("VAHTA_HOOK_DISABLE")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn vahta-hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// serde_json stops at 128 levels. A secret wrapped deeper than that must not
/// pass: the hook's own parser has no such limit, and past its generous limits
/// it still walks every string, escapes decoded.
#[test]
fn a_secret_nested_past_serde_depth_is_still_denied() {
    let mut input = format!("{{\"x\": \"{}\"}}", secret_anthropic());
    for _ in 0..5000 {
        input = format!("{{\"a\": {input}}}");
    }
    let payload = format!(
        "{{\"hook_event_name\": \"PreToolUse\", \"tool_name\": \"mcp__srv__do\", \"tool_input\": {input}}}"
    );
    for harness in ["claude", "codex"] {
        let out = run_raw(harness, "before_tool", &payload);
        assert!(out.contains("\"deny\""), "{harness}: {out}");
        assert!(
            !out.contains(&secret_anthropic()),
            "{harness}: value echoed"
        );
    }
    // The same with the secret spelled through a JSON escape.
    let escaped = secret_anthropic().replacen('k', "\\u006b", 1);
    let deep_escaped = payload.replace(&secret_anthropic(), &escaped);
    assert!(run_raw("claude", "before_tool", &deep_escaped).contains("\"deny\""));
    // And a clean deep payload is still allowed.
    let clean = payload.replace(&secret_anthropic(), "nothing here");
    assert_eq!(run_raw("claude", "before_tool", &clean), "");
}

/// Past the parser limits the payload is not built, but its strings are still
/// read: size is never a way through.
#[test]
fn a_secret_in_a_payload_past_the_parser_limits_is_still_denied() {
    let depth = 150_000;
    let input = format!(
        "{}{{\"x\": \"{}\"}}{}",
        "{\"a\": ".repeat(depth),
        secret_anthropic(),
        "}".repeat(depth)
    );
    let payload = format!(
        "{{\"hook_event_name\": \"PreToolUse\", \"tool_name\": \"mcp__srv__do\", \"tool_input\": {input}}}"
    );
    let out = run_raw("claude", "before_tool", &payload);
    assert!(out.contains("\"deny\""), "{out}");
}
