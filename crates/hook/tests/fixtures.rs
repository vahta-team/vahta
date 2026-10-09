//! Runs the built `vahta-hook` against every fixture under
//! `crates/harness/harnesses/<harness>/fixtures/`.
//!
//! A fixture is `{event, [args], [env], [files], stdin | stdin_raw, stdout, exit,
//! [spool]}`. `spool`, when present, is the list of signals the hook must have
//! spooled for the daemon (no daemon runs here), in order.
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

// Gap fixtures (2026-10-08). Each value is assembled from pieces so no file
// in the repository holds a secret-shaped string. High entropy on purpose:
// the name- and flag-based rules weaken low-transition values.
fn secret_aws() -> String {
    [
        "wJ7r", "Xu9t", "nFEM", "I2Kd", "Mq7Q", "bPxR", "fiCY", "5Zk3", "Ha8L", "tW0s",
    ]
    .concat()
}

// A test marker in front of a random tail, and one in front of a vendor token:
// neither is spelled as words, so neither is a marked test value.
fn fake_random() -> String {
    [
        "fake-", "aB3x", "Q9mK", "2pL7", "vN4w", "Z8rT", "5yUc", "H6jD",
    ]
    .concat()
}

fn secret_github() -> String {
    [
        "gh", "p_", "R4kT", "9xWm", "2LpQ", "7vZn", "B3yH", "5cJd", "8FsA", "1eUo", "X6gK",
    ]
    .concat()
}

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                out.push(A[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn secret_pw() -> String {
    ["x7Kq", "2NvR", "9pLm", "Wd4z"].concat()
}

fn secret_slack_path() -> String {
    [
        "T0", "4KQ7ZXNM", "/B0", "6RJH2PVD", "/", "q8WmT3vZ", "kN5xLr2C", "jY9pHs4D",
    ]
    .concat()
}

fn pem(edge: &str) -> String {
    ["-----", edge, " OPENSSH ", "PRIVATE KEY", "-----"].concat()
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
    // Forward slashes: the fixtures join paths with `/`, and a Windows `\`
    // would be a JSON (and shell) escape. Windows accepts both separators.
    let tmp_path = tmp.0.to_string_lossy().replace('\\', "/");
    let text = text
        .replace("{{SECRET_ANTHROPIC}}", &secret_anthropic())
        .replace("{{SECRET_AWS}}", &secret_aws())
        .replace("{{SECRET_PW}}", &secret_pw())
        .replace("{{FAKE_RANDOM}}", &fake_random())
        .replace("{{SECRET_GITHUB}}", &secret_github())
        // The same values, hidden: base64 and hex of an assignment, a vendor
        // key cut in two for joining.
        .replace(
            "{{B64_AWS}}",
            &b64(format!("AWS_SECRET_ACCESS_KEY={}", secret_aws()).as_bytes()),
        )
        .replace("{{B64_ANTHROPIC}}", &b64(secret_anthropic().as_bytes()))
        .replace(
            "{{HEX_AWS}}",
            &hex(format!("AWS_SECRET_ACCESS_KEY={}", secret_aws()).as_bytes()),
        )
        .replace("{{PAD_1_3MB}}", &"x ".repeat(650_000))
        .replace(
            "{{SLACK_URL}}",
            &format!("https://hooks.slack.com/services/{}", secret_slack_path()),
        )
        .replace(
            "{{HEX32}}",
            &[
                "3f9a", "c07e", "5b21", "d84a", "96e0", "71bc", "2a58", "f4d3",
            ]
            .concat(),
        )
        .replace("{{ANTHROPIC_HEAD}}", &secret_anthropic()[..9])
        .replace("{{ANTHROPIC_TAIL}}", &secret_anthropic()[9..])
        .replace("{{SECRET_SLACK_PATH}}", &secret_slack_path())
        .replace("{{PEM_BEGIN}}", &pem("BEGIN"))
        .replace("{{PEM_END}}", &pem("END"))
        .replace(
            "{{PEM_BODY}}",
            &["b3BlbnNzaC1rZXkt", "djEAAAAABG5vbmUA", "AAAEbm9uZQAAAAAA"].concat(),
        )
        .replace("{{TMP}}", &tmp_path);
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
    // The hook looks for a running daemon after a tool's output; it must find
    // none of the real ones, so every directory it could look in is ours.
    .env("VAHTA_RUNTIME_DIR", tmp.0.join("run"))
    .env("VAHTA_DATA_DIR", tmp.0.join("data"))
    .env("VAHTA_CONFIG_DIR", tmp.0.join("config"))
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
    if got != want_stdout && std::env::var_os("UPDATE_FIXTURES").is_some() {
        return update_fixture(path, &got, &tmp, &tmp_path);
    }
    if got != want_stdout {
        return Err(format!("stdout\n  want {want_stdout:?}\n  got  {got:?}"));
    }
    let want_exit = fx["exit"].as_i64().unwrap_or(0) as i32;
    if out.status.code() != Some(want_exit) {
        return Err(format!("exit {:?}, want {want_exit}", out.status.code()));
    }
    if let Some(want) = fx.get("spool") {
        let spooled =
            std::fs::read_to_string(tmp.0.join("data/hook-spool.jsonl")).unwrap_or_default();
        let got: Vec<Value> = spooled
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).map(|v| v["signal"].clone()))
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if &Value::Array(got.clone()) != want && std::env::var_os("UPDATE_FIXTURES").is_some() {
            return update_fixture(path, &String::from_utf8_lossy(&out.stdout), &tmp, &tmp_path);
        }
        if &Value::Array(got.clone()) != want {
            return Err(format!("spool\n  want {want}\n  got  {got:?}"));
        }
    }
    Ok(())
}

/// `UPDATE_FIXTURES=1 cargo test -p vahta-hook --test fixtures` rewrites each
/// fixture's `stdout` (and `spool`, where it has one) with what the hook did.
/// Read the diff: a fixture is a claim about the hook, not a snapshot.
fn update_fixture(path: &PathBuf, got: &str, tmp: &Tmp, tmp_path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut fx: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let got = got.replace(tmp_path, "{{TMP}}");
    fx["stdout"] = if got.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(got.trim()).map_err(|e| e.to_string())?
    };
    if fx.get("spool").is_some() {
        let spooled =
            std::fs::read_to_string(tmp.0.join("data/hook-spool.jsonl")).unwrap_or_default();
        let signals: Vec<Value> = spooled
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .map(|v| v["signal"].clone())
            .collect();
        fx["spool"] = Value::Array(signals);
    }
    let pretty = serde_json::to_string_pretty(&fx).map_err(|e| e.to_string())?;
    // Keep the file's own ending.
    let end = if text.ends_with('\n') { "\n" } else { "" };
    std::fs::write(path, pretty + end).map_err(|e| e.to_string())
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
    assert!(count >= 266, "only {count} fixtures found");
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
