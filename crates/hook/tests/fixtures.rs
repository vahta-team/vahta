//! Runs the built `vahta-hook` against every fixture under
//! `crates/harness/harnesses/<harness>/fixtures/`.
//!
//! A fixture is `{event, env, stdin | stdin_raw, stdout, exit}`. Secret-shaped
//! values are never written in the files: `{{SECRET_ANTHROPIC}}` is replaced
//! here, from pieces.

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

fn run_fixture(harness: &str, path: &PathBuf) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let text = text.replace("{{SECRET_ANTHROPIC}}", &secret_anthropic());
    let fx: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let stdin = match fx.get("stdin_raw") {
        Some(Value::String(raw)) => raw.clone(),
        _ => fx["stdin"].to_string(),
    };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vahta-hook"));
    cmd.args(["--harness", harness, "--event", fx["event"].as_str().unwrap_or("")])
        .env_remove("VAHTA_HOOK_DISABLE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(env) = fx["env"].as_object() {
        for (k, v) in env {
            cmd.env(k, v.as_str().unwrap_or(""));
        }
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    child.stdin.take().ok_or("no stdin")?.write_all(stdin.as_bytes()).map_err(|e| e.to_string())?;
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
                failures.push(format!("{harness}/{}: {e}", f.file_name().unwrap().to_string_lossy()));
            }
        }
    }
    assert!(count >= 36, "only {count} fixtures found");
    assert!(failures.is_empty(), "{} of {count} failed:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn manifests_parse() {
    for h in vahta_harness::HARNESSES {
        let m = vahta_harness::manifest(h).expect("known").expect("parses");
        assert_eq!(m.name, h);
    }
}
