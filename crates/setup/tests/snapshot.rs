//! Pins what `vahta setup` writes for each harness.
//!
//! `crates/harness/harnesses/<h>/setup.snapshot.json` holds `setup_version` and
//! the fragment (the config an install into an empty file produces, with the
//! hook path as `{hook}`). Installed copies of an older fragment are told apart
//! from current ones by `setup_version`, so changing the fragment without
//! bumping it would leave users with a stale setup and no notice. Hence:
//!
//! * fragment unchanged, version unchanged: pass;
//! * fragment changed, version unchanged: fail, bump `setup_version` in
//!   harness.toml;
//! * fragment or version differs from the snapshot otherwise: fail, regenerate
//!   the snapshot (also needed after a bump with no fragment change, so the
//!   snapshot never keeps an old number).
//!
//! Regenerate with `VAHTA_UPDATE_SNAPSHOTS=1 cargo test -p vahta-setup`; review
//! the diff before committing it.

use std::path::PathBuf;

use serde_json::{json, Value};
use vahta_harness::HARNESSES;

fn snapshot_path(h: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../harness/harnesses")
        .join(h)
        .join("setup.snapshot.json")
}

fn current(h: &str) -> Value {
    let m = vahta_harness::manifest(h).expect("known harness").expect("manifest parses");
    json!({ "setup_version": m.setup_version, "fragment": vahta_setup::fragment(&m) })
}

#[test]
fn the_fragment_matches_its_snapshot() {
    let update = std::env::var_os("VAHTA_UPDATE_SNAPSHOTS").is_some();
    let mut failures = Vec::new();
    for h in HARNESSES {
        let now = current(h);
        let path = snapshot_path(h);
        if update {
            let mut text = serde_json::to_string_pretty(&now).unwrap();
            text.push('\n');
            std::fs::write(&path, text).unwrap();
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            failures.push(format!("{h}: no snapshot at {}; regenerate it with VAHTA_UPDATE_SNAPSHOTS=1", path.display()));
            continue;
        };
        let snap: Value = serde_json::from_str(&text).expect("snapshot is JSON");
        if snap == now {
            continue;
        }
        let same_version = snap["setup_version"] == now["setup_version"];
        let same_fragment = snap["fragment"] == now["fragment"];
        failures.push(if !same_fragment && same_version {
            format!("{h}: what setup writes changed but setup_version is still {}; bump setup_version in crates/harness/harnesses/{h}/harness.toml, then regenerate the snapshot", now["setup_version"])
        } else {
            format!("{h}: setup_version or the fragment differs from the snapshot; regenerate it with VAHTA_UPDATE_SNAPSHOTS=1 cargo test -p vahta-setup and commit the result")
        });
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
