//! Turns `policy/factors.toml` into Rust statics, so the daemon parses nothing
//! at run time. A file that does not parse, or names an action or a factor
//! this crate does not know, fails the build.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

const ACTIONS: &[&str] = &[
    "unlock",
    "run_each_use",
    "run_ask",
    "http",
    "bind",
    "add",
    "reset",
    "remove",
    "reveal",
    "copy",
    "import",
    "set_tier",
    "hooks_pause",
    "output_allow",
    "alarm_lock",
    "extend",
    "guard_choice",
    "devices",
    "recover",
    "other",
];
const NEEDS: &[&str] = &[
    "presence",
    "knowledge",
    "possession_biometric",
    "password_only",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    default: String,
    actions: BTreeMap<String, String>,
    #[serde(default)]
    category: BTreeMap<String, BTreeMap<String, String>>,
}

fn check(action: &str, need: &str) {
    assert!(
        ACTIONS.contains(&action),
        "factors.toml: unknown action {action}"
    );
    assert!(NEEDS.contains(&need), "factors.toml: unknown factor {need}");
}

fn main() {
    println!("cargo:rerun-if-changed=policy/factors.toml");
    println!("cargo:rerun-if-changed=build.rs");
    let text = std::fs::read_to_string("policy/factors.toml").expect("read factors.toml");
    let raw: Raw = toml::from_str(&text).expect("factors.toml does not parse");
    assert!(
        NEEDS.contains(&raw.default.as_str()),
        "factors.toml: bad default"
    );
    for action in ACTIONS {
        assert!(
            raw.actions.contains_key(*action),
            "factors.toml: no row for {action}"
        );
    }
    let mut out = String::new();
    writeln!(out, "pub static DEFAULT: &str = {:?};", raw.default).unwrap();
    writeln!(out, "pub static ACTIONS: &[(&str, &str)] = &[").unwrap();
    for (a, n) in &raw.actions {
        check(a, n);
        writeln!(out, "    ({a:?}, {n:?}),").unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out, "pub static CATEGORIES: &[(&str, &str, &str)] = &[").unwrap();
    for (c, rows) in &raw.category {
        for (a, n) in rows {
            check(a, n);
            writeln!(out, "    ({c:?}, {a:?}, {n:?}),").unwrap();
        }
    }
    writeln!(out, "];").unwrap();
    let dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(Path::new(&dir).join("factors_gen.rs"), out).expect("write");
}
