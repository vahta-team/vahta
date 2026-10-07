//! Generates the golden vault of the current format, once, at release.
//!
//! ```text
//! cargo run -p vahta-vault --example gen_fixture --features test-kdf -- v1
//! ```
//!
//! writes `tests/fixtures/format/v1.vht` and `v1.expected.json`. A fixture is
//! committed and never regenerated after its format ships: the point of the
//! file is that a later build must still read what an earlier one wrote. It
//! is written with the cheap test KDF, so the test suite can unlock it without
//! a gibibyte per run; the real cost is exercised by a separate test.
//!
//! Test material only: the phrase and the values are made up.

use std::path::PathBuf;

use vahta_vault::rules::parse_rule;
use vahta_vault::store::LocalStore;
use vahta_vault::{Binding, Class, KdfParams, Kind, Tier, Vault};

const PHRASE: &str = "correct horse";

fn main() {
    let Some(name) = std::env::args().nth(1) else {
        eprintln!("usage: gen_fixture <name>   (e.g. v1)");
        std::process::exit(2);
    };
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format");
    let work = tempdir();
    let store = LocalStore::new(work.join("store"));
    // Saved in a temp dir (the lock file lives beside the vault), then copied.
    let saved = work.join("vault.vht");
    let path = dir.join(format!("{name}.vht"));

    let (mut vault, _recovery) = Vault::create(PHRASE.as_bytes(), KdfParams::TEST).expect("create");
    let items: [(&str, &[u8], Kind, Tier); 3] = [
        ("ALPHA", b"fake-one", Kind::Env, Tier::Session),
        (
            "BETA",
            b"fake two lines\nx",
            Kind::File {
                file_name: "beta.txt".into(),
            },
            Tier::EachUse,
        ),
        ("GAMMA", b"", Kind::Env, Tier::Session),
    ];
    for (n, v, k, t) in &items {
        vault.set(n, v, k.clone(), *t).expect("set");
    }
    // Format 1 also carries a class and approved command rules. BETA is bound
    // to an absolute path that need not exist: the vault only stores it.
    vault
        .set_class("ALPHA", Some(Class::Payment))
        .expect("class");
    let allow = parse_rule("beta-tool push", true)
        .expect("rule")
        .to_allow("/opt/fixture/beta-tool".to_string());
    let deny = parse_rule("@network", false).expect("rule").to_deny();
    vault
        .set_bindings(
            "BETA",
            Some(Binding {
                name: "BETA".into(),
                allow: vec![allow],
                deny: vec![deny],
            }),
        )
        .expect("bindings");
    vault.save(&saved, &store).expect("save");
    std::fs::copy(&saved, &path).expect("copy the vault into the fixtures");

    let mut json = String::from("{\n  \"phrase\": \"correct horse\",\n  \"secrets\": [\n");
    for (i, (n, v, k, t)) in items.iter().enumerate() {
        let kind = match k {
            Kind::Env => "env".to_string(),
            Kind::File { file_name } => format!("file:{file_name}"),
        };
        let tier = match t {
            Tier::Session => "session",
            Tier::EachUse => "each_use",
        };
        let value = String::from_utf8_lossy(v).replace('\n', "\\n");
        let comma = if i + 1 < items.len() { "," } else { "" };
        json.push_str(&format!(
            "    {{\"name\": \"{n}\", \"value\": \"{value}\", \"kind\": \"{kind}\", \"tier\": \"{tier}\"}}{comma}\n"
        ));
    }
    json.push_str("  ],\n  \"classes\": {\"ALPHA\": \"payment\"},\n");
    json.push_str("  \"bindings\": {\"BETA\": {\"allow\": [\"beta-tool push\"], \"deny\": [\"@network\"]}}\n}\n");
    std::fs::write(dir.join(format!("{name}.expected.json")), json).expect("write expected");
    eprintln!("wrote {}", path.display());
}

fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("vahta-gen-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&p).expect("temp dir");
    p
}
