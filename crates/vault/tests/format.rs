//! The version discipline: every released format has a golden fixture
//! (`tests/fixtures/format/vN.vht` and `vN.expected.json`), and this build must
//! read all of them, carry them to the current format and say so honestly. A
//! fixture is made once, at release, by `examples/gen_fixture.rs`, and never
//! regenerated.

use std::path::PathBuf;

use vahta_json::Value;
use vahta_vault::store::LocalStore;
use vahta_vault::{Error, Kind, Tier, Vault, format};

struct Expected {
    phrase: String,
    secrets: Vec<(String, String, String, String)>,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format")
}

fn field<'a>(v: &'a Value, key: &str) -> &'a str {
    let Value::Object(entries) = v else {
        panic!("expected an object")
    };
    match entries.iter().find(|(k, _)| k == key) {
        Some((_, Value::Str(s))) => s,
        _ => panic!("missing string field {key}"),
    }
}

fn expected(name: &str) -> Expected {
    let text = std::fs::read_to_string(dir().join(format!("{name}.expected.json"))).unwrap();
    let doc = vahta_json::parse(&text).unwrap();
    let Value::Object(entries) = &doc else {
        panic!("expected an object")
    };
    let Some((_, Value::Array(secrets))) = entries.iter().find(|(k, _)| k == "secrets") else {
        panic!("no secrets")
    };
    Expected {
        phrase: field(&doc, "phrase").to_string(),
        secrets: secrets
            .iter()
            .map(|s| {
                (
                    field(s, "name").to_string(),
                    field(s, "value").to_string(),
                    field(s, "kind").to_string(),
                    field(s, "tier").to_string(),
                )
            })
            .collect(),
    }
}

/// Every `vN.vht` in the fixtures directory, as `(N, name)`.
fn fixtures() -> Vec<(u16, String)> {
    let mut found: Vec<(u16, String)> = std::fs::read_dir(dir())
        .unwrap()
        .filter_map(|e| {
            let name = e.ok()?.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".vht")?;
            let n = stem.strip_prefix('v')?.parse().ok()?;
            Some((n, stem.to_string()))
        })
        .collect();
    found.sort();
    found
}

fn kind_text(k: &Kind) -> String {
    match k {
        Kind::Env => "env".into(),
        Kind::File { file_name } => format!("file:{file_name}"),
    }
}

fn tier_text(t: Tier) -> &'static str {
    match t {
        Tier::Session => "session",
        Tier::EachUse => "each_use",
    }
}

#[test]
fn there_is_a_fixture_for_every_released_format() {
    let have: Vec<u16> = fixtures().into_iter().map(|(n, _)| n).collect();
    let want: Vec<u16> = (1..=format::CURRENT).collect();
    assert_eq!(have, want, "one golden vault per released format");
}

#[test]
fn every_released_format_upgrades_to_current() {
    for (n, name) in fixtures() {
        let want = expected(&name);
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("vault.vht");
        let original = std::fs::read(dir().join(format!("{name}.vht"))).unwrap();
        std::fs::write(&path, &original).unwrap();
        let store = LocalStore::new(work.path().join("store"));

        // Peek reports the format and never upgrades.
        let peek = Vault::peek(&path).unwrap();
        assert_eq!(peek.format, n, "{name}");
        assert_eq!(peek.upgrade_pending, n < format::CURRENT, "{name}");
        assert_eq!(std::fs::read(&path).unwrap(), original, "{name}");

        // Unlock: names, values, tiers and kinds are the expected ones.
        let mut v = Vault::unlock_password(&path, want.phrase.as_bytes(), &store).unwrap();
        assert_eq!(v.entries().len(), want.secrets.len(), "{name}");
        for (secret, value, kind, tier) in &want.secrets {
            let e = v.entries().iter().find(|e| &e.name == secret).unwrap();
            assert_eq!(&kind_text(&e.kind), kind, "{name} {secret}");
            assert_eq!(tier_text(e.tier), tier, "{name} {secret}");
            assert_eq!(
                v.get(secret).unwrap().expose(),
                value.as_bytes(),
                "{name} {secret}"
            );
        }

        // Save: the file is now current, the generation went up by one, and
        // an older fixture's original sits beside it, byte for byte.
        let generation = peek.generation;
        v.save(&path, &store).unwrap();
        let after = Vault::peek(&path).unwrap();
        assert_eq!(after.format, format::CURRENT, "{name}");
        assert_eq!(after.generation, generation + 1, "{name}");
        let backup = path.with_file_name(format!("vault.vht.v{n}-backup"));
        if n < format::CURRENT {
            assert_eq!(std::fs::read(&backup).unwrap(), original, "{name}");
        } else {
            assert!(!backup.exists(), "{name}: no backup for the current format");
        }

        // A second save does not touch it.
        v.save(&path, &store).unwrap();
        if n < format::CURRENT {
            assert_eq!(std::fs::read(&backup).unwrap(), original, "{name}");
        }
        let again = Vault::unlock_password(&path, want.phrase.as_bytes(), &store).unwrap();
        for (secret, value, ..) in &want.secrets {
            assert_eq!(again.get(secret).unwrap().expose(), value.as_bytes());
        }
    }
}

#[test]
fn newer_format_is_refused() {
    for (_, name) in fixtures() {
        let want = expected(&name);
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("vault.vht");
        let mut bytes = std::fs::read(dir().join(format!("{name}.vht"))).unwrap();
        bytes[8..10].copy_from_slice(&(format::CURRENT + 1).to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let store = LocalStore::new(work.path().join("store"));

        let err = Vault::peek(&path).unwrap_err();
        assert!(matches!(err, Error::NewerFormat { found, supported }
            if found == format::CURRENT + 1 && supported == format::CURRENT));
        assert_eq!(
            err.to_string(),
            "this vault was written by a newer Vahta; update Vahta"
        );
        assert!(matches!(
            Vault::unlock_password(&path, want.phrase.as_bytes(), &store),
            Err(Error::NewerFormat { .. })
        ));
        // Even a file whose body is garbage reports the version first.
        let mut junk = b"VAHTAVLT".to_vec();
        junk.extend_from_slice(&(format::CURRENT + 1).to_le_bytes());
        junk.extend_from_slice(&[0xff; 40]);
        assert!(matches!(
            Vault::peek_bytes(&junk),
            Err(Error::NewerFormat { .. })
        ));
    }
}

#[test]
fn format_zero_does_not_exist_outside_tests_and_unknown_numbers_are_not_vaults() {
    // Zero is the pseudo-format of the unit tests; a release build of the
    // library does not know it, and the integration tests see a release build.
    let mut junk = b"VAHTAVLT".to_vec();
    junk.extend_from_slice(&0u16.to_le_bytes());
    junk.extend_from_slice(&[0; 40]);
    assert!(matches!(Vault::peek_bytes(&junk), Err(Error::NotAVault)));
}
