//! The version discipline: every released format has a golden fixture
//! (`tests/fixtures/format/vN.vht` and `vN.expected.json`), and this build must
//! read all of them, carry them to the current format and say so honestly. A
//! fixture is made once, at release, by `examples/gen_fixture.rs`, and never
//! regenerated.

use std::path::PathBuf;

use vahta_json::Value;
use vahta_vault::store::LocalStore;
use vahta_vault::{Error, Kind, Network, SLOT_PASSWORD, SLOT_RECOVERY, Tier, Vault, format};

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

        // The class and the approved rules ride in the signed body.
        let alpha = v.entries().iter().find(|e| e.name == "ALPHA").unwrap();
        assert_eq!(alpha.class, Some(vahta_vault::Class::Payment), "{name}");
        assert_eq!(v.bindings().len(), 1, "{name}");
        let b = &v.bindings()[0];
        assert_eq!(b.name, "BETA", "{name}");
        assert_eq!(b.allow[0].text, "beta-tool push", "{name}");
        assert_eq!(
            b.allow[0].program,
            vahta_vault::Program::Path("/opt/fixture/beta-tool".into()),
            "{name}"
        );
        assert_eq!(b.allow[0].args, vec!["push"], "{name}");
        assert_eq!(
            b.deny[0].program,
            vahta_vault::Program::Group("@network".into()),
            "{name}"
        );
        assert_eq!(peek.bindings, v.bindings(), "{name}");

        // Save: the file is now current, the generation went up by one, and
        // an older fixture's original sits beside it, byte for byte.
        let generation = peek.generation;
        v.save(&path, &store).unwrap();
        let after = Vault::peek(&path).unwrap();
        assert_eq!(after.format, format::CURRENT, "{name}");
        assert_eq!(after.generation, generation + 1, "{name}");
        let backup = path.with_file_name(format!("vault.vht.v{n}.bak"));
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

/// What a format 1 binding becomes, and the old file kept beside the new one.
#[test]
fn a_v1_fixture_becomes_rule_sets_and_keeps_its_slots() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    let original = std::fs::read(dir().join("v1.vht")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let store = LocalStore::new(work.path().join("store"));

    let mut v = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert!(v.upgrade_pending());
    let b = &v.bindings()[0];
    assert_eq!(b.network, Network::App);
    assert!(b.dirs.is_empty() && b.category.is_none() && b.downgraded_from.is_none());
    assert!(v.devices().is_empty());
    let slots = v.slots();
    assert_eq!(
        slots.iter().map(|s| s.kind).collect::<Vec<_>>(),
        [SLOT_PASSWORD, SLOT_RECOVERY]
    );
    // Opening wrote nothing, not even the copy.
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(!path.with_file_name("vault.vht.v1.bak").exists());

    v.save(&path, &store).unwrap();
    let bak = path.with_file_name("vault.vht.v1.bak");
    assert_eq!(std::fs::read(&bak).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // The slots came through with the same ids, and the password still opens.
    let again = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert_eq!(again.slots(), slots);
    assert_eq!(again.bindings()[0].network, Network::App);
}

/// A machine that has seen the upgraded file refuses the old one put back.
#[test]
fn rollback_to_the_pre_upgrade_file_is_detected() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    let original = std::fs::read(dir().join("v1.vht")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let store = LocalStore::new(work.path().join("store"));

    let mut v = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    v.save(&path, &store).unwrap();
    std::fs::write(&path, &original).unwrap();
    assert!(matches!(
        Vault::unlock_password(&path, b"correct horse", &store),
        Err(Error::RolledBack { found: 1, seen: 2 })
    ));
}

/// The v2 fixture carries a device, a rule set with directories and hosts,
/// and a slot of a kind no build defines; opening it here upgrades it to
/// format 3 on the first save, with `.v2.bak` beside it.
#[test]
fn the_v2_fixture_carries_what_format_2_adds() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    let original = std::fs::read(dir().join("v2.vht")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let store = LocalStore::new(work.path().join("store"));

    let mut v = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert!(v.upgrade_pending());
    let b = &v.bindings()[0];
    assert_eq!(b.category.as_deref(), Some("package-manager"));
    assert_eq!(b.dirs[0].path, "/opt/fixture/work");
    assert!(matches!(&b.network, Network::Hosts(h) if h[0].port == Some(443)));
    assert_eq!(v.devices()[0].name, "fixture phone");
    let unknown: Vec<_> = v.slots().into_iter().filter(|s| s.kind == 0x7001).collect();
    assert_eq!(unknown.len(), 1);

    // Saving again keeps the unknown slot and the password still unlocks.
    let slots_before = v.slots();
    v.save(&path, &store).unwrap();
    assert_eq!(Vault::peek(&path).unwrap().format, 4);
    assert!(Vault::peek(&path).unwrap().successors.is_empty());
    assert_eq!(
        std::fs::read(path.with_file_name("vault.vht.v2.bak")).unwrap(),
        original
    );
    // The slots, ids and enrollment times included, came through unchanged.
    assert_eq!(slots_before, v.slots());
    let again = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert_eq!(again.slots(), v.slots());
}

/// The same rollback protection across the v2 to v3 upgrade.
#[test]
fn rollback_to_the_pre_upgrade_v2_file_is_detected() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    let original = std::fs::read(dir().join("v2.vht")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let store = LocalStore::new(work.path().join("store"));

    let mut v = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    v.save(&path, &store).unwrap();
    std::fs::write(&path, &original).unwrap();
    assert!(matches!(
        Vault::unlock_password(&path, b"correct horse", &store),
        Err(Error::RolledBack { found: 1, seen: 2 })
    ));
}

/// The v3 fixture upgrades to format 4 on the first save: secrets, rules and
/// the slot of an unknown kind come through intact, remote use is off and
/// `from` is empty, and `.v3.bak` holds the original.
#[test]
fn the_v3_fixture_upgrades_to_v4_with_remote_off() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    let original = std::fs::read(dir().join("v3.vht")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let store = LocalStore::new(work.path().join("store"));

    let peek = Vault::peek(&path).unwrap();
    assert_eq!(peek.format, 3);
    assert!(!peek.remote);
    let mut v = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert!(v.upgrade_pending());
    assert!(!v.remote());
    let before = v.bindings()[0].clone();
    assert!(before.from.is_empty());
    let slots_before = v.slots();

    v.save(&path, &store).unwrap();
    let after = Vault::peek(&path).unwrap();
    assert_eq!(after.format, 4);
    assert!(!after.remote);
    assert_eq!(after.bindings[0], before);
    assert_eq!(
        std::fs::read(path.with_file_name("vault.vht.v3.bak")).unwrap(),
        original
    );
    let again = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert_eq!(again.slots(), slots_before);
    assert_eq!(again.get("BETA").unwrap().expose(), b"fake two lines\nx");
    assert!(again.slots().iter().any(|s| s.kind == 0x7001));
}

/// Putting the pre-upgrade v3 file back is a rollback, not a downgrade the
/// vault silently accepts.
#[test]
fn rollback_to_the_pre_upgrade_v3_file_is_detected() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    let original = std::fs::read(dir().join("v3.vht")).unwrap();
    std::fs::write(&path, &original).unwrap();
    let store = LocalStore::new(work.path().join("store"));

    let mut v = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    v.save(&path, &store).unwrap();
    std::fs::write(&path, &original).unwrap();
    assert!(matches!(
        Vault::unlock_password(&path, b"correct horse", &store),
        Err(Error::RolledBack { found: 1, seen: 2 })
    ));
}

/// The v4 fixture carries the flag and a `from` list; both survive a save, and
/// turning the flag off is a signed edit.
#[test]
fn the_v4_fixture_carries_remote_and_from() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    std::fs::write(&path, std::fs::read(dir().join("v4.vht")).unwrap()).unwrap();
    let store = LocalStore::new(work.path().join("store"));

    assert!(Vault::peek(&path).unwrap().remote);
    let mut v = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert!(!v.upgrade_pending());
    assert!(v.remote());
    assert_eq!(v.bindings()[0].from, vec!["/opt/fixture/project"]);
    v.set_remote(false).unwrap();
    v.save(&path, &store).unwrap();
    assert!(!Vault::peek(&path).unwrap().remote);
    let again = Vault::unlock_password(&path, b"correct horse", &store).unwrap();
    assert!(!again.remote());
    assert_eq!(again.bindings()[0].from, vec!["/opt/fixture/project"]);
}

/// A format 4 file has no room for a field this build does not know: extra
/// bytes in the body are refused, never silently dropped.
#[test]
fn a_v4_body_with_an_unknown_trailing_field_is_refused() {
    let mut bytes = std::fs::read(dir().join("v4.vht")).unwrap();
    // Grow body_len by one and add a byte after the body: the signature no
    // longer covers what the body says, and the body no longer parses exactly.
    let len = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize + 1;
    bytes[10..14].copy_from_slice(&(len as u32).to_le_bytes());
    bytes.insert(14 + len - 1, 0);
    assert!(format::decode(&bytes).is_err());
}

/// A relative or oversized `from` is refused when a rule set is stored.
#[test]
fn from_must_be_absolute_and_bounded() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("vault.vht");
    let store = LocalStore::new(work.path().join("store"));
    let (mut v, _) = Vault::create(b"correct horse", vahta_vault::KdfParams::TEST).unwrap();
    v.set("ALPHA", b"x", Kind::Env, Tier::Session).unwrap();
    let rules = |from: Vec<String>| vahta_vault::RuleSet {
        name: "ALPHA".into(),
        allow: vec![
            vahta_vault::rules::parse_rule("tool run", true)
                .unwrap()
                .to_allow("/opt/tool".into()),
        ],
        from,
        ..Default::default()
    };
    assert!(
        v.set_bindings("ALPHA", Some(rules(vec!["rel/dir".into()])))
            .is_err()
    );
    assert!(
        v.set_bindings("ALPHA", Some(rules(vec!["/p".to_string(); 17])))
            .is_err()
    );
    v.set_bindings("ALPHA", Some(rules(vec!["/work/app".into()])))
        .unwrap();
    v.save(&path, &store).unwrap();
    assert_eq!(
        Vault::peek(&path).unwrap().bindings[0].from,
        vec!["/work/app"]
    );
}
