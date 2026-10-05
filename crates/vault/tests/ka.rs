//! Import of the ka fixtures (`tests/fixtures/ka/`, made by the script beside
//! them with ka's own code). ka writes its SENSITIVE KDF settings, one
//! gibibyte each, so these tests take turns instead of holding several
//! gibibytes at once.

use std::path::PathBuf;
use std::sync::Mutex;

use vahta_vault::ka::import_ka;
use vahta_vault::{Error, KdfParams, SecretValue, Vault};

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

const PHRASE: &[u8] = b"correct horse";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ka")
        .join(name)
}

fn expected() -> Vec<(String, Vec<u8>)> {
    vec![
        ("ALPHA".into(), b"fake-one".to_vec()),
        ("BETA".into(), b"fake two lines\nx".to_vec()),
        ("GAMMA".into(), b"fake-three".to_vec()),
    ]
}

fn sorted(items: Vec<(String, SecretValue)>) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<_> = items
        .into_iter()
        .map(|(n, s)| (n, s.expose().to_vec()))
        .collect();
    v.sort();
    v
}

#[test]
fn kam1_gives_exactly_the_expected_names_and_values() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let got = import_ka(&fixture("kam1.bin"), PHRASE).unwrap();
    assert_eq!(sorted(got), expected());
}

#[test]
fn kam2_opens_with_the_admin_key_the_password_holds() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let got = import_ka(&fixture("kam2.bin"), PHRASE).unwrap();
    assert_eq!(sorted(got), expected());
}

#[test]
fn a_wrong_password_fails_without_detail() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let err = import_ka(&fixture("kam1.bin"), b"incorrect horse").unwrap_err();
    assert!(matches!(err, Error::Unlock));
}

#[test]
fn a_hostile_header_is_refused_before_any_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = std::fs::read(fixture("kam1.bin")).unwrap();
    // memlimit of 2^60 bytes.
    bytes[29..37].copy_from_slice(&(1u64 << 60).to_le_bytes());
    let p = dir.path().join("hostile.bin");
    std::fs::write(&p, &bytes).unwrap();
    assert!(matches!(import_ka(&p, PHRASE), Err(Error::Ka(_))));

    std::fs::write(&p, b"KAM1\x01short").unwrap();
    assert!(matches!(import_ka(&p, PHRASE), Err(Error::Ka(_))));
    std::fs::write(&p, vec![0u8; 100]).unwrap();
    assert!(matches!(import_ka(&p, PHRASE), Err(Error::Ka(_))));
}

#[test]
fn import_lands_in_a_vault_and_collisions_are_refused() {
    let _g = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let items = import_ka(&fixture("kam1.bin"), PHRASE).unwrap();
    let (mut vault, _recovery) = Vault::create(b"new phrase", KdfParams::TEST).unwrap();
    vault.import(items.clone()).unwrap();
    assert_eq!(vault.get("BETA").unwrap().expose(), b"fake two lines\nx");
    // The same names again collide, and nothing is half-added.
    let before = vault.entries().len();
    let err = vault.import(items).unwrap_err();
    assert!(matches!(err, Error::ImportCollision(_)));
    assert_eq!(vault.entries().len(), before);
    // A name that is not env-like is refused as a whole batch too.
    let bad = vec![
        ("FINE".to_string(), SecretValue::new(b"x".to_vec())),
        ("not a name".to_string(), SecretValue::new(b"y".to_vec())),
    ];
    assert!(matches!(vault.import(bad), Err(Error::InvalidName)));
    assert!(vault.get("FINE").is_err());
}
