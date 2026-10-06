//! Black-box tests of the vault through its public API, in temp directories
//! only: the vault, the lock and the local store all live under a temp dir.
//! The KDF is the cheap test one (the `test-kdf` feature, switched on for this
//! crate's own tests through its dev-dependency on itself).

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use vahta_vault::store::LocalStore;
use vahta_vault::write::VaultLock;
use vahta_vault::{
    Error, KdfParams, Kind, RecipientKind, RecipientSecret, Role, Tier, Vault, Verification,
};

const PW: &[u8] = b"correct horse";

struct Env {
    _dir: TempDir,
    path: PathBuf,
    store: LocalStore,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".vahta").join("vault.vht");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let store = LocalStore::new(dir.path().join("store"));
    Env {
        _dir: dir,
        path,
        store,
    }
}

fn new_vault(e: &Env) -> (Vault, vahta_vault::RecoveryKey) {
    let (mut v, key) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.save(&e.path, &e.store).unwrap();
    (v, key)
}

fn reopen(e: &Env) -> Vault {
    Vault::unlock_password(&e.path, PW, &e.store).unwrap()
}

#[test]
fn round_trips_values_at_the_padding_edges() {
    let big = vec![b'z'; 64 * 1024];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("EMPTY", vec![]),
        ("ONE", b"x".to_vec()),
        ("SIXTY", vec![b'a'; 60]),
        ("SIXTY_FOUR", vec![b'b'; 64]),
        ("SIXTY_FIVE", vec![b'c'; 65]),
        ("LINES", b"fake two lines\nx\r\n".to_vec()),
        ("BIG", big),
        ("BINARY", vec![0, 1, 2, 255, 0, 0]),
    ];
    let e = env();
    let (mut v, _) = new_vault(&e);
    for (name, value) in &cases {
        v.set(name, value, Kind::Env, Tier::Session).unwrap();
    }
    v.save(&e.path, &e.store).unwrap();
    let v = reopen(&e);
    for (name, value) in &cases {
        assert_eq!(v.get(name).unwrap().expose(), &value[..], "{name}");
    }
    assert_eq!(v.entries().len(), cases.len());
}

#[test]
fn set_replaces_and_remove_removes_and_tier_changes() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.set("A", b"fake-two", Kind::Env, Tier::Session).unwrap();
    v.set(
        "F",
        b"file body",
        Kind::File {
            file_name: "cert.pem".into(),
        },
        Tier::Session,
    )
    .unwrap();
    v.set_tier("A", Tier::EachUse).unwrap();
    v.save(&e.path, &e.store).unwrap();
    let mut v = reopen(&e);
    assert_eq!(v.get("A").unwrap().expose(), b"fake-two");
    let a = v.entries().iter().find(|x| x.name == "A").unwrap();
    assert_eq!(a.tier, Tier::EachUse);
    v.remove("A").unwrap();
    assert!(matches!(v.get("A"), Err(Error::NotFound(_))));
    assert!(matches!(v.remove("A"), Err(Error::NotFound(_))));

    for bad in ["", "1A", "A-B", "a b", &"X".repeat(129)] {
        assert!(matches!(
            v.set(bad, b"x", Kind::Env, Tier::Session),
            Err(Error::InvalidName)
        ));
    }
    for bad in ["", "..", "a/b", "a\\b"] {
        assert!(matches!(
            v.set(
                "OK",
                b"x",
                Kind::File {
                    file_name: bad.into()
                },
                Tier::Session
            ),
            Err(Error::InvalidFileName)
        ));
    }
    assert!(matches!(
        v.set("BIG", &vec![0u8; (1 << 20) + 1], Kind::Env, Tier::Session),
        Err(Error::ValueTooLarge)
    ));
}

#[test]
fn a_wrong_password_fails_and_the_recovery_key_works() {
    let e = env();
    let (mut v, key) = new_vault(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap();

    let err = Vault::unlock_password(&e.path, b"incorrect horse", &e.store).unwrap_err();
    assert!(matches!(err, Error::Unlock));

    let by_key = Vault::unlock_recovery(&e.path, &key, &e.store).unwrap();
    assert_eq!(by_key.get("A").unwrap().expose(), b"fake-one");

    // The paper form round-trips, with or without the dashes.
    let paper = key.to_paper();
    let again = vahta_vault::RecoveryKey::from_paper(&paper.replace('-', " ")).unwrap();
    Vault::unlock_recovery(&e.path, &again, &e.store).unwrap();
    assert!(vahta_vault::RecoveryKey::from_paper("not a key").is_none());
}

#[test]
fn change_password_keeps_the_recovery_slot_working() {
    let e = env();
    let (_, key) = new_vault(&e);
    let mut v = reopen(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.change_password(b"new horse", KdfParams::TEST).unwrap();
    v.save(&e.path, &e.store).unwrap();

    assert!(matches!(
        Vault::unlock_password(&e.path, PW, &e.store),
        Err(Error::Unlock)
    ));
    let v = Vault::unlock_password(&e.path, b"new horse", &e.store).unwrap();
    assert_eq!(v.get("A").unwrap().expose(), b"fake-one");
    Vault::unlock_recovery(&e.path, &key, &e.store).unwrap();
}

#[test]
fn a_cost_below_the_floor_is_refused_on_create() {
    let weak = KdfParams {
        m_kib: 1,
        t: 1,
        p: 1,
    };
    assert!(matches!(Vault::create(PW, weak), Err(Error::KdfBelowFloor)));
}

fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut b = bytes.to_vec();
    b[at] ^= 0x01;
    b
}

fn populated(e: &Env) -> Vec<u8> {
    let (mut v, _) = new_vault(e);
    v.set("ALPHA", b"fake-one", Kind::Env, Tier::Session)
        .unwrap();
    v.set("BETA", b"fake-two", Kind::Env, Tier::EachUse)
        .unwrap();
    let r = RecipientSecret::generate().unwrap();
    let id = v
        .add_recipient(
            "ci",
            RecipientKind::Device,
            Role::Runner,
            &r.public().unwrap(),
        )
        .unwrap();
    v.grant("ALPHA", &id).unwrap();
    v.save(&e.path, &e.store).unwrap();
    std::fs::read(&e.path).unwrap()
}

#[test]
fn flipping_any_single_byte_anywhere_is_detected() {
    // Every section is covered by the signature, so no byte can change
    // unnoticed: header, slots, owner, recipients, index, ciphertext, wraps,
    // the signature section and the frame itself.
    let e = env();
    let good = populated(&e);
    assert!(Vault::peek_bytes(&good).is_ok());
    for at in 0..good.len() {
        assert!(
            Vault::peek_bytes(&flip(&good, at)).is_err(),
            "a flipped byte at offset {at} went unnoticed"
        );
    }
}

#[test]
fn truncation_and_a_wrong_body_length_are_detected() {
    let e = env();
    let good = populated(&e);
    for cut in 0..good.len() {
        assert!(Vault::peek_bytes(&good[..cut]).is_err(), "cut at {cut}");
    }
    // body_len one too long or one too short; and a file with junk appended.
    for delta in [-1i64, 1, 1000] {
        let mut b = good.clone();
        let len = u32::from_le_bytes(b[10..14].try_into().unwrap()) as i64 + delta;
        b[10..14].copy_from_slice(&(len as u32).to_le_bytes());
        assert!(Vault::peek_bytes(&b).is_err(), "delta {delta}");
    }
    let mut longer = good.clone();
    longer.push(0);
    assert!(Vault::peek_bytes(&longer).is_err());
}

#[test]
fn a_file_over_sixteen_mebibytes_is_refused_before_parsing() {
    let mut huge = b"VAHTAVLT".to_vec();
    huge.resize(16 * 1024 * 1024 + 1, 0);
    assert!(matches!(Vault::peek_bytes(&huge), Err(Error::TooLarge)));

    let e = env();
    std::fs::write(&e.path, &huge).unwrap();
    assert!(matches!(Vault::peek(&e.path), Err(Error::TooLarge)));
    assert!(matches!(
        Vault::unlock_password(&e.path, PW, &e.store),
        Err(Error::TooLarge)
    ));
}

#[test]
fn garbage_is_not_a_vault() {
    for junk in [
        &b""[..],
        b"x",
        b"VAHTAVLT",
        b"not a vault at all, just text",
    ] {
        assert!(Vault::peek_bytes(junk).is_err());
    }
    assert!(matches!(
        Vault::peek_bytes(b"not a vault at all, just text"),
        Err(Error::NotAVault)
    ));
    let e = env();
    assert!(matches!(
        Vault::peek(&e.path.with_file_name("missing.vht")),
        Err(Error::Io { .. })
    ));
}

#[test]
fn rollback_to_an_older_generation_is_refused() {
    let e = env();
    let (mut v, _) = new_vault(&e); // generation 1
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap(); // 2
    v.set("A", b"fake-two", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap(); // 3
    let gen3 = std::fs::read(&e.path).unwrap();
    for n in 4..=5 {
        v.set("A", b"fake-three", Kind::Env, Tier::Session).unwrap();
        v.save(&e.path, &e.store).unwrap();
        assert_eq!(v.generation(), n);
    }
    std::fs::write(&e.path, &gen3).unwrap();

    let err = Vault::unlock_password(&e.path, PW, &e.store).unwrap_err();
    assert!(matches!(err, Error::RolledBack { found: 3, seen: 5 }));
    // The generation is checked against an authenticated state, so only
    // after the unlock: a wrong password is just a wrong password.
    assert!(matches!(
        Vault::unlock_password(&e.path, b"incorrect horse", &e.store),
        Err(Error::Unlock)
    ));
    let peek = Vault::peek(&e.path).unwrap();
    assert!(matches!(
        peek.verified(&e.store),
        Err(Error::RolledBack { .. })
    ));
}

#[test]
fn peek_is_unpinned_until_this_machine_unlocks() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::EachUse).unwrap();
    v.save(&e.path, &e.store).unwrap();
    let peek = Vault::peek(&e.path).unwrap();
    assert_eq!(peek.entries.len(), 1);
    assert_eq!(peek.entries[0].name, "A");
    assert_eq!(peek.entries[0].tier, Tier::EachUse);
    assert_eq!(peek.generation, 2);
    assert!(!peek.upgrade_pending);

    // The creator saved, which pinned it; a different machine's store is empty.
    assert_eq!(
        peek.verified(&e.store).unwrap().status,
        Verification::Pinned
    );
    let other = LocalStore::new(e._dir.path().join("other-machine"));
    let v = peek.verified(&other).unwrap();
    assert_eq!(v.status, Verification::Unpinned);
    assert!(!v.mac_checked);
    Vault::unlock_password(&e.path, PW, &other).unwrap();
    assert_eq!(peek.verified(&other).unwrap().status, Verification::Pinned);
}

#[test]
fn a_recipient_sees_only_what_it_was_granted() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    v.set("GRANTED", b"fake-one", Kind::Env, Tier::Session)
        .unwrap();
    v.set("HIDDEN", b"fake-two", Kind::Env, Tier::Session)
        .unwrap();
    let keys = RecipientSecret::generate().unwrap();
    let id = v
        .add_recipient(
            "ci",
            RecipientKind::Device,
            Role::Runner,
            &keys.public().unwrap(),
        )
        .unwrap();
    v.grant("GRANTED", &id).unwrap();
    v.save(&e.path, &e.store).unwrap();

    let other = LocalStore::new(e._dir.path().join("ci-machine"));
    let mut r = Vault::open_as_recipient(&e.path, &id, &keys, &other).unwrap();
    assert_eq!(r.get("GRANTED").unwrap().expose(), b"fake-one");
    assert!(matches!(r.get("HIDDEN"), Err(Error::NoAccess)));
    assert!(matches!(r.get("NOPE"), Err(Error::NotFound(_))));
    // The names are in the signed index for anyone to see.
    assert_eq!(r.entries().len(), 2);
    // A runner cannot write.
    assert!(matches!(
        r.set("X", b"x", Kind::Env, Tier::Session),
        Err(Error::NotPermitted)
    ));
    assert!(matches!(r.save(&e.path, &other), Err(Error::NotPermitted)));
    assert!(matches!(
        r.change_password(b"x", KdfParams::TEST),
        Err(Error::NotOwner)
    ));

    // Someone else's keys do not open it.
    let stranger = RecipientSecret::generate().unwrap();
    let fresh = LocalStore::new(e._dir.path().join("stranger-machine"));
    assert!(matches!(
        Vault::open_as_recipient(&e.path, &id, &stranger, &fresh),
        Err(Error::Unlock)
    ));
}

#[test]
fn revoke_and_remove_recipient_cut_access_and_name_what_to_rotate() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.set("B", b"fake-two", Kind::Env, Tier::Session).unwrap();
    v.set("C", b"fake-three", Kind::Env, Tier::Session).unwrap();
    let k1 = RecipientSecret::generate().unwrap();
    let k2 = RecipientSecret::generate().unwrap();
    let r1 = v
        .add_recipient(
            "one",
            RecipientKind::Person,
            Role::Runner,
            &k1.public().unwrap(),
        )
        .unwrap();
    let r2 = v
        .add_recipient(
            "two",
            RecipientKind::Cloud,
            Role::Runner,
            &k2.public().unwrap(),
        )
        .unwrap();
    for name in ["A", "B"] {
        v.grant(name, &r1).unwrap();
    }
    v.grant("A", &r2).unwrap();
    v.save(&e.path, &e.store).unwrap();
    let ci = LocalStore::new(e._dir.path().join("ci"));
    let before = std::fs::read(&e.path).unwrap();

    v.revoke("A", &r1).unwrap();
    v.save(&e.path, &e.store).unwrap();
    let r = Vault::open_as_recipient(&e.path, &r1, &k1, &ci).unwrap();
    assert!(matches!(r.get("A"), Err(Error::NoAccess)));
    assert_eq!(r.get("B").unwrap().expose(), b"fake-two");
    // The other recipient still reads A, from the re-keyed ciphertext.
    let r = Vault::open_as_recipient(&e.path, &r2, &k2, &ci).unwrap();
    assert_eq!(r.get("A").unwrap().expose(), b"fake-one");
    assert_ne!(before, std::fs::read(&e.path).unwrap());

    // Removing a recipient re-keys everything it held and says what to rotate.
    let mut rotate = v.remove_recipient(&r1).unwrap();
    rotate.sort();
    assert_eq!(rotate, vec!["B".to_string()]);
    assert!(matches!(
        v.remove_recipient(&r1),
        Err(Error::UnknownRecipient)
    ));
    v.save(&e.path, &e.store).unwrap();
    assert!(matches!(
        Vault::open_as_recipient(&e.path, &r1, &k1, &ci),
        Err(Error::Unlock)
    ));
    assert_eq!(v.get("B").unwrap().expose(), b"fake-two");
}

fn file_len_with_value(len: usize) -> u64 {
    let e = env();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", &vec![b'v'; len], Kind::Env, Tier::Session)
        .unwrap();
    v.save(&e.path, &e.store).unwrap();
    std::fs::metadata(&e.path).unwrap().len()
}

#[test]
fn ciphertext_length_does_not_leak_the_value_length() {
    assert_eq!(file_len_with_value(10), file_len_with_value(50));
    assert_eq!(file_len_with_value(0), file_len_with_value(59));
    // The next power of two is a visible step: 60 fits in 64, 61 does not.
    assert_eq!(file_len_with_value(59), file_len_with_value(60));
    assert!(file_len_with_value(61) > file_len_with_value(60));
}

#[test]
fn concurrent_saves_under_the_lock_serialise() {
    let e = env();
    new_vault(&e);
    let path = e.path.clone();
    let store = e.store.clone();
    let mut handles = Vec::new();
    for n in 0..4 {
        let (path, store) = (path.clone(), store.clone());
        handles.push(std::thread::spawn(move || {
            let lock = VaultLock::acquire(&path).unwrap();
            let mut v = Vault::unlock_password(&path, PW, &store).unwrap();
            v.set(&format!("NAME_{n}"), b"fake-one", Kind::Env, Tier::Session)
                .unwrap();
            v.save_locked(&path, &store, &lock).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let v = reopen(&e);
    assert_eq!(v.entries().len(), 4);
    assert_eq!(v.generation(), 5);
}

#[test]
fn a_stale_save_is_a_conflict_not_a_lost_update() {
    let e = env();
    new_vault(&e);
    let mut a = reopen(&e);
    let mut b = reopen(&e);
    a.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    b.set("B", b"fake-two", Kind::Env, Tier::Session).unwrap();
    a.save(&e.path, &e.store).unwrap();
    assert!(matches!(b.save(&e.path, &e.store), Err(Error::Conflict)));
    let v = reopen(&e);
    assert!(v.get("A").is_ok() && v.get("B").is_err());
}

#[test]
fn a_crash_before_the_rename_leaves_the_old_vault_readable() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap();
    // What an interrupted write leaves: a half-written temp file.
    let dir: &Path = e.path.parent().unwrap();
    std::fs::write(
        dir.join(".vault.vht.tmp-0123456789abcdef"),
        b"VAHTAVLT half",
    )
    .unwrap();
    let v = reopen(&e);
    assert_eq!(v.get("A").unwrap().expose(), b"fake-one");
    let mut v = v;
    v.set("B", b"fake-two", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap();
    assert_eq!(reopen(&e).entries().len(), 2);
}

#[test]
fn no_value_appears_in_any_error_or_debug_output() {
    let e = env();
    let (mut v, key) = new_vault(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    let keys = RecipientSecret::generate().unwrap();
    let id = v
        .add_recipient(
            "ci",
            RecipientKind::Device,
            Role::Runner,
            &keys.public().unwrap(),
        )
        .unwrap();
    v.grant("A", &id).unwrap();
    v.save(&e.path, &e.store).unwrap();

    let value = v.get("A").unwrap();
    let r = Vault::open_as_recipient(&e.path, &id, &keys, &e.store).unwrap();
    let mut shown = vec![
        format!("{v:?}"),
        format!("{r:?}"),
        format!("{value:?}"),
        format!("{key:?}"),
        format!("{keys:?}"),
        format!("{:?}", Vault::peek(&e.path).unwrap()),
        format!("{:?}", v.entries()),
        format!("{:?}", v.recipients()),
    ];
    let errors: Vec<Error> = vec![
        Vault::unlock_password(&e.path, b"incorrect fake-one", &e.store).unwrap_err(),
        Vault::peek_bytes(b"fake-one").unwrap_err(),
        v.get("fake-one").unwrap_err(),
        v.set("fake-one", b"x", Kind::Env, Tier::Session)
            .ok()
            .map_or(Error::Rng, |_| Error::Rng),
        Error::NotFound("A".into()),
        Error::Unlock,
        Error::BadSignature,
        Error::OwnerChanged,
        Error::RolledBack { found: 1, seen: 2 },
        Error::NewerFormat {
            found: 9,
            supported: 1,
        },
        Error::Conflict,
        Error::NoAccess,
        Error::NotOwner,
        Error::Corrupt("x"),
    ];
    for err in &errors {
        shown.push(format!("{err}"));
        shown.push(format!("{err:?}"));
    }
    for s in &shown {
        assert!(!s.contains("fake-one"), "a value leaked: {s}");
    }
    // And the file itself holds no plaintext.
    let bytes = std::fs::read(&e.path).unwrap();
    assert!(!bytes.windows(8).any(|w| w == b"fake-one"));
}

/// One real-KDF round trip: 1 GiB, four passes. Ignored by default because it
/// needs a gibibyte and a few seconds; run it with `--ignored`, in release for
/// the timing that matters.
#[test]
#[ignore = "runs the production KDF: 1 GiB of memory"]
fn real_kdf_round_trip_and_timing() {
    let e = env();
    let (mut v, _) = Vault::create(PW, KdfParams::PRODUCTION).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap();
    let start = std::time::Instant::now();
    let v = Vault::unlock_password(&e.path, PW, &e.store).unwrap();
    eprintln!("real-KDF unlock took {:?}", start.elapsed());
    assert_eq!(v.get("A").unwrap().expose(), b"fake-one");
}

// --- Admins and editors write ------------------------------------------------

fn state_path(e: &Env, id: &[u8; 16], file: &str) -> PathBuf {
    e.store
        .root()
        .join("vaults")
        .join(vahta_vault::hex_encode(id))
        .join(file)
}

struct Member {
    id: [u8; 16],
    keys: RecipientSecret,
    store: LocalStore,
}

impl Member {
    fn open(&self, e: &Env) -> Vault {
        Vault::open_as_recipient(&e.path, &self.id, &self.keys, &self.store).unwrap()
    }
}

fn add(v: &mut Vault, e: &Env, name: &str, role: Role) -> Member {
    let keys = RecipientSecret::generate().unwrap();
    let id = v
        .add_recipient(name, RecipientKind::Person, role, &keys.public().unwrap())
        .unwrap();
    Member {
        id,
        keys,
        store: LocalStore::new(e._dir.path().join(format!("store-{name}"))),
    }
}

#[test]
fn an_editor_adds_a_secret_and_the_owner_reads_it() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let editor = add(&mut v, &e, "ed", Role::Editor);
    v.set("OWN", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap();

    let mut ed = editor.open(&e);
    ed.set("FROM_EDITOR", b"fake-two", Kind::Env, Tier::EachUse)
        .unwrap();
    ed.save(&e.path, &editor.store).unwrap();
    let peek = Vault::peek(&e.path).unwrap();
    assert_eq!(peek.signer, vahta_vault::Actor::Recipient(editor.id));
    assert_eq!(peek.generation, 3);

    let owner = reopen(&e);
    assert_eq!(owner.get("FROM_EDITOR").unwrap().expose(), b"fake-two");
    let entry = owner
        .entries()
        .iter()
        .find(|x| x.name == "FROM_EDITOR")
        .unwrap();
    assert_eq!(entry.changed_by, vahta_vault::Actor::Recipient(editor.id));
    assert_eq!(entry.tier, Tier::EachUse);
    // The editor holds what it wrote, and the owner can keep editing.
    assert_eq!(
        editor.open(&e).get("FROM_EDITOR").unwrap().expose(),
        b"fake-two"
    );
    let mut owner = owner;
    owner
        .set("OWN", b"fake-three", Kind::Env, Tier::Session)
        .unwrap();
    owner.save(&e.path, &e.store).unwrap();
}

#[test]
fn an_editor_cannot_read_or_replace_what_it_was_not_granted() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let editor = add(&mut v, &e, "ed", Role::Editor);
    let runner = add(&mut v, &e, "run", Role::Runner);
    v.set("MINE", b"fake-one", Kind::Env, Tier::Session)
        .unwrap();
    v.set("OTHERS", b"fake-two", Kind::Env, Tier::Session)
        .unwrap();
    v.grant("MINE", &editor.id).unwrap();
    v.grant("OTHERS", &runner.id).unwrap();
    v.save(&e.path, &e.store).unwrap();

    let mut ed = editor.open(&e);
    assert!(matches!(ed.get("OTHERS"), Err(Error::NoAccess)));
    assert!(matches!(
        ed.set("OTHERS", b"x", Kind::Env, Tier::Session),
        Err(Error::NoAccess)
    ));
    assert!(matches!(
        ed.grant("OTHERS", &editor.id),
        Err(Error::NoAccess)
    ));
    assert!(matches!(
        ed.revoke("OTHERS", &runner.id),
        Err(Error::NoAccess)
    ));
    ed.set("MINE", b"fake-new", Kind::Env, Tier::Session)
        .unwrap();
    ed.set_tier("MINE", Tier::EachUse).unwrap();
    ed.save(&e.path, &editor.store).unwrap();

    // The secret it could not read is untouched: its holders still read it.
    assert_eq!(runner.open(&e).get("OTHERS").unwrap().expose(), b"fake-two");
    assert_eq!(reopen(&e).get("OTHERS").unwrap().expose(), b"fake-two");
    assert_eq!(reopen(&e).get("MINE").unwrap().expose(), b"fake-new");
}

#[test]
fn an_editor_grants_and_revokes_what_it_can_read() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let editor = add(&mut v, &e, "ed", Role::Editor);
    let runner = add(&mut v, &e, "run", Role::Runner);
    v.set("MINE", b"fake-one", Kind::Env, Tier::Session)
        .unwrap();
    v.grant("MINE", &editor.id).unwrap();
    v.save(&e.path, &e.store).unwrap();

    let mut ed = editor.open(&e);
    ed.grant("MINE", &runner.id).unwrap();
    ed.save(&e.path, &editor.store).unwrap();
    assert_eq!(runner.open(&e).get("MINE").unwrap().expose(), b"fake-one");

    let mut ed = editor.open(&e);
    ed.revoke("MINE", &runner.id).unwrap();
    ed.remove("MINE").unwrap();
    ed.save(&e.path, &editor.store).unwrap();
    assert!(reopen(&e).get("MINE").is_err());
}

#[test]
fn a_runner_cannot_save_and_an_editor_cannot_change_membership() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let runner = add(&mut v, &e, "run", Role::Runner);
    let editor = add(&mut v, &e, "ed", Role::Editor);
    v.save(&e.path, &e.store).unwrap();
    let public = RecipientSecret::generate().unwrap().public().unwrap();

    let mut r = runner.open(&e);
    assert!(matches!(
        r.set("X", b"x", Kind::Env, Tier::Session),
        Err(Error::NotPermitted)
    ));
    assert!(matches!(
        r.save(&e.path, &runner.store),
        Err(Error::NotPermitted)
    ));

    let mut ed = editor.open(&e);
    assert!(matches!(
        ed.add_recipient("new", RecipientKind::Person, Role::Runner, &public),
        Err(Error::NotPermitted)
    ));
    assert!(matches!(
        ed.remove_recipient(&runner.id),
        Err(Error::NotPermitted)
    ));
}

#[test]
fn an_admin_adds_a_runner_who_reads_a_granted_secret() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let admin = add(&mut v, &e, "adm", Role::Admin);
    v.set("SHARED", b"fake-one", Kind::Env, Tier::Session)
        .unwrap();
    v.grant("SHARED", &admin.id).unwrap();
    v.save(&e.path, &e.store).unwrap();

    let mut ad = admin.open(&e);
    let runner = add(&mut ad, &e, "run", Role::Runner);
    ad.grant("SHARED", &runner.id).unwrap();
    ad.save(&e.path, &admin.store).unwrap();

    assert_eq!(runner.open(&e).get("SHARED").unwrap().expose(), b"fake-one");
    // The file the admin signed verifies, and the owner still opens it.
    let owner = reopen(&e);
    let r = owner
        .recipients()
        .iter()
        .find(|r| r.id == runner.id)
        .unwrap();
    assert_eq!(r.added_by, vahta_vault::Actor::Recipient(admin.id));

    // The admin removes the runner again: the entry just disappears.
    let mut ad = admin.open(&e);
    let rotate = ad.remove_recipient(&runner.id).unwrap();
    assert_eq!(rotate, vec!["SHARED".to_string()]);
    ad.save(&e.path, &admin.store).unwrap();
    assert!(matches!(
        Vault::open_as_recipient(&e.path, &runner.id, &runner.keys, &runner.store),
        Err(Error::Unlock)
    ));
    assert_eq!(reopen(&e).get("SHARED").unwrap().expose(), b"fake-one");
}

#[test]
fn an_admin_cannot_add_or_remove_an_admin_only_the_owner_does() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let admin = add(&mut v, &e, "adm", Role::Admin);
    let other = add(&mut v, &e, "adm2", Role::Admin);
    v.save(&e.path, &e.store).unwrap();
    let public = RecipientSecret::generate().unwrap().public().unwrap();

    let mut ad = admin.open(&e);
    assert!(matches!(
        ad.add_recipient("third", RecipientKind::Person, Role::Admin, &public),
        Err(Error::NotPermitted)
    ));
    assert!(matches!(
        ad.remove_recipient(&other.id),
        Err(Error::NotPermitted)
    ));

    // The owner removes an admin; the members it added are re-certified and
    // the file still verifies.
    let mut ad = admin.open(&e);
    let runner = add(&mut ad, &e, "run", Role::Runner);
    ad.save(&e.path, &admin.store).unwrap();
    let mut owner = reopen(&e);
    owner.remove_recipient(&admin.id).unwrap();
    owner.save(&e.path, &e.store).unwrap();
    let owner = reopen(&e);
    let r = owner
        .recipients()
        .iter()
        .find(|r| r.id == runner.id)
        .unwrap();
    assert_eq!(r.added_by, vahta_vault::Actor::Owner);
    assert!(Vault::peek(&e.path).is_ok());
}

#[test]
fn a_stale_recipient_save_is_a_conflict_too() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let editor = add(&mut v, &e, "ed", Role::Editor);
    v.save(&e.path, &e.store).unwrap();
    let mut ed = editor.open(&e);
    ed.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    let mut owner = reopen(&e);
    owner
        .set("B", b"fake-two", Kind::Env, Tier::Session)
        .unwrap();
    owner.save(&e.path, &e.store).unwrap();
    assert!(matches!(
        ed.save(&e.path, &editor.store),
        Err(Error::Conflict)
    ));
}

// --- The authenticated local store ---------------------------------------------

#[test]
fn an_edited_state_file_is_refused_on_unlock() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.save(&e.path, &e.store).unwrap();
    let id = v.vault_id();
    let state = state_path(&e, &id, "state");
    let good = std::fs::read_to_string(&state).unwrap();
    assert!(good.contains("max_generation = 2"));

    // Raised, as for a denial of service; lowered, as before a rollback.
    for edited in ["max_generation = 9", "max_generation = 1"] {
        std::fs::write(&state, good.replace("max_generation = 2", edited)).unwrap();
        assert!(matches!(
            Vault::unlock_password(&e.path, PW, &e.store),
            Err(Error::StoreTampered)
        ));
    }
    // A save refuses to build on a tampered state too.
    std::fs::write(&state, &good).unwrap();
    let mut ok = reopen(&e);
    std::fs::write(
        &state,
        good.replace("max_generation = 2", "max_generation = 0"),
    )
    .unwrap();
    ok.set("B", b"fake-two", Kind::Env, Tier::Session).unwrap();
    assert!(matches!(
        ok.save(&e.path, &e.store),
        Err(Error::StoreTampered)
    ));
}

#[test]
fn a_missing_state_is_a_first_open_not_an_error() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    assert!(v.first_open_on_this_machine());
    v.save(&e.path, &e.store).unwrap();
    assert!(!reopen(&e).first_open_on_this_machine());

    std::fs::remove_file(state_path(&e, &v.vault_id(), "state")).unwrap();
    let again = reopen(&e);
    assert!(again.first_open_on_this_machine());
    // The open wrote the state back: the next one is ordinary.
    assert!(!reopen(&e).first_open_on_this_machine());
}

#[test]
fn a_recipient_keeps_its_own_state_file() {
    let e = env();
    let (mut v, _) = new_vault(&e);
    let editor = add(&mut v, &e, "ed", Role::Editor);
    v.save(&e.path, &e.store).unwrap();
    let id = v.vault_id();

    let mut ed = editor.open(&e);
    assert!(ed.first_open_on_this_machine());
    ed.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    ed.save(&e.path, &editor.store).unwrap();
    let again = editor.open(&e);
    assert!(!again.first_open_on_this_machine());
    let own = editor
        .store
        .root()
        .join("vaults")
        .join(vahta_vault::hex_encode(&id))
        .join(format!("state-{}", vahta_vault::hex_encode(&editor.id)));
    assert!(own.is_file());
    assert!(!own.with_file_name("state").exists());

    // Its state is MAC'd under its own key: edited, it is refused.
    let text = std::fs::read_to_string(&own).unwrap();
    let edited: String = text
        .lines()
        .map(|l| {
            if l.starts_with("max_generation") {
                "max_generation = 99"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&own, edited).unwrap();
    assert!(matches!(
        Vault::open_as_recipient(&e.path, &editor.id, &editor.keys, &editor.store),
        Err(Error::StoreTampered)
    ));
    // The owner's state is a different file and unaffected.
    assert!(!reopen(&e).first_open_on_this_machine());
    // A recipient's save never pins a new owner: the pin is the file's own.
    let peek = Vault::peek(&e.path).unwrap();
    let state = std::fs::read_to_string(state_path(&e, &id, "state")).unwrap();
    assert!(state.contains(&vahta_vault::hex_encode(&peek.owner_sign_pk)));
}
