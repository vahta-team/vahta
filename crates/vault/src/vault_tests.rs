//! Tests that need the vault's insides: they build files the public API
//! would never write (a runner signature, a swapped owner, a re-signed
//! tamper) to prove the reader refuses them, and they run the upgrade chain
//! through the test pseudo-format.

use ed25519_dalek::SigningKey;

use super::*;
use crate::format::current::{Model, encode_as};

const PW: &[u8] = b"correct horse";

struct T {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: LocalStore,
}

fn t() -> T {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    let store = LocalStore::new(dir.path().join("store"));
    T {
        _dir: dir,
        path,
        store,
    }
}

fn unlocked(v: &Vault) -> &current::Unlocked {
    match &v.access {
        Access::Owner(u) => u,
        Access::Recipient(_) => unreachable!("tests build owner vaults"),
    }
}

fn owner_key(v: &Vault) -> SigningKey {
    current::owner_keys(&unlocked(v).vk).sign
}

fn model(v: &Vault) -> Model {
    unlocked(v).model.clone()
}

/// A saved vault with secrets A and B and one recipient per role.
fn built(t: &T) -> (Vault, [(Role, [u8; 16], RecipientSecret); 3]) {
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.set("B", b"fake-two", Kind::Env, Tier::Session).unwrap();
    let mut out = Vec::new();
    for (name, role) in [
        ("adm", Role::Admin),
        ("edit", Role::Editor),
        ("run", Role::Runner),
    ] {
        let keys = RecipientSecret::generate().unwrap();
        let id = v
            .add_recipient(name, RecipientKind::Person, role, &keys.public().unwrap())
            .unwrap();
        out.push((role, id, keys));
    }
    v.grant("A", &out[2].1).unwrap();
    v.save(&t.path, &t.store).unwrap();
    let [a, b, c]: [_; 3] = out.try_into().ok().unwrap();
    (v, [a, b, c])
}

fn signed_by(v: &Vault, signer: Actor, key: &SigningKey) -> Vec<u8> {
    encode_as(current::FORMAT, &model(v), &owner_key(v), signer, key).unwrap()
}

#[test]
fn a_runner_signature_is_refused_and_an_editor_or_admin_one_is_accepted() {
    let t = t();
    let (v, [(_, adm, adm_k), (_, edit, edit_k), (_, run, run_k)]) = built(&t);
    let sk = |k: &RecipientSecret| crypto::signing_key(k.sign_sk());

    let by_runner = signed_by(&v, Actor::Recipient(run), &sk(&run_k));
    assert!(matches!(
        Vault::peek_bytes(&by_runner),
        Err(Error::SignerNotAllowed)
    ));

    for (id, k) in [(adm, &adm_k), (edit, &edit_k)] {
        let bytes = signed_by(&v, Actor::Recipient(id), &sk(k));
        assert_eq!(
            Vault::peek_bytes(&bytes).unwrap().signer,
            Actor::Recipient(id)
        );
    }

    // The right id with the wrong key is a bad signature, not a pass.
    let forged = signed_by(&v, Actor::Recipient(edit), &sk(&run_k));
    assert!(matches!(
        Vault::peek_bytes(&forged),
        Err(Error::BadSignature)
    ));
}

#[test]
fn an_editor_missing_from_the_owner_signed_list_is_refused() {
    let t = t();
    let (v, _) = built(&t);
    let outsider = RecipientSecret::generate().unwrap();
    let bytes = signed_by(
        &v,
        Actor::Recipient([7; 16]),
        &crypto::signing_key(outsider.sign_sk()),
    );
    assert!(matches!(
        Vault::peek_bytes(&bytes),
        Err(Error::SignerNotAllowed)
    ));
}

#[test]
fn another_owners_key_in_the_same_vault_is_owner_changed() {
    let t = t();
    let (v, _) = built(&t);
    // A different vault, made to carry the first one's id, correctly signed
    // by its own owner: it verifies on its own, but this machine pinned the
    // other owner key for that id.
    let (other, _) = Vault::create(b"other horse", KdfParams::TEST).unwrap();
    let mut m = model(&other);
    m.header.vault_id = v.vault_id();
    m.header.generation = 99;
    let bytes = encode_as(
        current::FORMAT,
        &m,
        &owner_key(&other),
        Actor::Owner,
        &owner_key(&other),
    )
    .unwrap();
    std::fs::write(&t.path, &bytes).unwrap();
    assert!(matches!(
        Vault::unlock_password(&t.path, b"other horse", &t.store),
        Err(Error::OwnerChanged)
    ));
    assert!(matches!(
        Vault::peek(&t.path).unwrap().verified(&t.store),
        Err(Error::OwnerChanged)
    ));
}

#[test]
fn a_kdf_below_the_floor_in_the_file_is_refused_before_it_runs() {
    let t = t();
    let (v, _) = built(&t);
    let mut m = model(&v);
    if let Some(current::Slot::Password { m_kib, .. }) = m
        .slots
        .iter_mut()
        .find(|s| matches!(s, current::Slot::Password { .. }))
    {
        *m_kib = 4; // under the (test) floor of 8
    }
    let key = owner_key(&v);
    let bytes = encode_as(current::FORMAT, &m, &key, Actor::Owner, &key).unwrap();
    std::fs::write(&t.path, bytes).unwrap();
    assert!(matches!(
        Vault::unlock_password(&t.path, PW, &t.store),
        Err(Error::KdfBelowFloor)
    ));

    // And a cost over the ceiling is not even a vault.
    if let Some(current::Slot::Password { m_kib, .. }) = m
        .slots
        .iter_mut()
        .find(|s| matches!(s, current::Slot::Password { .. }))
    {
        *m_kib = u32::MAX;
    }
    let bytes = encode_as(current::FORMAT, &m, &key, Actor::Owner, &key).unwrap();
    assert!(matches!(Vault::peek_bytes(&bytes), Err(Error::Corrupt(_))));
}

#[test]
fn the_aead_catches_what_a_resigned_file_hides_from_the_signature() {
    let t = t();
    let (v, _) = built(&t);
    let key = owner_key(&v);
    let resign = |m: &Model| encode_as(current::FORMAT, m, &key, Actor::Owner, &key).unwrap();

    // A changed ciphertext byte, under a valid signature.
    let mut m = model(&v);
    m.secrets[0].ct[3] ^= 1;
    std::fs::write(&t.path, resign(&m)).unwrap();
    let opened = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert!(matches!(opened.get("A"), Err(Error::Unlock)));

    // Two secrets' bodies swapped: each AAD names its own secret id.
    let mut m = model(&v);
    let (a, b) = (m.secrets[0].clone(), m.secrets[1].clone());
    m.secrets[0].nonce = b.nonce;
    m.secrets[0].ct = b.ct;
    m.secrets[1].nonce = a.nonce;
    m.secrets[1].ct = a.ct;
    std::fs::write(&t.path, resign(&m)).unwrap();
    let store = LocalStore::new(t._dir.path().join("fresh"));
    let opened = Vault::unlock_password(&t.path, PW, &store).unwrap();
    assert!(opened.get("A").is_err() && opened.get("B").is_err());

    // A changed slot ciphertext: the vault will not unlock at all.
    let mut m = model(&v);
    if let current::Slot::Password { ct, .. } = &mut m.slots[0] {
        ct[0] ^= 1;
    }
    std::fs::write(&t.path, resign(&m)).unwrap();
    let store = LocalStore::new(t._dir.path().join("fresh2"));
    assert!(matches!(
        Vault::unlock_password(&t.path, PW, &store),
        Err(Error::Unlock)
    ));
}

#[test]
fn an_old_wrap_cannot_open_the_new_ciphertext_after_a_revoke() {
    let t = t();
    let (mut v, [_, _, (_, run, run_k)]) = built(&t);
    let old_wrap = model(&v).secrets[0].wraps[0].clone();
    assert_eq!(old_wrap.recipient_id, run);

    v.revoke("A", &run).unwrap();
    v.save(&t.path, &t.store).unwrap();

    // Put the revoked recipient's old wrap back next to the re-keyed
    // ciphertext, as a malicious file would.
    let mut m = model(&v);
    assert!(m.secrets[0].wraps.is_empty());
    m.secrets[0].wraps.push(old_wrap);
    let key = owner_key(&v);
    let bytes = encode_as(current::FORMAT, &m, &key, Actor::Owner, &key).unwrap();
    std::fs::write(&t.path, bytes).unwrap();
    let ci = LocalStore::new(t._dir.path().join("ci"));
    assert!(matches!(
        Vault::open_as_recipient(&t.path, &run, &run_k, &ci),
        Err(Error::Unlock)
    ));
}

// --- The upgrade chain, through the pseudo-format 0 ------------------------

const V0_ITEMS: [(&str, &[u8]); 2] = [("ALPHA", b"fake-one"), ("BETA", b"fake two lines\nx")];

#[test]
fn peek_on_an_old_format_reports_it_and_never_upgrades() {
    let t = t();
    Vault::write_v0_for_test(&t.path, PW, &V0_ITEMS).unwrap();
    let before = std::fs::read(&t.path).unwrap();
    let peek = Vault::peek(&t.path).unwrap();
    assert_eq!(peek.format, 0);
    assert!(peek.upgrade_pending);
    assert_eq!(peek.entries.len(), 2);
    assert_eq!(std::fs::read(&t.path).unwrap(), before);
    assert_eq!(format::read_version(&before).unwrap(), 0);
}

#[test]
fn an_old_format_upgrades_on_unlock_and_is_written_on_the_first_save() {
    let t = t();
    Vault::write_v0_for_test(&t.path, PW, &V0_ITEMS).unwrap();
    let original = std::fs::read(&t.path).unwrap();

    let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert!(v.upgrade_pending());
    assert_eq!(v.get("BETA").unwrap().expose(), b"fake two lines\nx");
    // Nothing is written by unlocking.
    assert_eq!(std::fs::read(&t.path).unwrap(), original);
    assert!(!backup_path(&t.path, 0).exists());

    v.save(&t.path, &t.store).unwrap();
    // Generation continues (1 in the old file, 2 now) and the format moved.
    let peek = Vault::peek(&t.path).unwrap();
    assert_eq!((peek.format, peek.generation), (CURRENT, 2));
    assert!(!peek.upgrade_pending);
    assert_eq!(std::fs::read(backup_path(&t.path, 0)).unwrap(), original);
    assert!(!v.upgrade_pending());

    // A second save does not touch the backup.
    v.set("GAMMA", b"fake-three", Kind::Env, Tier::Session)
        .unwrap();
    v.save(&t.path, &t.store).unwrap();
    assert_eq!(std::fs::read(backup_path(&t.path, 0)).unwrap(), original);
    let again = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert_eq!(again.get("ALPHA").unwrap().expose(), b"fake-one");
    assert_eq!(again.generation(), 3);
}

#[test]
fn an_existing_backup_is_never_overwritten() {
    let t = t();
    Vault::write_v0_for_test(&t.path, PW, &V0_ITEMS).unwrap();
    std::fs::write(backup_path(&t.path, 0), b"an earlier backup").unwrap();
    let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    v.save(&t.path, &t.store).unwrap();
    assert_eq!(
        std::fs::read(backup_path(&t.path, 0)).unwrap(),
        b"an earlier backup"
    );
}

#[test]
fn an_old_format_cannot_be_downgraded_to() {
    // Only the current module encodes, and encode stamps the current number.
    let (v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    let key = owner_key(&v);
    let bytes = current::encode(&model(&v), &key).unwrap();
    assert_eq!(format::read_version(&bytes).unwrap(), CURRENT);
}

#[test]
fn secrets_out_of_index_order_are_refused() {
    // Editing finds a secret by its index position, so a file whose secrets
    // list is not in index order must never load: `set` would re-seal the
    // wrong secret under the right name.
    let t = t();
    let (v, _) = built(&t);
    let mut m = model(&v);
    m.secrets.swap(0, 1);
    let key = owner_key(&v);
    let bytes = encode_as(current::FORMAT, &m, &key, Actor::Owner, &key).unwrap();
    assert!(matches!(
        format::decode(&bytes),
        Err(Error::Corrupt("index and secrets disagree"))
    ));
}
