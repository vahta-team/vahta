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
        _ => unreachable!("tests build owner vaults"),
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
    encode_as(current::FORMAT, &model(v), signer, key).unwrap()
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
    let bytes = encode_as(current::FORMAT, &m, Actor::Owner, &owner_key(&other)).unwrap();
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
    let bytes = encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap();
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
    let bytes = encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap();
    assert!(matches!(Vault::peek_bytes(&bytes), Err(Error::Corrupt(_))));
}

#[test]
fn the_aead_catches_what_a_resigned_file_hides_from_the_signature() {
    let t = t();
    let (v, _) = built(&t);
    let key = owner_key(&v);
    let resign = |m: &Model| encode_as(current::FORMAT, m, Actor::Owner, &key).unwrap();

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
    let bytes = encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap();
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
    let bytes = encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap();
    assert!(matches!(
        format::decode(&bytes),
        Err(Error::Corrupt("index and secrets disagree"))
    ));
}

// --- Membership certificates and writers ------------------------------------

fn resigned(v: &Vault, m: &Model) -> Vec<u8> {
    encode_as(current::FORMAT, m, Actor::Owner, &owner_key(v)).unwrap()
}

fn entry(
    v: &Vault,
    name: &str,
    role: Role,
    added_by: Actor,
    issuer: &SigningKey,
) -> current::Recipient {
    let keys = RecipientSecret::generate().unwrap().public().unwrap();
    let mut r = current::Recipient {
        id: crypto::random::<16>().unwrap(),
        name: name.to_string(),
        kind: RecipientKind::Person,
        role,
        enc_pk: keys.enc_pk,
        sign_pk: keys.sign_pk,
        added: 1,
        added_by,
        cert: current::Sig([0; 64]),
    };
    r.certify(&v.vault_id(), issuer);
    r
}

#[test]
fn an_admin_added_admin_and_other_misissued_certificates_are_refused() {
    let t = t();
    let (v, [(_, adm, adm_k), (_, edit, edit_k), _]) = built(&t);
    let sk = |k: &RecipientSecret| crypto::signing_key(k.sign_sk());

    // An admin certifying an admin.
    let mut m = model(&v);
    m.recipients.push(entry(
        &v,
        "bad",
        Role::Admin,
        Actor::Recipient(adm),
        &sk(&adm_k),
    ));
    assert!(matches!(
        Vault::peek_bytes(&resigned(&v, &m)),
        Err(Error::MembershipNotAllowed)
    ));

    // An editor certifying anyone.
    let mut m = model(&v);
    m.recipients.push(entry(
        &v,
        "bad",
        Role::Runner,
        Actor::Recipient(edit),
        &sk(&edit_k),
    ));
    assert!(matches!(
        Vault::peek_bytes(&resigned(&v, &m)),
        Err(Error::MembershipNotAllowed)
    ));

    // An issuer that is not in the file at all.
    let mut m = model(&v);
    m.recipients.push(entry(
        &v,
        "bad",
        Role::Runner,
        Actor::Recipient([9; 16]),
        &sk(&adm_k),
    ));
    assert!(matches!(
        Vault::peek_bytes(&resigned(&v, &m)),
        Err(Error::MembershipNotAllowed)
    ));

    // An admin that an admin added cannot certify an editor: delegation is one
    // level deep. (Its own entry is already refused; this is the second line.)
    let mut m = model(&v);
    let deep = entry(&v, "deep", Role::Admin, Actor::Recipient(adm), &sk(&adm_k));
    let deep_key = RecipientSecret::generate().unwrap();
    let mut deep = deep;
    deep.sign_pk = deep_key.public().unwrap().sign_pk;
    deep.certify(&v.vault_id(), &sk(&adm_k));
    let deep_id = deep.id;
    m.recipients.push(deep);
    m.recipients.push(entry(
        &v,
        "under",
        Role::Editor,
        Actor::Recipient(deep_id),
        &sk(&deep_key),
    ));
    assert!(Vault::peek_bytes(&resigned(&v, &m)).is_err());
}

#[test]
fn a_forged_certificate_is_refused() {
    let t = t();
    let (v, [_, _, (_, _run, run_k)]) = built(&t);

    // A flipped byte in a certificate.
    let mut m = model(&v);
    m.recipients[0].cert.0[0] ^= 1;
    assert!(matches!(
        Vault::peek_bytes(&resigned(&v, &m)),
        Err(Error::BadSignature)
    ));

    // An entry claiming the owner added it, signed by someone else.
    let mut m = model(&v);
    m.recipients.push(entry(
        &v,
        "forged",
        Role::Runner,
        Actor::Owner,
        &crypto::signing_key(run_k.sign_sk()),
    ));
    assert!(matches!(
        Vault::peek_bytes(&resigned(&v, &m)),
        Err(Error::BadSignature)
    ));

    // A changed field breaks the certificate over it.
    let mut m = model(&v);
    m.recipients[2].role = Role::Admin;
    assert!(matches!(
        Vault::peek_bytes(&resigned(&v, &m)),
        Err(Error::BadSignature)
    ));
    // An entry certified for another vault is not valid here.
    let mut m = model(&v);
    let other = entry(&v, "moved", Role::Runner, Actor::Owner, &owner_key(&v));
    m.recipients
        .push(entry(&v, "x", Role::Runner, Actor::Owner, &owner_key(&v)));
    let last = m.recipients.len() - 1;
    m.recipients[last].cert = other.cert;
    assert!(matches!(
        Vault::peek_bytes(&resigned(&v, &m)),
        Err(Error::BadSignature)
    ));
}

fn sealed_of(path: &Path, name: &str) -> current::Sealed {
    let bytes = std::fs::read(path).unwrap();
    let loaded = format::decode(&bytes).unwrap();
    let m = loaded.model();
    let i = m.index.iter().position(|e| e.name == name).unwrap();
    m.secrets[i].clone()
}

#[test]
fn an_editors_edits_leave_other_secrets_byte_identical() {
    let t = t();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    let keys = RecipientSecret::generate().unwrap();
    let id = v
        .add_recipient(
            "ed",
            RecipientKind::Person,
            Role::Editor,
            &keys.public().unwrap(),
        )
        .unwrap();
    v.set("MINE", b"fake-one", Kind::Env, Tier::Session)
        .unwrap();
    v.set("OTHERS", b"fake-two", Kind::Env, Tier::Session)
        .unwrap();
    v.grant("MINE", &id).unwrap();
    v.save(&t.path, &t.store).unwrap();
    let before = sealed_of(&t.path, "OTHERS");

    let ed_store = LocalStore::new(t._dir.path().join("ed"));
    let mut ed = Vault::open_as_recipient(&t.path, &id, &keys, &ed_store).unwrap();
    ed.set("MINE", b"fake-new", Kind::Env, Tier::Session)
        .unwrap();
    ed.set("ADDED", b"fake-three", Kind::Env, Tier::Session)
        .unwrap();
    ed.save(&t.path, &ed_store).unwrap();

    assert_eq!(sealed_of(&t.path, "OTHERS"), before);
    assert_ne!(
        sealed_of(&t.path, "MINE").ct,
        sealed_of(&t.path, "OTHERS").ct
    );
    // A new secret from an editor is wrapped for the owner and the editor only.
    let added = sealed_of(&t.path, "ADDED");
    assert_eq!(added.wraps.len(), 1);
    assert_eq!(added.wraps[0].recipient_id, id);
}

// --- Slots and the recovery key across an upgrade ------------------------------

fn slots_of(path: &Path) -> Vec<current::Slot> {
    format::decode(&std::fs::read(path).unwrap())
        .unwrap()
        .model()
        .slots
        .clone()
}

#[test]
fn slots_are_copied_verbatim_across_an_upgrade_and_need_no_key() {
    let t = t();
    let key = Vault::write_v0_for_test(&t.path, PW, &V0_ITEMS).unwrap();
    let before = slots_of(&t.path);
    assert_eq!(before.len(), 2);

    let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert!(v.upgrade_pending() && !v.blocked_on_recovery_key());
    v.save(&t.path, &t.store).unwrap();

    // Format 1 now, the same two slots byte for byte, and the old recovery
    // slot still opens the vault.
    assert_eq!(Vault::peek(&t.path).unwrap().format, CURRENT);
    assert_eq!(slots_of(&t.path), before);
    let by_key = Vault::unlock_recovery(&t.path, &key, &t.store).unwrap();
    assert_eq!(by_key.get("ALPHA").unwrap().expose(), b"fake-one");
}

#[test]
fn a_step_that_rewrites_the_recovery_slot_needs_the_paper_key() {
    let _rewrite = format::testing::rewrite_recovery_slot();
    let t = t();
    let key = Vault::write_v0_for_test(&t.path, PW, &V0_ITEMS).unwrap();
    let original = std::fs::read(&t.path).unwrap();
    let before = slots_of(&t.path);

    // Opened with the password: open and readable, but blocked.
    let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert!(v.upgrade_pending() && v.blocked_on_recovery_key());
    assert_eq!(v.get("BETA").unwrap().expose(), b"fake two lines\nx");
    assert_eq!(v.entries().len(), 2);
    assert!(matches!(
        v.set("NEW", b"x", Kind::Env, Tier::Session),
        Err(Error::UpgradeNeedsRecoveryKey)
    ));
    assert!(matches!(
        v.save(&t.path, &t.store),
        Err(Error::UpgradeNeedsRecoveryKey)
    ));
    assert!(matches!(
        v.change_password(b"x", KdfParams::TEST),
        Err(Error::UpgradeNeedsRecoveryKey)
    ));
    // Nothing was written.
    assert_eq!(std::fs::read(&t.path).unwrap(), original);

    // A key that does not open the recovery slot cannot replace it.
    let (_, wrong) = Vault::create(PW, KdfParams::TEST).unwrap();
    assert!(matches!(v.provide_recovery_key(&wrong), Err(Error::Unlock)));
    assert!(v.blocked_on_recovery_key());

    v.provide_recovery_key(&key).unwrap();
    assert!(!v.blocked_on_recovery_key() && v.upgrade_pending());
    v.save(&t.path, &t.store).unwrap();
    assert_eq!(Vault::peek(&t.path).unwrap().format, CURRENT);
    assert_ne!(slots_of(&t.path), before);
    assert_eq!(std::fs::read(backup_path(&t.path, 0)).unwrap(), original);
    // The rewritten recovery slot still opens with the same paper key.
    let again = Vault::unlock_recovery(&t.path, &key, &t.store).unwrap();
    assert_eq!(again.get("ALPHA").unwrap().expose(), b"fake-one");
}

#[test]
fn unlocking_with_the_recovery_key_is_never_blocked() {
    let _rewrite = format::testing::rewrite_recovery_slot();
    let t = t();
    let key = Vault::write_v0_for_test(&t.path, PW, &V0_ITEMS).unwrap();
    let mut v = Vault::unlock_recovery(&t.path, &key, &t.store).unwrap();
    assert!(v.upgrade_pending() && !v.blocked_on_recovery_key());
    v.save(&t.path, &t.store).unwrap();
    assert_eq!(Vault::peek(&t.path).unwrap().format, CURRENT);
}

// --- Bindings and class ---------------------------------------------------------

fn sample_binding(name: &str) -> Binding {
    Binding {
        name: name.to_string(),
        allow: vec![
            crate::rules::parse_rule("tool push", true)
                .unwrap()
                .to_allow("/opt/x/tool".to_string()),
        ],
        deny: vec![
            crate::rules::parse_rule("@network", false)
                .unwrap()
                .to_deny(),
        ],
    }
}

#[test]
fn bindings_and_class_round_trip_and_peek_shows_them() {
    let t = t();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.set_class("A", Some(Class::Cloud)).unwrap();
    v.set_bindings("A", Some(sample_binding("ignored")))
        .unwrap();
    v.save(&t.path, &t.store).unwrap();

    let peek = Vault::peek(&t.path).unwrap();
    assert_eq!(peek.entries[0].class, Some(Class::Cloud));
    assert_eq!(peek.bindings.len(), 1);
    assert_eq!(
        peek.bindings[0].name, "A",
        "the name is the one given to set"
    );
    let again = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert_eq!(again.bindings(), peek.bindings.as_slice());

    // Replacing the value forgets the class but keeps the rules; removing the
    // secret drops the rules.
    let mut v = again;
    v.set("A", b"fake-two", Kind::Env, Tier::Session).unwrap();
    assert_eq!(v.entries()[0].class, None);
    assert_eq!(v.bindings().len(), 1);
    v.set_bindings("A", None).unwrap();
    assert!(v.bindings().is_empty());
    v.set_bindings("A", Some(sample_binding("A"))).unwrap();
    v.remove("A").unwrap();
    assert!(v.bindings().is_empty());
}

#[test]
fn an_empty_or_malformed_binding_is_not_stored() {
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    let empty = Binding {
        name: "A".into(),
        allow: vec![],
        deny: vec![],
    };
    v.set_bindings("A", Some(empty)).unwrap();
    assert!(v.bindings().is_empty());

    let mut bad = sample_binding("A");
    bad.allow[0].program = crate::Program::Group("@network".into());
    assert!(matches!(
        v.set_bindings("A", Some(bad)),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        v.set_bindings("NOPE", Some(sample_binding("NOPE"))),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn the_signature_covers_the_bindings() {
    let t = t();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    v.set_bindings("A", Some(sample_binding("A"))).unwrap();
    v.save(&t.path, &t.store).unwrap();

    // Flip one byte inside the stored path of the allow rule.
    let mut bytes = std::fs::read(&t.path).unwrap();
    let needle = b"/opt/x/tool";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the path is in the plaintext body");
    bytes[at + 5] ^= 1;
    assert!(matches!(
        Vault::peek_bytes(&bytes),
        Err(Error::BadSignature)
    ));

    // A binding for a secret that does not exist is refused even when signed.
    let (v, _) = {
        let v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
        (v, ())
    };
    let mut m = model(&v);
    m.bindings.push(sample_binding("GHOST"));
    let key = owner_key(&v);
    let bytes = encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap();
    assert!(matches!(Vault::peek_bytes(&bytes), Err(Error::Corrupt(_))));
}

#[test]
fn a_runner_cannot_edit_bindings() {
    let t = t();
    let (_, [_, _, (_, run, run_k)]) = built(&t);
    let mut v = Vault::open_as_recipient(&t.path, &run, &run_k, &t.store).unwrap();
    assert!(v.set_bindings("A", Some(sample_binding("A"))).is_err());
}
