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

fn set_password_m_kib(m: &mut Model, m_kib: u32) {
    let slot = m
        .slots
        .iter_mut()
        .find(|s| s.kind == current::SLOT_PASSWORD)
        .unwrap();
    let mut p = current::PasswordParams::decode(&slot.params).unwrap();
    p.m_kib = m_kib;
    slot.params = p.encode();
}

#[test]
fn a_kdf_below_the_floor_in_the_file_is_refused_before_it_runs() {
    let t = t();
    let (v, _) = built(&t);
    let mut m = model(&v);
    set_password_m_kib(&mut m, 4); // under the (test) floor of 8
    let key = owner_key(&v);
    let bytes = encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap();
    std::fs::write(&t.path, bytes).unwrap();
    assert!(matches!(
        Vault::unlock_password(&t.path, PW, &t.store),
        Err(Error::KdfBelowFloor)
    ));

    // And a cost over the ceiling is not even a vault.
    set_password_m_kib(&mut m, u32::MAX);
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
    m.slots[0].ct[0] ^= 1;
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
    let m = &loaded.current().unwrap().model;
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
        .slots()
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

    // Format 2 now, the same two slots byte for byte, and the old recovery
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

fn sample_binding(name: &str) -> RuleSet {
    RuleSet {
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
        ..Default::default()
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
    let empty = RuleSet {
        name: "A".into(),
        allow: vec![],
        deny: vec![],
        ..Default::default()
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

// --- Format 1 to 2, generic slots, devices, limits ----------------------------------

const KEK: [u8; 32] = [5; 32];

fn future_slot(label: &str) -> NewSlot {
    NewSlot {
        kind: 0x7001,
        slot_id: None,
        label: label.into(),
        expires_at: None,
        params: vec![1, 2, 3],
    }
}

fn add_future(v: &mut Vault, label: &str) -> Result<[u8; 16], Error> {
    v.add_slot(future_slot(label), |vk, aad| {
        current::seal_vault_key(&KEK, aad, vk)
    })
}

fn device(n: u8) -> Device {
    Device {
        device_id: [n; 16],
        name: format!("phone {n}"),
        sign_pub: [&[2u8][..], &[n; 32]].concat(),
        ecdh_pub: [&[4u8][..], &[n; 64]].concat(),
        paired_at: 100,
        expires_at: None,
        transports: vec!["lan".into()],
    }
}

#[test]
fn a_real_v1_vault_upgrades_with_everything_intact_and_a_bak() {
    let t = t();
    let key = Vault::write_v1_for_test(&t.path, PW, &V0_ITEMS).unwrap();
    let original = std::fs::read(&t.path).unwrap();
    assert_eq!(format::read_version(&original).unwrap(), 1);

    let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert!(v.upgrade_pending() && !v.blocked_on_recovery_key());
    v.set_class("ALPHA", Some(Class::Payment)).unwrap();
    v.set_tier("BETA", Tier::EachUse).unwrap();
    v.set_bindings("BETA", Some(sample_binding("BETA")))
        .unwrap();
    v.save(&t.path, &t.store).unwrap();

    assert_eq!(
        std::fs::read(t.path.with_extension("vht.v1.bak")).unwrap(),
        original
    );
    let v = Vault::unlock_recovery(&t.path, &key, &t.store).unwrap();
    assert_eq!(v.get("ALPHA").unwrap().expose(), b"fake-one");
    assert_eq!(v.get("BETA").unwrap().expose(), b"fake two lines\nx");
    let e = |n: &str| v.entries().iter().find(|e| e.name == n).unwrap().clone();
    assert_eq!(e("ALPHA").class, Some(Class::Payment));
    assert_eq!(e("BETA").tier, Tier::EachUse);
    assert_eq!(v.bindings().len(), 1);
}

#[test]
fn an_unknown_slot_kind_survives_read_and_write_and_never_blocks_unlock() {
    let t = t();
    let (mut v, key) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    let id = add_future(&mut v, "someone's phone").unwrap();
    v.save(&t.path, &t.store).unwrap();

    // Pretend this build does not know the kind: edit the stored params and
    // re-sign. Reading, unlocking and saving must not care what is in it.
    let mut m = model(&v);
    let slot = m.slots.iter_mut().find(|s| s.slot_id == id).unwrap();
    slot.kind = 0xBEEF;
    slot.params = vec![0xFF; 200];
    slot.ct = vec![0xAB; 500];
    let kept = slot.clone();
    let mut m2 = m.clone();
    m2.header.generation = 1;
    let bytes = encode_as(current::FORMAT, &m2, Actor::Owner, &owner_key(&v)).unwrap();
    std::fs::write(&t.path, bytes).unwrap();

    let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert_eq!(v.get("A").unwrap().expose(), b"fake-one");
    assert_eq!(v.slots().len(), 3);
    v.set("B", b"fake-two", Kind::Env, Tier::Session).unwrap();
    v.save(&t.path, &t.store).unwrap();
    assert_eq!(
        slots_of(&t.path).into_iter().find(|s| s.slot_id == id),
        Some(kept)
    );
    // Both known ways in still work, and the unknown slot cannot be a way in.
    Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    Vault::unlock_recovery(&t.path, &key, &t.store).unwrap();
    assert!(matches!(
        Vault::unlock_with_slot(&t.path, &id, &KEK, &t.store),
        Err(Error::Unlock)
    ));
}

#[test]
fn a_slot_added_through_the_api_unlocks_expires_and_can_be_removed() {
    let t = t();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    let id = add_future(&mut v, "phone").unwrap();
    let mut short = future_slot("short");
    short.expires_at = Some(now() - 1);
    let expired = v
        .add_slot(short, |vk, aad| current::seal_vault_key(&KEK, aad, vk))
        .unwrap();
    v.save(&t.path, &t.store).unwrap();

    let listed = v.slots();
    assert_eq!(listed.len(), 4);
    assert_eq!(
        listed.iter().find(|s| s.slot_id == id).unwrap().label,
        "phone"
    );

    let by_slot = Vault::unlock_with_slot(&t.path, &id, &KEK, &t.store).unwrap();
    assert_eq!(by_slot.get("A").unwrap().expose(), b"fake-one");
    assert!(matches!(
        Vault::unlock_with_slot(&t.path, &id, &[6; 32], &t.store),
        Err(Error::Unlock)
    ));
    assert!(matches!(
        Vault::unlock_with_slot(&t.path, &expired, &KEK, &t.store),
        Err(Error::Unlock)
    ));

    let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    v.remove_slot(&id).unwrap();
    assert!(matches!(v.remove_slot(&id), Err(Error::UnknownSlot)));
    let pw_slot = v
        .slots()
        .into_iter()
        .find(|s| s.kind == current::SLOT_PASSWORD)
        .unwrap();
    assert!(matches!(
        v.remove_slot(&pw_slot.slot_id),
        Err(Error::Invalid(_))
    ));
    v.save(&t.path, &t.store).unwrap();
    assert!(matches!(
        Vault::unlock_with_slot(&t.path, &id, &KEK, &t.store),
        Err(Error::Unlock)
    ));
}

#[test]
fn slot_limits_and_one_of_each_known_kind() {
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    // Password and recovery exist; the cap leaves room for 14 more.
    for n in 0..current::MAX_SLOTS - 2 {
        add_future(&mut v, &format!("s{n}")).unwrap();
    }
    assert!(matches!(
        add_future(&mut v, "one too many"),
        Err(Error::Invalid(_))
    ));
    assert_eq!(v.slots().len(), current::MAX_SLOTS);

    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    for kind in [current::SLOT_PASSWORD, current::SLOT_RECOVERY] {
        let mut s = future_slot("again");
        s.kind = kind;
        let r = v.add_slot(s, |vk, aad| current::seal_vault_key(&KEK, aad, vk));
        assert!(matches!(r, Err(Error::Invalid(_))));
    }
    let mut long = future_slot(&"x".repeat(current::MAX_LABEL + 1));
    assert!(
        v.add_slot(long.clone(), |vk, aad| current::seal_vault_key(
            &KEK, aad, vk
        ))
        .is_err()
    );
    long.label = "ok".into();
    long.params = vec![0; 257];
    assert!(
        v.add_slot(long, |vk, aad| current::seal_vault_key(&KEK, aad, vk))
            .is_err()
    );

    // A file with two password slots, or a repeated id, is not a vault.
    let (v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    let key = owner_key(&v);
    let mut m = model(&v);
    let dup = m.slots[0].clone();
    m.slots.push(dup);
    assert!(
        Vault::peek_bytes(&encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap()).is_err()
    );
    let mut m = model(&v);
    m.slots[1].slot_id = m.slots[0].slot_id;
    assert!(
        Vault::peek_bytes(&encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap()).is_err()
    );
}

#[test]
fn a_slot_is_bound_to_its_id_and_kind() {
    let t = t();
    let (v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    let key = owner_key(&v);
    let mut m = model(&v);
    m.slots[0].slot_id = [9; 16];
    std::fs::write(
        &t.path,
        encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        Vault::unlock_password(&t.path, PW, &t.store),
        Err(Error::Unlock)
    ));
}

#[test]
fn devices_are_owner_only_checked_and_signed() {
    let t = t();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.add_device(device(1)).unwrap();
    v.add_device(device(2)).unwrap();
    assert!(v.add_device(device(1)).is_err());
    let mut same_name = device(3);
    same_name.name = "phone 1".into();
    assert!(v.add_device(same_name).is_err());
    let mut bad_key = device(3);
    bad_key.sign_pub = vec![1, 2, 3];
    assert!(v.add_device(bad_key).is_err());
    let mut bad_transport = device(3);
    bad_transport.transports = vec!["a b".into()];
    assert!(v.add_device(bad_transport).is_err());

    let mut renamed = device(2);
    renamed.name = "tablet".into();
    renamed.expires_at = Some(5);
    v.update_device(renamed.clone()).unwrap();
    assert!(matches!(
        v.update_device(device(9)),
        Err(Error::UnknownDevice)
    ));
    v.remove_device(&[1; 16]).unwrap();
    assert!(matches!(
        v.remove_device(&[1; 16]),
        Err(Error::UnknownDevice)
    ));
    v.save(&t.path, &t.store).unwrap();

    let again = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
    assert_eq!(again.devices(), [renamed]);

    // The record is under the signature.
    let mut m = model(&v);
    m.devices[0].name = "evil".into();
    let forged = encode_as(current::FORMAT, &m, Actor::Owner, &owner_key(&v)).unwrap();
    assert!(Vault::peek_bytes(&forged).is_ok()); // re-signed by the owner: valid
    let stranger = SigningKey::from_bytes(&[3; 32]);
    let by_stranger = encode_as(current::FORMAT, &m, Actor::Owner, &stranger).unwrap();
    assert!(matches!(
        Vault::peek_bytes(&by_stranger),
        Err(Error::BadSignature)
    ));

    // Recipients cannot touch devices.
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    let keys = RecipientSecret::generate().unwrap();
    let id = v
        .add_recipient(
            "ed",
            RecipientKind::Person,
            Role::Admin,
            &keys.public().unwrap(),
        )
        .unwrap();
    v.save(&t.path.with_file_name("other.vht"), &t.store)
        .unwrap();
    let mut ed =
        Vault::open_as_recipient(&t.path.with_file_name("other.vht"), &id, &keys, &t.store)
            .unwrap();
    assert!(matches!(ed.add_device(device(1)), Err(Error::NotOwner)));
    assert!(matches!(
        ed.add_slot(future_slot("x"), |vk, aad| current::seal_vault_key(
            &KEK, aad, vk
        )),
        Err(Error::NotOwner)
    ));
}

#[test]
fn device_count_is_limited() {
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    for n in 0..current::MAX_DEVICES as u8 {
        v.add_device(device(n)).unwrap();
    }
    assert!(v.add_device(device(200)).is_err());
}

#[test]
fn rule_set_shapes_are_checked_on_write_and_read() {
    use crate::format::current::{DirRule, HostRule, Network};
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
    let host = |h: &str, port| HostRule {
        text: "t".into(),
        host: h.into(),
        subdomains: false,
        port,
    };
    let dir = |p: &str| DirRule {
        text: "t".into(),
        path: p.into(),
        write: false,
    };
    let with = |f: &dyn Fn(&mut RuleSet)| {
        let mut r = sample_binding("A");
        f(&mut r);
        r
    };
    let ok = [
        with(&|r| r.dirs = vec![dir("/home/me/work")]),
        with(&|r| {
            r.dirs = vec![
                dir("C:\\Users\\me"),
                dir("D:/work"),
                dir("\\\\srv\\share\\x"),
            ]
        }),
        with(&|r| r.network = Network::Hosts(vec![host("api.example.com", Some(443))])),
        with(&|r| r.category = Some("cloud".into())),
        // Only dirs and a network, no commands: still a rule set.
        RuleSet {
            name: "A".into(),
            dirs: vec![dir("/tmp/x")],
            network: Network::App,
            ..Default::default()
        },
    ];
    for r in ok {
        v.set_bindings("A", Some(r)).unwrap();
        assert_eq!(v.bindings().len(), 1);
    }
    let bad = [
        with(&|r| r.dirs = vec![dir("relative/path")]),
        with(&|r| r.dirs = vec![dir("/a/../b")]),
        with(&|r| r.dirs = vec![dir("C:\\a\\..\\b")]),
        with(&|r| r.dirs = vec![dir("C:rel")]),
        with(&|r| r.dirs = vec![dir("")]),
        with(&|r| {
            r.dirs = (0..=current::MAX_DIRS)
                .map(|n| dir(&format!("/d{n}")))
                .collect()
        }),
        with(&|r| r.network = Network::Hosts(vec![])),
        with(&|r| r.network = Network::Hosts(vec![host("Example.com", None)])),
        with(&|r| r.network = Network::Hosts(vec![host("a..b", None)])),
        with(&|r| r.network = Network::Hosts(vec![host("ok.com", Some(0))])),
        with(&|r| {
            r.network = Network::Hosts(
                (0..=current::MAX_HOSTS)
                    .map(|n| host(&format!("h{n}.com"), None))
                    .collect(),
            )
        }),
        with(&|r| r.category = Some(String::new())),
        with(&|r| r.downgraded_from = Some("x\ny".into())),
    ];
    for r in bad {
        assert!(v.set_bindings("A", Some(r)).is_err());
    }

    // A reader holds a file to the same checks.
    let key = owner_key(&v);
    let mut m = model(&v);
    m.bindings[0].dirs = vec![dir("relative")];
    assert!(
        Vault::peek_bytes(&encode_as(current::FORMAT, &m, Actor::Owner, &key).unwrap()).is_err()
    );
}
