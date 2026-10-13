//! The device slot, the registry and the signed decisions, against a software
//! phone and a real vault file.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vahta_auth::loopback::{Behavior, LoopbackDevice};
use vahta_auth::*;
use vahta_vault::store::LocalStore;
use vahta_vault::{Device, Error, KdfParams, Kind, RecoveryKey, RecoveryPlan, Tier, Vault};
use zeroize::Zeroizing;

const PW: &[u8] = b"correct horse";

struct World {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: LocalStore,
    recovery: RecoveryKey,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    let store = LocalStore::new(dir.path().join("store"));
    let (mut v, recovery) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("A", b"fake-one", Kind::Env, Tier::EachUse).unwrap();
    v.save(&path, &store).unwrap();
    World {
        _dir: dir,
        path,
        store,
        recovery,
    }
}

struct Ctx {
    req: Request,
    pw: Vec<&'static [u8]>,
    asked_pw: usize,
    devices: Vec<LinkedDevice>,
}

impl UnlockCtx for Ctx {
    fn request(&self) -> &Request {
        &self.req
    }
    fn password(&mut self, _: Option<&str>) -> Result<Option<Zeroizing<Vec<u8>>>, AuthError> {
        self.asked_pw += 1;
        Ok(if self.pw.is_empty() {
            None
        } else {
            Some(Zeroizing::new(self.pw.remove(0).to_vec()))
        })
    }
    fn recovery_key(&mut self) -> Result<Option<RecoveryKey>, AuthError> {
        Ok(None)
    }
    fn device(&mut self, id: &[u8; 16]) -> Option<LinkedDevice> {
        self.devices
            .iter()
            .find(|d| &d.record.device_id == id)
            .cloned()
    }
}

fn ctx(
    vault_id: [u8; 16],
    phone: &Arc<LoopbackDevice>,
    record: &Device,
    pw: &[&'static [u8]],
) -> Ctx {
    Ctx {
        req: Request::new(
            Action::RunEachUse {
                names: vec!["A".into()],
                command: "deploy".into(),
            },
            "/p",
            vault_id,
            Duration::from_secs(30),
        )
        .unwrap(),
        pw: pw.to_vec(),
        asked_pw: 0,
        devices: vec![LinkedDevice {
            record: record.clone(),
            channel: phone.clone(),
        }],
    }
}

fn paired(w: &World, expires: Option<u64>) -> (Arc<LoopbackDevice>, Device) {
    let phone = Arc::new(LoopbackDevice::new("phone"));
    let mut v = Vault::unlock_password(&w.path, PW, &w.store).unwrap();
    enroll_device(&mut v, phone.record(None), expires).unwrap();
    v.save(&w.path, &w.store).unwrap();
    let record = Vault::peek(&w.path).unwrap().devices[0].clone();
    (phone, record)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn slot_params(w: &World) -> Vec<u8> {
    Vault::peek(&w.path)
        .unwrap()
        .slots
        .iter()
        .find(|s| s.info.kind == vahta_vault::SLOT_DEVICE)
        .unwrap()
        .params
        .clone()
}

#[test]
fn a_paired_device_opens_the_vault_without_the_password_and_the_slot_is_rewrapped() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let before = slot_params(&w);
    let gen_before = Vault::peek(&w.path).unwrap().generation;
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(Vault::peek(&w.path).unwrap().vault_id, &phone, &record, &[]);
    let (vault, by) = Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    assert_eq!(c.asked_pw, 0, "no password window");
    assert_eq!(by.factor, Factor::PossessionBiometric);
    assert_eq!(by.device_id, Some(record.device_id));
    assert!(by.rewrapped);
    assert_eq!(vault.get("A").unwrap().expose(), b"fake-one");
    // A new ephemeral key is in the file, and the file is a generation on.
    assert_ne!(slot_params(&w), before);
    assert!(Vault::peek(&w.path).unwrap().generation > gen_before);

    // The next unlock works against the rewrapped slot, and the old shared
    // secret does not open the file any more.
    let old_shared = phone.shared_secret(&before).unwrap();
    let old_kek = vahta_auth_kek(&old_shared, &record, &before);
    assert!(matches!(
        Vault::unlock_with_slot(&w.path, &record.device_id, &old_kek, &w.store),
        Err(Error::Unlock)
    ));
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(vault.vault_id(), &phone, &record, &[]);
    Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
}

/// The KEK a captured shared secret would give (the derivation is public).
fn vahta_auth_kek(shared: &[u8; 32], d: &Device, params: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut info = b"vahta/v2/device-kek".to_vec();
    info.extend_from_slice(&d.device_id);
    info.extend_from_slice(params);
    vahta_vault::crypto::hkdf(shared, &info)
}

#[test]
fn an_unreachable_denying_or_silent_phone_falls_through_to_the_password() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    for b in [None, Some(Behavior::Deny), Some(Behavior::Timeout)] {
        if let Some(b) = b {
            phone.queue(b);
        }
        let mut c = ctx(id, &phone, &record, &[PW]);
        let (v, by) = Registry::standard()
            .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
            .unwrap();
        assert_eq!(by.factor, Factor::Knowledge);
        assert_eq!(c.asked_pw, 1);
        assert_eq!(v.get("A").unwrap().expose(), b"fake-one");
    }
}

#[test]
fn a_forged_or_replayed_answer_is_refused_and_the_password_still_works() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    // A good unlock first, so the phone has an old decision to replay.
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(id, &phone, &record, &[]);
    Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    for cheat in [Behavior::Forge, Behavior::Replay] {
        phone.queue(cheat);
        let mut c = ctx(id, &phone, &record, &[PW]);
        let (_, by) = Registry::standard()
            .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
            .unwrap();
        assert_eq!(by.factor, Factor::Knowledge, "{cheat:?} must not open it");
    }
    // Directly: the unlocker itself refuses.
    phone.queue(Behavior::Forge);
    let mut c = ctx(id, &phone, &record, &[]);
    let slot = Vault::peek(&w.path)
        .unwrap()
        .slots
        .into_iter()
        .find(|s| s.info.kind == 2)
        .unwrap();
    let err = DeviceUnlocker
        .unwrap_kek(&slot.info, &slot.params, &mut c)
        .err()
        .unwrap();
    assert!(matches!(err, AuthError::BadDecision(_)));
}

#[test]
fn an_expired_device_or_slot_is_refused() {
    let w = world();
    let (phone, record) = paired(&w, Some(now() + 2));
    let id = Vault::peek(&w.path).unwrap().vault_id;
    // Still good.
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(id, &phone, &record, &[]);
    Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    // The rewrap kept the expiry.
    let peek = Vault::peek(&w.path).unwrap();
    assert!(
        peek.slots
            .iter()
            .any(|s| s.info.expires_at == record.expires_at && s.info.kind == 2)
    );
    std::thread::sleep(Duration::from_millis(2100));
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(id, &phone, &record, &[PW]);
    let (_, by) = Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    assert_eq!(by.factor, Factor::Knowledge, "the phone was not asked");
    // It was never asked: its script still holds the approval.
    assert!(phone.reachable());
    // The vault refuses the slot even given the right key.
    let params = slot_params(&w);
    let shared = phone.shared_secret(&params).unwrap();
    let kek = vahta_auth_kek(&shared, &record, &params);
    assert!(matches!(
        Vault::unlock_with_slot(&w.path, &record.device_id, &kek, &w.store),
        Err(Error::Unlock)
    ));
}

#[test]
fn a_need_the_phone_cannot_meet_never_asks_it() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(id, &phone, &record, &[PW]);
    let (_, by) = Registry::standard()
        .unlock(&w.path, &w.store, Need::PasswordOnly, &mut c)
        .unwrap();
    assert_eq!(by.factor, Factor::Knowledge);
}

#[test]
fn removing_the_slot_and_rekeying_makes_the_old_phone_useless_on_the_new_file() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let copy = std::fs::read(&w.path).unwrap();
    let old_params = slot_params(&w);

    let mut v = Vault::unlock_password(&w.path, PW, &w.store).unwrap();
    v.remove_device(&record.device_id).unwrap();
    let kek = v.password_kek(PW).unwrap();
    let out = v.rekey(&kek, RecoveryPlan::Replace, vec![]).unwrap();
    assert_eq!(out.dropped.len(), 1);
    v.save(&w.path, &w.store).unwrap();

    // The phone's key, applied to the slot it knew, opens only the old copy.
    let shared = phone.shared_secret(&old_params).unwrap();
    let kek = vahta_auth_kek(&shared, &record, &old_params);
    let old = w._dir.path().join("old.vht");
    std::fs::write(&old, &copy).unwrap();
    let elsewhere = LocalStore::new(w._dir.path().join("elsewhere"));
    assert!(Vault::unlock_with_slot(&old, &record.device_id, &kek, &elsewhere).is_ok());
    assert!(matches!(
        Vault::unlock_with_slot(&w.path, &record.device_id, &kek, &w.store),
        Err(Error::Unlock)
    ));
    assert!(Vault::peek(&w.path).unwrap().devices.is_empty());
}

#[test]
fn a_kept_device_is_wrapped_for_the_new_key_without_the_phone() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    let mut v = Vault::unlock_password(&w.path, PW, &w.store).unwrap();
    let kek = v.password_kek(PW).unwrap();
    v.rekey(
        &kek,
        RecoveryPlan::Keep(&w.recovery),
        vec![kept_device_slot(&record).unwrap()],
    )
    .unwrap();
    v.save(&w.path, &w.store).unwrap();
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(id, &phone, &record, &[]);
    let (vault, by) = Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    assert_eq!(by.factor, Factor::PossessionBiometric);
    assert_eq!(vault.get("A").unwrap().expose(), b"fake-one");
}

#[test]
fn recovery_opens_when_the_password_is_forgotten() {
    // B3: forgot the password, use the paper key, set a new password.
    let w = world();
    let mut v = Vault::unlock_recovery(&w.path, &w.recovery, &w.store).unwrap();
    v.change_password(b"a new password", KdfParams::TEST)
        .unwrap();
    v.save(&w.path, &w.store).unwrap();
    assert!(matches!(
        Vault::unlock_password(&w.path, PW, &w.store),
        Err(Error::Unlock)
    ));
    let v = Vault::unlock_password(&w.path, b"a new password", &w.store).unwrap();
    assert_eq!(v.get("A").unwrap().expose(), b"fake-one");
}

#[test]
fn a_device_approver_gives_a_verified_choice() {
    let phone = Arc::new(LoopbackDevice::new("phone"));
    let record = phone.record(None);
    let approver = DeviceApprover {
        record: record.clone(),
        channel: phone.clone(),
    };
    let req = Request::new(Action::AlarmLock, "/p", [0; 16], Duration::from_secs(30))
        .unwrap()
        .with_options(&["Yes".to_string(), "No".to_string()]);
    phone.queue(Behavior::Approve(1));
    let got = decide_any(
        &[&approver],
        &req,
        &req.options,
        Need::Presence,
        Duration::from_secs(5),
    )
    .unwrap()
    .unwrap();
    assert_eq!((got.choice, got.device_id), (1, Some(record.device_id)));
    // Out of reach: not asked at all.
    assert!(
        decide_any(
            &[&approver],
            &req,
            &req.options,
            Need::Presence,
            Duration::from_secs(5)
        )
        .is_err()
    );
    // A forged answer is an error, not a yes.
    phone.queue(Behavior::Forge);
    assert!(
        approver
            .decide(&req, &req.options, Duration::from_secs(5), &Cancel::new())
            .is_err()
    );
    // An old answer to another request.
    phone.queue(Behavior::Approve(0));
    let other = Request::new(Action::AlarmLock, "/p", [0; 16], Duration::from_secs(30))
        .unwrap()
        .with_options(&req.options);
    phone.approve(&other).unwrap();
    phone.queue(Behavior::Replay);
    assert!(
        approver
            .decide(&req, &req.options, Duration::from_secs(5), &Cancel::new())
            .is_err()
    );
}
