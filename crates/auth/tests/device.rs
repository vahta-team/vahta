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
    /// What `attempt_failed` was told.
    failed: Vec<String>,
    /// Stands for the person choosing the password while the phone is asked:
    /// the phone is then not asked at all, and the unlock passes on.
    choose_password: bool,
    waited: usize,
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
    fn ask_device(
        &mut self,
        _slot: &vahta_vault::SlotInfo,
        cancel: &Cancel,
        ask: &(dyn Fn(&Cancel) -> Result<UnlockReply, AuthError> + Sync),
    ) -> Result<UnlockReply, AuthError> {
        self.waited += 1;
        if self.choose_password {
            cancel.cancel();
            return Err(AuthError::Unavailable("you chose the password".into()));
        }
        ask(cancel)
    }
    fn attempt_failed(&mut self, _: &vahta_vault::SlotInfo, why: &AuthError) {
        self.failed.push(why.to_string());
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
        failed: Vec::new(),
        choose_password: false,
        waited: 0,
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
fn an_unreachable_or_silent_phone_falls_through_to_the_password() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    for b in [None, Some(Behavior::Timeout)] {
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
fn a_no_on_the_phone_ends_the_unlock_and_the_password_is_never_asked() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    phone.queue(Behavior::Deny);
    // The password is at hand, and must not be asked for.
    let mut c = ctx(id, &phone, &record, &[PW]);
    let got = Registry::standard().unlock(&w.path, &w.store, Need::Knowledge, &mut c);
    assert!(matches!(got, Err(AuthError::Denied)), "{:?}", got.err());
    assert_eq!(c.asked_pw, 0);
    // The journal is told, once.
    assert_eq!(c.failed, ["refused on the device"]);
    // The same with the phone named first, and with the password current.
    phone.queue(Behavior::Deny);
    let mut c = ctx(id, &phone, &record, &[PW]);
    let pref = UnlockPref::parse("device:phone").unwrap();
    let got = Registry::standard().unlock_by(&w.path, &w.store, Need::Knowledge, &pref, &mut c);
    assert!(matches!(got, Err(AuthError::Denied)));
    assert_eq!(c.asked_pw, 0);
    // A no is not forever: the next ask goes to the phone again.
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(id, &phone, &record, &[]);
    let (_, by) = Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    assert_eq!(by.factor, Factor::PossessionBiometric);
    // The master password still opens the vault on an explicit unlock.
    let mut c = ctx(id, &phone, &record, &[PW]);
    let (_, by) = Registry::standard()
        .unlock_with(vahta_vault::SLOT_PASSWORD, &w.path, &w.store, &mut c)
        .unwrap();
    assert_eq!(by.factor, Factor::Knowledge);
    assert_eq!(c.waited, 0, "no phone in an explicit password unlock");
}

#[test]
fn choosing_the_password_while_the_phone_is_asked_goes_to_the_password() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    // The phone would have said yes; the person did not wait for it.
    phone.queue(Behavior::Approve(0));
    let mut c = ctx(id, &phone, &record, &[PW]);
    c.choose_password = true;
    let (_, by) = Registry::standard()
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    assert_eq!(by.factor, Factor::Knowledge);
    assert_eq!((c.waited, c.asked_pw), (1, 1));
}

#[test]
fn a_no_on_the_phone_refuses_an_approval_at_once_and_the_window_is_stopped() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;
    // A window that waits for a person until it is told to stop.
    struct Window(AtomicBool);
    impl Approver for Window {
        fn factor(&self) -> Factor {
            Factor::Presence
        }
        fn label(&self) -> String {
            "window".into()
        }
        fn available(&self) -> bool {
            true
        }
        fn decide(
            &self,
            _: &Request,
            _: &[String],
            _: Duration,
            cancel: &Cancel,
        ) -> Result<Option<usize>, AuthError> {
            let end = Instant::now() + Duration::from_secs(20);
            while Instant::now() < end {
                if cancel.is_cancelled() {
                    self.0.store(true, Ordering::SeqCst);
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None)
        }
    }
    let phone = Arc::new(LoopbackDevice::new("phone"));
    let approver = DeviceApprover {
        record: phone.record(None),
        channel: phone.clone(),
    };
    let window = Window(AtomicBool::new(false));
    let req = Request::new(Action::AlarmLock, "/p", [0; 16], Duration::from_secs(30))
        .unwrap()
        .with_options(&["Yes".to_string(), "No".to_string()]);
    phone.queue(Behavior::Deny);
    let started = Instant::now();
    let got = decide_any(
        &[&window, &approver],
        &req,
        &req.options,
        Need::Presence,
        Duration::from_secs(20),
    );
    assert!(matches!(got, Err(AuthError::Denied)), "{:?}", got.err());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        window.0.load(Ordering::SeqCst),
        "the window was told to stop"
    );
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

// --- The current unlock method -----------------------------------------------------------

/// A phone that counts how often it was asked to unlock.
struct Counting {
    inner: Arc<LoopbackDevice>,
    asked: std::sync::atomic::AtomicUsize,
}

impl Counting {
    fn new(inner: Arc<LoopbackDevice>) -> Arc<Counting> {
        Arc::new(Counting {
            inner,
            asked: std::sync::atomic::AtomicUsize::new(0),
        })
    }
    fn asked(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl DeviceChannel for Counting {
    fn unlock(&self, req: &Request, eph_pub: &[u8]) -> Result<UnlockReply, AuthError> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.unlock(req, eph_pub)
    }
    fn approve(&self, req: &Request) -> Result<Decision, AuthError> {
        self.inner.approve(req)
    }
}

fn counting_ctx(
    vault_id: [u8; 16],
    phones: &[(&Arc<Counting>, &Device)],
    pw: &[&'static [u8]],
) -> Ctx {
    let mut c = ctx(
        vault_id,
        &Arc::new(LoopbackDevice::new("unused")),
        &phones[0].1.clone(),
        pw,
    );
    c.devices = phones
        .iter()
        .map(|(p, r)| LinkedDevice {
            record: (*r).clone(),
            channel: (*p).clone(),
        })
        .collect();
    c
}

fn pair_another(w: &World, name: &str) -> (Arc<LoopbackDevice>, Device) {
    let phone = Arc::new(LoopbackDevice::new(name));
    let mut v = Vault::unlock_password(&w.path, PW, &w.store).unwrap();
    enroll_device(&mut v, phone.record(None), None).unwrap();
    v.save(&w.path, &w.store).unwrap();
    let record = Vault::peek(&w.path)
        .unwrap()
        .devices
        .into_iter()
        .find(|d| d.name == name)
        .unwrap();
    (phone, record)
}

#[test]
fn by_default_the_last_enrolled_method_is_current() {
    let w = world();
    let reg = Registry::standard();
    let id = Vault::peek(&w.path).unwrap().vault_id;
    // Only the password: it is current.
    let peek = Vault::peek(&w.path).unwrap();
    let now_ = reg
        .current(&peek, Need::Knowledge, &UnlockPref::Last)
        .unwrap();
    assert_eq!(now_.kind, vahta_vault::SLOT_PASSWORD);

    let (phone, record) = paired(&w, None);
    let (tablet, tablet_record) = pair_another(&w, "tablet");
    let peek = Vault::peek(&w.path).unwrap();
    // The tablet came last.
    let cur = reg
        .current(&peek, Need::Knowledge, &UnlockPref::Last)
        .unwrap();
    assert_eq!(cur.slot_id, tablet_record.device_id);
    let order: Vec<_> = reg
        .order(&peek, Need::Knowledge, &UnlockPref::Last)
        .iter()
        .map(|s| s.label.clone())
        .collect();
    assert_eq!(order.len(), 3);
    assert_eq!(
        order.last().unwrap(),
        "password",
        "the password is the fallback"
    );

    // And the tablet is the one asked.
    let (p, t) = (Counting::new(phone.clone()), Counting::new(tablet.clone()));
    tablet.queue(Behavior::Approve(0));
    let mut c = counting_ctx(id, &[(&p, &record), (&t, &tablet_record)], &[]);
    let (_, by) = reg
        .unlock(&w.path, &w.store, Need::Knowledge, &mut c)
        .unwrap();
    assert_eq!(by.device_id, Some(tablet_record.device_id));
    assert_eq!((p.asked(), t.asked(), c.asked_pw), (0, 1, 0));

    // The rewrap after that use did not make the slot newer: same order.
    let peek = Vault::peek(&w.path).unwrap();
    let cur = reg
        .current(&peek, Need::Knowledge, &UnlockPref::Last)
        .unwrap();
    assert_eq!(cur.slot_id, tablet_record.device_id);
    // An expired newest device is not current.
    let mut v = Vault::unlock_password(&w.path, PW, &w.store).unwrap();
    refresh_device(&mut v, &tablet_record.device_id, Some(1)).unwrap();
    v.save(&w.path, &w.store).unwrap();
    let peek = Vault::peek(&w.path).unwrap();
    let cur = reg
        .current(&peek, Need::Knowledge, &UnlockPref::Last)
        .unwrap();
    assert_eq!(cur.slot_id, record.device_id);
}

#[test]
fn an_explicit_password_does_not_ask_the_phone() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let id = Vault::peek(&w.path).unwrap().vault_id;
    let p = Counting::new(phone.clone());
    phone.queue(Behavior::Approve(0));
    let mut c = counting_ctx(id, &[(&p, &record)], &[PW]);
    let (v, by) = Registry::standard()
        .unlock_by(
            &w.path,
            &w.store,
            Need::Knowledge,
            &UnlockPref::Password,
            &mut c,
        )
        .unwrap();
    assert_eq!(by.factor, Factor::Knowledge);
    assert_eq!((p.asked(), c.asked_pw), (0, 1));
    assert_eq!(v.get("A").unwrap().expose(), b"fake-one");
    // A cancelled password window ends it; the phone is not a way around that.
    let mut c = counting_ctx(id, &[(&p, &record)], &[]);
    assert!(matches!(
        Registry::standard().unlock_by(
            &w.path,
            &w.store,
            Need::Knowledge,
            &UnlockPref::Password,
            &mut c
        ),
        Err(AuthError::Cancelled)
    ));
    assert_eq!(p.asked(), 0);
}

#[test]
fn an_explicit_device_is_asked_first_and_the_password_follows() {
    let w = world();
    let (phone, record) = paired(&w, None);
    let (tablet, tablet_record) = pair_another(&w, "tablet");
    let id = Vault::peek(&w.path).unwrap().vault_id;
    let (p, t) = (Counting::new(phone.clone()), Counting::new(tablet.clone()));
    let pref = UnlockPref::parse("device:PHONE").unwrap();

    // Phone first although the tablet is newer; by name in any case.
    phone.queue(Behavior::Approve(0));
    let mut c = counting_ctx(id, &[(&p, &record), (&t, &tablet_record)], &[]);
    let (_, by) = Registry::standard()
        .unlock_by(&w.path, &w.store, Need::Knowledge, &pref, &mut c)
        .unwrap();
    assert_eq!(by.device_id, Some(record.device_id));
    assert_eq!((p.asked(), t.asked()), (1, 0));

    // Out of reach or silent: the next in line is asked (the tablet), then the
    // password.
    phone.queue(Behavior::Timeout);
    tablet.queue(Behavior::Timeout);
    let mut c = counting_ctx(id, &[(&p, &record), (&t, &tablet_record)], &[PW]);
    let (_, by) = Registry::standard()
        .unlock_by(&w.path, &w.store, Need::Knowledge, &pref, &mut c)
        .unwrap();
    assert_eq!(by.factor, Factor::Knowledge);
    assert_eq!((p.asked(), t.asked(), c.asked_pw), (2, 1, 1));

    // The start of the id works too.
    let by_id = UnlockPref::Device(hex_id(&record.device_id)[..8].to_string());
    let peek = Vault::peek(&w.path).unwrap();
    assert_eq!(
        Registry::standard()
            .current(&peek, Need::Knowledge, &by_id)
            .unwrap()
            .slot_id,
        record.device_id
    );
}

fn hex_id(id: &[u8; 16]) -> String {
    vahta_vault::hex_encode(id)
}

#[test]
fn a_setting_that_names_no_device_here_is_the_default() {
    let w = world();
    let (_, record) = paired(&w, None);
    let peek = Vault::peek(&w.path).unwrap();
    let reg = Registry::standard();
    for pref in [
        UnlockPref::Device("nobody".into()),
        UnlockPref::Device("ab".into()),
    ] {
        assert_eq!(
            reg.current(&peek, Need::Knowledge, &pref).unwrap().slot_id,
            record.device_id
        );
    }
    // Password-only actions never have a phone in the list.
    let only = reg.order(&peek, Need::PasswordOnly, &UnlockPref::Last);
    assert_eq!(only.len(), 1);
    assert_eq!(only[0].kind, vahta_vault::SLOT_PASSWORD);
    assert_eq!(UnlockPref::parse("device:"), None);
    assert_eq!(UnlockPref::parse("phone"), None);
    assert_eq!(
        UnlockPref::parse("device: x y").unwrap().as_text(),
        "device:x y"
    );
}
