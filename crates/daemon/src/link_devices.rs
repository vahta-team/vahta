//! Reaching paired phones: [`LinkDevices`] implements `vahta_auth::DeviceLinks`
//! over `vahta-link` (Bluetooth LE and the local network, one Noise session
//! over either).
//!
//! **What is kept, and where.** In the daemon's data directory, under
//! `link/<vault id>/`:
//!
//! * `desktop.key`: this computer's static X25519 key for the phone link, one
//!   per vault, 64 hex characters, mode 0600. It is a *transport identity*, not
//!   a vault secret: it lets a phone recognise this computer, nothing more.
//!   Whoever reads it can talk to a paired phone as this computer, but cannot
//!   answer for the phone, so cannot unlock or approve anything (approvals are
//!   checked against the keys in the vault's signed device list; unlocking
//!   needs the phone's own key-agreement key). The worst they can do is make
//!   the phone show prompts, which the person declines.
//! * `<device id>.json`: for each paired phone, its static Noise public key
//!   and where it was last reached (a Bluetooth address, a LAN address).
//!   These are hints and a pin, not trust: the vault record (signed) holds the
//!   keys that matter. They live here, not in the vault, because a Bluetooth
//!   address changes and because they are per computer: the phone pins *this*
//!   computer's key, so another computer with a copy of the vault cannot reach
//!   the phone and falls back to the password.
//!
//! On non-Linux systems there is no Bluetooth transport (`LinkDevices::standard`
//! uses the local network alone).
//!
//! **Reachability** is a cached guess (`reachable`): the last probe or contact
//! counts for 45 seconds if it succeeded and 10 if it failed, and a stale entry
//! is refreshed by a probe on a thread of its own, never in the caller's way.
//! A phone nothing has been tried with yet is assumed reachable.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use vahta_auth::{
    AuthError, Cancel, Decision as AuthDecision, DeviceChannel, DeviceLinks, NewDevice,
    PairContext, PairingCode, Request, UnlockReply, device_id_for,
};
use vahta_link::channel::{Handshake, Keypair, PipeChannel};
use vahta_link::lan::LanTransport;
use vahta_link::messages::{ApproveRequest, Choice, UnlockRequest, UnlockResponse, pairing_tag};
use vahta_link::pairing::pair_desktop;
use vahta_link::{
    DeviceAddr, LinkError, Message, PairOffer, PeerHint, Transport, probe_any, reach_first,
    render_qr, unix_now,
};
use vahta_vault::{Device, hex_decode, hex_encode};
use zeroize::Zeroizing;

/// How long a connection to a phone is tried before an approval or an unlock
/// gives up on it (a Bluetooth connect is slow; the window is open meanwhile).
const CONNECT_WAIT: Duration = Duration::from_secs(12);
/// How long a probe looks for a phone.
const PROBE_WAIT: Duration = Duration::from_secs(5);
/// How long a successful probe or contact counts.
const SEEN_FOR: Duration = Duration::from_secs(45);
/// How long a failed one counts.
const MISSED_FOR: Duration = Duration::from_secs(10);
/// How long a handshake or a pairing step may take once connected.
const STEP_WAIT: Duration = Duration::from_secs(10);
/// One try at finding a pairing phone; the loop checks for cancellation
/// between tries.
const PAIR_TRY: Duration = Duration::from_secs(4);
/// How often a waiting approval looks at its cancellation.
const POLL: Duration = Duration::from_millis(200);
/// The longest a pairing code lives, whatever the caller waits.
const MAX_OFFER_SECS: u64 = 300;

#[derive(Debug, Clone, Copy)]
struct Seen {
    ok: bool,
    at: Instant,
    probing: bool,
}

impl Seen {
    fn fresh(&self) -> bool {
        self.at.elapsed() < if self.ok { SEEN_FOR } else { MISSED_FOR }
    }
}

/// What is kept of a paired phone (`<device id>.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Phone {
    name: String,
    /// Hex of its static X25519 public key.
    static_pub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ble_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lan_hint: Option<String>,
}

impl Phone {
    fn key(&self) -> Option<[u8; 32]> {
        hex_decode(&self.static_pub)?.try_into().ok()
    }

    fn addr(&self) -> Option<DeviceAddr> {
        Some(DeviceAddr::paired(
            &self.name,
            self.key()?,
            self.ble_address.clone(),
            self.lan_hint.as_deref().and_then(|s| s.parse().ok()),
        ))
    }
}

struct Core {
    dir: PathBuf,
    transports: Vec<Arc<dyn Transport>>,
    pair_hint: Option<SocketAddr>,
    seen: Mutex<HashMap<[u8; 16], Seen>>,
}

/// Paired phones, reached over Bluetooth LE and the local network.
pub struct LinkDevices {
    core: Arc<Core>,
}

impl LinkDevices {
    /// The shipped set of transports, keeping its state under `data/link`.
    pub fn standard(data: &Path) -> LinkDevices {
        let transports: Vec<Arc<dyn Transport>> = vec![
            #[cfg(target_os = "linux")]
            Arc::new(vahta_link::ble::BleTransport::default()),
            Arc::new(LanTransport::new()),
        ];
        LinkDevices::with_transports(data.join("link"), transports)
    }

    /// Any set of transports, keeping its state in `dir` (tests use the memory
    /// transport and the LAN transport on loopback).
    pub fn with_transports(dir: PathBuf, transports: Vec<Arc<dyn Transport>>) -> LinkDevices {
        LinkDevices {
            core: Arc::new(Core {
                dir,
                transports,
                pair_hint: None,
                seen: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Where a phone that is pairing listens, when discovery cannot find it
    /// (a test; a phone on a network without multicast).
    pub fn with_pair_hint(mut self, addr: SocketAddr) -> LinkDevices {
        if let Some(core) = Arc::get_mut(&mut self.core) {
            core.pair_hint = Some(addr);
        }
        self
    }
}

// --- State on disk ------------------------------------------------------------------------

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

impl Core {
    fn vault_dir(&self, vault_id: &[u8; 16]) -> PathBuf {
        self.dir.join(hex_encode(vault_id))
    }

    fn phone_file(&self, vault_id: &[u8; 16], id: &[u8; 16]) -> PathBuf {
        self.vault_dir(vault_id)
            .join(format!("{}.json", hex_encode(id)))
    }

    /// This computer's key for the vault; made on first use.
    fn desktop_key(&self, vault_id: &[u8; 16]) -> Result<Keypair, AuthError> {
        let io = |e: std::io::Error| AuthError::Unavailable(format!("the phone link's key: {e}"));
        let dir = self.vault_dir(vault_id);
        let path = dir.join("desktop.key");
        if let Ok(text) = std::fs::read_to_string(&path) {
            let bytes: Zeroizing<Vec<u8>> =
                Zeroizing::new(hex_decode(text.trim()).unwrap_or_default());
            let private: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                AuthError::Unavailable("the phone link's key file is damaged".into())
            })?;
            return Keypair::from_private(&private).map_err(link_err);
        }
        private_dir(&dir).map_err(io)?;
        let kp = Keypair::generate().map_err(link_err)?;
        let text = Zeroizing::new(hex_encode(&kp.private[..]));
        write_private(&path, text.as_bytes()).map_err(io)?;
        Ok(kp)
    }

    fn save_phone(&self, vault_id: &[u8; 16], id: &[u8; 16], p: &Phone) -> std::io::Result<()> {
        private_dir(&self.vault_dir(vault_id))?;
        let text = serde_json::to_string_pretty(p).map_err(std::io::Error::other)?;
        write_private(&self.phone_file(vault_id, id), text.as_bytes())
    }

    fn load_phone(&self, vault_id: &[u8; 16], id: &[u8; 16]) -> Option<Phone> {
        let text = std::fs::read_to_string(self.phone_file(vault_id, id)).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn mark(&self, id: &[u8; 16], ok: bool) {
        if let Ok(mut seen) = self.seen.lock() {
            let probing = seen.get(id).is_some_and(|s| s.probing);
            seen.insert(
                *id,
                Seen {
                    ok,
                    at: Instant::now(),
                    probing,
                },
            );
        }
    }
}

fn link_err(e: LinkError) -> AuthError {
    AuthError::Unavailable(e.to_string())
}

/// This computer's name, for the phone's confirmation screen.
fn computer_name() -> String {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_default();
    let clean: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(48)
        .collect();
    if clean.is_empty() {
        "this computer".to_string()
    } else {
        clean
    }
}

// --- DeviceLinks --------------------------------------------------------------------------

impl DeviceLinks for LinkDevices {
    fn channel(&self, vault_id: &[u8; 16], device: &Device) -> Option<Arc<dyn DeviceChannel>> {
        let phone = self.core.load_phone(vault_id, &device.device_id)?;
        phone.key()?;
        Some(Arc::new(LinkChannel {
            core: self.core.clone(),
            vault_id: *vault_id,
            device_id: device.device_id,
            phone,
        }))
    }

    fn pair(&self, name: &str, ctx: &PairContext<'_>) -> Result<NewDevice, AuthError> {
        let core = &self.core;
        let kp = core.desktop_key(&ctx.vault_id)?;
        let now = unix_now();
        let ttl = ctx.wait.as_secs().clamp(1, MAX_OFFER_SECS);
        let offer = PairOffer::new(kp.public, ctx.vault_id, &computer_name(), now, ttl)
            .map_err(link_err)?;
        let text = offer.to_qr_string();
        let qr =
            render_qr(&text).map_err(|e| AuthError::Unavailable(format!("the QR code: {e}")))?;
        (ctx.show)(PairingCode {
            qr,
            text,
            expires_at: offer.expires_at,
        });

        let target = DeviceAddr::pairing(pairing_tag(&offer.psk), core.pair_hint);
        let end = Instant::now() + Duration::from_secs(ttl);
        let (hint, accept) = loop {
            if ctx.cancel.is_cancelled() {
                return Err(AuthError::Cancelled);
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(AuthError::Unavailable(
                    "no phone connected before the pairing code expired".into(),
                ));
            }
            let Ok((_, mut pipe)) = reach_first(
                &core.transports,
                &target,
                Instant::now() + PAIR_TRY.min(left),
            ) else {
                // Nothing yet (a transport that fails at once must not spin).
                std::thread::sleep(Duration::from_millis(100).min(left));
                continue;
            };
            let hint = pipe.peer_hint();
            let _ = pipe.set_recv_timeout(Some(STEP_WAIT));
            // Whoever dials with the wrong code, or speaks nonsense, is dropped
            // and the wait goes on: the code is still good.
            if let Ok(paired) = pair_desktop(pipe, &offer, &kp, unix_now()) {
                break (hint, paired.accept);
            }
        };

        let id = device_id_for(&accept.sign_pub, &accept.ecdh_pub);
        let (mut ble, mut lan) = (None, None);
        match hint {
            Some(PeerHint::Ble(a)) => ble = Some(a),
            Some(PeerHint::Lan(a)) => lan = Some(a.to_string()),
            None => {}
        }
        let phone = Phone {
            name: accept.phone_name.clone(),
            static_pub: hex_encode(&accept.phone_static_pub),
            ble_address: ble,
            lan_hint: lan,
        };
        core.save_phone(&ctx.vault_id, &id, &phone)
            .map_err(|e| AuthError::Unavailable(format!("cannot keep the phone's keys: {e}")))?;
        core.mark(&id, true);
        // The name the person typed is the one the vault records; the phone's
        // own name for itself is kept beside its keys.
        Ok(NewDevice {
            name: name.to_string(),
            sign_pub: accept.sign_pub,
            ecdh_pub: accept.ecdh_pub,
            transports: core
                .transports
                .iter()
                .map(|t| t.name().to_string())
                .collect(),
        })
    }

    fn forget(&self, vault_id: &[u8; 16], device_id: &[u8; 16]) {
        let _ = std::fs::remove_file(self.core.phone_file(vault_id, device_id));
        if let Ok(mut seen) = self.core.seen.lock() {
            seen.remove(device_id);
        }
    }
}

// --- One phone ----------------------------------------------------------------------------

struct LinkChannel {
    core: Arc<Core>,
    vault_id: [u8; 16],
    device_id: [u8; 16],
    phone: Phone,
}

impl LinkChannel {
    fn not_in_reach(&self, why: impl std::fmt::Display) -> AuthError {
        AuthError::Unavailable(format!("{} is not in reach: {why}", self.phone.name))
    }

    /// A Noise session with the phone, tried until `connect_by`.
    fn session(&self, connect_by: Instant) -> Result<PipeChannel, AuthError> {
        let core = &self.core;
        let addr = self
            .phone
            .addr()
            .ok_or_else(|| self.not_in_reach("its record is damaged"))?;
        let kp = core.desktop_key(&self.vault_id)?;
        let result = (|| {
            let (_, mut pipe) = reach_first(&core.transports, &addr, connect_by)?;
            let hint = pipe.peer_hint();
            pipe.set_recv_timeout(Some(STEP_WAIT))?;
            let chan =
                Handshake::session_initiator(&kp, &addr.static_pub, &self.vault_id)?.run(pipe)?;
            Ok::<_, LinkError>((chan, hint))
        })();
        match result {
            Ok((chan, hint)) => {
                core.mark(&self.device_id, true);
                self.remember(hint);
                Ok(chan)
            }
            Err(e) => {
                core.mark(&self.device_id, false);
                Err(self.not_in_reach(e))
            }
        }
    }

    /// Keep where the phone was found this time, when it changed.
    fn remember(&self, hint: Option<PeerHint>) {
        let mut phone = self.phone.clone();
        match hint {
            Some(PeerHint::Ble(a)) => phone.ble_address = Some(a),
            Some(PeerHint::Lan(a)) => phone.lan_hint = Some(a.to_string()),
            None => return,
        }
        if phone != self.phone {
            let _ = self
                .core
                .save_phone(&self.vault_id, &self.device_id, &phone);
        }
    }

    /// Waits for the phone's answer to the request already sent, until the
    /// request ends or `cancel` fires.
    fn wait_for(
        &self,
        chan: &mut PipeChannel,
        req: &Request,
        cancel: &Cancel,
    ) -> Result<Message, AuthError> {
        let end = Instant::now() + Duration::from_secs(req.expires_at.saturating_sub(unix_now()));
        loop {
            if cancel.is_cancelled() {
                return Err(AuthError::Cancelled);
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(AuthError::Timeout);
            }
            chan.set_recv_timeout(Some(POLL.min(left)))
                .map_err(|e| self.not_in_reach(e))?;
            match chan.recv() {
                Ok(Message::Ping(n)) => chan
                    .send(&Message::Pong(n))
                    .map_err(|e| self.not_in_reach(e))?,
                Ok(Message::Pong(_)) => {}
                Ok(m) => return Ok(m),
                Err(LinkError::Timeout) => {}
                Err(e) => return Err(self.not_in_reach(e)),
            }
        }
    }

    fn connect_by(&self, req: &Request) -> Instant {
        let left = Duration::from_secs(req.expires_at.saturating_sub(unix_now()));
        Instant::now() + CONNECT_WAIT.min(left)
    }

    fn decision(&self, req: &Request, option: u8, signature: Vec<u8>) -> AuthDecision {
        AuthDecision {
            request_hash: req.hash(),
            choice: option,
            device_id: self.device_id,
            signature,
        }
    }

    /// Look for the phone on a thread of its own and note the result.
    fn refresh(&self) {
        let core = self.core.clone();
        let Some(addr) = self.phone.addr() else {
            return;
        };
        let id = self.device_id;
        {
            let Ok(mut seen) = core.seen.lock() else {
                return;
            };
            let entry = seen.entry(id).or_insert(Seen {
                ok: true,
                at: Instant::now(),
                probing: false,
            });
            if entry.probing {
                return;
            }
            entry.probing = true;
        }
        std::thread::spawn(move || {
            let ok = probe_any(&core.transports, &addr, Instant::now() + PROBE_WAIT);
            if let Ok(mut seen) = core.seen.lock() {
                seen.insert(
                    id,
                    Seen {
                        ok,
                        at: Instant::now(),
                        probing: false,
                    },
                );
            }
        });
    }
}

impl DeviceChannel for LinkChannel {
    fn reachable(&self) -> bool {
        let seen = self
            .core
            .seen
            .lock()
            .ok()
            .and_then(|s| s.get(&self.device_id).copied());
        match seen {
            Some(s) if s.fresh() => s.ok,
            Some(s) => {
                self.refresh();
                s.ok
            }
            None => {
                self.refresh();
                true
            }
        }
    }

    fn unlock(&self, req: &Request, eph_pub: &[u8]) -> Result<UnlockReply, AuthError> {
        let mut chan = self.session(self.connect_by(req))?;
        chan.send(&Message::UnlockRequest(UnlockRequest {
            slot_id: self.device_id.to_vec(),
            eph_pub: eph_pub.to_vec(),
            request: req.to_bytes(),
        }))
        .map_err(|e| self.not_in_reach(e))?;
        match self.wait_for(&mut chan, req, &Cancel::new())? {
            Message::UnlockResponse(UnlockResponse::Approved { shared, signature }) => {
                let mut key = Zeroizing::new([0u8; 32]);
                if shared.len() != key.len() {
                    return Err(AuthError::BadDecision(
                        "the shared value has the wrong size",
                    ));
                }
                key.copy_from_slice(&shared);
                Ok(UnlockReply {
                    shared: key,
                    decision: self.decision(req, 0, signature),
                })
            }
            Message::UnlockResponse(UnlockResponse::Denied) => Err(AuthError::Denied),
            Message::UnlockResponse(UnlockResponse::Error(why)) => {
                Err(AuthError::Refused(format!("{}: {why}", self.phone.name)))
            }
            _ => Err(AuthError::BadDecision("not an answer to the unlock")),
        }
    }

    fn approve(&self, req: &Request) -> Result<AuthDecision, AuthError> {
        self.approve_cancellable(req, &Cancel::new())
    }

    fn approve_cancellable(
        &self,
        req: &Request,
        cancel: &Cancel,
    ) -> Result<AuthDecision, AuthError> {
        let mut chan = self.session(self.connect_by(req))?;
        if cancel.is_cancelled() {
            return Err(AuthError::Cancelled);
        }
        let envelope = ApproveRequest::new(req.to_bytes(), req.nonce, req.expires_at);
        let sent_hash = envelope.request_hash;
        chan.send(&Message::ApproveRequest(envelope))
            .map_err(|e| self.not_in_reach(e))?;
        // Leaving this function drops the connection, which is how a phone is
        // told that another approver answered first.
        match self.wait_for(&mut chan, req, cancel)? {
            Message::Decision(d) if d.request_hash == sent_hash => match d.choice {
                Choice::Deny => Err(AuthError::Denied),
                Choice::Approve => Ok(self.decision(req, d.option, d.signature)),
            },
            Message::Decision(_) => Err(AuthError::BadDecision("another request")),
            _ => Err(AuthError::BadDecision("not an answer to the request")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vahta_auth::{Action, device_id_for};
    use vahta_link::memory::MemoryTransport;
    use vahta_mobile::fake::{Behavior, FakePhone};

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vahta-link-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn record() -> Device {
        Device {
            device_id: [9; 16],
            name: "pixel".into(),
            sign_pub: [&[4u8][..], &[1; 64]].concat(),
            ecdh_pub: [&[4u8][..], &[2; 64]].concat(),
            paired_at: 0,
            expires_at: None,
            transports: vec![],
        }
    }

    fn phone() -> Phone {
        Phone {
            name: "pixel".into(),
            static_pub: hex_encode(&[5; 32]),
            ble_address: None,
            lan_hint: None,
        }
    }

    #[test]
    fn pairing_ends_when_the_person_gives_up_or_the_code_runs_out() {
        let d = dir("pair-end");
        let links = LinkDevices::with_transports(d.clone(), vec![Arc::new(MemoryTransport::new())]);
        let shown = Mutex::new(Vec::new());
        let show = |c: PairingCode| shown.lock().unwrap().push(c);
        let cancel = Cancel::new();
        let ctx = PairContext {
            vault_id: [1; 16],
            wait: Duration::from_secs(30),
            show: &show,
            cancel: &cancel,
        };
        let t = Instant::now();
        let gate = cancel.clone();
        let outcome = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                gate.cancel();
            });
            links.pair("pixel", &ctx)
        });
        assert!(matches!(outcome, Err(AuthError::Cancelled)), "{outcome:?}");
        assert!(t.elapsed() < Duration::from_secs(3));
        assert_eq!(shown.lock().unwrap().len(), 1, "the code was shown once");

        // A code is good for the time asked, no longer.
        let ctx = PairContext {
            wait: Duration::from_secs(1),
            cancel: &Cancel::new(),
            ..ctx
        };
        let outcome = links.pair("pixel", &ctx);
        assert!(
            matches!(outcome, Err(AuthError::Unavailable(_))),
            "{outcome:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_desktop_key_is_made_once_per_vault_and_kept_private() {
        let d = dir("key");
        let links = LinkDevices::with_transports(d.clone(), vec![]);
        let a = links.core.desktop_key(&[1; 16]).unwrap();
        let again = links.core.desktop_key(&[1; 16]).unwrap();
        assert_eq!(a.public, again.public);
        let other = links.core.desktop_key(&[2; 16]).unwrap();
        assert_ne!(a.public, other.public);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            let vault = d.join(hex_encode(&[1; 16]));
            assert_eq!(mode(&vault.join("desktop.key")), 0o600);
            assert_eq!(mode(&vault), 0o700);
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_phone_with_no_record_has_no_channel_and_a_forgotten_one_loses_it() {
        let d = dir("forget");
        let links = LinkDevices::with_transports(d.clone(), vec![Arc::new(MemoryTransport::new())]);
        let device = record();
        assert!(links.channel(&[1; 16], &device).is_none());
        links.core.save_phone(&[1; 16], &[9; 16], &phone()).unwrap();
        assert!(links.channel(&[1; 16], &device).is_some());
        assert!(links.channel(&[2; 16], &device).is_none(), "another vault");
        links.forget(&[1; 16], &[9; 16]);
        assert!(links.channel(&[1; 16], &device).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reachability_is_a_cached_guess_that_never_blocks() {
        let d = dir("reach");
        let links = LinkDevices::with_transports(d.clone(), vec![Arc::new(MemoryTransport::new())]);
        links.core.save_phone(&[1; 16], &[9; 16], &phone()).unwrap();
        let ch = links.channel(&[1; 16], &record()).unwrap();
        let t = Instant::now();
        assert!(ch.reachable(), "unknown: assumed reachable");
        assert!(t.elapsed() < Duration::from_millis(500));
        // Nobody listens on the memory transport: the probe finds that out.
        let end = Instant::now() + Duration::from_secs(5);
        while ch.reachable() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!ch.reachable());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A phone that serves every connection it gets on the memory transport.
    fn serve_forever(
        phone: &Arc<FakePhone>,
        listener: vahta_link::memory::MemoryListener,
        stop: &Arc<std::sync::atomic::AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        let (phone, stop) = (phone.clone(), stop.clone());
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !stop.load(Ordering::SeqCst) {
                if let Ok(pipe) = listener.accept(Duration::from_millis(100)) {
                    let phone = phone.clone();
                    std::thread::spawn(move || {
                        let _ = phone.serve(pipe);
                    });
                }
            }
        })
    }

    #[test]
    fn a_fake_phone_pairs_approves_denies_and_unlocks_over_the_memory_transport() {
        use p256::ecdh::EphemeralSecret;
        use std::sync::atomic::{AtomicBool, Ordering};

        let d = dir("memory-e2e");
        let mem = MemoryTransport::new();
        let links = LinkDevices::with_transports(d.clone(), vec![Arc::new(mem.clone())]);
        let vault_id = [0x42; 16];
        let phone = Arc::new(FakePhone::new("Pixel 9"));

        // --- Pair: the code goes to the "window"; the phone reads it and dials back.
        let (code_tx, code_rx) = std::sync::mpsc::channel::<PairingCode>();
        let code_tx = Mutex::new(code_tx);
        let show = move |c: PairingCode| {
            let _ = code_tx.lock().unwrap().send(c);
        };
        let cancel = Cancel::new();
        let new = std::thread::scope(|s| {
            let pairing = s.spawn(|| {
                links.pair(
                    "pixel",
                    &PairContext {
                        vault_id,
                        wait: Duration::from_secs(30),
                        show: &show,
                        cancel: &cancel,
                    },
                )
            });
            let code = code_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(code.qr.lines().count() > 10, "a QR code to scan");
            let offer = PairOffer::from_qr_string(&code.text).unwrap();
            assert_eq!(offer.vault_id, vault_id);
            let listener = mem.listen_tag(pairing_tag(&offer.psk));
            let pipe = listener.accept(Duration::from_secs(5)).unwrap();
            phone.pair_over(pipe, &code.text, unix_now()).unwrap();
            pairing.join().unwrap().unwrap()
        });
        assert_eq!(
            new.name, "pixel",
            "the vault records the name the person typed"
        );
        assert_eq!(new.transports, ["memory"]);
        let id = device_id_for(&new.sign_pub, &new.ecdh_pub);
        assert_eq!(id.to_vec(), phone.device_id().unwrap());

        // --- A session from then on, pinned to the phone's key.
        let static_pub: [u8; 32] = phone.static_pub().try_into().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server = serve_forever(&phone, mem.listen(static_pub), &stop);
        let device = Device {
            device_id: id,
            name: "pixel".into(),
            sign_pub: new.sign_pub.clone(),
            ecdh_pub: new.ecdh_pub.clone(),
            paired_at: 0,
            expires_at: None,
            transports: new.transports.clone(),
        };
        let channel = links.channel(&vault_id, &device).unwrap();
        assert!(channel.reachable());
        let request = |options: &[&str]| {
            Request::new(
                Action::RunAsk {
                    names: vec!["STRIPE_KEY".into()],
                    command: "deploy".into(),
                    reason: None,
                },
                "/home/me/shop",
                vault_id,
                Duration::from_secs(30),
            )
            .unwrap()
            .with_options(&options.iter().map(|o| o.to_string()).collect::<Vec<_>>())
            .with_label(Some("shipping".into()))
        };

        // Approve: the phone signs option 1, the desktop verifies it.
        let req = request(&["Allow once", "No"]);
        phone.queue(Behavior::Approve(1));
        let decision = channel.approve(&req).unwrap();
        assert_eq!(decision.choice, 1);
        decision.verify(&req, &id, &new.sign_pub).unwrap();
        let asked = phone.asked();
        assert_eq!(asked[0].kind, "approve");
        assert_eq!(asked[0].view.kind, "run_ask");
        assert_eq!(asked[0].view.names, ["STRIPE_KEY"]);
        assert_eq!(asked[0].view.agent_label.as_deref(), Some("shipping"));
        assert!(!asked[0].view.agent_label_verified);

        // Deny.
        phone.queue(Behavior::Deny);
        assert!(matches!(
            channel.approve(&request(&["Allow once", "No"])),
            Err(AuthError::Denied)
        ));

        // Unlock: the ECDH output and a signed decision on the same request.
        let eph = EphemeralSecret::random(&mut rand_core::OsRng);
        let eph_pub = p256::EncodedPoint::from(eph.public_key())
            .as_bytes()
            .to_vec();
        let req = request(&["Allow"]);
        phone.queue(Behavior::Approve(0));
        let reply = channel.unlock(&req, &eph_pub).unwrap();
        reply.decision.verify(&req, &id, &new.sign_pub).unwrap();
        let theirs = p256::PublicKey::from_sec1_bytes(&new.ecdh_pub).unwrap();
        let mine = eph.diffie_hellman(&theirs);
        assert_eq!(&reply.shared[..], mine.raw_secret_bytes().as_slice());
        phone.queue(Behavior::Deny);
        assert!(matches!(
            channel.unlock(&request(&["Allow"]), &eph_pub),
            Err(AuthError::Denied)
        ));

        // Another approver answers first: the wait ends, and the phone's
        // connection is closed.
        phone.queue(Behavior::Ignore);
        let cancel = Cancel::new();
        let gate = cancel.clone();
        let t = Instant::now();
        let outcome = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                gate.cancel();
            });
            channel.approve_cancellable(&request(&["Allow once", "No"]), &cancel)
        });
        assert!(matches!(outcome, Err(AuthError::Cancelled)), "{outcome:?}");
        assert!(t.elapsed() < Duration::from_secs(5));

        // A request whose time has run out takes no answer.
        let mut late = request(&["Allow once", "No"]);
        late.expires_at = unix_now() + 1;
        phone.queue(Behavior::Ignore);
        assert!(matches!(channel.approve(&late), Err(AuthError::Timeout)));

        // A phone that is gone is out of reach, quickly.
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        let mut other = links.core.load_phone(&vault_id, &id).unwrap();
        other.static_pub = hex_encode(&[7; 32]);
        links.core.save_phone(&vault_id, &id, &other).unwrap();
        let lost = links.channel(&vault_id, &device).unwrap();
        let t = Instant::now();
        assert!(matches!(
            lost.approve(&request(&["Allow once", "No"])),
            Err(AuthError::Unavailable(_))
        ));
        assert!(t.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(&d);
    }
}
