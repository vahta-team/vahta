//! A software phone, for tests only (the `test-surface` feature).
//!
//! [`LoopbackDevice`] has real P-256 keys and does what a phone does: ECDH for
//! an unlock, an ECDSA signature for a decision. What it does when asked is
//! scripted: approve, deny, not answer, be out of reach, or cheat (sign with
//! another key, or answer with an old decision). [`LoopbackLinks`] keeps such
//! devices in a directory so a daemon in another process can reach the same
//! "phones" a test paired.
//!
//! Script file (`<dir>/script`), one behaviour per line, consumed from the
//! top, one per question; with none left the device is out of reach:
//! `approve`, `approve:N` (choice N), `deny`, `timeout`, `unreachable`,
//! `forge`, `replay`. Every question is appended to `<dir>/log`.

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p256::ecdsa::SigningKey;
use p256::{PublicKey, SecretKey};
use vahta_vault::{Device, hex_decode, hex_encode};
use zeroize::Zeroizing;

use crate::device::{DeviceChannel, DeviceLinks, NewDevice, UnlockReply};
use crate::error::AuthError;
use crate::request::{Decision, Request};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Approve(u8),
    Deny,
    Timeout,
    Unreachable,
    /// Sign with a key the vault does not know.
    Forge,
    /// Answer with the previous decision.
    Replay,
}

impl Behavior {
    fn parse(line: &str) -> Option<Behavior> {
        let line = line.trim();
        Some(match line {
            "approve" => Behavior::Approve(0),
            "deny" => Behavior::Deny,
            "timeout" => Behavior::Timeout,
            "unreachable" => Behavior::Unreachable,
            "forge" => Behavior::Forge,
            "replay" => Behavior::Replay,
            _ => Behavior::Approve(line.strip_prefix("approve:")?.parse().ok()?),
        })
    }
}

enum Script {
    Memory(Mutex<VecDeque<Behavior>>),
    File(PathBuf),
}

impl Script {
    fn peek(&self) -> Behavior {
        match self {
            Script::Memory(q) => q
                .lock()
                .ok()
                .and_then(|q| q.front().copied())
                .unwrap_or(Behavior::Unreachable),
            Script::File(path) => std::fs::read_to_string(path)
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find(|l| !l.trim().is_empty())
                        .and_then(Behavior::parse)
                })
                .unwrap_or(Behavior::Unreachable),
        }
    }

    fn next(&self) -> Behavior {
        match self {
            Script::Memory(q) => q
                .lock()
                .ok()
                .and_then(|mut q| q.pop_front())
                .unwrap_or(Behavior::Unreachable),
            Script::File(path) => {
                let Ok(text) = std::fs::read_to_string(path) else {
                    return Behavior::Unreachable;
                };
                let mut lines = text.lines().filter(|l| !l.trim().is_empty());
                let first = lines.next().and_then(Behavior::parse);
                let rest: Vec<&str> = lines.collect();
                let mut left = rest.join("\n");
                if !left.is_empty() {
                    left.push('\n');
                }
                let _ = std::fs::write(path, left);
                first.unwrap_or(Behavior::Unreachable)
            }
        }
    }
}

/// An in-process phone.
pub struct LoopbackDevice {
    pub device_id: [u8; 16],
    pub name: String,
    sign: SigningKey,
    ecdh: SecretKey,
    script: Script,
    log: Option<PathBuf>,
    last: Mutex<Option<Decision>>,
    last_file: Option<PathBuf>,
}

impl LoopbackDevice {
    /// A new phone with fresh keys and an empty script (out of reach).
    pub fn new(name: &str) -> LoopbackDevice {
        let sign = SigningKey::random(&mut rand_core::OsRng);
        let ecdh = SecretKey::random(&mut rand_core::OsRng);
        let sign_pub = sign.verifying_key().to_encoded_point(false);
        let ecdh_pub = p256::EncodedPoint::from(ecdh.public_key());
        LoopbackDevice {
            device_id: crate::device_id_for(sign_pub.as_bytes(), ecdh_pub.as_bytes()),
            name: name.to_string(),
            sign,
            ecdh,
            script: Script::Memory(Mutex::new(VecDeque::new())),
            log: None,
            last: Mutex::new(None),
            last_file: None,
        }
    }

    /// Queue what it does for the next question.
    pub fn queue(&self, behavior: Behavior) {
        if let Script::Memory(q) = &self.script
            && let Ok(mut q) = q.lock()
        {
            q.push_back(behavior);
        }
    }

    pub fn sign_pub(&self) -> Vec<u8> {
        self.sign
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    pub fn ecdh_pub(&self) -> Vec<u8> {
        p256::EncodedPoint::from(self.ecdh.public_key())
            .as_bytes()
            .to_vec()
    }

    /// The record the vault keeps.
    pub fn record(&self, expires_at: Option<u64>) -> Device {
        Device {
            device_id: self.device_id,
            name: self.name.clone(),
            sign_pub: self.sign_pub(),
            ecdh_pub: self.ecdh_pub(),
            paired_at: now(),
            expires_at,
            transports: vec!["loopback".into()],
        }
    }

    /// What the phone computes for an unlock: ECDH of its private key with
    /// the ephemeral public key. Public so a test can derive the key a
    /// removed device would still hold.
    pub fn shared_secret(&self, eph_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>, AuthError> {
        let theirs = PublicKey::from_sec1_bytes(eph_pub)
            .map_err(|_| AuthError::Refused("bad ephemeral key".into()))?;
        let shared = p256::ecdh::diffie_hellman(self.ecdh.to_nonzero_scalar(), theirs.as_affine());
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(out)
    }

    fn note(&self, what: &str, req: &Request, behavior: Behavior) {
        if let Some(path) = &self.log
            && let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(f, "{what} {} {} {behavior:?}", self.name, req.action.key());
        }
    }

    fn remember(&self, d: &Decision) {
        if let Ok(mut last) = self.last.lock() {
            *last = Some(d.clone());
        }
        if let Some(path) = &self.last_file
            && let Ok(bytes) = postcard::to_allocvec(d)
        {
            let _ = std::fs::write(path, hex_encode(&bytes));
        }
    }

    fn previous(&self) -> Option<Decision> {
        if let Some(path) = &self.last_file {
            let text = std::fs::read_to_string(path).ok()?;
            return postcard::from_bytes(&hex_decode(text.trim())?).ok();
        }
        self.last.lock().ok().and_then(|l| l.clone())
    }

    fn answer(
        &self,
        what: &str,
        req: &Request,
        unlock_choice: Option<u8>,
    ) -> Result<Decision, AuthError> {
        let behavior = self.script.next();
        self.note(what, req, behavior);
        match behavior {
            Behavior::Unreachable => Err(AuthError::Unavailable(format!(
                "{} is not in reach",
                self.name
            ))),
            Behavior::Timeout => {
                // A real phone would be waited on until the request ends.
                std::thread::sleep(Duration::from_millis(50));
                Err(AuthError::Timeout)
            }
            Behavior::Deny => Err(AuthError::Denied),
            Behavior::Approve(c) => {
                let d = Decision::sign(req, unlock_choice.unwrap_or(c), self.device_id, &self.sign);
                self.remember(&d);
                Ok(d)
            }
            Behavior::Forge => {
                let other = SigningKey::random(&mut rand_core::OsRng);
                Ok(Decision::sign(
                    req,
                    unlock_choice.unwrap_or(0),
                    self.device_id,
                    &other,
                ))
            }
            Behavior::Replay => self
                .previous()
                .ok_or_else(|| AuthError::Unavailable("nothing to replay".into())),
        }
    }
}

impl DeviceChannel for LoopbackDevice {
    fn reachable(&self) -> bool {
        self.script.peek() != Behavior::Unreachable
    }

    fn unlock(&self, req: &Request, eph_pub: &[u8]) -> Result<UnlockReply, AuthError> {
        let decision = self.answer("unlock", req, Some(0))?;
        Ok(UnlockReply {
            shared: self.shared_secret(eph_pub)?,
            decision,
        })
    }

    fn approve(&self, req: &Request) -> Result<Decision, AuthError> {
        self.answer("approve", req, None)
    }
}

// --- Devices kept in a directory -----------------------------------------------------------

/// Phones kept as files under one directory (`VAHTA_TEST_LOOPBACK`), so the
/// test and the daemon it runs share them. [`DeviceLinks::pair`] makes a new
/// one.
pub struct LoopbackLinks {
    dir: PathBuf,
}

impl LoopbackLinks {
    pub fn new(dir: impl Into<PathBuf>) -> LoopbackLinks {
        LoopbackLinks { dir: dir.into() }
    }

    pub fn from_env() -> Option<LoopbackLinks> {
        std::env::var_os("VAHTA_TEST_LOOPBACK").map(LoopbackLinks::new)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn key_file(&self, id: &[u8; 16]) -> PathBuf {
        self.dir.join(format!("{}.key", hex_encode(id)))
    }

    /// The phone with this id, as a test sees it (to read its keys).
    pub fn load(&self, id: &[u8; 16]) -> Option<LoopbackDevice> {
        let text = std::fs::read_to_string(self.key_file(id)).ok()?;
        let field = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .map(str::to_string)
        };
        let sign = SigningKey::from_slice(&hex_decode(&field("sign")?)?).ok()?;
        let ecdh = SecretKey::from_slice(&hex_decode(&field("ecdh")?)?).ok()?;
        Some(LoopbackDevice {
            device_id: *id,
            name: field("name")?,
            sign,
            ecdh,
            script: Script::File(self.dir.join("script")),
            log: Some(self.dir.join("log")),
            last: Mutex::new(None),
            last_file: Some(self.dir.join(format!("{}.last", hex_encode(id)))),
        })
    }
}

impl DeviceLinks for LoopbackLinks {
    fn channel(&self, device: &Device) -> Option<Arc<dyn DeviceChannel>> {
        self.load(&device.device_id)
            .map(|d| Arc::new(d) as Arc<dyn DeviceChannel>)
    }

    fn pair(&self, name: &str, _wait: Duration) -> Result<NewDevice, AuthError> {
        let d = LoopbackDevice::new(name);
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| AuthError::Unavailable(format!("loopback directory: {e}")))?;
        let text = format!(
            "name={}\nsign={}\necdh={}\n",
            d.name,
            hex_encode(&d.sign.to_bytes()),
            hex_encode(&d.ecdh.to_bytes())
        );
        std::fs::write(self.key_file(&d.device_id), text)
            .map_err(|e| AuthError::Unavailable(format!("loopback directory: {e}")))?;
        Ok(NewDevice {
            name: d.name.clone(),
            sign_pub: d.sign_pub(),
            ecdh_pub: d.ecdh_pub(),
            transports: vec!["loopback".into()],
        })
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
