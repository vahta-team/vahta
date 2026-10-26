//! okono as an unlocker of the connectors vault (Linux).
//!
//! okono is a root service that checks the person's face through the webcam
//! and then gives the calling program a stable value of its own: an HMAC in the
//! TPM over `(app, label, version)`. Vahta wraps the connectors vault's key
//! under a key derived from that value (slot kind 3) and asks okono for it when
//! a harness process wants its MCP servers. It is a convenience factor, not a
//! strong one: the password always works, and a failure of any kind sends the
//! person to the password window.
//!
//! **The caller is the daemon, never the CLI and never an agent.** okono tells
//! callers apart by socket credentials and the executable's path, so only the
//! daemon's executable is allowed in okono's `apps.toml`.
//!
//! This file is the whole of Vahta's knowledge of okono's protocol; the exact
//! shape it expects is written down in `docs/connectors.md` ("Contract with
//! okono"). One request per connection, JSON lines, every line `"v":1`, lines
//! at most 16 KiB. The daemon sends zero or more event lines (ignored) and then
//! one final line, `ok` with the value (64 hex characters) or an error with a code. Closing the
//! connection is how okono is told to cancel.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use vahta_auth::{AuthError, Cancel, Factor, UnlockCtx, Unlocker};
use vahta_vault::store::LocalStore;
use vahta_vault::{NewSlot, Peek, SLOT_OKONO, SlotInfo, Vault};
use zeroize::Zeroizing;

/// Where okono listens. The only place the shipped daemon asks.
pub(crate) const SOCKET: &str = "/run/okono/okono.sock";
/// The name okono's `apps.toml` gives Vahta's daemon.
pub(crate) const APP: &str = "vahta";
/// The version of the per-program value; a new one is a new value.
pub(crate) const VERSION: u32 = 1;
/// The whole exchange, the person looking at the camera and pressing Enter on
/// okono's card included.
pub(crate) const EXCHANGE: Duration = Duration::from_secs(120);
/// The longest line either way.
const MAX_LINE: usize = 16 * 1024;
/// How often a wait looks at the cancel flag and the clock.
const POLL: Duration = Duration::from_millis(100);
/// The key-encryption key's HKDF info.
const INFO_KEK: &[u8] = b"vahta-okono-kek-v1";
/// The card text okono shows (untrusted there, at most 120 characters).
const DISPLAY: &str = "connectors vault key";
const VALUE_LEN: usize = 32;

/// Why okono gave no value. `code` is short and safe for the journal: one of
/// okono's own codes (not_allowed, denied, no_confirmer, no_tpm, not_enrolled, locked_out, camera, bad_request, internal), or one of ours (`no_socket`, `connect`, `timeout`,
/// `cancelled`, `closed`, `io`, `malformed`, `too_long`, `unsupported`,
/// `wrong_value`, `bad_params`, `vault`). Never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub code: String,
}

impl Failure {
    fn new(code: &str) -> Failure {
        Failure {
            code: code.to_string(),
        }
    }

    /// A code okono sent: kept when it looks like one, else `unknown`.
    fn from_okono(code: &str) -> Failure {
        let plain = !code.is_empty()
            && code.len() <= 32
            && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        Failure::new(if plain { code } else { "unknown" })
    }

    pub(crate) fn cancelled(&self) -> bool {
        self.code == "cancelled"
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code)
    }
}

// --- The slot ---------------------------------------------------------------------

/// What an okono slot stores: which value to ask for. No secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Params {
    pub app: String,
    pub label: String,
    pub version: u32,
}

impl Params {
    /// The value of the vault `vault_id`: label `vault:<id hex>`.
    pub(crate) fn for_vault(vault_id: &[u8; 16]) -> Params {
        Params {
            app: APP.to_string(),
            label: format!("vault:{}", vahta_vault::hex_encode(vault_id)),
            version: VERSION,
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// The params of a slot of this vault, or `None` for ones that ask for
    /// anything else (another app, another vault's label): a slot in a file
    /// that was edited must not make the daemon ask okono for a different value.
    pub(crate) fn decode(bytes: &[u8], vault_id: &[u8; 16]) -> Option<Params> {
        let p: Params = serde_json::from_slice(bytes).ok()?;
        let want = Params::for_vault(vault_id);
        (p.app == want.app && p.label == want.label && p.version >= 1).then_some(p)
    }
}

/// The key that wraps the vault key in an okono slot.
pub(crate) fn kek(value: &[u8; VALUE_LEN], vault_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    vahta_vault::crypto::hkdf_salted(vault_id, value, INFO_KEK)
}

/// The okono slot of `peek`, if it has one that has not expired.
pub(crate) fn slot_of(peek: &Peek) -> Option<SlotInfo> {
    peek.slots
        .iter()
        .map(|s| &s.info)
        .find(|i| i.kind == SLOT_OKONO && i.expires_at.is_none_or(|t| t > now()))
        .cloned()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- The client ---------------------------------------------------------------------

/// How to reach okono.
#[derive(Debug, Clone)]
pub(crate) struct Okono {
    socket: PathBuf,
    timeout: Duration,
}

impl Okono {
    pub(crate) fn new(socket: PathBuf, timeout: Duration) -> Okono {
        Okono { socket, timeout }
    }

    /// The real okono, or in a test build the one `VAHTA_TEST_OKONO_SOCKET`
    /// names.
    pub(crate) fn standard() -> Okono {
        Okono::new(
            crate::testing::okono_socket().unwrap_or_else(|| PathBuf::from(SOCKET)),
            crate::testing::okono_timeout().unwrap_or(EXCHANGE),
        )
    }

    /// Ask okono for the value of `params`. Blocks until the person has been
    /// checked, okono refuses, `cancel` fires (the connection is closed, which
    /// okono takes as a cancel) or the exchange has taken too long.
    pub(crate) fn ask(
        &self,
        params: &Params,
        cancel: &Cancel,
    ) -> Result<Zeroizing<[u8; VALUE_LEN]>, Failure> {
        exchange(&self.socket, self.timeout, params, cancel)
    }
}

#[cfg(not(target_os = "linux"))]
fn exchange(
    _socket: &Path,
    _timeout: Duration,
    _params: &Params,
    _cancel: &Cancel,
) -> Result<Zeroizing<[u8; VALUE_LEN]>, Failure> {
    Err(Failure::new("unsupported"))
}

#[cfg(target_os = "linux")]
fn exchange(
    socket: &Path,
    timeout: Duration,
    params: &Params,
    cancel: &Cancel,
) -> Result<Zeroizing<[u8; VALUE_LEN]>, Failure> {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;

    let deadline = Instant::now() + timeout;
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        Failure::new(match e.kind() {
            ErrorKind::NotFound => "no_socket",
            _ => "connect",
        })
    })?;
    let request = request_line(params);
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .and_then(|()| stream.set_read_timeout(Some(POLL)))
        .and_then(|()| stream.write_all(&request))
        .map_err(|_| Failure::new("io"))?;
    // The reply may hold the value: wiped when this function returns.
    let mut pending: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        // Lines that are already in, one at a time.
        while let Some(end) = pending.iter().position(|&b| b == b'\n') {
            if end > MAX_LINE {
                return Err(Failure::new("too_long"));
            }
            let line: Zeroizing<Vec<u8>> = Zeroizing::new(pending[..end].to_vec());
            pending.drain(..=end);
            if let Some(done) = read_line(&line)? {
                return done;
            }
        }
        if pending.len() > MAX_LINE {
            return Err(Failure::new("too_long"));
        }
        if cancel.is_cancelled() {
            return Err(Failure::new("cancelled"));
        }
        if Instant::now() >= deadline {
            return Err(Failure::new("timeout"));
        }
        match stream.read(&mut *chunk) {
            Ok(0) => return Err(Failure::new("closed")),
            Ok(n) => pending.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(Failure::new("io")),
        }
    }
}

/// The request, as one line.
pub(crate) fn request_line(params: &Params) -> Vec<u8> {
    let mut line = serde_json::json!({
        "v": 1,
        "op": "secret",
        "app": params.app,
        "label": params.label,
        "version": params.version,
        "display": DISPLAY,
    })
    .to_string()
    .into_bytes();
    line.push(b'\n');
    line
}

#[derive(Deserialize)]
struct Line {
    v: Option<u64>,
    ok: Option<bool>,
    result: Option<Reply>,
    error: Option<Refusal>,
}

#[derive(Deserialize)]
struct Reply {
    kind: Option<String>,
    hex: Option<String>,
}

#[derive(Deserialize)]
struct Refusal {
    code: Option<String>,
}

/// One line of okono's answer. `Ok(None)`: an event (or any line that is not
/// the final one) to ignore. `Ok(Some(..))`: the final line's result. `Err`:
/// a line that is not valid.
#[allow(clippy::type_complexity)]
pub(crate) fn read_line(
    line: &[u8],
) -> Result<Option<Result<Zeroizing<[u8; VALUE_LEN]>, Failure>>, Failure> {
    let parsed: Line = serde_json::from_slice(line).map_err(|_| Failure::new("malformed"))?;
    if parsed.v != Some(1) {
        return Err(Failure::new("malformed"));
    }
    let Some(ok) = parsed.ok else {
        // An event: `{"v":1,"event":{...}}`, of a kind we may not know.
        return Ok(None);
    };
    if !ok {
        let code = parsed.error.and_then(|e| e.code).unwrap_or_default();
        return Ok(Some(Err(Failure::from_okono(&code))));
    }
    let Some(Reply {
        kind: Some(kind),
        hex: Some(hex),
    }) = parsed.result
    else {
        return Err(Failure::new("malformed"));
    };
    let hex = Zeroizing::new(hex);
    if kind != "secret" {
        return Err(Failure::new("malformed"));
    }
    let out = hex_decode(hex.as_bytes()).ok_or_else(|| Failure::new("malformed"))?;
    Ok(Some(Ok(out)))
}

/// Exactly 64 hex characters (either case) as 32 bytes.
fn hex_decode(text: &[u8]) -> Option<Zeroizing<[u8; VALUE_LEN]>> {
    if text.len() != VALUE_LEN * 2 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Zeroizing::new([0u8; VALUE_LEN]);
    for (byte, pair) in out.iter_mut().zip(text.chunks(2)) {
        *byte = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

// --- Using it ---------------------------------------------------------------------

/// Open the vault at `path` with its okono slot: ask okono, derive the key,
/// open. Any failure is a [`Failure`] and the vault stays shut. A value that
/// does not open the slot is `wrong_value`.
pub(crate) fn open_vault(
    okono: &Okono,
    path: &Path,
    peek: &Peek,
    store: &LocalStore,
    cancel: &Cancel,
) -> Result<Vault, Failure> {
    let slot = slot_of(peek).ok_or_else(|| Failure::new("no_slot"))?;
    let view = peek
        .slots
        .iter()
        .find(|s| s.info.slot_id == slot.slot_id)
        .ok_or_else(|| Failure::new("no_slot"))?;
    let params =
        Params::decode(&view.params, &peek.vault_id).ok_or_else(|| Failure::new("bad_params"))?;
    let value = okono.ask(&params, cancel)?;
    let key = kek(&value, &peek.vault_id);
    Vault::unlock_with_slot_accepting(path, &slot.slot_id, &key, store, &mut |_| false).map_err(
        |e| match e {
            vahta_vault::Error::Unlock => Failure::new("wrong_value"),
            _ => Failure::new("vault"),
        },
    )
}

/// Give the open `vault` an okono slot: ask okono now (the person is checked),
/// wrap the vault key under what it returns. Nothing is saved.
pub(crate) fn enroll(vault: &mut Vault, okono: &Okono, cancel: &Cancel) -> Result<(), Failure> {
    let id = vault.vault_id();
    let params = Params::for_vault(&id);
    let value = okono.ask(&params, cancel)?;
    let key = kek(&value, &id);
    vault
        .add_slot(
            NewSlot {
                kind: SLOT_OKONO,
                slot_id: None,
                label: "okono".to_string(),
                expires_at: None,
                params: params.encode(),
            },
            |vk, aad| vahta_vault::seal_vault_key(&key, aad, vk),
        )
        .map(|_| ())
        .map_err(|_| Failure::new("vault"))
}

/// Kind 3 in the registry. It is not part of the ordinary unlock flow
/// (`normal_flow`): the daemon asks it itself, for the connectors session
/// only, with a cancel that follows the client.
pub(crate) struct OkonoUnlocker {
    pub(crate) okono: Okono,
}

impl Unlocker for OkonoUnlocker {
    fn kind(&self) -> u16 {
        SLOT_OKONO
    }

    fn label(&self) -> String {
        "okono".into()
    }

    /// A face check on this machine: someone is there. Weaker than a password
    /// (a face can be shown, the daemon cannot tell who holds the camera), so
    /// it is `Presence` and satisfies only what a yes in a window would.
    fn factor(&self) -> Factor {
        Factor::Presence
    }

    fn priority(&self) -> u8 {
        20
    }

    fn normal_flow(&self) -> bool {
        false
    }

    fn unwrap_kek(
        &self,
        _slot: &SlotInfo,
        params: &[u8],
        ctx: &mut dyn UnlockCtx,
    ) -> Result<Zeroizing<[u8; 32]>, AuthError> {
        let vault_id = ctx.request().vault_id;
        let params = Params::decode(params, &vault_id)
            .ok_or_else(|| AuthError::Unavailable("bad_params".into()))?;
        let value = self
            .okono
            .ask(&params, &Cancel::new())
            .map_err(|f| AuthError::Unavailable(f.code))?;
        Ok(kek(&value, &vault_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn final_of(line: &str) -> Result<Zeroizing<[u8; 32]>, Failure> {
        read_line(line.as_bytes()).unwrap().unwrap()
    }

    #[test]
    fn events_are_skipped_whatever_they_are() {
        for line in [
            r#"{"v":1,"event":{"type":"card"}}"#,
            r#"{"v":1,"event":{"type":"never_heard_of","n":[1]}}"#,
            r#"{"v":1,"event":"odd"}"#,
        ] {
            assert!(read_line(line.as_bytes()).unwrap().is_none(), "{line}");
        }
    }

    #[test]
    fn a_value_is_exactly_64_hex_characters() {
        let bytes: Vec<u8> = (0u8..32)
            .map(|i| i.wrapping_mul(5).wrapping_add(1))
            .collect();
        let ok = |hex: &str| {
            format!(r#"{{"v":1,"ok":true,"result":{{"kind":"secret","hex":"{hex}"}}}}"#)
        };
        let got = final_of(&ok(&hex_of(&bytes))).unwrap();
        assert_eq!(&got[..], &bytes[..]);
        // Upper case is the same value.
        assert_eq!(
            &final_of(&ok(&hex_of(&bytes).to_uppercase())).unwrap()[..],
            &bytes[..]
        );
        for bad in [
            hex_of(&bytes[..31]),
            format!("{}00", hex_of(&bytes)),
            "zz".repeat(32),
            String::new(),
        ] {
            assert!(read_line(ok(&bad).as_bytes()).is_err(), "{bad}");
        }
        let wrong_kind = r#"{"v":1,"ok":true,"result":{"kind":"other","hex":"00"}}"#;
        assert!(read_line(wrong_kind.as_bytes()).is_err());
    }

    #[test]
    fn an_error_carries_only_a_plain_code() {
        let line = |code: &str| {
            format!(r#"{{"v":1,"ok":false,"error":{{"code":"{code}","message":"x"}}}}"#)
        };
        assert_eq!(final_of(&line("denied")).unwrap_err().code, "denied");
        assert_eq!(final_of(&line("Bad Code!")).unwrap_err().code, "unknown");
        assert_eq!(
            final_of(&line(&"a".repeat(80))).unwrap_err().code,
            "unknown"
        );
    }

    #[test]
    fn a_line_of_the_wrong_version_or_shape_is_malformed() {
        for line in ["", "[]", "{", r#"{"ok":true}"#, r#"{"v":"1","ok":false}"#] {
            assert_eq!(read_line(line.as_bytes()).unwrap_err().code, "malformed");
        }
    }

    #[test]
    fn the_slot_asks_only_for_this_vaults_value() {
        let id = [7u8; 16];
        let p = Params::for_vault(&id);
        assert_eq!(Params::decode(&p.encode(), &id), Some(p.clone()));
        assert_eq!(Params::decode(&p.encode(), &[8u8; 16]), None);
        let other_app = Params {
            app: "other".into(),
            ..p
        };
        assert_eq!(Params::decode(&other_app.encode(), &id), None);
    }

    #[test]
    fn the_key_depends_on_the_value_and_the_vault() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_ne!(*kek(&a, &[0; 16]), *kek(&b, &[0; 16]));
        assert_ne!(*kek(&a, &[0; 16]), *kek(&a, &[1; 16]));
        assert_eq!(*kek(&a, &[0; 16]), *kek(&a, &[0; 16]));
    }
}
