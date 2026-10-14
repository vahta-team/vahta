//! Vahta's link to a paired phone: how the desktop reaches it
//! ([`Transport`]), the secure channel over any transport ([`channel`]), the
//! pairing flow ([`pairing`]) and the messages ([`messages`]). The transport is
//! untrusted; see docs/phone-link.md.

pub mod channel;
mod error;
mod frame;
pub mod lan;
pub mod memory;
pub mod messages;
pub mod pairing;
mod qr;
mod transport;

#[cfg(target_os = "linux")]
pub mod ble;
pub mod ble_frame;

pub use channel::{Channel, Handshake, Keypair, Partial, PipeChannel};
pub use error::{LinkError, Result};
pub use frame::{MAX_FRAME, PeerHint, Pipe, read_frame, write_frame};
pub use messages::{Message, PairAccept, PairOffer};
pub use qr::render_qr;
pub use transport::{DeviceAddr, Transport, probe_any, reach_first};

/// Unix seconds now.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn random_bytes(buf: &mut [u8]) -> Result<()> {
    use rand_core::TryRngCore;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| LinkError::Io("no system randomness".into()))
}
