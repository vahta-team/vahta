//! How Vahta decides that a person is there and what they may do.
//!
//! Three questions, three kinds of thing:
//!
//! * **Unlock** ([`Unlocker`]): what opens the vault. The password and the
//!   recovery key are two; a paired phone ([`DeviceUnlocker`], slot kind 2) is
//!   a third. The core asks a [`Registry`] and never matches on a slot kind.
//! * **Approve** ([`Approver`]): did a person say yes to *this*. The answer to
//!   a structured [`Request`] is a [`Decision`] bound to the request's hash and,
//!   for a device, signed. [`decide_any`] asks every approver that is good
//!   enough in parallel; the first answer wins.
//! * **Reach** ([`DeviceChannel`], [`DeviceLinks`]): how to talk to a device.
//!   Nothing here knows about Bluetooth or Wi-Fi; `vahta-link` will implement
//!   the traits. [`loopback`] is a software phone for tests.
//!
//! What a given action needs is data: `policy/factors.toml`, compiled in (see
//! [`policy`]). The master password satisfies everything but device
//! management, by decision of the founder: the window with the password is
//! always a way in.

mod approve;
mod device;
mod error;
mod factor;
#[cfg(feature = "test-surface")]
pub mod loopback;
pub mod policy;
mod request;
mod unlock;

pub use approve::{Approver, Cancel, Decided, decide_any};
pub use device::{
    DeviceApprover, DeviceChannel, DeviceLinks, DeviceUnlocker, NewDevice, NoLinks, UnlockReply,
    device_id_for, enroll_device, kept_device_slot, refresh_device,
};
pub use error::AuthError;
pub use factor::{Factor, Need};
pub use request::{Action, Decision, Request};
pub use unlock::{
    LinkedDevice, MAX_TRIES, PasswordUnlocker, RecoveryUnlocker, Registry, UnlockCtx, UnlockedBy,
    Unlocker,
};
