//! How a client talks to the Vahta daemon.
//!
//! The daemon is the vault's only owner; the `vahta` command and the agent
//! hook are clients. They need the wire protocol ([`protocol`]), a way to
//! reach the daemon ([`client`]), where it lives ([`paths`]) and the person's
//! settings ([`config`]), and none of the daemon itself. Keeping these here
//! keeps the hook, which runs on every tool call, free of the vault's
//! cryptography and the daemon's system-bus code.

#![forbid(unsafe_code)]

pub mod client;
pub mod config;
pub mod duration;
pub mod paths;
pub mod protocol;
pub mod spool;

/// This build's version, compared at the handshake. A client and a daemon of
/// different versions do not talk past the hello. The daemon reports this
/// one, so a client built from the same tree always agrees with it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
