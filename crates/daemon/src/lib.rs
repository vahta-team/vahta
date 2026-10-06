//! The Vahta daemon as a library.
//!
//! The daemon is the vault's only owner. The `vahta` command, the agent hook
//! and later the MCP server are *clients*: they ask, and never hold a vault
//! key. A secret value or the password crosses exactly one kind of connection,
//! the prompt window's, which is a separate connection type authenticated by a
//! one-time token the daemon issued for one request. The client message types
//! in [`protocol`] have no field in which a value or a password could travel.
//!
//! One daemon runs per user, started on demand by the command line (never by
//! the hook), listening on a socket in a private runtime directory, and exits
//! when it has been idle.

mod anchor;
pub mod client;
mod clipboard;
pub mod config;
mod dotenv;
pub mod journal;
mod ops;
pub mod paths;
pub mod protocol;
pub mod server;
mod session;
mod session_ops;
pub mod surface;
pub mod terminal;
pub mod testing;

/// This build's version, compared at the handshake. A client and a daemon of
/// different versions do not talk past the hello.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
