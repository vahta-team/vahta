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

mod alarm;
mod anchor;
mod bind_ops;
mod binding;
mod clipboard;
mod dotenv;
mod encoded;
mod guard_ops;
pub mod journal;
mod lock;
mod ops;
mod output;
mod pathfind;
mod report;
mod run;
mod run_ask;
mod run_ops;
mod scrub;
pub mod server;
mod session;
mod session_ops;
pub mod surface;
pub mod terminal;
pub mod testing;

// The protocol, the client, the paths and the config live in `vahta-ipc`, so
// that a client (the hook above all) need not build the daemon. Inside the
// daemon they keep their old paths.
use vahta_ipc::{config, paths, protocol};

/// This build's version, compared at the handshake: the one `vahta-ipc`
/// gives every client, so the two cannot drift apart.
pub const VERSION: &str = vahta_ipc::VERSION;
