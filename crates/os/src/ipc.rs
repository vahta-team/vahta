//! The local connection between the `vahta` command, the prompt window and the
//! daemon: a Unix domain socket in a private directory (Linux, macOS) or a
//! named pipe that only the user may open (Windows).
//!
//! The same API on every platform. A [`Stream`] is a reliable byte stream you
//! can read, write, clone for a second thread and shut down; on a server-side
//! stream [`Stream::peer`] says, from the kernel, which process connected.

#[cfg(unix)]
#[path = "ipc_unix.rs"]
mod imp;
#[cfg(windows)]
#[path = "ipc_windows.rs"]
mod imp;

pub use imp::{Listener, Stream};

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;

/// Where the daemon listens. An opaque name that survives being put in an
/// environment variable and read back ([`Address::as_os_str`] and
/// [`Address::from_os_string`]), which is how the prompt window learns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address(OsString);

impl Address {
    /// The address for a daemon whose runtime directory is `dir`. On Unix the
    /// socket `dir/daemon.sock`; on Windows a pipe named from the user's SID
    /// and `dir`, so two runtime directories (two test sandboxes) do not
    /// collide.
    pub fn for_runtime_dir(dir: &Path) -> io::Result<Address> {
        imp::address_for(dir).map(Address)
    }

    pub fn from_os_string(raw: OsString) -> Address {
        Address(raw)
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }

    /// The socket file, where there is one (Unix). Cleaned up by the daemon
    /// when it exits.
    pub fn socket_path(&self) -> Option<&Path> {
        cfg!(unix).then(|| Path::new(&self.0))
    }
}
