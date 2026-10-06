//! The operating-system calls Vahta needs, behind one small API.
//!
//! This is the only crate in the workspace that may contain `unsafe`, and the
//! only things it does are the calls the standard library does not make:
//!
//! * who is on the other end of a local connection (`SO_PEERCRED` on Linux,
//!   `LOCAL_PEERPID` on macOS, `GetNamedPipeClientProcessId` on Windows), as a
//!   process id plus its start time, so a recycled pid is not mistaken for the
//!   process it replaced;
//! * a process's parent, start time, executable name and owner, and the chain
//!   of ancestors from those;
//! * hardening the current process (no dumps, no core files, locked memory);
//! * starting a process detached from the caller's terminal;
//! * the local socket the daemon listens on: a Unix socket in a private
//!   directory, or a named pipe whose access list names only the user.
//!
//! On Linux everything goes through `rustix`, whose calls are safe, so the
//! Linux build has no `unsafe` of its own. macOS (`libc`) and Windows
//! (`windows-sys`) need it; each block says why it is sound.
//!
//! The logic follows ka's `peer_identity.py`: identity is `(pid, start time)`,
//! the start time is only compared with another taken the same way on the same
//! machine, and any failure to read it is an error the caller treats as an
//! unknown process, never as permission.

use std::io;
use std::process::Command;

pub mod ipc;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod sys;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod sys;
#[cfg(windows)]
#[path = "windows.rs"]
mod sys;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("vahta-os supports Linux, macOS and Windows");

/// Longest ancestor chain ever walked. Real process trees are a handful of
/// levels; this stops a cyclic or pathological chain from spinning.
pub const MAX_ANCESTORS: usize = 32;

/// The lowest pid a session may be anchored to: init on Unix, System on
/// Windows. Anything at or below it is not an agent.
#[cfg(windows)]
pub const MIN_PID: u32 = 4;
#[cfg(not(windows))]
pub const MIN_PID: u32 = 1;

/// A process, as the kernel identifies it: the pid and when it started. The
/// start time is an opaque number (clock ticks since boot on Linux, ticks
/// since 1601 on Windows, microseconds since the epoch on macOS); compare it
/// only for equality with another taken the same way on the same machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId {
    pub pid: u32,
    pub start_time: u64,
}

/// The process at the other end of an accepted connection, kernel-verified.
/// While this value lives the operating system keeps the process's identity
/// from being reused where it can (a pidfd on Linux, an open process handle on
/// Windows); drop it when the request has been served.
#[derive(Debug)]
pub struct Peer {
    pub id: ProcessId,
    /// Whether the peer runs as the same user as this process. A connection
    /// from another user is refused before anything is read from it.
    pub same_user: bool,
    _hold: sys::Hold,
}

impl Peer {
    pub(crate) fn new(id: ProcessId, same_user: bool, hold: sys::Hold) -> Peer {
        Peer {
            id,
            same_user,
            _hold: hold,
        }
    }
}

/// `pid`'s own identity.
pub fn identity_of(pid: u32) -> io::Result<ProcessId> {
    sys::identity_of(pid)
}

/// `pid`'s parent.
pub fn parent_of(pid: u32) -> io::Result<u32> {
    sys::parent_of(pid)
}

/// `[pid itself, its parent, its grandparent, ...]`, at most `max` entries.
/// Stops at a process that cannot be read (exited, not ours), at pid 0, at a
/// repeated pid, and where a parent started *after* its child (its pid has been
/// recycled, so it is not the real parent). Never fails: an unwalkable chain is
/// short, down to empty when `pid` is already gone.
pub fn ancestor_chain(pid: u32, max: usize) -> Vec<ProcessId> {
    sys::ancestor_chain(pid, max.min(MAX_ANCESTORS))
}

/// The executable's base name (`bash`, `claude`, `explorer.exe`), if it can be
/// read.
pub fn exe_name(pid: u32) -> Option<String> {
    sys::exe_name(pid)
}

/// Whether `pid` runs as the user this process runs as. False when it cannot
/// be told: unknown is not mine.
pub fn owned_by_me(pid: u32) -> bool {
    sys::owned_by_me(pid)
}

/// This process's effective user id, where users have numeric ids (Unix).
pub fn effective_uid() -> Option<u32> {
    sys::effective_uid()
}

/// A signal a command can be sent. Unix only; on Windows there is no such
/// thing to send to a process group and [`signal_process_group`] says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Interrupt,
    Terminate,
    Hangup,
    Kill,
}

/// Send `sig` to the process group led by `pid` (a command started with its own
/// group). On Windows this is `Unsupported` and the caller ends the process
/// another way.
pub fn signal_process_group(pid: u32, sig: Signal) -> io::Result<()> {
    sys::signal_process_group(pid, sig)
}

/// Make this process harder to read from outside: not dumpable, no core
/// files. Call once at startup. The error names the step that failed; the
/// process carries on, as hardening is best effort.
pub fn harden_process() -> io::Result<()> {
    sys::harden_process()
}

/// Leave the caller's session, so closing the terminal that started this
/// process does not signal it. A daemon calls this once at startup.
pub fn detach_session() {
    sys::detach_session();
}

/// Start `cmd` so that it keeps running after this process and its terminal
/// are gone: no standard streams, its own session or process group, no console
/// window. Returns once it has been started, not when it ends.
pub fn spawn_detached(cmd: &mut Command) -> io::Result<()> {
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    sys::detach_command(cmd);
    cmd.spawn().map(drop)
}

/// The chain walk behind [`ancestor_chain`], over any way of reading a
/// process's `(parent, start time)`. Separate from the platforms so the rules
/// are tested without a process tree.
pub(crate) fn walk_chain(
    pid: u32,
    max: usize,
    mut read: impl FnMut(u32) -> io::Result<(u32, u64)>,
) -> Vec<ProcessId> {
    let mut chain: Vec<ProcessId> = Vec::new();
    let mut current = pid;
    while chain.len() < max && current != 0 {
        if chain.iter().any(|p| p.pid == current) {
            break;
        }
        let Ok((ppid, start_time)) = read(current) else {
            break;
        };
        // A parent that started after its child is a recycled pid, not the
        // real parent (the real one would have to be older).
        if let Some(child) = chain.last()
            && start_time > child.start_time
        {
            break;
        }
        chain.push(ProcessId {
            pid: current,
            start_time,
        });
        if ppid == current {
            break;
        }
        current = ppid;
    }
    chain
}

/// The access list of a named pipe in SDDL: nobody but `sid` (a user SID such
/// as `S-1-5-21-...`) may open it. A protected DACL, so nothing is inherited
/// from the pipe namespace, and a single allow entry for the user with generic
/// all access. Compiled everywhere so it is unit-tested everywhere; Windows is
/// where it is used.
pub fn pipe_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

/// A short stable hash for names derived from paths and SIDs. FNV-1a, because
/// the standard library's hashers are not stable across releases and two
/// Vahta versions must agree on the name.
pub fn stable_hash(parts: &[&str]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for b in part.bytes().chain(std::iter::once(0)) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_own_identity_is_stable_and_the_chain_starts_with_us() {
        let me = std::process::id();
        let a = identity_of(me).expect("own identity");
        let b = identity_of(me).expect("own identity again");
        assert_eq!(a, b);
        assert_eq!(a.pid, me);
        let chain = ancestor_chain(me, 8);
        assert_eq!(chain.first(), Some(&a));
    }

    #[test]
    fn the_chain_contains_our_parent() {
        let me = std::process::id();
        let parent = parent_of(me).expect("own parent");
        let chain = ancestor_chain(me, 8);
        assert!(
            chain.iter().any(|p| p.pid == parent),
            "parent {parent} not in {chain:?}"
        );
    }

    #[test]
    fn we_own_ourselves_and_have_a_name() {
        let me = std::process::id();
        assert!(owned_by_me(me));
        assert!(exe_name(me).is_some_and(|n| !n.is_empty()));
    }

    #[test]
    fn a_pid_that_does_not_exist_is_an_error_not_an_identity() {
        // The kernel's pid space ends well below this on every platform.
        assert!(identity_of(u32::MAX - 1).is_err());
        assert!(ancestor_chain(u32::MAX - 1, 8).is_empty());
        assert!(!owned_by_me(u32::MAX - 1));
    }

    #[test]
    fn the_pipe_acl_names_only_the_user() {
        let sddl = pipe_sddl("S-1-5-21-1-2-3-1001");
        assert_eq!(sddl, "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)");
        // One entry, protected: nothing for Everyone, Users or inheritance.
        assert_eq!(sddl.matches("(A;").count(), 1);
        assert!(sddl.starts_with("D:P"));
    }

    #[test]
    fn the_walk_stops_at_a_recycled_parent_a_cycle_and_the_limit() {
        use std::collections::HashMap;
        // 10 <- 20 <- 30, and 30's recorded parent 99 is younger than 30.
        let table: HashMap<u32, (u32, u64)> = [
            (10, (20, 500)),
            (20, (30, 400)),
            (30, (99, 300)),
            (99, (1, 900)),
            (1, (0, 1)),
            (5, (6, 10)),
            (6, (5, 10)),
        ]
        .into_iter()
        .collect();
        let read = |p: u32| {
            table
                .get(&p)
                .copied()
                .ok_or_else(|| io::Error::other("gone"))
        };
        let pids = |c: Vec<ProcessId>| c.into_iter().map(|p| p.pid).collect::<Vec<_>>();
        assert_eq!(pids(walk_chain(10, 8, read)), [10, 20, 30]);
        assert_eq!(pids(walk_chain(10, 2, read)), [10, 20]);
        assert_eq!(pids(walk_chain(5, 8, read)), [5, 6]);
        assert!(walk_chain(77, 8, read).is_empty());
    }

    #[test]
    fn the_hash_is_stable_and_separates_its_parts() {
        assert_eq!(stable_hash(&["a", "b"]), stable_hash(&["a", "b"]));
        assert_ne!(stable_hash(&["ab", ""]), stable_hash(&["a", "b"]));
        assert_eq!(stable_hash(&["x"]).len(), 16);
    }
}
