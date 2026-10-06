//! Linux: `/proc` for process facts, `rustix` for everything that is a system
//! call. None of it needs `unsafe`.

use std::fs;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::process::Command;

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::net::sockopt::socket_peercred;
use rustix::process::{
    DumpableBehavior, PidfdFlags, Resource, Rlimit, geteuid, pidfd_open, set_dumpable_behavior,
    setrlimit, setsid,
};

use crate::{Peer, ProcessId, walk_chain};

/// A pidfd for the peer, held while its request is served: the kernel does not
/// reuse a pid while a pidfd to it is open. `None` on a kernel without pidfd.
pub(crate) type Hold = Option<OwnedFd>;

/// `(ppid, start time in clock ticks since boot)` from the text of
/// `/proc/<pid>/stat`. The command name (field 2) is in parentheses and may
/// itself hold spaces and parentheses, so the fields are counted from the last
/// `)`: the state is field 3, the parent field 4, the start time field 22.
pub(crate) fn parse_stat(content: &str) -> Option<(u32, u64)> {
    let rparen = content.rfind(')')?;
    let rest: Vec<&str> = content[rparen + 1..].split_whitespace().collect();
    if rest.len() <= 19 {
        return None;
    }
    Some((rest[1].parse().ok()?, rest[19].parse().ok()?))
}

fn read_stat(pid: u32) -> io::Result<(u32, u64)> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_stat(&text).ok_or_else(|| io::Error::other("unreadable /proc stat"))
}

pub(crate) fn identity_of(pid: u32) -> io::Result<ProcessId> {
    let (_, start_time) = read_stat(pid)?;
    Ok(ProcessId { pid, start_time })
}

pub(crate) fn parent_of(pid: u32) -> io::Result<u32> {
    read_stat(pid).map(|(ppid, _)| ppid)
}

pub(crate) fn ancestor_chain(pid: u32, max: usize) -> Vec<ProcessId> {
    walk_chain(pid, max, read_stat)
}

pub(crate) fn exe_name(pid: u32) -> Option<String> {
    let from_exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        // A replaced binary reads as `name (deleted)`.
        .map(|n| n.trim_end_matches(" (deleted)").to_string());
    match from_exe {
        Some(n) if !n.is_empty() => Some(n),
        _ => fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty()),
    }
}

pub(crate) fn owned_by_me(pid: u32) -> bool {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1)?.parse::<u32>().ok())
        .is_some_and(|euid| euid == geteuid().as_raw())
}

/// The kernel's account of who connected, taken from the socket itself
/// (`SO_PEERCRED`), never from anything the peer sent.
pub(crate) fn peer_of(sock: impl AsFd) -> io::Result<Peer> {
    let cred = socket_peercred(&sock)?;
    let pid = u32::try_from(cred.pid.as_raw_pid()).map_err(|_| io::Error::other("bad pid"))?;
    // Open the pidfd before reading the start time, so a pid reused in between
    // is the one the pidfd holds and the read below can be believed.
    let hold = pidfd_open(cred.pid, PidfdFlags::empty()).ok();
    let id = identity_of(pid)?;
    Ok(Peer::new(id, cred.uid == geteuid(), hold))
}

pub(crate) fn effective_uid() -> Option<u32> {
    Some(geteuid().as_raw())
}

pub(crate) fn signal_process_group(pid: u32, sig: crate::Signal) -> io::Result<()> {
    use rustix::process::{Pid, Signal, kill_process_group};
    let pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::other("bad pid"))?;
    let signal = match sig {
        crate::Signal::Interrupt => Signal::INT,
        crate::Signal::Terminate => Signal::TERM,
        crate::Signal::Hangup => Signal::HUP,
        crate::Signal::Kill => Signal::KILL,
    };
    kill_process_group(pid, signal).map_err(io::Error::from)
}

pub(crate) fn harden_process() -> io::Result<()> {
    let dump = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    let core = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    dump.map_err(|e| io::Error::other(format!("PR_SET_DUMPABLE: {e}")))?;
    core.map_err(|e| io::Error::other(format!("RLIMIT_CORE: {e}")))?;
    Ok(())
}

pub(crate) fn lock_memory() -> io::Result<()> {
    // ONFAULT locks pages as they are touched, so a small daemon does not pay
    // for its whole address space up front.
    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE | MlockAllFlags::ONFAULT)
        .map_err(io::Error::from)
}

pub(crate) fn detach_session() {
    // Fails only for a process that already leads a group, which is already
    // detached enough.
    let _ = setsid();
}

pub(crate) fn detach_command(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_are_counted_from_the_last_paren() {
        // comm "a) b (c": spaces and parentheses inside it.
        let line = "42 (a) b (c) S 7 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 1000 50 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        assert_eq!(parse_stat(line), Some((7, 12345)));
        assert_eq!(parse_stat("42 (x) S 7"), None);
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn the_peer_of_a_connected_pair_is_this_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let peer = peer_of(&a).expect("peer");
        assert_eq!(peer.id, identity_of(std::process::id()).expect("identity"));
        assert!(peer.same_user);
    }
}
