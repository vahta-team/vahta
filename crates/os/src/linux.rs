//! Linux: `/proc` for process facts, `rustix` for everything that is a system
//! call. None of it needs `unsafe`.

use std::fs;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::process::Command;

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

pub(crate) fn detach_session() {
    // Fails only for a process that already leads a group, which is already
    // detached enough.
    let _ = setsid();
}

pub(crate) fn detach_command(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}

/// What `isolate_network` makes of each failure the child can hit, as a raw
/// errno it hands back through `spawn`. `ECANCELED` is the probe's "it worked".
const PROBE_OK: i32 = 125;

/// Prepare `cmd` to start in a fresh user and network namespace, mapping the
/// caller's own uid and gid to themselves so file access is unchanged.
pub(crate) fn isolate_network(cmd: &mut Command) -> Result<(), crate::Unsupported> {
    use std::os::unix::process::CommandExt;
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    // Built here, before the fork: the closure below must not allocate.
    let uid_map = format!("{uid} {uid} 1\n").into_bytes();
    let gid_map = format!("{gid} {gid} 1\n").into_bytes();
    // SAFETY: the closure runs in the forked child before exec, where only
    // async-signal-safe calls are allowed. `enter_isolation` makes only raw
    // syscalls (unshare, open, write, close through rustix) on buffers that
    // were built before the fork, and never allocates or takes a lock.
    unsafe {
        cmd.pre_exec(move || enter_isolation(&uid_map, &gid_map));
    }
    Ok(())
}

/// In the child: leave the parent's network, then map the user back to itself.
/// The order is fixed by the kernel: `setgroups` must be `deny` before an
/// unprivileged `gid_map` write is accepted.
fn enter_isolation(uid_map: &[u8], gid_map: &[u8]) -> io::Result<()> {
    use rustix::thread::{UnshareFlags, unshare_unsafe};
    // SAFETY: unshare of NEWUSER and NEWNET in a single-threaded just-forked
    // child. It changes only this process's namespaces; no memory is touched.
    unsafe { unshare_unsafe(UnshareFlags::NEWUSER | UnshareFlags::NEWNET) }?;
    write_file(c"/proc/self/setgroups", b"deny")?;
    write_file(c"/proc/self/uid_map", uid_map)?;
    write_file(c"/proc/self/gid_map", gid_map)?;
    Ok(())
}

fn write_file(path: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags, open};
    let fd = open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())?;
    // One write: the kernel takes a map file in a single write or not at all.
    let n = rustix::io::write(&fd, data)?;
    if n != data.len() {
        return Err(io::Error::from_raw_os_error(5));
    }
    Ok(())
}

/// Whether a child can get a network namespace of its own here: does the whole
/// sequence in a forked child, which then reports success as a spawn error
/// instead of running anything.
pub(crate) fn network_isolation_available() -> bool {
    use std::os::unix::process::CommandExt;
    let mut probe = Command::new("/");
    let (u, g) = (b"0 0 1\n".to_vec(), b"0 0 1\n".to_vec());
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    let u = if uid == 0 {
        u
    } else {
        format!("{uid} {uid} 1\n").into_bytes()
    };
    let g = if gid == 0 {
        g
    } else {
        format!("{gid} {gid} 1\n").into_bytes()
    };
    // SAFETY: same constraints and same body as in `isolate_network`; the
    // closure then returns an error so the child never reaches exec.
    unsafe {
        probe.pre_exec(move || {
            enter_isolation(&u, &g)?;
            Err(io::Error::from_raw_os_error(PROBE_OK))
        });
    }
    matches!(probe.spawn(), Err(e) if e.raw_os_error() == Some(PROBE_OK))
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
