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

pub(crate) fn process_cwd(pid: u32) -> io::Result<std::path::PathBuf> {
    // A directory that was removed reads as `/path (deleted)`; canonicalizing
    // it fails, which is the answer: no verified directory.
    fs::canonicalize(fs::read_link(format!("/proc/{pid}/cwd"))?)
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

/// The probe's "it worked": `ECANCELED`, handed back through `spawn`.
const PROBE_OK: i32 = 125;

/// Directories whose Unix sockets give a way out of the network namespace (the
/// system and session buses, systemd-resolved, docker.sock, the XDG runtime
/// directory, X11). Each that exists is covered with an empty tmpfs.
const HIDDEN: [&str; 3] = ["/run", "/var/run", "/tmp/.X11-unix"];

/// Paths under `HIDDEN` that are handed back, with everything mounted below
/// them, after the tmpfs is in place: where removable media is mounted
/// (udisks: `/run/media/$USER/<label>`; some systems: `/run/mnt`). A program
/// that writes to a mounted card or stick must not have the write land in an
/// empty tmpfs and vanish.
///
/// Why this allowlist rather than a denylist of sockets: a denylist fails open
/// (a socket nobody listed is a hole in "no network"), an allowlist fails
/// closed (a path nobody listed is merely not there, and `hidden_path` lets the
/// caller say so). Why these are safe: both hold only mount points of
/// block-device file systems, never daemon sockets (those live in `/run/user`,
/// `/run/dbus`, `/run/systemd`, ...). A socket file on a foreign file system
/// has no listener behind it: connecting to a stale inode is refused, and a
/// listener on it would have to be started by the user on that medium.
const PASSTHROUGH: [&str; 2] = ["/run/media", "/run/mnt"];

/// Room for the file descriptors of the trees held across the tmpfs mount.
const MAX_KEEP: usize = 8;

/// A directory tree to bring back into the emptied directory it lives in.
struct Keep {
    src: std::ffi::CString,
    /// Directories to create inside the tmpfs, outermost first, ending with
    /// `src` itself.
    make: Vec<std::ffi::CString>,
}

/// All of what the child does, built before the fork so that nothing after it
/// allocates.
struct Plan {
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    hide: Vec<std::ffi::CString>,
    keep: Vec<Keep>,
}

fn is_real_dir(p: &std::path::Path) -> bool {
    // A symlink (`/var/run` -> `/run`) is covered by its target; mounting on
    // the link would mount on the target again.
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
}

impl Plan {
    fn new(extra: &[&std::path::Path]) -> Plan {
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let hide: Vec<std::ffi::CString> = HIDDEN
            .iter()
            .filter(|p| is_real_dir(std::path::Path::new(p)))
            .filter_map(|p| std::ffi::CString::new(*p).ok())
            .collect();
        let run_hidden = hide.iter().any(|d| d.as_bytes() == b"/run");
        let mut keep = Vec::new();
        let wanted = PASSTHROUGH
            .iter()
            .map(std::path::Path::new)
            .chain(extra.iter().copied());
        for path in wanted {
            // Only what lies under `/run` is hidden by a tmpfs over it, and
            // only a real directory is brought back.
            if !run_hidden
                || !path.starts_with("/run")
                || keep.len() >= MAX_KEEP
                || !is_real_dir(path)
            {
                continue;
            }
            // Every ancestor below `/run` must itself be a real directory:
            // the tree is cloned by path, and a symlink would leave the
            // allowlisted place.
            let mut make = Vec::new();
            let mut walk = std::path::PathBuf::from("/run");
            let mut sound = true;
            for part in path.components().skip(2) {
                walk.push(part);
                sound &= is_real_dir(&walk);
                match std::ffi::CString::new(walk.as_os_str().as_encoded_bytes()) {
                    Ok(c) => make.push(c),
                    Err(_) => sound = false,
                }
            }
            if let (true, Some(src)) = (sound, make.last().cloned()) {
                keep.push(Keep { src, make });
            }
        }
        Plan {
            uid_map: format!("{uid} {uid} 1\n").into_bytes(),
            gid_map: format!("{gid} {gid} 1\n").into_bytes(),
            hide,
            keep,
        }
    }
}

/// Whether `path` lies where a command started by [`isolate_network`] sees an
/// empty directory instead of the real one, so that what it writes there would
/// be lost. The path need not exist yet: the deepest existing ancestor is
/// resolved (symlinks included) and the rest appended.
pub(crate) fn hidden_path(path: &std::path::Path) -> bool {
    hidden_path_with(path, &[])
}

fn hidden_path_with(path: &std::path::Path, extra: &[&std::path::Path]) -> bool {
    let mut tail = Vec::new();
    let mut head = path;
    let resolved = loop {
        if let Ok(real) = fs::canonicalize(head) {
            break real;
        }
        match (head.parent(), head.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name);
                head = parent;
            }
            _ => return false,
        }
    };
    let full = tail.iter().rev().fold(resolved, |p, n| p.join(n));
    let under = |root: &std::path::Path| full.starts_with(root);
    // `/var/run` resolves to `/run` when it is a link; when it is a real
    // directory it is hidden on its own.
    let hidden = HIDDEN.iter().any(|h| under(std::path::Path::new(h)));
    let kept = PASSTHROUGH
        .iter()
        .map(std::path::Path::new)
        .chain(extra.iter().copied())
        .any(under);
    hidden && !kept
}

/// Prepare `cmd` to start in a fresh user, network and mount namespace, with
/// the caller's own uid and gid mapped to themselves so file access is
/// unchanged, and the socket directories in `HIDDEN` emptied (except the
/// removable-media trees in `PASSTHROUGH`).
pub(crate) fn isolate_network(cmd: &mut Command) -> Result<(), crate::Unsupported> {
    isolate_network_passing(cmd, &[])
}

/// As [`isolate_network`], also passing `extra` (paths under `/run`) through.
/// For tests, which cannot create `/run/media`.
pub(crate) fn isolate_network_passing(
    cmd: &mut Command,
    extra: &[&std::path::Path],
) -> Result<(), crate::Unsupported> {
    use std::os::unix::process::CommandExt;
    let plan = Plan::new(extra);
    // SAFETY: the closure runs in the forked child before exec, where only
    // async-signal-safe calls are allowed. `enter_isolation` makes only raw
    // syscalls (unshare, open, write, mount through rustix) on data built
    // before the fork, and never allocates or takes a lock.
    unsafe {
        cmd.pre_exec(move || enter_isolation(&plan));
    }
    Ok(())
}

/// In the child: leave the parent's network and mounts, map the user back to
/// itself, and hide the socket directories. The order is fixed by the kernel:
/// `setgroups` must be `deny` before an unprivileged `gid_map` write is
/// accepted, and mounts need the mapped user namespace's rights.
fn enter_isolation(plan: &Plan) -> io::Result<()> {
    use rustix::fs::{CWD, Mode, mkdirat};
    use rustix::mount::{
        MountFlags, MountPropagationFlags, MoveMountFlags, OpenTreeFlags, mount, mount_change,
        move_mount, open_tree,
    };
    use rustix::thread::{UnshareFlags, unshare_unsafe};
    // The daemon is not dumpable (`harden_process`), and the child inherits
    // that: the kernel then makes its /proc/self/{uid,gid}_map unwritable.
    // Only this just-forked child is made dumpable again (a normal command is
    // anyway; exec resets the flag for it).
    set_dumpable_behavior(DumpableBehavior::Dumpable)?;
    // SAFETY: unshare of NEWUSER, NEWNET and NEWNS in a single-threaded
    // just-forked child. It changes only this process's namespaces; no memory
    // is touched.
    unsafe { unshare_unsafe(UnshareFlags::NEWUSER | UnshareFlags::NEWNET | UnshareFlags::NEWNS) }?;
    write_file(c"/proc/self/setgroups", b"deny")?;
    write_file(c"/proc/self/uid_map", &plan.uid_map)?;
    write_file(c"/proc/self/gid_map", &plan.gid_map)?;
    // Nothing mounted below may propagate back to the parent's tree.
    mount_change(
        c"/",
        MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
    )?;
    // The passed-through trees are detached copies held by descriptor, since
    // the path to them is covered next. A fixed array: no allocation here.
    let mut held: [Option<OwnedFd>; MAX_KEEP] = [const { None }; MAX_KEEP];
    for (slot, k) in held.iter_mut().zip(&plan.keep) {
        *slot = Some(open_tree(
            CWD,
            k.src.as_c_str(),
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_RECURSIVE,
        )?);
    }
    for dir in &plan.hide {
        mount(
            c"tmpfs",
            dir.as_c_str(),
            c"tmpfs",
            MountFlags::empty(),
            None,
        )?;
    }
    for (slot, k) in held.iter().zip(&plan.keep) {
        let Some(fd) = slot else { continue };
        for dir in &k.make {
            match mkdirat(CWD, dir.as_c_str(), Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        move_mount(
            fd,
            c"",
            CWD,
            k.src.as_c_str(),
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )?;
    }
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

/// Whether a child can get the namespaces here: does the whole sequence in a
/// forked child, which then reports success as a spawn error instead of
/// running anything.
pub(crate) fn network_isolation_available() -> bool {
    use std::os::unix::process::CommandExt;
    let mut probe = Command::new("/");
    let plan = Plan::new(&[]);
    // SAFETY: same constraints and same body as in `isolate_network`; the
    // closure then returns an error so the child never reaches exec.
    unsafe {
        probe.pre_exec(move || {
            enter_isolation(&plan)?;
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
    fn a_process_cwd_is_read_from_the_kernel() {
        let here = fs::canonicalize(std::env::current_dir().expect("cwd")).expect("canonical");
        assert_eq!(process_cwd(std::process::id()).expect("cwd"), here);
        assert!(process_cwd(u32::MAX).is_err());
    }

    #[test]
    fn the_peer_of_a_connected_pair_is_this_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let peer = peer_of(&a).expect("peer");
        assert_eq!(peer.id, identity_of(std::process::id()).expect("identity"));
        assert!(peer.same_user);
    }
}
