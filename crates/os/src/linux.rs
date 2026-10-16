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

/// The kernel's id of this boot.
pub(crate) fn boot_id() -> Option<String> {
    let id = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let id = id.trim();
    (!id.is_empty()).then(|| id.to_string())
}

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

pub(crate) fn command_line(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let words: Vec<String> = bytes
        .split(|b| *b == 0)
        .filter(|w| !w.is_empty())
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect();
    (!words.is_empty()).then(|| words.join(" "))
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
    /// Set for a run that may reach named hosts (see [`isolate_network_hosts`]).
    hosts: Option<HostPlan>,
}

/// The extra work of a run with named hosts: a loopback that is up, one
/// listening socket per host and port, handed out over `ctrl`, and a few files
/// in `/etc` replaced so that only the listed names resolve.
struct HostPlan {
    /// The child's end of the socket the listeners go out over.
    ctrl: OwnedFd,
    addrs: Vec<std::net::SocketAddrV4>,
    binds: Vec<Bind>,
}

struct Bind {
    /// A file in the scratch directory of [`HostSocket`].
    src: std::ffi::CString,
    target: std::ffi::CString,
    /// A failed mount of a file the run cannot do without refuses the start;
    /// the others are best effort.
    required: bool,
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
            hosts: None,
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
    if let Some(hosts) = &plan.hosts {
        enter_hosts(hosts)?;
    }
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

/// The most listening sockets one run gets.
pub(crate) const MAX_LISTENERS: usize = 64;

/// `struct ifreq` as `SIOCSIFFLAGS` reads it.
#[repr(C)]
struct IfReq {
    name: [u8; 16],
    flags: i16,
    pad: [u8; 22],
}

/// Bring `lo` up in the new network namespace.
fn loopback_up() -> io::Result<()> {
    use rustix::ioctl::{Setter, ioctl};
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socket_with};
    const IFF_UP: i16 = 1;
    const IFF_RUNNING: i16 = 0x40;
    let sock = socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let mut name = [0u8; 16];
    name[..2].copy_from_slice(b"lo");
    let req = IfReq {
        name,
        flags: IFF_UP | IFF_RUNNING,
        pad: [0; 22],
    };
    // SAFETY: SIOCSIFFLAGS (0x8914) takes a pointer to a `struct ifreq`, which `IfReq`
    // matches in size and layout (16-byte name, 16-bit flags, padding to 40).
    unsafe { ioctl(&sock, Setter::<0x8914, IfReq>::new(req)) }?;
    Ok(())
}

/// The part of the child's setup for a run with named hosts: loopback up,
/// listeners bound and sent out over the control socket, name files replaced.
/// Raw system calls on data built before the fork.
fn enter_hosts(plan: &HostPlan) -> io::Result<()> {
    use rustix::mount::mount_bind;
    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
        SocketType, bind, listen, sendmsg, socket_with,
    };
    use std::io::IoSlice;
    use std::mem::MaybeUninit;
    loopback_up()?;
    for addr in &plan.addrs {
        let fd = socket_with(
            AddressFamily::INET,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )?;
        bind(&fd, addr)?;
        listen(&fd, 128)?;
        // One message per listener, in order; the descriptor is a duplicate
        // in the receiver, so this one closes at the end of the iteration.
        let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let borrowed = [fd.as_fd()];
        if !control.push(SendAncillaryMessage::ScmRights(&borrowed)) {
            return Err(io::Error::from_raw_os_error(22));
        }
        sendmsg(
            &plan.ctrl,
            &[IoSlice::new(&[0])],
            &mut control,
            SendFlags::empty(),
        )?;
    }
    for b in &plan.binds {
        match mount_bind(b.src.as_c_str(), b.target.as_c_str()) {
            Ok(()) => {}
            Err(e) if b.required => return Err(e.into()),
            Err(_) => {}
        }
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

/// The parent's end of the socket the listeners of a run with named hosts
/// arrive on.
pub(crate) struct HostSocket {
    parent: OwnedFd,
    count: usize,
    /// Where the replacement files were written. They are only needed until
    /// the child has mounted them (the mounts keep the files), so the
    /// directory goes when this does.
    scratch: std::path::PathBuf,
}

impl Drop for HostSocket {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

impl HostSocket {
    /// The listening sockets the child made, in the order of the hosts given.
    /// Call once, after the child has started (it sends them before `exec`).
    pub(crate) fn take(&self) -> io::Result<Vec<std::net::TcpListener>> {
        use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};
        use std::io::IoSliceMut;
        let mut out = Vec::with_capacity(self.count);
        for _ in 0..self.count {
            let mut byte = [0u8; 1];
            let mut space =
                [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            recvmsg(
                &self.parent,
                &mut [IoSliceMut::new(&mut byte)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            )?;
            let fd = control.drain().find_map(|m| match m {
                RecvAncillaryMessage::ScmRights(mut fds) => fds.next(),
                _ => None,
            });
            let fd = fd.ok_or_else(|| io::Error::other("a listener did not arrive"))?;
            out.push(std::net::TcpListener::from(fd));
        }
        Ok(out)
    }
}

/// A new private directory for the files that replace the names files.
fn scratch_dir() -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir = std::env::temp_dir().join(format!(
        "vahta-hosts-{}-{}-{nanos}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// The text of `/etc/hosts` for a run that may reach `names`: each gets the
/// loopback address `127.0.0.(2 + position)`.
pub(crate) fn hosts_file(names: &[String]) -> String {
    let mut text = String::from("127.0.0.1 localhost\n::1 localhost\n");
    for (i, n) in names.iter().enumerate() {
        text.push_str(&format!("127.0.0.{} {n}\n", i + 2));
    }
    text
}

/// `/etc/nsswitch.conf` with the `hosts` line reduced to `files`, so no
/// resolver service is asked. `None` when the real file cannot be read (the C
/// library's own default then applies, and the sockets give no way out
/// anyway).
fn nsswitch_files_only() -> Option<String> {
    let text = fs::read_to_string("/etc/nsswitch.conf").ok()?;
    let mut out = String::new();
    let mut done = false;
    for line in text.lines() {
        if line.trim_start().starts_with("hosts:") {
            if !done {
                out.push_str("hosts: files\n");
                done = true;
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !done {
        out.push_str("hosts: files\n");
    }
    Some(out)
}

/// As [`isolate_network`], and the command may open connections to `hosts`
/// (name and port). Inside the namespace the loopback is up and each distinct
/// name is `127.0.0.(2 + position)` in a replaced `/etc/hosts` (nothing else
/// resolves: `nsswitch.conf` consults files only, `resolv.conf` is empty); a
/// socket listens on that address and each port given for it, and all of them
/// are handed to the caller, who relays what is accepted. Anything else has no
/// route. The caller gets the sockets with [`HostSocket::take`] once
/// `spawn` has returned.
pub(crate) fn isolate_network_hosts(
    cmd: &mut Command,
    hosts: &[(String, u16)],
) -> io::Result<HostSocket> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
    use std::os::unix::process::CommandExt;
    if hosts.is_empty() || hosts.len() > MAX_LISTENERS {
        return Err(io::Error::from_raw_os_error(22));
    }
    let mut names: Vec<String> = Vec::new();
    for (h, _) in hosts {
        if !names.contains(h) {
            names.push(h.clone());
        }
    }
    if names.len() > 200 {
        return Err(io::Error::from_raw_os_error(22));
    }
    let addrs = hosts
        .iter()
        .map(|(h, port)| {
            let i = names.iter().position(|n| n == h).unwrap_or(0);
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, (i + 2) as u8), *port)
        })
        .collect();
    let scratch = scratch_dir()?;
    let made = (|| -> io::Result<(Vec<Bind>, OwnedFd, OwnedFd)> {
        let mut binds = Vec::new();
        let mut add = |file: &str, data: &str, target: &str, required: bool| -> io::Result<()> {
            let src = scratch.join(file);
            fs::write(&src, data)?;
            binds.push(Bind {
                src: std::ffi::CString::new(src.as_os_str().as_encoded_bytes())
                    .map_err(io::Error::other)?,
                target: std::ffi::CString::new(target).map_err(io::Error::other)?,
                required,
            });
            Ok(())
        };
        add("hosts", &hosts_file(&names), "/etc/hosts", true)?;
        add(
            "resolv.conf",
            "# no name server is reachable from here\n",
            "/etc/resolv.conf",
            false,
        )?;
        if let Some(conf) = nsswitch_files_only() {
            add("nsswitch.conf", &conf, "/etc/nsswitch.conf", false)?;
        }
        let (parent, child) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        Ok((binds, parent, child))
    })();
    let (binds, parent, child) = match made {
        Ok(m) => m,
        Err(e) => {
            let _ = fs::remove_dir_all(&scratch);
            return Err(e);
        }
    };
    let mut plan = Plan::new(&[]);
    let count = hosts.len();
    plan.hosts = Some(HostPlan {
        ctrl: child,
        addrs,
        binds,
    });
    // SAFETY: as in `isolate_network_passing`: the closure makes only raw
    // system calls on data built before the fork (unshare, writes to the map
    // files, mounts, socket, bind, listen, sendmsg, ioctl) and does not
    // allocate or take a lock.
    unsafe {
        cmd.pre_exec(move || enter_isolation(&plan));
    }
    Ok(HostSocket {
        parent,
        count,
        scratch,
    })
}

/// Make a blocked `accept` on `listener` (in another thread, on this socket or
/// a duplicate of it) return with an error.
pub(crate) fn wake_listener(listener: &std::net::TcpListener) {
    let _ = rustix::net::shutdown(listener, rustix::net::Shutdown::Read);
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
