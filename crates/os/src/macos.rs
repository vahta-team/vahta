//! macOS: `LOCAL_PEERPID` and `getpeereid` for the peer, `proc_pidinfo` for
//! parent, start time and owner. The calls are `libc`'s; each unsafe block is
//! a single call with plain arguments and a buffer that outlives it.

use std::ffi::c_void;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::process::Command;

use rustix::process::{Resource, Rlimit, geteuid, setrlimit, setsid};

use crate::{Peer, ProcessId, walk_chain};

/// Nothing to hold: macOS offers no handle that pins a pid.
pub(crate) type Hold = ();

fn bsd_info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    let pid = libc::c_int::try_from(pid).map_err(|_| io::Error::other("pid out of range"))?;
    // SAFETY: `proc_bsdinfo` is plain data; all-zero bytes are a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer is `size` bytes of writable memory that outlives the
    // call; the flavor asks for exactly a `proc_bsdinfo`.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            std::ptr::addr_of_mut!(info).cast::<c_void>(),
            size,
        )
    };
    if got != size {
        return Err(io::Error::other("proc_pidinfo failed"));
    }
    Ok(info)
}

fn read_ids(pid: u32) -> io::Result<(u32, u64)> {
    let info = bsd_info(pid)?;
    let start = info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec;
    Ok((info.pbi_ppid, start))
}

pub(crate) fn identity_of(pid: u32) -> io::Result<ProcessId> {
    let (_, start_time) = read_ids(pid)?;
    Ok(ProcessId { pid, start_time })
}

pub(crate) fn parent_of(pid: u32) -> io::Result<u32> {
    read_ids(pid).map(|(ppid, _)| ppid)
}

pub(crate) fn ancestor_chain(pid: u32, max: usize) -> Vec<ProcessId> {
    walk_chain(pid, max, read_ids)
}

pub(crate) fn exe_name(pid: u32) -> Option<String> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is `len` bytes of writable memory that outlives the
    // call.
    let len =
        unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<c_void>(), buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buf[..len as usize]).into_owned();
    path.rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .map(str::to_string)
}

pub(crate) fn owned_by_me(pid: u32) -> bool {
    bsd_info(pid).is_ok_and(|i| i.pbi_uid == geteuid().as_raw())
}

pub(crate) fn peer_of(sock: impl AsFd) -> io::Result<Peer> {
    let fd = sock.as_fd().as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `fd` is an open socket for the duration of the call; the value
    // and length pointers refer to live locals of the sizes declared.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast::<c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let (mut euid, mut egid): (libc::uid_t, libc::gid_t) = (0, 0);
    // SAFETY: `fd` is an open socket; the two out pointers are live locals.
    if unsafe { libc::getpeereid(fd, &mut euid, &mut egid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let pid = u32::try_from(pid).map_err(|_| io::Error::other("bad pid"))?;
    let id = identity_of(pid)?;
    Ok(Peer::new(id, euid == geteuid().as_raw(), ()))
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
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| io::Error::other(format!("RLIMIT_CORE: {e}")))
}

pub(crate) fn lock_memory() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "macOS has no mlockall; memory is not locked",
    ))
}

pub(crate) fn detach_session() {
    let _ = setsid();
}

pub(crate) fn detach_command(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
}
