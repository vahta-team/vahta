//! Windows: `windows-sys` for process facts and the named pipe's identity.
//!
//! Identity is `(pid, creation time)`. The pid of a connecting client comes
//! from the pipe itself (`GetNamedPipeClientProcessId`), and the process is
//! opened at once and the handle kept for the request: Windows does not recycle
//! a pid while a handle to the process is open. What remains is the brief
//! window between the pipe's answer and `OpenProcess`, which ka documented and
//! so do we. Parent pids come from one Toolhelp snapshot; `th32ParentProcessID`
//! is fixed when a process is created and is not updated if the parent exits,
//! so a parent that is younger than its child is treated as recycled.

use std::collections::HashMap;
use std::ffi::{OsString, c_void};
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::process::Command;

use windows_sys::Win32::Foundation::{FILETIME, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::{Peer, ProcessId, stable_hash, walk_chain};

/// The peer's process handle, held while its request is served.
pub(crate) type Hold = Option<OwnedHandle>;

/// Take ownership of a handle a Win32 call returned, or the error it set.
fn owned(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a valid, open handle that the call just returned to us
    // and that nothing else owns or will close.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) })
}

fn open_process(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: plain values in, a new handle (or null) out.
    owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
}

fn start_time_of(process: &OwnedHandle) -> io::Result<u64> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the handle is open and has query access; the four out pointers
    // refer to live `FILETIME`s on this stack frame.
    let ok = unsafe {
        GetProcessTimes(
            process.as_raw_handle() as HANDLE,
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// `{pid: parent pid}` for every process, from one snapshot.
fn parent_map() -> io::Result<HashMap<u32, u32>> {
    // SAFETY: plain flag and pid values.
    let snapshot = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    // SAFETY: `PROCESSENTRY32W` is plain data for which all-zero bytes are valid.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let raw = snapshot.as_raw_handle() as HANDLE;
    let mut map = HashMap::new();
    // SAFETY: a valid snapshot handle and an entry whose `dwSize` is set.
    let mut more = unsafe { Process32FirstW(raw, &mut entry) };
    while more != 0 {
        map.insert(entry.th32ProcessID, entry.th32ParentProcessID);
        // SAFETY: as above.
        more = unsafe { Process32NextW(raw, &mut entry) };
    }
    Ok(map)
}

pub(crate) fn identity_of(pid: u32) -> io::Result<ProcessId> {
    let process = open_process(pid)?;
    Ok(ProcessId {
        pid,
        start_time: start_time_of(&process)?,
    })
}

pub(crate) fn parent_of(pid: u32) -> io::Result<u32> {
    parent_map()?
        .get(&pid)
        .copied()
        .ok_or_else(|| io::Error::other("no such process"))
}

pub(crate) fn ancestor_chain(pid: u32, max: usize) -> Vec<ProcessId> {
    let Ok(parents) = parent_map() else {
        return Vec::new();
    };
    walk_chain(pid, max, |p| {
        let ppid = *parents
            .get(&p)
            .ok_or_else(|| io::Error::other("no such process"))?;
        let process = open_process(p)?;
        Ok((ppid, start_time_of(&process)?))
    })
}

pub(crate) fn exe_name(pid: u32) -> Option<String> {
    let process = open_process(pid).ok()?;
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: an open handle with query access; `buf` holds `len` UTF-16 units
    // and `len` is updated to the number written.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process.as_raw_handle() as HANDLE,
            0,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    if ok == 0 {
        return None;
    }
    let path = OsString::from_wide(&buf[..len as usize]);
    Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

/// ka's rule: a process this user can open for query is this user's; one it
/// cannot is not (fail closed).
pub(crate) fn owned_by_me(pid: u32) -> bool {
    open_process(pid).is_ok()
}

/// The client of a connected named pipe, from the kernel.
pub(crate) fn peer_of_pipe(pipe: HANDLE) -> io::Result<Peer> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a live server-side pipe handle and `pid` a live u32.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let process = open_process(pid)?;
    let start_time = start_time_of(&process)?;
    // The pipe's access list admits only this user, so any client that got in
    // is this user's.
    Ok(Peer::new(
        ProcessId { pid, start_time },
        true,
        Some(process),
    ))
}

pub(crate) fn effective_uid() -> Option<u32> {
    None
}

pub(crate) fn harden_process() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no process hardening is applied on Windows",
    ))
}

pub(crate) fn lock_memory() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "memory locking is not applied on Windows",
    ))
}

pub(crate) fn detach_session() {}

pub(crate) fn detach_command(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW.
    cmd.creation_flags(0x0000_0008 | 0x0000_0200 | 0x0800_0000);
}

/// This user's SID as a string (`S-1-5-21-...`).
pub(crate) fn user_sid_string() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the current-process pseudo handle needs no closing; `token` is a
    // live out pointer.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned(token)?;
    let raw = token.as_raw_handle() as HANDLE;
    let mut needed = 0u32;
    // SAFETY: a size query: a null buffer of length 0 is how it is asked.
    unsafe { GetTokenInformation(raw, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64 units, so the buffer is aligned for the pointer inside TOKEN_USER.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` is at least `needed` bytes, which is what is declared.
    let ok = unsafe {
        GetTokenInformation(
            raw,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call filled `buf` with a TOKEN_USER, and the buffer is
    // suitably aligned and outlives this reference.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points into `buf`; `wide` is a live out pointer that
    // receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut len = 0usize;
    // SAFETY: `wide` is a NUL-terminated string the call just returned.
    while unsafe { *wide.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units were just read from it.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(wide, len) });
    // SAFETY: the string was allocated by the call above with LocalAlloc and
    // is not used again.
    unsafe { LocalFree(wide.cast::<c_void>()) };
    Ok(text)
}

/// The pipe name for a runtime directory: the user's SID and the directory,
/// hashed, so the name is the same for every Vahta version and differs between
/// users and between test sandboxes.
pub(crate) fn pipe_name(dir: &Path) -> io::Result<OsString> {
    let sid = user_sid_string()?;
    let hash = stable_hash(&[&sid, &dir.to_string_lossy()]);
    Ok(OsString::from(format!(r"\\.\pipe\vahta-{hash}")))
}
