//! Windows named pipes with overlapped I/O.
//!
//! The pipe is created with an access list naming only this user, with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` (so another process cannot have squatted on
//! the name before the daemon) and with remote clients rejected. Handles are
//! overlapped so that one thread can read a connection while another writes it:
//! a synchronous handle serialises the two and a relayed `vahta run` would
//! deadlock.

use std::ffi::{OsString, c_void};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FlushFileBuffers,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::CreateEventW;

use crate::ipc::Address;
use crate::{Peer, pipe_sddl, sys};

pub(crate) fn address_for(dir: &Path) -> io::Result<OsString> {
    sys::pipe_name(dir)
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error() -> u32 {
    // SAFETY: reads the calling thread's last-error value.
    unsafe { GetLastError() }
}

fn raw(h: &OwnedHandle) -> HANDLE {
    h.as_raw_handle() as HANDLE
}

/// Take ownership of a handle just returned by a call, or the error it set.
fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid open handle the call just returned and nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

/// Run one overlapped call to completion on `handle` and return the byte count.
/// `start` receives the OVERLAPPED and returns the call's BOOL result. The
/// error is the Win32 error code.
fn overlapped(handle: HANDLE, start: impl FnOnce(*mut OVERLAPPED) -> i32) -> Result<u32, u32> {
    // SAFETY: plain arguments; a manual-reset, unsignalled, unnamed event.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    let event = owned(event).map_err(|e| e.raw_os_error().map_or(1, |c| c as u32))?;
    // SAFETY: OVERLAPPED is plain data for which all-zero is the initial state.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = raw(&event);
    if start(&mut ov) == 0 {
        let e = last_error();
        if e != ERROR_IO_PENDING {
            return Err(e);
        }
    }
    let mut n = 0u32;
    // SAFETY: `ov` is the structure the call was started with and is still
    // alive; waiting here is what keeps it (and the caller's buffer) alive
    // until the operation is complete.
    if unsafe { GetOverlappedResult(handle, &ov, &mut n, 1) } == 0 {
        return Err(last_error());
    }
    Ok(n)
}

/// A pipe handle. A server end is flushed before it is closed, so frames the
/// client has not read yet are not thrown away with the handle.
struct Pipe {
    handle: OwnedHandle,
    server: bool,
    connected: AtomicBool,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        if self.server && self.connected.load(Ordering::SeqCst) {
            // SAFETY: the handle is open until this struct's field drops.
            unsafe { FlushFileBuffers(raw(&self.handle)) };
        }
    }
}

/// A security descriptor made from SDDL, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable memory that this struct owns and frees
// once; it is only ever read.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: as above, shared reads only.
unsafe impl Sync for SecurityDescriptor {}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptor... with
        // LocalAlloc, freed only here.
        unsafe { LocalFree(self.0.cast::<c_void>()) };
    }
}

pub struct Listener {
    name: Vec<u16>,
    sd: SecurityDescriptor,
    /// The instance waiting for the next client, created ahead so a client
    /// arriving while another is being served finds a pipe to open.
    pending: Mutex<Option<Pipe>>,
    first: AtomicBool,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Listener(named pipe)")
    }
}

impl Listener {
    pub fn bind(addr: &Address) -> io::Result<Listener> {
        let sid = sys::user_sid_string()?;
        let sddl = wide(std::ffi::OsStr::new(&pipe_sddl(&sid)));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated; `sd` is a live out pointer; a null
        // size pointer is allowed.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = Listener {
            name: wide(addr.as_os_str()),
            sd: SecurityDescriptor(sd),
            pending: Mutex::new(None),
            first: AtomicBool::new(true),
        };
        // Creating the first instance now is what makes a name already taken
        // by someone else an error at start, not at the first client.
        let first = listener.new_instance()?;
        *listener
            .pending
            .lock()
            .map_err(|_| io::Error::other("poisoned"))? = Some(first);
        Ok(listener)
    }

    fn new_instance(&self) -> io::Result<Pipe> {
        let mut open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if self.first.swap(false, Ordering::SeqCst) {
            open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: 0,
        };
        // SAFETY: `name` is NUL-terminated; `attrs` and the descriptor it
        // points to outlive the call.
        let handle = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                65_536,
                65_536,
                0,
                &attrs,
            )
        };
        Ok(Pipe {
            handle: owned(handle)?,
            server: true,
            connected: AtomicBool::new(false),
        })
    }

    /// Wait for a client. Blocks.
    pub fn accept(&self) -> io::Result<Stream> {
        let waiting = {
            let mut slot = self
                .pending
                .lock()
                .map_err(|_| io::Error::other("poisoned"))?;
            slot.take()
        };
        let pipe = match waiting {
            Some(p) => p,
            None => self.new_instance()?,
        };
        let h = raw(&pipe.handle);
        let connected = overlapped(h, |ov| {
            // SAFETY: `h` is an open overlapped server pipe; `ov` is supplied
            // by `overlapped` and lives until the wait ends.
            unsafe { ConnectNamedPipe(h, ov) }
        });
        match connected {
            Ok(_) => {}
            // The client connected between the pipe's creation and this call.
            Err(e) if e == ERROR_PIPE_CONNECTED => {}
            Err(e) => return Err(io::Error::from_raw_os_error(e as i32)),
        }
        pipe.connected.store(true, Ordering::SeqCst);
        // Make the next instance before handing this one out.
        let next = self.new_instance()?;
        if let Ok(mut slot) = self.pending.lock() {
            *slot = Some(next);
        }
        Ok(Stream::from_pipe(pipe))
    }
}

#[derive(Clone)]
pub struct Stream {
    pipe: Arc<Pipe>,
    closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Stream(named pipe)")
    }
}

impl Stream {
    fn from_pipe(pipe: Pipe) -> Stream {
        Stream {
            pipe: Arc::new(pipe),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn connect(addr: &Address) -> io::Result<Stream> {
        let name = wide(addr.as_os_str());
        for _ in 0..50 {
            // SAFETY: `name` is NUL-terminated; no security attributes and no
            // template file.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                return Ok(Stream::from_pipe(Pipe {
                    handle: owned(handle)?,
                    server: false,
                    connected: AtomicBool::new(false),
                }));
            }
            match last_error() {
                ERROR_PIPE_BUSY => {
                    // SAFETY: `name` is NUL-terminated.
                    unsafe { WaitNamedPipeW(name.as_ptr(), 200) };
                }
                ERROR_FILE_NOT_FOUND => {
                    return Err(io::Error::from(io::ErrorKind::NotFound));
                }
                e => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        }
        Err(io::Error::from(io::ErrorKind::TimedOut))
    }

    pub fn try_clone(&self) -> io::Result<Stream> {
        Ok(self.clone())
    }

    /// End the connection: a thread blocked in a read returns end-of-file. A
    /// read begun after this returns end-of-file at once.
    pub fn shutdown(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        // SAFETY: the handle is open; a null OVERLAPPED cancels every pending
        // operation on it.
        unsafe { CancelIoEx(raw(&self.pipe.handle), std::ptr::null()) };
        Ok(())
    }

    pub fn peer(&self) -> io::Result<Peer> {
        sys::peer_of_pipe(raw(&self.pipe.handle))
    }

    fn read_impl(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(0);
        }
        let h = raw(&self.pipe.handle);
        let want = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let ptr = buf.as_mut_ptr();
        let read = overlapped(h, |ov| {
            // SAFETY: `ptr` and `want` describe `buf`, which outlives the wait
            // in `overlapped`; `ov` is supplied by it.
            unsafe { ReadFile(h, ptr, want, std::ptr::null_mut(), ov) }
        });
        match read {
            Ok(n) => Ok(n as usize),
            Err(e)
                if e == ERROR_BROKEN_PIPE
                    || e == ERROR_PIPE_NOT_CONNECTED
                    || e == ERROR_NO_DATA =>
            {
                Ok(0)
            }
            Err(e) if e == ERROR_OPERATION_ABORTED && self.closed.load(Ordering::SeqCst) => Ok(0),
            Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }

    fn write_impl(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let h = raw(&self.pipe.handle);
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let ptr = buf.as_ptr();
        let written = overlapped(h, |ov| {
            // SAFETY: as for the read.
            unsafe { WriteFile(h, ptr, len, std::ptr::null_mut(), ov) }
        });
        match written {
            Ok(n) => Ok(n as usize),
            Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_impl(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_impl(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
