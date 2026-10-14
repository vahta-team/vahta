//! Reading standard input with a time limit, so a prompt window can watch
//! other things (the daemon, the clock) while it waits for a key, and never
//! leaves a reader blocked on input that a later prompt wants.

use std::io;
use std::time::Duration;

/// Read what is on standard input into `buf`, waiting at most `wait`.
/// `Ok(None)` is the time running out with nothing to read; `Ok(Some(0))` is
/// the end of input. Nothing is read ahead: a caller that stops asking leaves
/// the rest of the input where it was.
#[cfg(unix)]
pub fn read_stdin(buf: &mut [u8], wait: Duration) -> io::Result<Option<usize>> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use std::os::fd::AsFd;
    let stdin = std::io::stdin();
    let stdin = stdin.as_fd();
    let limit = Timespec {
        tv_sec: i64::try_from(wait.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(wait.subsec_nanos()),
    };
    loop {
        let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
        match poll(&mut fds, Some(&limit)) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    // Readable, or hung up (which reads as the end of input).
    match rustix::io::read(stdin, buf) {
        Ok(n) => Ok(Some(n)),
        Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Where a platform has no way to wait on standard input with a limit, one
/// thread of the process reads it and hands over what it got; a caller that
/// gives up on a wait loses nothing, the next call gets the bytes.
#[cfg(not(unix))]
pub fn read_stdin(buf: &mut [u8], wait: Duration) -> io::Result<Option<usize>> {
    use std::io::Read;
    use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
    use std::sync::{Mutex, OnceLock};

    struct Feed {
        chunks: Receiver<Vec<u8>>,
        /// The part of the last chunk that did not fit.
        left: Vec<u8>,
    }
    static FEED: OnceLock<Mutex<Feed>> = OnceLock::new();
    let feed = FEED.get_or_init(|| {
        let (tx, chunks) = channel();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match std::io::stdin().read(&mut chunk) {
                    // The end of input is an empty chunk, then the reader stops.
                    Ok(0) | Err(_) => {
                        let _ = tx.send(Vec::new());
                        return;
                    }
                    Ok(n) => {
                        if tx.send(chunk[..n].to_vec()).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Mutex::new(Feed {
            chunks,
            left: Vec::new(),
        })
    });
    let mut feed = feed.lock().unwrap_or_else(|e| e.into_inner());
    if feed.left.is_empty() {
        match feed.chunks.recv_timeout(wait) {
            Ok(chunk) if chunk.is_empty() => return Ok(Some(0)),
            Ok(chunk) => feed.left = chunk,
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => return Ok(Some(0)),
        }
    }
    let n = buf.len().min(feed.left.len());
    buf[..n].copy_from_slice(&feed.left[..n]);
    feed.left.drain(..n);
    Ok(Some(n))
}
