//! Knowing that the client gave up.
//!
//! A request is served on one thread while its client waits for the reply. If
//! the client dies meanwhile (the harness that started `vahta run` gave up and
//! killed it), nothing on that thread would notice: the password window would
//! stay up until it timed out, and the command would then start for nobody.
//! [`Gone`] watches the connection while a request is held up on a person and
//! cancels whatever is open for it.
//!
//! The watch is lazy: a request that opens no window and waits for nothing
//! never starts the thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vahta_auth::Cancel;
use vahta_os::ipc::Stream;

use crate::surface::Window;

/// How often a silent connection is looked at.
const POLL: Duration = Duration::from_millis(100);

pub(crate) struct Gone {
    cancel: Cancel,
    stream: Option<Stream>,
    stop: Arc<AtomicBool>,
    started: AtomicBool,
}

impl Gone {
    /// For the request on `stream`. A request with no connection to watch
    /// (none today outside tests) is never gone.
    pub(crate) fn new(stream: Option<&Stream>) -> Gone {
        Gone {
            cancel: Cancel::new(),
            stream: stream.and_then(|s| s.try_clone().ok()),
            stop: Arc::default(),
            started: AtomicBool::new(false),
        }
    }

    /// Whether the client has gone away. Looks at the connection itself, so
    /// it is exact even between two polls.
    pub(crate) fn is_gone(&self) -> bool {
        if self.cancel.is_cancelled() {
            return true;
        }
        if self.stream.as_ref().is_some_and(Stream::peer_closed) {
            self.cancel.cancel();
            return true;
        }
        false
    }

    /// Cancelled when the client is gone; what a wait or a window hooks onto.
    pub(crate) fn cancel(&self) -> &Cancel {
        &self.cancel
    }

    /// Start watching, once. Called when the request is about to wait on a
    /// person.
    pub(crate) fn watch(&self) {
        let Some(stream) = &self.stream else { return };
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let (stream, cancel, stop) = (
            match stream.try_clone() {
                Ok(s) => s,
                Err(_) => return,
            },
            self.cancel.clone(),
            self.stop.clone(),
        );
        let _ = std::thread::Builder::new()
            .name("client-watch".into())
            .spawn(move || {
                while !stop.load(Ordering::SeqCst) && !cancel.is_cancelled() {
                    if stream.peer_closed() {
                        cancel.cancel();
                        return;
                    }
                    std::thread::sleep(POLL);
                }
            });
    }

    /// Withdraw `window` the moment the client is gone, and start watching.
    pub(crate) fn guard(&self, window: &dyn Window) {
        self.watch();
        if let Some(close) = window.canceller() {
            self.cancel.on_cancel(close);
        }
    }

    /// Stop watching: the request is over, or the connection is about to be
    /// used for something else (a run's input and output).
    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for Gone {
    fn drop(&mut self) {
        self.stop();
    }
}
