//! An in-process transport for tests (and for anything that wants the whole
//! protocol without hardware): channel-backed pipes and a registry of
//! "listening" devices.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{LinkError, Result};
use crate::frame::{MAX_FRAME, Pipe};
use crate::messages::{TAG_LEN, device_tag};
use crate::transport::{DeviceAddr, Transport};

pub struct MemoryPipe {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    timeout: Option<Duration>,
    sent: usize,
    flip_from: Option<usize>,
    log: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
}

/// Two connected ends.
pub fn memory_pipe() -> (MemoryPipe, MemoryPipe) {
    let (a_tx, b_rx) = mpsc::channel();
    let (b_tx, a_rx) = mpsc::channel();
    let end = |tx, rx| MemoryPipe {
        tx,
        rx,
        timeout: None,
        sent: 0,
        flip_from: None,
        log: None,
    };
    (end(a_tx, a_rx), end(b_tx, b_rx))
}

impl MemoryPipe {
    /// A wire tamperer for tests: from the `n`th frame this end sends (0 is
    /// the first), one bit of each frame is flipped.
    pub fn corrupt_sends_from(mut self, n: usize) -> Self {
        self.flip_from = Some(n);
        self
    }

    /// Records every frame this end sends, as an eavesdropper would see it.
    pub fn record_sends(mut self, log: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        self.log = Some(log);
        self
    }
}

impl Pipe for MemoryPipe {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() > MAX_FRAME {
            return Err(LinkError::FrameTooLarge(frame.len()));
        }
        let mut f = frame.to_vec();
        if let Some(log) = &self.log {
            log.lock().unwrap().push(f.clone());
        }
        if self.flip_from.is_some_and(|n| self.sent >= n)
            && let Some(b) = f.last_mut()
        {
            *b ^= 1;
        }
        self.sent += 1;
        self.tx.send(f).map_err(|_| LinkError::Closed)
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        match self.timeout {
            Some(t) => self.rx.recv_timeout(t).map_err(|e| match e {
                mpsc::RecvTimeoutError::Timeout => LinkError::Timeout,
                mpsc::RecvTimeoutError::Disconnected => LinkError::Closed,
            }),
            None => self.rx.recv().map_err(|_| LinkError::Closed),
        }
    }

    fn set_recv_timeout(&mut self, t: Option<Duration>) -> Result<()> {
        self.timeout = t;
        Ok(())
    }
}

type Listeners = Arc<Mutex<HashMap<[u8; TAG_LEN], Sender<MemoryPipe>>>>;

/// A registry of devices that accept connections, keyed by their tag.
/// Clones share the registry.
#[derive(Clone, Default)]
pub struct MemoryTransport {
    listeners: Listeners,
}

pub struct MemoryListener {
    rx: Receiver<MemoryPipe>,
}

impl MemoryListener {
    pub fn accept(&self, timeout: Duration) -> Result<Box<dyn Pipe>> {
        let p = self
            .rx
            .recv_timeout(timeout)
            .map_err(|_| LinkError::Timeout)?;
        Ok(Box::new(p))
    }
}

impl MemoryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the paired device with this static key reachable.
    pub fn listen(&self, static_pub: [u8; 32]) -> MemoryListener {
        self.listen_tag(device_tag(&static_pub))
    }

    /// Makes whatever advertises this tag reachable (a phone waiting to pair
    /// advertises [`crate::messages::pairing_tag`]).
    pub fn listen_tag(&self, tag: [u8; TAG_LEN]) -> MemoryListener {
        let (tx, rx) = mpsc::channel();
        self.listeners.lock().unwrap().insert(tag, tx);
        MemoryListener { rx }
    }
}

impl Transport for MemoryTransport {
    fn name(&self) -> &str {
        "memory"
    }

    fn reach(&self, device: &DeviceAddr, _deadline: Instant) -> Result<Box<dyn Pipe>> {
        let tx = self.listeners.lock().unwrap().get(&device.tag).cloned();
        let tx = tx.ok_or_else(|| LinkError::Unreachable("no such device".into()))?;
        let (mine, theirs) = memory_pipe();
        tx.send(theirs)
            .map_err(|_| LinkError::Unreachable("device went away".into()))?;
        Ok(Box::new(mine))
    }
}
