//! How a transport reaches a device, and the race between transports.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use crate::error::{LinkError, Result};
use crate::frame::Pipe;

/// What the desktop remembers about where to find a paired phone. The phone's
/// static key is its identity; the rest are hints a transport may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAddr {
    pub name: String,
    pub static_pub: [u8; 32],
    /// Bluetooth address learned at pairing, e.g. `AA:BB:CC:DD:EE:FF`.
    pub ble_address: Option<String>,
    /// A last-known LAN address; mDNS is tried when it is absent or stale.
    pub lan_hint: Option<SocketAddr>,
}

impl DeviceAddr {
    /// The mDNS instance name a phone advertises: a hash prefix of its public
    /// key, so the name identifies the device without carrying the key.
    pub fn lan_instance(&self) -> String {
        let h = crate::messages::sha256(&self.static_pub);
        h[..8].iter().map(|b| format!("{b:02x}")).collect()
    }
}

pub trait Transport: Send + Sync {
    fn name(&self) -> &str;
    /// A pipe to the device, or an error by `deadline`.
    fn reach(&self, device: &DeviceAddr, deadline: Instant) -> Result<Box<dyn Pipe>>;
}

/// Tries every transport in its own thread; the first to connect wins and the
/// rest are dropped as they finish. Returns the winner's name and pipe.
pub fn reach_first(
    transports: &[Arc<dyn Transport>],
    device: &DeviceAddr,
    deadline: Instant,
) -> Result<(String, Box<dyn Pipe>)> {
    if transports.is_empty() {
        return Err(LinkError::Unreachable("no transports".into()));
    }
    let (tx, rx) = mpsc::channel::<(String, Result<Box<dyn Pipe>>)>();
    for t in transports {
        let (t, tx, device) = (Arc::clone(t), tx.clone(), device.clone());
        thread::spawn(move || {
            let r = t.reach(&device, deadline);
            // The receiver is gone once someone has won; the pipe drops here.
            let _ = tx.send((t.name().to_string(), r));
        });
    }
    drop(tx);
    let mut failures = Vec::new();
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok((name, Ok(pipe))) => return Ok((name, pipe)),
            Ok((name, Err(e))) => failures.push((name, e.to_string())),
            Err(_) => {
                // Deadline, or every sender finished.
                if failures.is_empty() {
                    return Err(LinkError::Timeout);
                }
                return Err(LinkError::AllFailed(failures));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::memory_pipe;
    use std::time::Duration;

    struct Fake {
        name: &'static str,
        delay: Duration,
        ok: bool,
    }
    impl Transport for Fake {
        fn name(&self) -> &str {
            self.name
        }
        fn reach(&self, _: &DeviceAddr, _: Instant) -> Result<Box<dyn Pipe>> {
            thread::sleep(self.delay);
            if self.ok {
                Ok(Box::new(memory_pipe().0))
            } else {
                Err(LinkError::Unreachable("nope".into()))
            }
        }
    }

    fn dev() -> DeviceAddr {
        DeviceAddr {
            name: "p".into(),
            static_pub: [1; 32],
            ble_address: None,
            lan_hint: None,
        }
    }

    fn t(name: &'static str, ms: u64, ok: bool) -> Arc<dyn Transport> {
        Arc::new(Fake {
            name,
            delay: Duration::from_millis(ms),
            ok,
        })
    }

    #[test]
    fn fastest_success_wins_and_failures_are_skipped() {
        let ts = [
            t("slow", 400, true),
            t("fast", 10, true),
            t("broken", 0, false),
        ];
        let (name, _) = reach_first(&ts, &dev(), Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(name, "fast");
        let ts = [t("broken", 0, false), t("ok", 50, true)];
        let (name, _) = reach_first(&ts, &dev(), Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(name, "ok");
    }

    #[test]
    fn all_failed_and_deadline() {
        let ts = [t("a", 0, false), t("b", 0, false)];
        match reach_first(&ts, &dev(), Instant::now() + Duration::from_secs(5)) {
            Err(LinkError::AllFailed(v)) => assert_eq!(v.len(), 2),
            other => panic!("{other:?}", other = other.map(|(n, _)| n)),
        }
        let ts = [t("sleepy", 800, true)];
        let r = reach_first(&ts, &dev(), Instant::now() + Duration::from_millis(100));
        assert!(matches!(r, Err(LinkError::Timeout)));
    }
}
