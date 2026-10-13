//! The LAN transport: mDNS discovery of `_vahta._tcp`, then TCP carrying
//! length-prefixed frames. Same Noise above as every other transport.

use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::error::{LinkError, Result};
use crate::frame::{Pipe, read_frame, write_frame};
use crate::transport::{DeviceAddr, Transport};

pub const SERVICE_TYPE: &str = "_vahta._tcp.local.";

/// A pipe over a TCP stream.
pub struct TcpPipe(TcpStream);

impl TcpPipe {
    pub fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        Self(stream)
    }
}

impl Pipe for TcpPipe {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(&mut self.0, frame)
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.0)
    }
    fn set_recv_timeout(&mut self, t: Option<Duration>) -> Result<()> {
        self.0.set_read_timeout(t)?;
        Ok(())
    }
}

#[derive(Default)]
pub struct LanTransport;

impl LanTransport {
    pub fn new() -> Self {
        Self
    }
}

fn connect(addr: SocketAddr, deadline: Instant) -> Result<Box<dyn Pipe>> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(LinkError::Timeout);
    }
    let s = TcpStream::connect_timeout(&addr, left)?;
    Ok(Box::new(TcpPipe::new(s)))
}

impl Transport for LanTransport {
    fn name(&self) -> &str {
        "lan"
    }

    fn reach(&self, device: &DeviceAddr, deadline: Instant) -> Result<Box<dyn Pipe>> {
        // A remembered address first, but only for a short try: a stale one
        // must not eat the whole deadline.
        if let Some(hint) = device.lan_hint {
            let quick = deadline.min(Instant::now() + Duration::from_millis(1500));
            if let Ok(p) = connect(hint, quick) {
                return Ok(p);
            }
        }
        let instance = device.lan_instance();
        let daemon =
            ServiceDaemon::new().map_err(|e| LinkError::Unsupported(format!("mdns: {e}")))?;
        let rx = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| LinkError::Unsupported(format!("mdns: {e}")))?;
        let result = loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                break Err(LinkError::Timeout);
            }
            match rx.recv_timeout(wait) {
                Ok(ServiceEvent::ServiceResolved(info))
                    if info.get_fullname().starts_with(&instance) =>
                {
                    let port = info.get_port();
                    let mut last = LinkError::Unreachable("no address".into());
                    let mut won = None;
                    for ip in info.get_addresses() {
                        match connect(SocketAddr::new(ip.to_ip_addr(), port), deadline) {
                            Ok(p) => {
                                won = Some(p);
                                break;
                            }
                            Err(e) => last = e,
                        }
                    }
                    match won {
                        Some(p) => break Ok(p),
                        None => break Err(last),
                    }
                }
                Ok(_) => {}
                Err(_) => break Err(LinkError::Timeout),
            }
        };
        let _ = daemon.shutdown();
        result
    }
}

/// Accepts connections as a device would (tests, and a desktop-side stand-in
/// for the phone).
pub struct LanListener {
    listener: TcpListener,
}

impl LanListener {
    pub fn bind(addr: impl ToSocketAddrs) -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr)?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn accept(&self) -> Result<Box<dyn Pipe>> {
        let (s, _) = self.listener.accept()?;
        Ok(Box::new(TcpPipe::new(s)))
    }

    /// Advertises this listener over mDNS under `instance` until the returned
    /// daemon is shut down or dropped.
    pub fn advertise(&self, instance: &str, host_ip: std::net::IpAddr) -> Result<ServiceDaemon> {
        let port = self.local_addr()?.port();
        let host = format!("{instance}.local.");
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            instance,
            &host,
            host_ip,
            port,
            None::<std::collections::HashMap<String, String>>,
        )
        .map_err(|e| LinkError::Unsupported(format!("mdns: {e}")))?;
        let d = ServiceDaemon::new().map_err(|e| LinkError::Unsupported(format!("mdns: {e}")))?;
        d.register(info)
            .map_err(|e| LinkError::Unsupported(format!("mdns: {e}")))?;
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn dev(hint: Option<SocketAddr>) -> DeviceAddr {
        DeviceAddr {
            name: "p".into(),
            static_pub: [5; 32],
            ble_address: None,
            lan_hint: hint,
        }
    }

    #[test]
    fn loopback_frames_through_the_hint() {
        let l = LanListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = thread::spawn(move || {
            let mut p = l.accept().unwrap();
            let f = p.recv().unwrap();
            p.send(&f.iter().rev().copied().collect::<Vec<_>>())
                .unwrap();
        });
        let mut p = LanTransport::new()
            .reach(&dev(Some(addr)), Instant::now() + Duration::from_secs(5))
            .unwrap();
        p.send(b"abc").unwrap();
        assert_eq!(p.recv().unwrap(), b"cba");
        h.join().unwrap();
    }

    #[test]
    fn recv_timeout_applies() {
        let l = LanListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let _h = thread::spawn(move || {
            let _p = l.accept().unwrap();
            thread::sleep(Duration::from_millis(500));
        });
        let mut p = LanTransport::new()
            .reach(&dev(Some(addr)), Instant::now() + Duration::from_secs(5))
            .unwrap();
        p.set_recv_timeout(Some(Duration::from_millis(50))).unwrap();
        assert!(matches!(p.recv(), Err(LinkError::Timeout)));
    }

    #[test]
    #[ignore = "needs multicast on a real network interface"]
    fn mdns_discovery_finds_an_advertised_device() {
        let d = dev(None);
        let l = LanListener::bind("0.0.0.0:0").unwrap();
        let ip: std::net::IpAddr = std::env::var("VAHTA_TEST_LAN_IP")
            .expect("set VAHTA_TEST_LAN_IP")
            .parse()
            .unwrap();
        let _ad = l.advertise(&d.lan_instance(), ip).unwrap();
        let h = thread::spawn(move || l.accept().map(|_| ()));
        LanTransport::new()
            .reach(&d, Instant::now() + Duration::from_secs(10))
            .unwrap();
        h.join().unwrap().unwrap();
    }
}
