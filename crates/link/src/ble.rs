//! Bluetooth LE on Linux: BlueZ over D-Bus (blocking zbus). The desktop is the
//! GATT central; the phone runs the Vahta service. This module cannot be
//! exercised without a phone, so it keeps to the documented BlueZ API
//! (`org.bluez.Adapter1`, `Device1`, `GattCharacteristic1`) and the framing in
//! [`crate::ble_frame`] carries the unit tests.
//!
//! Bluetooth link-layer encryption is not relied on: everything above is Noise.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use zbus::blocking::{Connection, MessageIterator, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::ble_frame::{DEFAULT_CHUNK, Reassembler, chunk_frame};
use crate::error::{LinkError, Result};
use crate::frame::Pipe;
use crate::transport::{DeviceAddr, Transport};

/// The Vahta GATT service the phone advertises.
pub const SERVICE_UUID: &str = "11ca9b36-035f-4d80-8e4a-7819627ac4c0";
/// Central writes frames here (write with response).
pub const WRITE_CHAR_UUID: &str = "0e1a6dcf-3ae7-4ba5-a24c-fc4c243d0629";
/// Phone sends frames here (notify).
pub const NOTIFY_CHAR_UUID: &str = "5625b7a7-3f03-49f9-8d96-a25a49559adf";

const BLUEZ: &str = "org.bluez";
const ADAPTER: &str = "org.bluez.Adapter1";
const DEVICE: &str = "org.bluez.Device1";
const CHAR: &str = "org.bluez.GattCharacteristic1";
const PROPS: &str = "org.freedesktop.DBus.Properties";

type Props = HashMap<String, OwnedValue>;
type Managed = HashMap<OwnedObjectPath, HashMap<String, Props>>;

fn dbus<E: std::fmt::Display>(e: E) -> LinkError {
    LinkError::Io(format!("bluez: {e}"))
}

fn proxy<'a>(conn: &Connection, path: &'a str, iface: &'a str) -> Result<Proxy<'a>> {
    Proxy::new(conn, BLUEZ, path, iface).map_err(dbus)
}

fn managed(conn: &Connection) -> Result<Managed> {
    let p = Proxy::new(conn, BLUEZ, "/", "org.freedesktop.DBus.ObjectManager").map_err(dbus)?;
    p.call("GetManagedObjects", &()).map_err(dbus)
}

fn str_prop(p: &Props, k: &str) -> Option<String> {
    let v = p.get(k)?.try_clone().ok()?;
    String::try_from(v).ok()
}

fn bool_prop(p: &Props, k: &str) -> Option<bool> {
    bool::try_from(p.get(k)?.try_clone().ok()?).ok()
}

fn has_service(p: &Props) -> bool {
    p.get("UUIDs")
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<String>::try_from(v).ok())
        .is_some_and(|u| u.iter().any(|u| u.eq_ignore_ascii_case(SERVICE_UUID)))
}

fn adapter_path(m: &Managed, name: &str) -> Result<String> {
    let want = format!("/org/bluez/{name}");
    m.iter()
        .find(|(p, i)| p.as_str() == want && i.contains_key(ADAPTER))
        .map(|(p, _)| p.to_string())
        .ok_or_else(|| LinkError::Unsupported(format!("no Bluetooth adapter {name}")))
}

/// A nearby device advertising the Vahta service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleDevice {
    pub address: String,
    pub name: Option<String>,
    pub rssi: Option<i16>,
}

fn collect(m: &Managed, adapter: &str) -> Vec<BleDevice> {
    let prefix = format!("{adapter}/");
    let mut v: Vec<_> = m
        .iter()
        .filter(|(p, _)| p.as_str().starts_with(&prefix))
        .filter_map(|(_, i)| i.get(DEVICE))
        .filter(|d| has_service(d))
        .filter_map(|d| {
            Some(BleDevice {
                address: str_prop(d, "Address")?,
                name: str_prop(d, "Alias").or_else(|| str_prop(d, "Name")),
                rssi: d
                    .get("RSSI")
                    .and_then(|v| v.try_clone().ok())
                    .and_then(|v| i16::try_from(v).ok()),
            })
        })
        .collect();
    v.sort_by(|a, b| a.address.cmp(&b.address));
    v
}

fn start_discovery(conn: &Connection, adapter: &str) -> Result<()> {
    let p = proxy(conn, adapter, ADAPTER)?;
    let mut filter: HashMap<&str, Value> = HashMap::new();
    filter.insert("UUIDs", Value::from(vec![SERVICE_UUID]));
    filter.insert("Transport", Value::from("le"));
    p.call::<_, _, ()>("SetDiscoveryFilter", &(filter,))
        .map_err(dbus)?;
    match p.call::<_, _, ()>("StartDiscovery", &()) {
        Ok(()) => Ok(()),
        Err(e) if e.to_string().contains("InProgress") => Ok(()),
        Err(e) => Err(dbus(e)),
    }
}

fn stop_discovery(conn: &Connection, adapter: &str) {
    if let Ok(p) = proxy(conn, adapter, ADAPTER) {
        let _ = p.call::<_, _, ()>("StopDiscovery", &());
    }
}

/// Lists devices advertising the Vahta service, scanning for `duration`.
/// Read-only apart from the adapter's discovery state, which it restores.
pub fn scan(adapter_name: &str, duration: Duration) -> Result<Vec<BleDevice>> {
    let conn = Connection::system().map_err(dbus)?;
    let adapter = adapter_path(&managed(&conn)?, adapter_name)?;
    start_discovery(&conn, &adapter)?;
    let end = Instant::now() + duration;
    let mut found = Vec::new();
    while Instant::now() < end {
        thread::sleep(Duration::from_millis(500));
        found = collect(&managed(&conn)?, &adapter);
    }
    stop_discovery(&conn, &adapter);
    Ok(found)
}

pub struct BleTransport {
    adapter: String,
}

impl BleTransport {
    /// `adapter` is BlueZ's name for it, usually `hci0`.
    pub fn new(adapter: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
        }
    }
}

impl Default for BleTransport {
    fn default() -> Self {
        Self::new("hci0")
    }
}

impl Transport for BleTransport {
    fn name(&self) -> &str {
        "ble"
    }

    fn reach(&self, device: &DeviceAddr, deadline: Instant) -> Result<Box<dyn Pipe>> {
        let address = device
            .ble_address
            .clone()
            .ok_or_else(|| LinkError::Unsupported("no Bluetooth address remembered".into()))?;
        let adapter = self.adapter.clone();
        // BlueZ's Connect has its own long timeout; run it on a helper thread
        // so the deadline holds. A late result is dropped, which disconnects.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(BlePipe::connect(&adapter, &address, deadline));
        });
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(r) => r.map(|p| Box::new(p) as Box<dyn Pipe>),
            Err(_) => Err(LinkError::Timeout),
        }
    }
}

enum Event {
    Chunk(Vec<u8>),
    Closed,
}

pub struct BlePipe {
    conn: Connection,
    device_path: String,
    write_path: String,
    notify_path: String,
    chunk_len: usize,
    rx: Receiver<Event>,
    stop: Arc<AtomicBool>,
    reassembler: Reassembler,
    ready: VecDeque<Vec<u8>>,
    timeout: Option<Duration>,
    closed: bool,
}

fn device_path(adapter: &str, address: &str) -> String {
    format!(
        "{adapter}/dev_{}",
        address.to_ascii_uppercase().replace(':', "_")
    )
}

impl BlePipe {
    fn connect(adapter_name: &str, address: &str, deadline: Instant) -> Result<Self> {
        let conn = Connection::system().map_err(dbus)?;
        let adapter = adapter_path(&managed(&conn)?, adapter_name)?;
        let dpath = device_path(&adapter, address);

        // BlueZ forgets devices it has not seen; discover to bring it back.
        if !managed(&conn)?.keys().any(|p| p.as_str() == dpath) {
            start_discovery(&conn, &adapter)?;
            let seen = loop {
                if managed(&conn)?.keys().any(|p| p.as_str() == dpath) {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                thread::sleep(Duration::from_millis(300));
            };
            stop_discovery(&conn, &adapter);
            if !seen {
                return Err(LinkError::Unreachable(format!("{address} not in range")));
            }
        }

        let dev = proxy(&conn, &dpath, DEVICE)?;
        dev.call::<_, _, ()>("Connect", &())
            .map_err(|e| LinkError::Unreachable(e.to_string()))?;
        // From here a failure must disconnect; the pipe's Drop does it.
        let mut pipe = Self {
            conn: conn.clone(),
            device_path: dpath.clone(),
            write_path: String::new(),
            notify_path: String::new(),
            chunk_len: DEFAULT_CHUNK,
            rx: mpsc::channel().1,
            stop: Arc::new(AtomicBool::new(false)),
            reassembler: Reassembler::new(),
            ready: VecDeque::new(),
            timeout: None,
            closed: false,
        };

        loop {
            let resolved: bool = dev.get_property("ServicesResolved").map_err(dbus)?;
            if resolved {
                break;
            }
            if Instant::now() >= deadline {
                return Err(LinkError::Timeout);
            }
            thread::sleep(Duration::from_millis(200));
        }

        let m = managed(&conn)?;
        let prefix = format!("{dpath}/");
        let find = |uuid: &str| {
            m.iter()
                .filter(|(p, _)| p.as_str().starts_with(&prefix))
                .find(|(_, i)| {
                    i.get(CHAR)
                        .and_then(|c| str_prop(c, "UUID"))
                        .is_some_and(|u| u.eq_ignore_ascii_case(uuid))
                })
                .map(|(p, i)| (p.to_string(), i.get(CHAR).cloned().unwrap_or_default()))
        };
        let (wp, wprops) = find(WRITE_CHAR_UUID)
            .ok_or_else(|| LinkError::Unreachable("device lacks the Vahta service".into()))?;
        let (np, _) = find(NOTIFY_CHAR_UUID)
            .ok_or_else(|| LinkError::Unreachable("device lacks the Vahta service".into()))?;
        pipe.write_path = wp;
        pipe.notify_path = np.clone();
        // BlueZ >= 5.62 reports the negotiated MTU; ATT overhead is 3 bytes.
        if let Some(mtu) = wprops
            .get("MTU")
            .and_then(|v| v.try_clone().ok())
            .and_then(|v| u16::try_from(v).ok())
        {
            pipe.chunk_len = (mtu as usize).saturating_sub(3).clamp(DEFAULT_CHUNK, 512);
        }

        // Subscribe to signals before StartNotify so no early chunk is lost.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(BLUEZ)
            .map_err(dbus)?
            .interface(PROPS)
            .map_err(dbus)?
            .member("PropertiesChanged")
            .map_err(dbus)?
            .path_namespace(dpath.as_str())
            .map_err(dbus)?
            .build();
        let iter = MessageIterator::for_match_rule(rule, &conn, None).map_err(dbus)?;
        let (tx, rx) = mpsc::channel();
        pipe.rx = rx;
        let stop = pipe.stop.clone();
        let (device_p, notify_p) = (dpath.clone(), np.clone());
        thread::spawn(move || {
            for msg in iter {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(msg) = msg else { continue };
                let Some(path) = msg.header().path().map(|p| p.to_string()) else {
                    continue;
                };
                let Ok((iface, changed, _)) =
                    msg.body().deserialize::<(String, Props, Vec<String>)>()
                else {
                    continue;
                };
                if path == notify_p && iface == CHAR {
                    if let Some(v) = changed
                        .get("Value")
                        .and_then(|v| v.try_clone().ok())
                        .and_then(|v| Vec::<u8>::try_from(v).ok())
                        && tx.send(Event::Chunk(v)).is_err()
                    {
                        break;
                    }
                } else if path == device_p
                    && iface == DEVICE
                    && bool_prop(&changed, "Connected") == Some(false)
                {
                    let _ = tx.send(Event::Closed);
                    break;
                }
            }
        });

        proxy(&conn, &np, CHAR)?
            .call::<_, _, ()>("StartNotify", &())
            .map_err(dbus)?;
        Ok(pipe)
    }

    fn write_chunk(&self, chunk: &[u8]) -> Result<()> {
        let mut opts: HashMap<&str, Value> = HashMap::new();
        opts.insert("type", Value::from("request"));
        proxy(&self.conn, &self.write_path, CHAR)?
            .call::<_, _, ()>("WriteValue", &(chunk, opts))
            .map_err(dbus)
    }
}

impl Pipe for BlePipe {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed {
            return Err(LinkError::Closed);
        }
        for c in chunk_frame(frame, self.chunk_len)? {
            self.write_chunk(&c)?;
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        let end = self.timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(f) = self.ready.pop_front() {
                return Ok(f);
            }
            if self.closed {
                return Err(LinkError::Closed);
            }
            let ev = match end {
                Some(end) => self
                    .rx
                    .recv_timeout(end.saturating_duration_since(Instant::now()))
                    .map_err(|e| match e {
                        mpsc::RecvTimeoutError::Timeout => LinkError::Timeout,
                        mpsc::RecvTimeoutError::Disconnected => LinkError::Closed,
                    })?,
                None => self.rx.recv().map_err(|_| LinkError::Closed)?,
            };
            match ev {
                Event::Chunk(c) => self.ready.extend(self.reassembler.push(&c)),
                Event::Closed => self.closed = true,
            }
        }
    }

    fn set_recv_timeout(&mut self, t: Option<Duration>) -> Result<()> {
        self.timeout = t;
        Ok(())
    }
}

impl Drop for BlePipe {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if !self.notify_path.is_empty()
            && let Ok(p) = proxy(&self.conn, &self.notify_path, CHAR)
        {
            let _ = p.call::<_, _, ()>("StopNotify", &());
        }
        if let Ok(p) = proxy(&self.conn, &self.device_path, DEVICE) {
            let _ = p.call::<_, _, ()>("Disconnect", &());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_path_is_bluezs_spelling() {
        assert_eq!(
            device_path("/org/bluez/hci0", "aa:bb:cc:dd:ee:0f"),
            "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_0F"
        );
    }

    #[test]
    fn service_filter_matches_case_insensitively() {
        let mut p = Props::new();
        p.insert(
            "UUIDs".into(),
            Value::from(vec![SERVICE_UUID.to_uppercase()])
                .try_into()
                .unwrap(),
        );
        assert!(has_service(&p));
        p.insert(
            "UUIDs".into(),
            Value::from(vec!["0000180f-0000-1000-8000-00805f9b34fb"])
                .try_into()
                .unwrap(),
        );
        assert!(!has_service(&p));
    }

    /// Needs a phone (or a stand-in GATT server) running the Vahta service and
    /// its address in VAHTA_TEST_BLE_ADDRESS.
    #[test]
    #[ignore = "needs a phone advertising the Vahta service"]
    fn connects_and_pings() {
        let address = std::env::var("VAHTA_TEST_BLE_ADDRESS").expect("set VAHTA_TEST_BLE_ADDRESS");
        let dev = DeviceAddr {
            name: "phone".into(),
            static_pub: [0; 32],
            ble_address: Some(address),
            lan_hint: None,
        };
        let mut p = BleTransport::default()
            .reach(&dev, Instant::now() + Duration::from_secs(30))
            .unwrap();
        p.set_recv_timeout(Some(Duration::from_secs(10))).unwrap();
        p.send(b"hello").unwrap();
        let _ = p.recv().unwrap();
    }
}
