//! Bluetooth LE on Linux: BlueZ over D-Bus (blocking zbus). The desktop is the
//! GATT central; the phone runs the Vahta service. This module cannot be
//! exercised without a phone, so it keeps to the documented BlueZ API
//! (`org.bluez.Adapter1`, `Device1`, `GattCharacteristic1`) and the framing in
//! [`crate::ble_frame`] carries the unit tests.
//!
//! Bluetooth link-layer encryption is not relied on: everything above is Noise.
//!
//! **Finding the phone.** The phone advertises the service UUID and, in the
//! scan response, service data under the same UUID:
//! `[1, kind, tag (8 bytes)]` (see [`crate::messages::ble_service_data`]).
//! The tag is what identifies a device; the address does not, because phones
//! advertise with random addresses that rotate. The desktop scans for the
//! service, picks the devices whose tag matches, and connects to the address
//! BlueZ reports for them.

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
use crate::frame::{PeerHint, Pipe};
use crate::messages::{TAG_LEN, parse_ble_service_data};
use crate::transport::{DeviceAddr, Transport};

pub use crate::ble_frame::{NOTIFY_CHAR_UUID, SERVICE_UUID, WRITE_CHAR_UUID};

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

/// The tag in the device's service data: `(is pairing, tag)`.
fn service_tag(p: &Props) -> Option<(bool, [u8; TAG_LEN])> {
    let v = p.get("ServiceData")?.try_clone().ok()?;
    let map = HashMap::<String, OwnedValue>::try_from(v).ok()?;
    let (_, data) = map
        .into_iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(SERVICE_UUID))?;
    parse_ble_service_data(&Vec::<u8>::try_from(data).ok()?)
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
    /// `(is pairing, tag)` from the advertisement, when it carries one.
    pub tag: Option<(bool, [u8; TAG_LEN])>,
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
                tag: service_tag(d),
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
        let adapter = self.adapter.clone();
        let (tag, hint) = (device.tag, device.ble_address.clone());
        // BlueZ's Connect has its own long timeout; run it on a helper thread
        // so the deadline holds. A late result is dropped, which disconnects.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(find_and_connect(&adapter, &tag, hint.as_deref(), deadline));
        });
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(r) => r.map(|p| Box::new(p) as Box<dyn Pipe>),
            Err(_) => Err(LinkError::Timeout),
        }
    }

    fn probe(&self, device: &DeviceAddr, deadline: Instant) -> Result<()> {
        self.probe_inner(device, deadline)
    }
}

/// Scans until a device advertising `tag` is seen (no connection), or the
/// deadline.
fn seen(adapter_name: &str, tag: &[u8; TAG_LEN], deadline: Instant) -> Result<()> {
    let conn = Connection::system().map_err(dbus)?;
    let adapter = adapter_path(&managed(&conn)?, adapter_name)?;
    start_discovery(&conn, &adapter)?;
    let result = loop {
        // Only devices heard from lately: BlueZ keeps stale ones for minutes.
        let heard = collect(&managed(&conn)?, &adapter)
            .into_iter()
            .filter(|d| d.rssi.is_some())
            .collect::<Vec<_>>();
        if !candidates(&heard, tag, None).is_empty() {
            break Ok(());
        }
        if Instant::now() >= deadline {
            break Err(LinkError::Unreachable("the phone is not in range".into()));
        }
        thread::sleep(Duration::from_millis(300));
    };
    stop_discovery(&conn, &adapter);
    result
}

/// The addresses of the Vahta devices BlueZ knows whose advertisement carries
/// `tag`, the ones heard most recently (they have an RSSI) first. `hint` is
/// kept as a last resort for a device whose advertisement has no tag.
fn candidates(devices: &[BleDevice], tag: &[u8; TAG_LEN], hint: Option<&str>) -> Vec<String> {
    let mut hits: Vec<&BleDevice> = devices
        .iter()
        .filter(|d| d.tag.is_some_and(|(_, t)| &t == tag))
        .collect();
    hits.sort_by_key(|d| std::cmp::Reverse(d.rssi));
    let mut out: Vec<String> = hits.iter().map(|d| d.address.clone()).collect();
    if let Some(h) = hint
        && !out.iter().any(|a| a.eq_ignore_ascii_case(h))
        && devices
            .iter()
            .any(|d| d.tag.is_none() && d.address.eq_ignore_ascii_case(h))
    {
        out.push(h.to_string());
    }
    out
}

fn find_and_connect(
    adapter_name: &str,
    tag: &[u8; TAG_LEN],
    hint: Option<&str>,
    deadline: Instant,
) -> Result<BlePipe> {
    let conn = Connection::system().map_err(dbus)?;
    let adapter = adapter_path(&managed(&conn)?, adapter_name)?;
    let mut scanning = false;
    let mut tried: Vec<String> = Vec::new();
    let mut last = LinkError::Unreachable("the phone is not in range".into());
    let result = loop {
        let found = candidates(&collect(&managed(&conn)?, &adapter), tag, hint);
        if let Some(addr) = found.into_iter().find(|a| !tried.contains(a)) {
            tried.push(addr.clone());
            match BlePipe::connect(adapter_name, &addr, deadline) {
                Ok(p) => break Ok(p),
                Err(e) => last = e,
            }
            continue;
        }
        if Instant::now() >= deadline {
            break Err(last);
        }
        if !scanning {
            start_discovery(&conn, &adapter)?;
            scanning = true;
        }
        thread::sleep(Duration::from_millis(300));
    };
    if scanning {
        stop_discovery(&conn, &adapter);
    }
    result
}

impl BleTransport {
    fn probe_inner(&self, device: &DeviceAddr, deadline: Instant) -> Result<()> {
        let (adapter, tag) = (self.adapter.clone(), device.tag);
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(seen(&adapter, &tag, deadline));
        });
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(Err(LinkError::Timeout))
    }
}

enum Event {
    Chunk(Vec<u8>),
    Closed,
}

pub struct BlePipe {
    address: String,
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
            address: address.to_string(),
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

    fn peer_hint(&self) -> Option<PeerHint> {
        Some(PeerHint::Ble(self.address.clone()))
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

    #[test]
    fn candidates_match_by_tag_and_prefer_the_recently_heard() {
        let dev = |addr: &str, rssi: Option<i16>, tag: Option<[u8; 8]>| BleDevice {
            address: addr.into(),
            name: None,
            rssi,
            tag: tag.map(|t| (false, t)),
        };
        let devices = [
            dev("AA:00:00:00:00:01", None, Some([1; 8])),
            dev("AA:00:00:00:00:02", Some(-60), Some([1; 8])),
            dev("AA:00:00:00:00:03", Some(-40), Some([2; 8])),
            dev("AA:00:00:00:00:04", Some(-50), None),
        ];
        assert_eq!(
            candidates(&devices, &[1; 8], None),
            ["AA:00:00:00:00:02", "AA:00:00:00:00:01"]
        );
        assert!(candidates(&devices, &[9; 8], None).is_empty());
        // An address hint is used only for a device with no tag at all.
        assert_eq!(
            candidates(&devices, &[9; 8], Some("aa:00:00:00:00:04")),
            ["aa:00:00:00:00:04"]
        );
        assert!(candidates(&devices, &[9; 8], Some("AA:00:00:00:00:03")).is_empty());
    }

    /// Needs a phone (or a stand-in GATT server) running the Vahta service and
    /// its address in VAHTA_TEST_BLE_ADDRESS.
    #[test]
    #[ignore = "needs a phone advertising the Vahta service"]
    fn connects_and_pings() {
        let address = std::env::var("VAHTA_TEST_BLE_ADDRESS").expect("set VAHTA_TEST_BLE_ADDRESS");
        let dev = DeviceAddr::paired("phone", [0; 32], Some(address), None);
        let mut p = BleTransport::default()
            .reach(&dev, Instant::now() + Duration::from_secs(30))
            .unwrap();
        p.set_recv_timeout(Some(Duration::from_secs(10))).unwrap();
        p.send(b"hello").unwrap();
        let _ = p.recv().unwrap();
    }
}
