//! The relay behind `network = hosts` on Linux. A command that may reach named
//! hosts runs in a network namespace whose only addresses are loopback, each
//! allowed host name being its own `127.0.0.x` there (`vahta_os::isolate_network_hosts`).
//! The listening sockets for those addresses are handed to the daemon, which
//! accepts here, checks that a TLS connection asks for the host it was made
//! for, connects to the real host from outside the namespace and copies bytes
//! both ways. Nothing is decrypted.
//!
//! A connection to port 443 must open with a TLS ClientHello whose server name
//! is the host (without one, or with another, it is refused and journaled as
//! suspicious). On any other port, which the host's rule names explicitly, a
//! TLS hello is checked the same way and anything else goes through as it is:
//! the address already fixes where the bytes end up.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::journal::{Entry, Journal};

/// Connections served at once, per run. More are closed at once.
const MAX_CONNECTIONS: usize = 256;
/// How long a client has to send its ClientHello.
const HELLO_WAIT: Duration = Duration::from_secs(10);
/// How long a client of a port other than 443 has to say something first.
const SNIFF_WAIT: Duration = Duration::from_millis(200);
/// The most bytes read looking for the end of a ClientHello.
const HELLO_MAX: usize = 20 * 1024;
/// How long to connect to the real host.
const CONNECT_WAIT: Duration = Duration::from_secs(10);
/// How often a copying thread looks at the stop flag while idle.
const TICK: Duration = Duration::from_millis(500);

/// What a ClientHello says, as far as the relay cares.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Hello {
    /// More bytes are needed.
    Need,
    /// The stream does not open with a TLS handshake record.
    NotTls,
    /// Looks like TLS but is malformed.
    Bad,
    /// A complete ClientHello, with its server name if it has one.
    Name(Option<String>),
}

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(*b.get(at)?) << 8 | usize::from(*b.get(at + 1)?))
}

/// Read the server name out of the start of a TLS stream. Handles a ClientHello
/// split over several records.
pub(crate) fn parse_hello(buf: &[u8]) -> Hello {
    let mut handshake: Vec<u8> = Vec::new();
    let mut at = 0;
    loop {
        if buf.len() < at + 5 {
            // The first byte already tells TLS from something else.
            return match buf.first() {
                Some(0x16) | None => Hello::Need,
                Some(_) if at == 0 => Hello::NotTls,
                Some(_) => Hello::Bad,
            };
        }
        if buf[at] != 0x16 {
            return if at == 0 { Hello::NotTls } else { Hello::Bad };
        }
        if buf[at + 1] != 3 {
            return if at == 0 { Hello::NotTls } else { Hello::Bad };
        }
        let len = u16_at(buf, at + 3).unwrap_or(0);
        if len == 0 || len > 16384 + 256 {
            return Hello::Bad;
        }
        if buf.len() < at + 5 + len {
            return Hello::Need;
        }
        handshake.extend_from_slice(&buf[at + 5..at + 5 + len]);
        at += 5 + len;
        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return Hello::Bad;
            }
            let want = usize::from(handshake[1]) << 16
                | usize::from(handshake[2]) << 8
                | usize::from(handshake[3]);
            if want > HELLO_MAX {
                return Hello::Bad;
            }
            if handshake.len() >= 4 + want {
                return match server_name(&handshake[4..4 + want]) {
                    Some(n) => Hello::Name(n),
                    None => Hello::Bad,
                };
            }
        }
    }
}

/// The server name of a ClientHello body: `Some(None)` when it has no such
/// extension, `None` when it is malformed.
fn server_name(body: &[u8]) -> Option<Option<String>> {
    // version, random
    let mut at = 2 + 32;
    // session id
    at += 1 + usize::from(*body.get(at)?);
    // cipher suites
    at += 2 + u16_at(body, at)?;
    // compression methods
    at += 1 + usize::from(*body.get(at)?);
    if at == body.len() {
        return Some(None);
    }
    let ext_len = u16_at(body, at)?;
    at += 2;
    let exts = body.get(at..at + ext_len)?;
    let mut i = 0;
    while i < exts.len() {
        let kind = u16_at(exts, i)?;
        let len = u16_at(exts, i + 2)?;
        let data = exts.get(i + 4..i + 4 + len)?;
        i += 4 + len;
        if kind != 0 {
            continue;
        }
        // server_name_list: u16 length, then (type u8, u16 length, name).
        let list_len = u16_at(data, 0)?;
        let list = data.get(2..2 + list_len)?;
        let mut j = 0;
        while j < list.len() {
            let name_type = *list.get(j)?;
            let n = u16_at(list, j + 1)?;
            let name = list.get(j + 3..j + 3 + n)?;
            j += 3 + n;
            if name_type == 0 {
                let text = std::str::from_utf8(name).ok()?;
                return Some(Some(text.trim_end_matches('.').to_ascii_lowercase()));
            }
        }
        return Some(None);
    }
    Some(None)
}

/// One host and port the command may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub host: String,
    pub port: u16,
    /// The rule lets the name resolve to a loopback, private or link-local
    /// address. Otherwise such an answer is refused (DNS rebinding).
    pub allow_private: bool,
}

#[derive(Default)]
struct Tally {
    connections: u64,
    sent: u64,
    received: u64,
    refused: u64,
}

/// Where the journal lines of a run's relay belong.
pub(crate) struct Tag {
    pub vault: [u8; 16],
    pub names: Vec<String>,
}

struct Inner {
    journal: Arc<Journal>,
    tag: Tag,
    stop: AtomicBool,
    open: AtomicUsize,
    tallies: Mutex<HashMap<String, Tally>>,
}

impl Inner {
    fn entry(&self, event: &str) -> Entry {
        Entry::new(event)
            .vault(&self.tag.vault)
            .names(&self.tag.names)
    }

    fn tally(&self, host: &str, f: impl FnOnce(&mut Tally)) {
        if let Ok(mut t) = self.tallies.lock() {
            f(t.entry(host.to_string()).or_default());
        }
    }

    fn refuse(&self, host: &str, why: &str) {
        self.tally(host, |t| t.refused += 1);
        self.journal.record(
            self.entry("net_relay_refused")
                .http("TLS", host, None, None)
                .result("refused", Some(&format!("suspicious: {why}"))),
        );
    }
}

/// A running relay for one command. Stop it with [`Relay::finish`].
pub(crate) struct Relay {
    inner: Arc<Inner>,
    wakers: Vec<TcpListener>,
    accepters: Vec<JoinHandle<()>>,
}

/// Start accepting on `listeners`, one per target, in the same order.
pub(crate) fn start(
    listeners: Vec<TcpListener>,
    targets: Vec<Target>,
    journal: Arc<Journal>,
    tag: Tag,
) -> Relay {
    let inner = Arc::new(Inner {
        journal,
        tag,
        stop: AtomicBool::new(false),
        open: AtomicUsize::new(0),
        tallies: Mutex::new(HashMap::new()),
    });
    let mut wakers = Vec::new();
    let mut accepters = Vec::new();
    for (listener, target) in listeners.into_iter().zip(targets) {
        if let Ok(w) = listener.try_clone() {
            wakers.push(w);
        }
        let inner = inner.clone();
        accepters.push(std::thread::spawn(move || {
            accept_loop(listener, target, inner)
        }));
    }
    Relay {
        inner,
        wakers,
        accepters,
    }
}

impl Relay {
    /// Stop accepting, let the copying threads wind down, and journal what
    /// went through, one line per host.
    pub(crate) fn finish(self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        for w in &self.wakers {
            vahta_os::wake_listener(w);
        }
        for t in self.accepters {
            let _ = t.join();
        }
        // The copying threads notice the flag within a tick; give them that.
        let deadline = std::time::Instant::now() + TICK * 3;
        while self.inner.open.load(Ordering::SeqCst) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let Ok(tallies) = self.inner.tallies.lock() else {
            return;
        };
        let mut hosts: Vec<(&String, &Tally)> = tallies.iter().collect();
        hosts.sort_by(|a, b| a.0.cmp(b.0));
        for (host, t) in hosts {
            let text = format!(
                "{} connection{}, {} bytes out, {} bytes in, {} refused",
                t.connections,
                if t.connections == 1 { "" } else { "s" },
                t.sent,
                t.received,
                t.refused
            );
            self.inner.journal.record(
                self.inner
                    .entry("net_relay")
                    .http("TLS", host, None, Some(t.sent + t.received))
                    .result("ended", Some(&text)),
            );
        }
    }
}

fn accept_loop(listener: TcpListener, target: Target, inner: Arc<Inner>) {
    loop {
        let accepted = listener.accept();
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok((client, _)) = accepted else {
            // A transient error (a client that gave up) is not the end.
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };
        if inner.open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            inner.open.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (inner, target) = (inner.clone(), target.clone());
        std::thread::spawn(move || {
            serve(client, &target, &inner);
            inner.open.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Whether the name in a ClientHello is the one this address stands for.
fn same_name(sni: &str, host: &str) -> bool {
    sni.eq_ignore_ascii_case(host)
}

fn serve(mut client: TcpStream, target: &Target, inner: &Inner) {
    let _ = client.set_nodelay(true);
    let mut first: Vec<u8> = Vec::new();
    // Port 443 must open with a TLS hello. On another port the host's rule
    // named it on purpose, and what the client sends first decides: a TLS
    // hello is checked the same way, anything else (or nothing yet, as with a
    // server that speaks first) goes through as it is.
    let strict = target.port == 443;
    let _ = client.set_read_timeout(Some(if strict { HELLO_WAIT } else { SNIFF_WAIT }));
    let mut chunk = [0u8; 4096];
    loop {
        match parse_hello(&first) {
            Hello::Need => {}
            Hello::Name(Some(n)) if same_name(&n, &target.host) => break,
            Hello::Name(Some(n)) => {
                inner.refuse(
                    &target.host,
                    &format!(
                        "a connection made for {} asked for another server name ({})",
                        target.host,
                        printable(&n)
                    ),
                );
                return;
            }
            Hello::Name(None) => {
                inner.refuse(&target.host, "a TLS connection without a server name");
                return;
            }
            Hello::NotTls if !strict => break,
            Hello::NotTls | Hello::Bad => {
                inner.refuse(&target.host, "the connection did not open with TLS");
                return;
            }
        }
        if first.len() >= HELLO_MAX {
            inner.refuse(&target.host, "no complete TLS hello in the first bytes");
            return;
        }
        match client.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => first.extend_from_slice(&chunk[..n]),
            Err(e)
                if !strict
                    && first.is_empty()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                break;
            }
            Err(_) => return,
        }
    }
    let _ = client.set_read_timeout(None);
    let mut upstream = match connect_out(&target.host, target.port, target.allow_private) {
        Ok(s) => s,
        Err(Connect::Private(why)) => {
            inner.refuse(&target.host, &why);
            return;
        }
        Err(Connect::Failed) => {
            inner.tally(&target.host, |t| t.refused += 1);
            return;
        }
    };
    let _ = upstream.set_nodelay(true);
    inner.tally(&target.host, |t| t.connections += 1);
    if upstream.write_all(&first).is_err() {
        return;
    }
    let (Ok(mut client_r), Ok(mut up_r)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let out = Arc::new(AtomicU64::new(first.len() as u64));
    let inb = Arc::new(AtomicU64::new(0));
    let (stop_out, out2) = (&inner.stop, out.clone());
    std::thread::scope(|scope| {
        scope.spawn(|| pump(&mut client_r, &mut upstream, stop_out, &out2));
        pump(&mut up_r, &mut client, &inner.stop, &inb);
    });
    let (o, i) = (out.load(Ordering::SeqCst), inb.load(Ordering::SeqCst));
    inner.tally(&target.host, |t| {
        t.sent += o;
        t.received += i;
    });
}

/// A name from the wire, safe to put in the journal.
fn printable(s: &str) -> String {
    s.chars()
        .take(100)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

/// Copy `from` to `to` until `from` ends or the relay stops, then close the
/// way to `to` (and, on a stop, the way back too).
fn pump(from: &mut TcpStream, to: &mut TcpStream, stop: &AtomicBool, count: &AtomicU64) {
    let _ = from.set_read_timeout(Some(TICK));
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    let _ = from.shutdown(Shutdown::Read);
                    break;
                }
                count.fetch_add(n as u64, Ordering::SeqCst);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if stop.load(Ordering::SeqCst) {
                    let _ = from.shutdown(Shutdown::Both);
                    let _ = to.shutdown(Shutdown::Both);
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// Why the real host was not reached.
enum Connect {
    /// The name resolved only to addresses the rule does not allow; the text
    /// says which (for the journal and the reason line).
    Private(String),
    Failed,
}

/// Which of `addrs` may be connected to: all of them with `allow_private`,
/// else the public ones. When none is left and some were refused, the reason.
fn usable(host: &str, addrs: Vec<IpAddr>, allow_private: bool) -> Result<Vec<IpAddr>, Connect> {
    if allow_private {
        return Ok(addrs);
    }
    let mut refused = None;
    let kept: Vec<IpAddr> = addrs
        .into_iter()
        .filter(|ip| match vahta_net::private_kind(*ip) {
            None => true,
            Some(kind) => {
                refused.get_or_insert((*ip, kind));
                false
            }
        })
        .collect();
    match (kept.is_empty(), refused) {
        (true, Some((ip, kind))) => Err(Connect::Private(vahta_net::refusal_text(host, ip, kind))),
        _ => Ok(kept),
    }
}

/// Connect to the real host, from outside the command's namespace. The name is
/// resolved here, by the system; an answer in a loopback, private, link-local
/// or unspecified range is not connected to unless the rule allows it, and the
/// connection goes to the address that was checked.
fn connect_out(host: &str, port: u16, allow_private: bool) -> Result<TcpStream, Connect> {
    let resolved: Vec<IpAddr> = match crate::testing::relay_connect_override() {
        Some(ip) => vec![ip],
        None => (host, port)
            .to_socket_addrs()
            .map_err(|_| Connect::Failed)?
            .map(|a| a.ip())
            .collect(),
    };
    for ip in usable(host, resolved, allow_private)? {
        if let Ok(s) = TcpStream::connect_timeout(&(ip, port).into(), CONNECT_WAIT) {
            return Ok(s);
        }
    }
    Err(Connect::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello with the given extensions block, as one record.
    fn hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one suite
        body.extend_from_slice(&[1, 0]); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn sni_ext(name: &str) -> Vec<u8> {
        let n = name.len() as u16;
        let mut list = vec![0];
        list.extend_from_slice(&n.to_be_bytes());
        list.extend_from_slice(name.as_bytes());
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        let mut ext = vec![0, 0];
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&data);
        ext
    }

    #[test]
    fn the_server_name_is_read_and_lowercased() {
        let mut exts = vec![0, 43, 0, 3, 2, 3, 4]; // supported_versions first
        exts.extend_from_slice(&sni_ext("API.Example.com."));
        assert_eq!(
            parse_hello(&hello(&exts)),
            Hello::Name(Some("api.example.com".into()))
        );
    }

    #[test]
    fn a_hello_without_a_name_says_so() {
        assert_eq!(
            parse_hello(&hello(&[0, 43, 0, 3, 2, 3, 4])),
            Hello::Name(None)
        );
        assert_eq!(parse_hello(&hello(&[])), Hello::Name(None));
    }

    #[test]
    fn partial_input_waits_and_other_protocols_are_told_apart() {
        let full = hello(&sni_ext("a.example.com"));
        for cut in [0, 1, 4, 5, full.len() - 1] {
            assert_eq!(parse_hello(&full[..cut]), Hello::Need, "{cut}");
        }
        assert_eq!(parse_hello(b"GET / HTTP/1.1\r\n"), Hello::NotTls);
        assert_eq!(parse_hello(&[0x16, 3, 1, 0, 0]), Hello::Bad);
        // Truncated inner lengths do not read past the end.
        let mut bad = full.clone();
        let last = bad.len() - 1;
        bad[last - 3] = 0xff;
        assert_ne!(parse_hello(&bad), Hello::Name(Some("a.example.com".into())));
    }

    #[test]
    fn a_hello_split_over_two_records_is_joined() {
        let full = hello(&sni_ext("split.example.com"));
        let payload = &full[5..];
        let (a, b) = payload.split_at(20);
        let mut two = vec![0x16, 3, 1, 0, a.len() as u8];
        two.extend_from_slice(a);
        two.extend_from_slice(&[0x16, 3, 1, 0, b.len() as u8]);
        two.extend_from_slice(b);
        assert_eq!(
            parse_hello(&two),
            Hello::Name(Some("split.example.com".into()))
        );
    }

    #[test]
    fn a_name_that_resolves_locally_is_refused_unless_the_rule_allows_it() {
        let ips = |l: &[&str]| -> Vec<IpAddr> { l.iter().map(|s| s.parse().unwrap()).collect() };
        // Only local answers: refused, with the address and kind.
        let Err(Connect::Private(why)) = usable("a.example", ips(&["127.0.0.1"]), false) else {
            panic!("loopback must be refused");
        };
        assert!(why.contains("a.example") && why.contains("127.0.0.1") && why.contains("loopback"));
        for ip in [
            "10.0.0.1",
            "192.168.0.9",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "0.0.0.0",
        ] {
            assert!(matches!(
                usable("a.example", ips(&[ip]), false),
                Err(Connect::Private(_))
            ));
        }
        // A public answer next to a local one: only the public one is used.
        let kept = usable("a.example", ips(&["10.0.0.1", "93.184.216.34"]), false).ok();
        assert_eq!(kept, Some(ips(&["93.184.216.34"])));
        // The rule's marker allows them all.
        let kept = usable("a.example", ips(&["10.0.0.1", "127.0.0.1"]), true).ok();
        assert_eq!(kept, Some(ips(&["10.0.0.1", "127.0.0.1"])));
        // No answer at all is a failure to connect, not a private one.
        assert!(matches!(usable("a.example", vec![], false), Ok(v) if v.is_empty()));
    }

    #[test]
    fn garbage_never_panics() {
        for seed in 0u32..2000 {
            let mut x = seed.wrapping_mul(2654435761);
            let n = (x % 90) as usize;
            let bytes: Vec<u8> = (0..n)
                .map(|_| {
                    x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                    (x >> 24) as u8
                })
                .collect();
            let mut with_head = vec![0x16, 3, 1, 0, n as u8, 1, 0, 0, n.saturating_sub(4) as u8];
            with_head.extend_from_slice(&bytes);
            let _ = parse_hello(&bytes);
            let _ = parse_hello(&with_head);
        }
    }
}
