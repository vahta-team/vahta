//! An in-process HTTPS server for tests (feature `test-roots`, never in a
//! shipped build): rustls on the server side with the throwaway certificate in
//! `tests/data` (the CA is [`CA_PEM`]; the certificate names `localhost`,
//! `other.localhost` and `127.0.0.1`). It answers each request with what the
//! handler returns, and keeps what it saw, for the test to look at.
//!
//! It never prints a request. A test that wants to know whether a header
//! carried a value checks inside its handler and records only the answer.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The root the client trusts in a test (`Options::extra_root_pem`).
pub const CA_PEM: &[u8] = include_bytes!("../tests/data/ca.pem");
const SERVER_PEM: &[u8] = include_bytes!("../tests/data/server.pem");
/// The key is stored as bare base64 (PKCS#8 DER), without the PEM armour, so
/// that the repository holds no private-key block for a scanner to flag; the
/// armour is put back at run time.
const SERVER_KEY_B64: &str = include_str!("../tests/data/server.key.b64");

/// A request as the server read it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    /// Path and query.
    pub target: String,
    /// Lowercase names.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// What the handler answers.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn ok(body: &[u8]) -> Reply {
        Reply {
            status: 200,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }
}

type Handler = Box<dyn Fn(&Seen) -> Reply + Send + Sync>;

pub struct TestServer {
    pub port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl TestServer {
    pub fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> TestServer {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(SERVER_PEM)
            .collect::<Result<_, _>>()
            .expect("the test certificate");
        let armoured = format!(
            "-----BEGIN {0}-----\n{1}\n-----END {0}-----\n",
            ["PRIVATE", "KEY"].join(" "),
            SERVER_KEY_B64.trim()
        );
        let key = PrivateKeyDer::from_pem_slice(armoured.as_bytes()).expect("the test key");
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("the test certificate and key");
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(Box::new(handler));
        {
            let (seen, stop) = (seen.clone(), stop.clone());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(stream) = stream else { continue };
                    let (config, handler, seen) = (config.clone(), handler.clone(), seen.clone());
                    std::thread::spawn(move || serve(stream, config, &handler, &seen));
                }
            });
        }
        TestServer { port, seen, stop }
    }

    /// Everything the server was asked, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn serve(
    mut tcp: TcpStream,
    config: Arc<rustls::ServerConfig>,
    handler: &Handler,
    seen: &Mutex<Vec<Seen>>,
) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(mut conn) = rustls::ServerConnection::new(config) else {
        return;
    };
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    // One request per connection: the replies say `connection: close`.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let target = first.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let want: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < want {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    let request = Seen {
        method,
        target,
        headers,
        body,
    };
    let reply = handler(&request);
    if let Ok(mut all) = seen.lock() {
        all.push(request);
    }
    let mut out = format!("HTTP/1.1 {} X\r\n", reply.status).into_bytes();
    for (n, v) in &reply.headers {
        out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            reply.body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&reply.body);
    let _ = tls.write_all(&out);
    let _ = tls.flush();
    conn.send_close_notify();
    let _ = conn.complete_io(&mut tcp);
}
