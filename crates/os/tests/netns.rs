//! A command started through `isolate_network` has no network and keeps its
//! file access. The test re-runs this test binary as the child: the `child`
//! test below does the probing when `VAHTA_NETNS_CHILD` names a listener.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::Duration;

const ENV_ADDR: &str = "VAHTA_NETNS_CHILD";
const ENV_DIR: &str = "VAHTA_NETNS_DIR";

/// The child's half. A no-op when run as a normal test.
#[test]
fn child() {
    let Ok(addr) = std::env::var(ENV_ADDR) else {
        return;
    };
    let dir = std::env::var(ENV_DIR).expect("dir");
    let sock: std::net::SocketAddr = addr.parse().expect("addr");
    let local = TcpStream::connect_timeout(&sock, Duration::from_secs(2)).is_ok();
    let outward = TcpStream::connect_timeout(
        &"1.1.1.1:443".parse().expect("addr"),
        Duration::from_secs(2),
    )
    .is_ok();
    // Name lookup may still answer: a resolver daemon reached over a Unix
    // socket (systemd-resolved) is outside the network namespace. What counts
    // is that nothing can be connected to afterwards.
    let resolved = "example.com:443"
        .to_socket_addrs()
        .map(|mut a| a.next().is_some())
        .unwrap_or(false);
    let by_name = "example.com:443"
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok());
    let path = std::path::Path::new(&dir).join("from-child.txt");
    let wrote = std::fs::write(&path, b"hello").is_ok();
    let read = std::fs::read(std::path::Path::new(&dir).join("from-parent.txt")).ok();
    let uid = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .unwrap_or("")
        .to_string();
    println!(
        "RESULT local={local} outward={outward} resolved={resolved} by_name={by_name} wrote={wrote} read={} {}",
        read.as_deref() == Some(b"data"),
        uid.replace('\t', " ")
    );
}

#[test]
fn an_isolated_child_has_no_network_but_keeps_its_files() {
    if !vahta_os::network_isolation_available() {
        eprintln!("SKIP: unprivileged user namespaces are not available here");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let dir = std::env::temp_dir().join(format!("vahta-netns-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::File::create(dir.join("from-parent.txt"))
        .and_then(|mut f| f.write_all(b"data"))
        .expect("seed");

    let run = |isolate: bool| {
        let mut cmd = Command::new(std::env::current_exe().expect("exe"));
        cmd.args(["child", "--exact", "--nocapture", "--test-threads=1"])
            .env(ENV_ADDR, addr.to_string())
            .env(ENV_DIR, &dir);
        if isolate {
            vahta_os::isolate_network(&mut cmd).expect("supported");
        }
        let out = cmd.output().expect("spawn");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.find("RESULT ").map(|i| &l[i..]))
            .unwrap_or("NO RESULT")
            .to_string()
    };

    // Control: without isolation the same child reaches the listener.
    let open = run(false);
    assert!(open.contains("local=true"), "control: {open}");

    let closed = run(true);
    let uid_line = format!("Uid: {0} {0} {0} {0}", rustix::process::getuid().as_raw());
    assert!(closed.contains("local=false"), "{closed}");
    assert!(closed.contains("outward=false"), "{closed}");
    assert!(closed.contains("by_name=false"), "{closed}");
    assert!(closed.contains("wrote=true"), "{closed}");
    assert!(closed.contains("read=true"), "{closed}");
    assert!(closed.contains(&uid_line), "{closed} vs {uid_line}");
    assert!(dir.join("from-child.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("netns test ran for real: {closed}");
}
