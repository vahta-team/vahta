//! A command started through `isolate_network_hosts` sees only the listed
//! names, each at its own loopback address, with a listener for each handed to
//! the caller.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn hosts(list: &[(&str, u16)]) -> Vec<(String, u16)> {
    list.iter().map(|(h, p)| (h.to_string(), *p)).collect()
}

#[test]
fn the_names_file_and_the_listeners_reach_the_command() {
    if !vahta_os::network_isolation_available() {
        eprintln!("SKIP: unprivileged user namespaces are not available here");
        return;
    }
    let mut cmd = Command::new("cat");
    cmd.args(["/etc/hosts", "/etc/nsswitch.conf"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let sockets = vahta_os::isolate_network_hosts(
        &mut cmd,
        &hosts(&[("a.example", 443), ("b.example", 443), ("a.example", 8080)]),
    )
    .expect("supported");
    let out = cmd.output().expect("spawn");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("127.0.0.2 a.example\n"), "{text}");
    assert!(text.contains("127.0.0.3 b.example\n"), "{text}");
    assert!(text.contains("hosts: files\n"), "{text}");
    assert!(!text.contains("hosts: files dns"), "{text}");
    // The real files are untouched.
    let real = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    assert!(!real.contains("a.example"));
    let listeners = sockets.take().expect("listeners");
    let addrs: Vec<String> = listeners
        .iter()
        .map(|l| l.local_addr().expect("addr").to_string())
        .collect();
    assert_eq!(addrs, ["127.0.0.2:443", "127.0.0.3:443", "127.0.0.2:8080"]);
}

/// A client inside connects to the listener and the caller accepts from outside.
#[test]
fn a_connection_inside_is_accepted_outside() {
    if !vahta_os::network_isolation_available() {
        eprintln!("SKIP: unprivileged user namespaces are not available here");
        return;
    }
    let Ok(py) = Command::new("python3").arg("-V").output() else {
        eprintln!("SKIP: no python3");
        return;
    };
    let _ = py;
    let mut cmd = Command::new("python3");
    cmd.args([
        "-c",
        "import socket,sys\nip = socket.gethostbyname('a.example')\ns = socket.create_connection(('a.example', 8080), timeout=5)\ns.sendall(b'ping')\nprint(ip, s.recv(10))\ntry:\n    socket.create_connection(('1.1.1.1', 443), timeout=2)\n    print('open')\nexcept OSError as e:\n    print('closed', e.errno)\n",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let sockets = vahta_os::isolate_network_hosts(&mut cmd, &hosts(&[("a.example", 8080)]))
        .expect("supported");
    let child = cmd.spawn().expect("spawn");
    let listeners = sockets.take().expect("listeners");
    let (mut conn, _) = listeners[0].accept().expect("accept");
    let mut buf = [0u8; 4];
    conn.read_exact(&mut buf).expect("read");
    assert_eq!(&buf, b"ping");
    conn.write_all(b"pong").expect("write");
    let out = child.wait_with_output().expect("wait");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("127.0.0.2 b'pong'"),
        "{text} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("closed 101"), "{text}");
}
