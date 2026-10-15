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
const ENV_SOCK: &str = "VAHTA_NETNS_SOCK";

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
    // The resolver daemon is a Unix socket under /run, which is hidden.
    let resolved = "example.com:443"
        .to_socket_addrs()
        .map(|mut a| a.next().is_some())
        .unwrap_or(false);
    let by_name = "example.com:443"
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok());
    let unix = std::env::var(ENV_SOCK)
        .map(|p| std::os::unix::net::UnixStream::connect(p).is_ok())
        .unwrap_or(false);
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
        "RESULT local={local} outward={outward} resolved={resolved} by_name={by_name} unix={unix} wrote={wrote} read={} {}",
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

    // A pathname socket under the user's runtime directory, as a bus or
    // docker.sock would be.
    let runtime =
        std::path::PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()));
    let sock = runtime
        .is_dir()
        .then(|| runtime.join(format!("vahta-netns-{}.sock", std::process::id())));
    let _unix_listener = sock
        .as_ref()
        .and_then(|p| std::os::unix::net::UnixListener::bind(p).ok());
    let have_sock = _unix_listener.is_some();

    let run = |isolate: bool| {
        let mut cmd = Command::new(std::env::current_exe().expect("exe"));
        cmd.args(["child", "--exact", "--nocapture", "--test-threads=1"])
            .env(ENV_ADDR, addr.to_string())
            .env(ENV_DIR, &dir);
        if let (Some(p), true) = (&sock, have_sock) {
            cmd.env(ENV_SOCK, p);
        }
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
    if have_sock {
        assert!(open.contains("unix=true"), "control: {open}");
        assert!(closed.contains("unix=false"), "{closed}");
    } else {
        eprintln!("no /run/user/<uid> here: Unix socket check skipped");
    }
    assert!(closed.contains("resolved=false"), "{closed}");
    assert!(closed.contains("local=false"), "{closed}");
    assert!(closed.contains("outward=false"), "{closed}");
    assert!(closed.contains("by_name=false"), "{closed}");
    assert!(closed.contains("wrote=true"), "{closed}");
    assert!(closed.contains("read=true"), "{closed}");
    assert!(closed.contains(&uid_line), "{closed} vs {uid_line}");
    assert!(dir.join("from-child.txt").exists());
    if let Some(p) = &sock {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("netns test ran for real: {closed}");
}

const ENV_MEDIA: &str = "VAHTA_NETNS_MEDIA";

/// The child's half of the passthrough test. A no-op as a normal test.
#[test]
fn media_child() {
    let Ok(media) = std::env::var(ENV_MEDIA) else {
        return;
    };
    let media = std::path::Path::new(&media);
    let wrote = std::fs::write(media.join("sub").join("from-child.txt"), b"card").is_ok();
    let sees = std::fs::read(media.join("sub").join("seed.txt"))
        .ok()
        .as_deref()
        == Some(b"seed");
    // A sibling of the passed-through directory is not passed through.
    let sibling = media
        .parent()
        .map(|p| std::fs::read_dir(p).map(|d| d.count()).unwrap_or(0))
        .unwrap_or(0);
    let hidden = |p: &str| {
        std::fs::read_dir(p)
            .map(|mut d| d.next().is_none())
            .unwrap_or(true)
    };
    println!(
        "RESULT wrote={wrote} sees={sees} siblings={sibling} resolve_hidden={} dbus_hidden={} systemd_hidden={}",
        hidden("/run/systemd/resolve"),
        hidden("/run/dbus"),
        hidden("/run/systemd"),
    );
}

/// Under no network a write into a passed-through directory under `/run`
/// reaches the real file system (a stand-in for `/run/media/$USER/<card>`,
/// which needs root to create; it takes the same code path, since the built-in
/// list is only two more entries in the same list), while the resolver and bus
/// directories stay empty.
#[test]
fn a_passed_through_run_directory_keeps_its_writes() {
    if !vahta_os::network_isolation_available() {
        eprintln!("SKIP: unprivileged user namespaces are not available here");
        return;
    }
    let runtime =
        std::path::PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw()));
    if !runtime.is_dir() {
        eprintln!("SKIP: no /run/user/<uid> to stand in for /run/media");
        return;
    }
    let base = runtime.join(format!("vahta-netns-media-{}", std::process::id()));
    let media = base.join("card");
    std::fs::create_dir_all(media.join("sub")).expect("dirs");
    std::fs::write(media.join("sub").join("seed.txt"), b"seed").expect("seed");
    // A sibling that is not passed through.
    std::fs::create_dir_all(base.join("other")).expect("other");

    let run = |pass: bool| {
        let mut cmd = Command::new(std::env::current_exe().expect("exe"));
        cmd.args(["media_child", "--exact", "--nocapture", "--test-threads=1"])
            .env(ENV_MEDIA, &media);
        if pass {
            vahta_os::isolate_network_passing(&mut cmd, &[media.as_path()]).expect("supported");
        } else {
            vahta_os::isolate_network(&mut cmd).expect("supported");
        }
        let out = cmd.output().expect("spawn");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.find("RESULT ").map(|i| &l[i..]))
            .unwrap_or("NO RESULT")
            .to_string()
    };

    // Not on the list: the write goes to the tmpfs and fails or is lost.
    let plain = run(false);
    assert!(plain.contains("sees=false"), "{plain}");
    assert!(!media.join("sub").join("from-child.txt").exists());

    let passed = run(true);
    assert!(passed.contains("wrote=true"), "{passed}");
    assert!(passed.contains("sees=true"), "{passed}");
    assert!(passed.contains("siblings=1"), "{passed}");
    assert!(passed.contains("resolve_hidden=true"), "{passed}");
    assert!(passed.contains("dbus_hidden=true"), "{passed}");
    assert!(passed.contains("systemd_hidden=true"), "{passed}");
    assert_eq!(
        std::fs::read(media.join("sub").join("from-child.txt")).expect("kept"),
        b"card"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn paths_under_the_emptied_directories_are_reported_hidden() {
    use std::path::Path;
    assert!(vahta_os::hidden_by_isolation(Path::new("/run/user/1000/x")));
    assert!(vahta_os::hidden_by_isolation(Path::new(
        "/run/new-thing/file"
    )));
    assert!(vahta_os::hidden_by_isolation(Path::new(
        "/var/run/docker.sock"
    )));
    assert!(vahta_os::hidden_by_isolation(Path::new(
        "/tmp/.X11-unix/X0"
    )));
    assert!(!vahta_os::hidden_by_isolation(Path::new(
        "/run/media/me/BOOT/custom.toml"
    )));
    assert!(!vahta_os::hidden_by_isolation(Path::new("/run/mnt/x")));
    assert!(!vahta_os::hidden_by_isolation(Path::new("/tmp/file")));
    assert!(!vahta_os::hidden_by_isolation(Path::new("/home")));
    assert!(!vahta_os::hidden_by_isolation(Path::new("relative")));
}
