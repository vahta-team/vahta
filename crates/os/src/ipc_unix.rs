//! Unix domain sockets. The socket file is created inside a directory only the
//! user can enter and is chmod 0600 as well.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use crate::Peer;
use crate::ipc::Address;

pub(crate) fn address_for(dir: &Path) -> io::Result<OsString> {
    Ok(dir.join("daemon.sock").into_os_string())
}

#[derive(Debug)]
pub struct Listener {
    inner: UnixListener,
}

impl Listener {
    /// Bind the socket. The caller holds the daemon's exclusive lock, so a
    /// socket file already there belongs to a daemon that is gone, and it is
    /// replaced.
    pub fn bind(addr: &Address) -> io::Result<Listener> {
        let path = Path::new(addr.as_os_str());
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let inner = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(Listener { inner })
    }

    pub fn accept(&self) -> io::Result<Stream> {
        self.inner.accept().map(|(s, _)| Stream { inner: s })
    }
}

#[derive(Debug)]
pub struct Stream {
    inner: UnixStream,
}

impl Stream {
    pub fn connect(addr: &Address) -> io::Result<Stream> {
        UnixStream::connect(Path::new(addr.as_os_str())).map(|inner| Stream { inner })
    }

    pub fn try_clone(&self) -> io::Result<Stream> {
        self.inner.try_clone().map(|inner| Stream { inner })
    }

    /// End both directions; a thread blocked reading this stream returns.
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown(Shutdown::Both)
    }

    /// Which process is on the other end, from the kernel. Meaningful on the
    /// server side of a connection.
    pub fn peer(&self) -> io::Result<Peer> {
        crate::sys::peer_of(&self.inner)
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_reports_this_process_as_its_peer_and_carries_bytes() {
        let dir = std::env::temp_dir().join(format!("vahta-os-ipc-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let addr = Address(address_for(&dir).expect("addr"));
        let listener = Listener::bind(&addr).expect("bind");
        let server = std::thread::spawn(move || {
            let mut s = listener.accept().expect("accept");
            let peer = s.peer().expect("peer");
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).expect("read");
            s.write_all(&buf).expect("echo");
            (peer.id, peer.same_user)
        });
        let mut c = Stream::connect(&addr).expect("connect");
        c.write_all(b"ping").expect("write");
        let mut back = [0u8; 4];
        c.read_exact(&mut back).expect("read back");
        assert_eq!(&back, b"ping");
        let (id, same_user) = server.join().expect("server");
        assert_eq!(
            id,
            crate::identity_of(std::process::id()).expect("identity")
        );
        assert!(same_user);
        assert_eq!(
            fs::metadata(addr.socket_path().expect("path"))
                .expect("meta")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
