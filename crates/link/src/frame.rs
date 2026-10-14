//! The pipe: an ordered, reliable carrier of whole frames. The transport under
//! it is untrusted; everything that matters is sealed above this layer.

use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{LinkError, Result};

/// The largest frame, which is also the largest Noise message.
pub const MAX_FRAME: usize = 65535;

/// Where the far end of a pipe was found, for the caller to remember as a hint
/// for next time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerHint {
    /// A Bluetooth address (may be a random one that changes).
    Ble(String),
    Lan(std::net::SocketAddr),
}

pub trait Pipe: Send {
    fn send(&mut self, frame: &[u8]) -> Result<()>;
    /// The next whole frame; blocks (up to the receive timeout, if set).
    fn recv(&mut self) -> Result<Vec<u8>>;
    /// Bounds each `recv`; `None` blocks without limit. Pipes that cannot
    /// time out ignore it.
    fn set_recv_timeout(&mut self, _timeout: Option<Duration>) -> Result<()> {
        Ok(())
    }
    /// Where this pipe's peer was reached, if the transport knows.
    fn peer_hint(&self) -> Option<PeerHint> {
        None
    }
}

/// A frame on a byte stream: a 2-byte big-endian length, then the bytes.
pub fn write_frame<W: Write>(w: &mut W, frame: &[u8]) -> Result<()> {
    if frame.len() > MAX_FRAME {
        return Err(LinkError::FrameTooLarge(frame.len()));
    }
    let mut buf = Vec::with_capacity(frame.len() + 2);
    buf.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    buf.extend_from_slice(frame);
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_limit() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap(), b"hello");
        assert_eq!(read_frame(&mut r).unwrap(), b"");
        assert!(matches!(read_frame(&mut r), Err(LinkError::Closed)));
        assert!(matches!(
            write_frame(&mut Vec::new(), &vec![0; MAX_FRAME + 1]),
            Err(LinkError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn truncated_frame_is_closed() {
        let mut r: &[u8] = &[0, 9, 1, 2];
        assert!(matches!(read_frame(&mut r), Err(LinkError::Closed)));
    }
}
