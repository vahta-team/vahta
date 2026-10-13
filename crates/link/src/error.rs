//! One error type for the whole link: every failure a caller may want to tell
//! apart (time ran out, the peer is unreachable, the bytes were not ours).

use std::fmt;

#[derive(Debug)]
pub enum LinkError {
    Io(String),
    /// A deadline passed before the peer answered.
    Timeout,
    /// The peer closed the pipe.
    Closed,
    FrameTooLarge(usize),
    /// The Noise layer refused: a bad tag, a wrong key, a wrong PSK, a replay.
    Noise(String),
    /// The bytes decrypted but are not a message we accept.
    Protocol(String),
    OfferExpired,
    OfferInvalid(String),
    /// This transport cannot reach the device (not found, no address).
    Unreachable(String),
    /// This transport does not exist on this platform or for this device.
    Unsupported(String),
    /// Every transport failed: (transport name, why).
    AllFailed(Vec<(String, String)>),
}

pub type Result<T> = std::result::Result<T, LinkError>;

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Timeout => f.write_str("timed out"),
            Self::Closed => f.write_str("the peer closed the connection"),
            Self::FrameTooLarge(n) => write!(f, "frame of {n} bytes is over the limit"),
            Self::Noise(e) => write!(f, "secure channel: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::OfferExpired => f.write_str("the pairing code has expired"),
            Self::OfferInvalid(e) => write!(f, "invalid pairing code: {e}"),
            Self::Unreachable(e) => write!(f, "unreachable: {e}"),
            Self::Unsupported(e) => write!(f, "unsupported: {e}"),
            Self::AllFailed(v) => {
                f.write_str("no transport reached the device")?;
                for (n, e) in v {
                    write!(f, "; {n}: {e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LinkError {}

impl From<std::io::Error> for LinkError {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        match e.kind() {
            WouldBlock | TimedOut => Self::Timeout,
            UnexpectedEof | ConnectionReset | BrokenPipe | ConnectionAborted => Self::Closed,
            _ => Self::Io(e.to_string()),
        }
    }
}

impl From<snow::Error> for LinkError {
    fn from(e: snow::Error) -> Self {
        Self::Noise(e.to_string())
    }
}
