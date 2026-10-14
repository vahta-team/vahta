//! Bluetooth LE framing, platform independent (the Kotlin side implements the
//! same rules; the test vectors pin them).
//!
//! A pipe frame crosses GATT as a stream: a 2-byte big-endian length, then the
//! frame, cut into chunks of at most the usable ATT payload (MTU minus 3).
//! GATT writes and notifications are ordered and reliable, so chunks carry no
//! header of their own; the Noise layer above catches any damage anyway.

use crate::error::{LinkError, Result};
use crate::frame::MAX_FRAME;

/// The Vahta GATT service the phone advertises (random v4, fixed forever).
pub const SERVICE_UUID: &str = "11ca9b36-035f-4d80-8e4a-7819627ac4c0";
/// The desktop (GATT central) writes frames here (write with response).
pub const WRITE_CHAR_UUID: &str = "0e1a6dcf-3ae7-4ba5-a24c-fc4c243d0629";
/// The phone sends frames here (notify).
pub const NOTIFY_CHAR_UUID: &str = "5625b7a7-3f03-49f9-8d96-a25a49559adf";

/// The ATT payload when the MTU is unknown (the minimum, 23, minus 3).
pub const DEFAULT_CHUNK: usize = 20;

/// Cuts one frame into chunks of at most `chunk_len` bytes.
pub fn chunk_frame(frame: &[u8], chunk_len: usize) -> Result<Vec<Vec<u8>>> {
    if frame.len() > MAX_FRAME {
        return Err(LinkError::FrameTooLarge(frame.len()));
    }
    let chunk_len = chunk_len.max(1);
    let mut stream = Vec::with_capacity(frame.len() + 2);
    stream.extend_from_slice(&(frame.len() as u16).to_be_bytes());
    stream.extend_from_slice(frame);
    Ok(stream.chunks(chunk_len).map(<[u8]>::to_vec).collect())
}

/// Puts chunks back together into frames.
#[derive(Default)]
pub struct Reassembler {
    buf: Vec<u8>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one chunk; returns the frames it completed (zero, one or, if
    /// chunks were coalesced, several).
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() < 2 + len {
                break;
            }
            out.push(self.buf[2..2 + len].to_vec());
            self.buf.drain(..2 + len);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_reassemble_for_every_chunk_size() {
        let frame: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        for size in [1, 2, 3, 20, 185, 509, 1002, 5000] {
            let chunks = chunk_frame(&frame, size).unwrap();
            assert!(chunks.iter().all(|c| c.len() <= size));
            let mut r = Reassembler::new();
            let mut got = Vec::new();
            for c in &chunks {
                got.extend(r.push(c));
            }
            assert_eq!(got, vec![frame.clone()], "size {size}");
        }
    }

    #[test]
    fn coalesced_and_empty_frames() {
        let mut stream = Vec::new();
        for f in [&b"ab"[..], &b""[..], &b"cde"[..]] {
            for c in chunk_frame(f, 100).unwrap() {
                stream.extend(c);
            }
        }
        let got = Reassembler::new().push(&stream);
        assert_eq!(got, vec![b"ab".to_vec(), b"".to_vec(), b"cde".to_vec()]);
    }

    #[test]
    fn max_frame_and_over() {
        let f = vec![9u8; MAX_FRAME];
        let mut r = Reassembler::new();
        let got: Vec<_> = chunk_frame(&f, 512)
            .unwrap()
            .iter()
            .flat_map(|c| r.push(c))
            .collect();
        assert_eq!(got, vec![f]);
        assert!(chunk_frame(&vec![0; MAX_FRAME + 1], 20).is_err());
    }
}
