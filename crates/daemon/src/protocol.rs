//! The wire protocol: frames of a `u32` little-endian length and that many
//! bytes of JSON, at most 1 MiB each.
//!
//! Two kinds of peer speak it, told apart by the first frame, the [`Hello`]:
//!
//! * a **client** (the `vahta` command, later the hook and the MCP server),
//!   which sends [`ClientRequest`]s and receives [`ClientReply`]s. These types
//!   have no field for a secret value or the password, and every one refuses
//!   unknown fields, so a message carrying one is not a message;
//! * a **surface** (the prompt window), authenticated by a one-time token the
//!   daemon issued for exactly one request. Only this connection carries the
//!   password, a typed value or a value to show.
//!
//! The reader refuses a length over the limit before allocating for it, a frame
//! cut short, and anything that is not the JSON the type describes.

use std::fmt;
use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Bumped when a message changes shape. A daemon and a client that disagree do
/// not talk past the hello.
pub const PROTOCOL: u32 = 1;

/// The largest frame, in either direction.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug)]
pub enum ProtocolError {
    Io(io::Error),
    /// A frame announced more than [`MAX_FRAME`] bytes.
    TooLarge(usize),
    /// The stream ended inside a frame.
    Truncated,
    /// A whole frame that is not the message expected. Never quotes the frame.
    Garbage(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Io(e) => write!(f, "connection error: {e}"),
            ProtocolError::TooLarge(n) => write!(f, "a frame of {n} bytes is over the 1 MiB limit"),
            ProtocolError::Truncated => f.write_str("the connection ended inside a frame"),
            ProtocolError::Garbage(why) => write!(f, "not a valid message: {why}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<io::Error> for ProtocolError {
    fn from(e: io::Error) -> Self {
        ProtocolError::Io(e)
    }
}

/// Write one frame.
pub fn write_frame<T: Serialize>(w: &mut impl Write, msg: &T) -> Result<(), ProtocolError> {
    // Serialised into a buffer that is wiped when it goes: a surface frame may
    // hold the password.
    let body =
        Zeroizing::new(serde_json::to_vec(msg).map_err(|e| ProtocolError::Garbage(e.to_string()))?);
    if body.len() > MAX_FRAME {
        return Err(ProtocolError::TooLarge(body.len()));
    }
    let len = u32::try_from(body.len()).map_err(|_| ProtocolError::TooLarge(body.len()))?;
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

/// Read one frame. `Ok(None)` is the peer closing the connection between
/// frames, which is how every conversation ends.
pub fn read_frame<T: DeserializeOwned>(r: &mut impl Read) -> Result<Option<T>, ProtocolError> {
    let mut len_bytes = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut len_bytes[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(ProtocolError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME {
        return Err(ProtocolError::TooLarge(len));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut body).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => ProtocolError::Truncated,
        _ => ProtocolError::Io(e),
    })?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| ProtocolError::Garbage(e.classify_text()))
}

trait ClassifyText {
    fn classify_text(&self) -> String;
}

impl ClassifyText for serde_json::Error {
    /// What kind of mistake, without the offending text: an error message from
    /// serde can quote the field, and a field may hold a secret.
    fn classify_text(&self) -> String {
        use serde_json::error::Category;
        match self.classify() {
            Category::Io => "read error".to_string(),
            Category::Syntax => "malformed JSON".to_string(),
            Category::Data => "unexpected shape or an unknown field".to_string(),
            Category::Eof => "truncated JSON".to_string(),
        }
    }
}

// --- The hello ----------------------------------------------------------------

/// The first frame on every connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol: u32,
    pub version: String,
    pub kind: HelloKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HelloKind {
    Client,
    /// The prompt window, with the token the daemon gave it for one request.
    Surface {
        token: String,
    },
}

/// The daemon's answer to a hello. On `ok: false` the connection is closed
/// after it and `error` says why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloReply {
    pub ok: bool,
    pub protocol: u32,
    pub version: String,
    pub pid: u32,
    /// Live sessions, so a client facing an older daemon can tell whether
    /// replacing it would end any.
    pub sessions: usize,
    pub error: Option<String>,
}

// --- Client messages ------------------------------------------------------------------

/// What a client may ask. No variant has a field for a value or a password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientRequest {
    /// How the daemon is doing.
    // Struct variants, not unit ones: serde enforces `deny_unknown_fields`
    // for the fields of a struct variant but lets a unit variant of an
    // internally tagged enum ignore extra fields.
    Status {},
    /// End the daemon, and with it every session.
    Stop {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientReply {
    Ok,
    Status(StatusInfo),
    /// The request could not be carried out; `message` says why, never a value.
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusInfo {
    pub version: String,
    pub pid: u32,
    pub sessions: usize,
    pub connections: usize,
    pub uptime_secs: u64,
    pub runtime_dir: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn a_message_round_trips() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &ClientRequest::Status {}).unwrap();
        let back: Option<ClientRequest> = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, Some(ClientRequest::Status {}));
    }

    #[test]
    fn a_closed_stream_between_frames_is_not_an_error() {
        let back: Option<ClientRequest> = read_frame(&mut Cursor::new(Vec::new())).unwrap();
        assert_eq!(back, None);
    }

    #[test]
    fn a_frame_over_the_limit_is_refused_before_it_is_read() {
        let mut bytes = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        let r: Result<Option<ClientRequest>, _> = read_frame(&mut Cursor::new(bytes));
        assert!(matches!(r, Err(ProtocolError::TooLarge(n)) if n == MAX_FRAME + 1));
        // The writer refuses too.
        let big = ClientReply::Error {
            message: "x".repeat(MAX_FRAME),
        };
        assert!(matches!(
            write_frame(&mut Vec::new(), &big),
            Err(ProtocolError::TooLarge(_))
        ));
    }

    #[test]
    fn truncated_frames_are_refused() {
        // Cut inside the length.
        let r: Result<Option<ClientRequest>, _> = read_frame(&mut Cursor::new(vec![5, 0]));
        assert!(matches!(r, Err(ProtocolError::Truncated)));
        // Cut inside the body.
        let mut f = frame(br#"{"op":"status"}"#);
        f.truncate(f.len() - 3);
        let r: Result<Option<ClientRequest>, _> = read_frame(&mut Cursor::new(f));
        assert!(matches!(r, Err(ProtocolError::Truncated)));
    }

    #[test]
    fn garbage_is_refused_without_quoting_it() {
        for body in [
            &b"not json"[..],
            br#"{"op":"nonsense"}"#,
            br#"[1,2,3]"#,
            b"\xff\xfe",
        ] {
            let r: Result<Option<ClientRequest>, _> = read_frame(&mut Cursor::new(frame(body)));
            assert!(matches!(r, Err(ProtocolError::Garbage(_))), "{body:?}");
        }
    }

    #[test]
    fn a_client_message_carrying_a_value_or_a_password_is_not_a_message() {
        for body in [
            r#"{"op":"status","value":"fake-one"}"#,
            r#"{"op":"status","password":"correct horse"}"#,
            r#"{"op":"stop","secret":"fake-one"}"#,
        ] {
            let r: Result<Option<ClientRequest>, _> =
                read_frame(&mut Cursor::new(frame(body.as_bytes())));
            let Err(ProtocolError::Garbage(msg)) = r else {
                panic!("accepted {body}")
            };
            // The refusal does not echo what was in the message.
            assert!(!msg.contains("fake-one") && !msg.contains("correct horse"));
        }
        let hello = r#"{"protocol":1,"version":"x","kind":{"type":"client"},"password":"p"}"#;
        let r: Result<Option<Hello>, _> = read_frame(&mut Cursor::new(frame(hello.as_bytes())));
        assert!(r.is_err());
    }

    #[test]
    fn a_surface_hello_carries_its_token() {
        let mut buf = Vec::new();
        let h = Hello {
            protocol: PROTOCOL,
            version: "v".into(),
            kind: HelloKind::Surface {
                token: "abc".into(),
            },
        };
        write_frame(&mut buf, &h).unwrap();
        let back: Option<Hello> = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, Some(h));
    }
}
