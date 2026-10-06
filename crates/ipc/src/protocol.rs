//! The wire protocol: frames of a `u32` little-endian length and that many
//! bytes of JSON, at most 1 MiB each.
//!
//! Two kinds of peer speak it, told apart by the first frame, the [`Hello`]:
//!
//! * a **client** (the `vahta` command, the hook, later the MCP server),
//!   which sends [`ClientRequest`]s and receives [`ClientReply`]s. These types
//!   have no field for a secret value or the password, and every one refuses
//!   unknown fields, so a message carrying one is not a message. Two
//!   deliberate exceptions, both about a tool's output rather than the vault:
//!   the hook sends the output it already holds ([`ClientRequest::OutputScan`])
//!   so the daemon can find the values it knows in it, and after the person
//!   says yes in a window, `vahta output allow` receives that output back
//!   ([`ClientReply::OutputReleased`]). A reply to the hook never carries a
//!   value: only where the values are;
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
pub const PROTOCOL: u32 = 2;

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

/// A secret's tier, as a client names it. The vault has its own type; this one
/// mirrors it on the wire (same spelling) so a client needs no vault crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// A session may hold it.
    Session,
    /// It needs the password every time.
    EachUse,
}

/// Which file a project's secrets are imported from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportSource {
    /// A ka vault; the window also asks for the ka password.
    Ka { path: String },
    /// A `.env` file, read by the daemon.
    Dotenv { path: String },
}

/// How long a session lasts, as the client asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "for", rename_all = "snake_case", deny_unknown_fields)]
pub enum DurationSpec {
    /// `session_minutes` from the config.
    Default {},
    Secs {
        secs: u64,
    },
    /// Until revoked (or until its anchor is gone).
    Forever {},
}

/// What a client may ask. No variant has a field for a value or a password:
/// the person types those in the prompt window, which is not this connection.
/// `cwd` is where the command was run, from which the daemon finds the
/// project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientRequest {
    // Struct variants, not unit ones: serde enforces `deny_unknown_fields`
    // for the fields of a struct variant but lets a unit variant of an
    // internally tagged enum ignore extra fields.
    /// How the daemon is doing.
    Status {},
    /// End the daemon, and with it every session.
    Stop {},
    /// Create the project's vault in `cwd`.
    Init {
        cwd: String,
    },
    /// Add or replace a secret; its value is typed in the window.
    Set {
        cwd: String,
        name: String,
        tier: Tier,
        /// A file name hint: the secret is a file, not an environment variable.
        file: Option<String>,
    },
    Remove {
        cwd: String,
        name: String,
    },
    Import {
        cwd: String,
        source: ImportSource,
    },
    /// Show a value in the window.
    Reveal {
        cwd: String,
        name: String,
    },
    /// Put a value on the clipboard for a short time.
    Copy {
        cwd: String,
        name: String,
    },
    /// Open a session: the person types the password in the window, and
    /// `vahta run` from the caller's process tree then needs no window. With no
    /// `names`, every session-tier secret; with names, only those.
    Unlock {
        cwd: String,
        names: Option<Vec<String>>,
        duration: DurationSpec,
        /// A description from the agent; sanitised and shown as unverified.
        label: Option<String>,
    },
    /// End this project's sessions, or all of them. No password.
    Lock {
        cwd: String,
        all: bool,
    },
    /// List the sessions.
    Sessions {},
    /// End one session and every session below it. No password.
    SessionKill {
        id: String,
    },
    /// Run a command with secrets in its environment. The reply is
    /// `RunStarted`, after which the connection carries [`RunInput`] frames
    /// from the client and [`RunOutput`] frames from the daemon until the
    /// command ends.
    Run {
        cwd: String,
        argv: Vec<String>,
        /// The caller's environment, from which the command's is made.
        env: Vec<(String, String)>,
        /// With no names, every name in `vahta.toml` that the vault holds.
        names: Option<Vec<String>>,
        /// `(NAME, VARIABLE)`: put NAME in this variable instead.
        renames: Vec<(String, String)>,
        label: Option<String>,
    },
    /// The hook, after a tool ran and before its output reaches the model:
    /// `texts` are the strings of that output (every one, in order), and
    /// `spans` what the hook's own detector would cut. The daemon adds the
    /// values it holds for the caller's agent, drops what the person has
    /// already let through, and answers with [`ClientReply::OutputSpans`].
    /// `possible` names the kinds the detector found too weak to cut, for the
    /// journal only.
    OutputScan {
        cwd: String,
        tool: String,
        texts: Vec<String>,
        spans: Vec<OutputSpan>,
        possible: Vec<String>,
    },
    /// Ask the person to let the agent see what was cut out of a tool's
    /// output kept under `reference`. Only the agent whose hook made the
    /// reference may ask. `reason` is the agent's, shown as unverified.
    OutputAllow {
        reference: String,
        reason: Option<String>,
    },
    /// Narrow the caller's session for a sub-agent. The child session is
    /// anchored to the calling process, which then runs the sub-agent; the
    /// session ends when it exits. A scope that is not a subset of the
    /// parent's, or a later deadline, is refused without a window.
    Delegate {
        cwd: String,
        names: Vec<String>,
        /// `Default` is as long as the parent has.
        duration: DurationSpec,
        label: Option<String>,
    },
}

/// One value to cut out of a tool's output: `text` is which of the output's
/// strings, `start..end` the byte range in it, and `label` what replaces it:
/// a secret's name when the daemon knew the value, else the detector's kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpan {
    pub text: usize,
    pub start: usize,
    pub end: usize,
    pub label: String,
}

/// What the client sends while a command runs: the command's input, and the
/// signals its user sends. Input is the caller's own data, relayed as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunInput {
    /// Bytes for the command's standard input, in base64.
    Stdin {
        data: String,
    },
    /// The caller's standard input has ended.
    StdinEof {},
    Signal {
        signal: RunSignal,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunSignal {
    Interrupt,
    Terminate,
    Hangup,
}

/// What the daemon sends while a command runs: its output with the secret
/// values already taken out, and how it ended. The bytes are scrubbed bytes
/// only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunOutput {
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    /// The command ended: its exit code, or 128 plus the signal that ended it.
    Exit {
        code: i32,
        signal: Option<i32>,
    },
    /// The command could not be started or kept running.
    Failed {
        message: String,
    },
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, for bytes inside a JSON frame.
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The inverse of [`b64_encode`]; `None` for anything that is not canonical
/// padded base64.
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| B64.iter().position(|b| *b == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (i, quad) in bytes.chunks(4).enumerate() {
        let last = (i + 1) * 4 == bytes.len();
        let pad = quad.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, c) in quad.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { value(*c)? };
            n = (n << 6) | v;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// A session as a client may see it: never a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    pub id: String,
    /// Whose daemon holds it: `local` until there is a cloud.
    pub tenant: String,
    pub parent: Option<String>,
    pub project: String,
    pub vault: String,
    pub names: Vec<String>,
    /// Always `runner`: a session runs commands and does nothing else.
    pub role: String,
    pub anchor_exe: String,
    pub anchor_pid: u32,
    /// Seconds left, or `None` for one that lasts until revoked.
    pub remaining_secs: Option<u64>,
    pub uses: u64,
    pub label: Option<String>,
}

/// Why a request was refused outright, before any window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// A name that is not in the vault.
    UnknownName,
    /// An each-use secret, which no session may hold.
    EachUse,
    /// A name the caller's session does not cover.
    OutOfScope,
    /// A delegated session asked for more than its parent has.
    NotASubset,
    /// A delegated session asked for longer than its parent has.
    LaterDeadline,
    /// There is no vault, or no project.
    NoVault,
    /// Nothing to act on (no names).
    NothingToDo,
    /// Already there (a vault, a name).
    Exists,
    /// The caller is not something a session can be anchored to.
    NoAnchor,
    /// The session no longer opens what it covered: a secret was changed,
    /// removed or re-tiered since it was opened.
    Stale,
    /// There is no session to narrow.
    NoSession,
    /// No tool output is kept under that reference for this agent: it was
    /// never there, its time ran out, or another agent's hook made it.
    UnknownOutput,
}

/// One name in a refusal and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameIssue {
    pub name: String,
    pub why: RefusalKind,
}

/// A structured refusal: enough for the caller, a mistaken agent included, to
/// rebuild the command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    pub kind: RefusalKind,
    pub message: String,
    pub names: Vec<NameIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientReply {
    Ok {},
    /// A `Run` was accepted and the command is running; what follows on this
    /// connection is `RunInput` and `RunOutput`.
    RunStarted {},
    Status(StatusInfo),
    /// A session was opened.
    /// Boxed: it is by far the largest reply.
    Session(Box<SessionInfo>),
    Sessions {
        sessions: Vec<SessionInfo>,
    },
    /// The request was carried out; `message` is for the person, and never a
    /// value.
    Done {
        message: String,
    },
    /// Refused before any window opened.
    Refused(Refusal),
    /// The window was closed, cancelled or timed out.
    Cancelled {
        message: String,
    },
    /// The request could not be carried out; `message` says why, never a value.
    Error {
        message: String,
    },
    /// The answer to an `OutputScan`: what to cut, and the reference under
    /// which the daemon keeps the original for a while, so the agent can ask
    /// the person for it (`vahta output allow <reference>`). No reference when
    /// nothing is cut, or the original could not be kept.
    OutputSpans {
        spans: Vec<OutputSpan>,
        reference: Option<String>,
    },
    /// The person agreed to show the agent a tool's output as it was: `text`
    /// is that output, its non-empty strings joined by newlines. The one reply that
    /// carries what may be a secret value, sent only after a "Show to the
    /// agent" in a window, to the agent that asked.
    OutputReleased {
        text: String,
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

// --- Surface messages --------------------------------------------------------------------

/// A string that is a password, a typed value or a value to show: zeroed when
/// dropped, redacted in `Debug`, with no `Display`. It appears only in surface
/// messages, never in a client's.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(text: String) -> Secret {
        Secret(Zeroizing::new(text))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Secret, D::Error> {
        String::deserialize(d).map(Secret::new)
    }
}

/// What a window shows the person above its question: what they are approving,
/// as Vahta renders it. The lines are Vahta's own (project, vault, names,
/// duration, anchor); `agent_note` is the one thing an agent wrote, shown as
/// such.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Panel {
    pub title: String,
    pub lines: Vec<String>,
    pub warning: Option<String>,
    /// A description from the agent, already sanitised, to be shown marked as
    /// "from the agent, not verified".
    pub agent_note: Option<String>,
}

/// The daemon's questions to the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ask", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfaceRequest {
    /// A password, typed hidden. With `confirm` it is asked twice and only a
    /// matching pair is sent back.
    Password {
        panel: Panel,
        prompt: String,
        confirm: bool,
    },
    /// A value to store, typed hidden, and asked twice with `confirm`.
    Value {
        panel: Panel,
        prompt: String,
        confirm: bool,
    },
    /// Yes or no, no secret. `timeout_secs` is how long to wait.
    Confirm {
        panel: Panel,
        question: String,
        timeout_secs: Option<u64>,
    },
    /// One of `options`, no secret; answered with its index.
    Choose {
        panel: Panel,
        question: String,
        options: Vec<String>,
    },
    /// A line of plain text, typed in the open: a name, never a value.
    Text { panel: Panel, prompt: String },
    /// Show something secret until a key is pressed, or `seconds` pass.
    Show {
        panel: Panel,
        what: String,
        value: Secret,
        seconds: Option<u32>,
        /// Ask for an explicit acknowledgement, as for a recovery key.
        acknowledge: bool,
    },
    /// The conversation is over; the window may close after the message.
    Close { message: Option<String> },
}

/// The window's answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfaceAnswer {
    Secret {
        value: Secret,
    },
    Yes {},
    No {},
    /// A `Show` was seen (acknowledged, or its time ran out).
    Done {},
    Cancel {},
    /// The index of the option chosen.
    Choice {
        index: usize,
    },
    /// The line typed for a `Text`.
    Text {
        value: String,
    },
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
    fn no_vault_request_has_a_place_for_a_value_or_a_password() {
        let good = r#"{"op":"set","cwd":"/p","name":"A","tier":"Session","file":null}"#;
        let ok: Result<Option<ClientRequest>, _> =
            read_frame(&mut Cursor::new(frame(good.as_bytes())));
        assert!(matches!(ok, Ok(Some(ClientRequest::Set { .. }))));
        for extra in ["value", "secret", "password", "typed", "plaintext"] {
            let bad = format!(
                r#"{{"op":"set","cwd":"/p","name":"A","tier":"Session","file":null,"{extra}":"fake-one"}}"#
            );
            let r: Result<Option<ClientRequest>, _> =
                read_frame(&mut Cursor::new(frame(bad.as_bytes())));
            assert!(r.is_err(), "{extra} was accepted");
        }
        // Nor does any reply: a reply has no field that could carry one.
        let reply = r#"{"reply":"done","message":"saved","value":"fake-one"}"#;
        let r: Result<Option<ClientReply>, _> =
            read_frame(&mut Cursor::new(frame(reply.as_bytes())));
        assert!(r.is_err());
    }

    #[test]
    fn a_secret_is_redacted_when_printed_and_travels_only_in_surface_messages() {
        let s = Secret::new("fake-one".to_string());
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        let answer = SurfaceAnswer::Secret { value: s };
        assert!(!format!("{answer:?}").contains("fake-one"));
        let mut buf = Vec::new();
        write_frame(&mut buf, &answer).unwrap();
        let back: Option<SurfaceAnswer> = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, Some(answer));
    }

    #[test]
    fn base64_round_trips_and_refuses_what_is_not_base64() {
        for bytes in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0, 255, 1, 128, 7],
        ] {
            assert_eq!(b64_decode(&b64_encode(bytes)).unwrap(), bytes);
        }
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(b64_decode(&b64_encode(&all)).unwrap(), all);
        for bad in ["Zm9", "Zm9v!", "Zg=a", "=Zm9", "Z===", "Zm9vYg==Zm9v"] {
            assert!(b64_decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn run_messages_refuse_unknown_fields_and_carry_only_bytes() {
        let bad = r#"{"msg":"stdout","data":"","value":"fake-one"}"#;
        let r: Result<Option<RunOutput>, _> = read_frame(&mut Cursor::new(frame(bad.as_bytes())));
        assert!(r.is_err());
        let bad = r#"{"msg":"signal","signal":"interrupt","password":"x"}"#;
        let r: Result<Option<RunInput>, _> = read_frame(&mut Cursor::new(frame(bad.as_bytes())));
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
