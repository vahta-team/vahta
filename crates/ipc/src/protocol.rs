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
pub const PROTOCOL: u32 = 17;

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

impl ClientRequest {
    /// The directory the daemon must verify against the kernel before serving
    /// the request: the `cwd` of every request that carries one, except the
    /// hook's (`CheckRun`, `CheckHttp`, `ToolCheck`, `OutputScan`, `HookReport`).
    /// The hook is not the shell whose directory it reports, and what it sends
    /// only answers a question or feeds the journal and the alarm.
    pub fn cwd_to_verify(&self) -> Option<&str> {
        use ClientRequest::*;
        match self {
            CheckRun { .. }
            | CheckHttp { .. }
            | ToolCheck { .. }
            | OutputScan { .. }
            | HookReport { .. } => None,
            Init { cwd }
            | Add { cwd, .. }
            | Reset { cwd, .. }
            | Remove { cwd, .. }
            | SetTier { cwd, .. }
            | Import { cwd, .. }
            | Reveal { cwd, .. }
            | Copy { cwd, .. }
            | Unlock { cwd, .. }
            | Lock { cwd, .. }
            | Run { cwd, .. }
            | Http { cwd, .. }
            | Bind { cwd, .. }
            | Delegate { cwd, .. }
            | HooksPause { cwd, .. }
            | Remote { cwd, .. }
            | DevicesList { cwd }
            | DevicesPair { cwd, .. }
            | DevicesExtend { cwd, .. }
            | DevicesRevoke { cwd, .. }
            | DevicesLost { cwd, .. }
            | Recover { cwd }
            | Members { cwd, .. }
            | UnlockRole { cwd, .. }
            | DelegateRole { cwd, .. }
            | Role { cwd, .. } => Some(cwd),
            Connector {
                cmd: ConnectorCmd::Run { cwd, .. },
            } => Some(cwd),
            _ => None,
        }
    }
}

/// The rules a client proposes for a secret it adds. All of it is text: the
/// daemon parses and resolves it and the person approves what comes out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleArgs {
    /// A category id (`payment`, `server`, `ordinary`, `database`, `publish`,
    /// `local-only`); `None` lets the daemon suggest one from the value and
    /// the name.
    pub category: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    /// Directories (`PATH`, optionally `:ro` or `:rw`).
    pub dirs: Vec<String>,
    /// `none`, `app` or `hosts:H[,H...]`; `None` is the category's default.
    pub net: Option<String>,
    /// Why, for the window; shown marked as unverified.
    pub reason: Option<String>,
    /// The caller's `PATH`, to resolve the programs of the rules.
    pub path: Option<String>,
    /// The harnesses (`claude`, `codex`, `cursor`) that may launch the server
    /// that uses the secret; only for a connectors vault.
    pub harnesses: Vec<String>,
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
    /// Add a new secret; its value is typed in the window. Refused if the
    /// name is already in the vault. The rules it will have are proposed in
    /// `rules`, shown in the same window after the value, and stored in the
    /// same save.
    Add {
        cwd: String,
        name: String,
        /// `None`: the category's tier.
        tier: Option<Tier>,
        /// A file name hint: the secret is a file, not an environment variable.
        file: Option<String>,
        #[serde(default)]
        rules: RuleArgs,
    },
    /// Replace the value of a secret the vault has; the new value is typed in
    /// the window. Refused if the name is not there. `None` keeps the tier
    /// or the kind the secret has.
    Reset {
        cwd: String,
        name: String,
        tier: Option<Tier>,
        file: Option<String>,
    },
    Remove {
        cwd: String,
        name: String,
    },
    /// `vahta tier NAME session|each-use`: change only the tier; the value is
    /// not typed again.
    SetTier {
        cwd: String,
        name: String,
        tier: Tier,
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
        /// `--vault DIR`: use the vault whose project root is `DIR` from this
        /// directory (remote use; see `docs/daemon.md`). `None`: the vault of
        /// the project holding `cwd`, as always.
        #[serde(default)]
        vault: Option<String>,
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
        /// `--ask`: if a secret's command rules do not allow this command,
        /// ask the person (a window) instead of refusing.
        ask: bool,
        /// `--reason`: why, for that window; shown marked as unverified.
        reason: Option<String>,
        /// `--vault DIR`: use the vault whose project root is `DIR` from this
        /// directory (remote use; see `docs/daemon.md`). `None`: the vault of
        /// the project holding `cwd`, as always.
        #[serde(default)]
        vault: Option<String>,
    },
    /// `vahta http`: one HTTPS request with secrets put in headers or query
    /// values, made by the daemon. The reply is `HttpResponse`, after which
    /// the connection carries [`RunOutput::Stdout`] frames with the body and
    /// one [`RunOutput::Exit`] (or [`RunOutput::Failed`] if the body could not
    /// be sent). The client never holds a value.
    Http {
        cwd: String,
        /// Upper-case; `GET`, `POST`...
        method: String,
        /// Must be `https://`, with no `{NAME}` in it.
        url: String,
        /// The secrets that may be used (`--secret`); each must appear in a
        /// header or query value.
        names: Vec<String>,
        /// `(name, value template)`: `{NAME}` in a value is replaced by the
        /// secret.
        headers: Vec<(String, String)>,
        /// `(key, value template)`, appended to the URL's query, encoded.
        query: Vec<(String, String)>,
        /// The body, base64. Never has a secret put in it.
        body: Option<String>,
        /// Cap on the response body kept, in bytes.
        max_response: Option<u64>,
        timeout_secs: Option<u32>,
        label: Option<String>,
        /// `--vault DIR`: use the vault whose project root is `DIR` from this
        /// directory (remote use; see `docs/daemon.md`). `None`: the vault of
        /// the project holding `cwd`, as always.
        #[serde(default)]
        vault: Option<String>,
    },
    /// Propose command rules for a secret (or, with no name, approve what
    /// `vahta.toml` says for every name). Replies `Done`, `Refused` or
    /// `Cancelled`; nothing changes without a window and the password.
    Bind {
        cwd: String,
        /// `None`: approve `vahta.toml` as written.
        name: Option<String>,
        /// Rule texts (see the daemon docs); with `name`, they replace the
        /// secret's approved rules.
        allow: Vec<String>,
        deny: Vec<String>,
        /// Remove the secret's rules.
        clear: bool,
        /// Why, for the window; shown marked as unverified.
        reason: Option<String>,
        /// The caller's `PATH`, to resolve the programs of the rules.
        path: Option<String>,
        /// The rule set's category id; with `name` and no other rule-set
        /// field, the rest of the approved rules is kept.
        #[serde(default)]
        category: Option<String>,
        /// Directories (`PATH`, optionally `:ro` or `:rw`).
        #[serde(default)]
        dirs: Vec<String>,
        /// `none`, `app` or `hosts:H[,H...]`.
        #[serde(default)]
        net: Option<String>,
        /// Absolute project roots the secret may be used from, outside the
        /// vault's own project (`--from`). `None` keeps what the secret has;
        /// `Some` of an empty list takes the roots away (`--no-from`). With
        /// `name` and nothing but this, the rest of the approved rules is kept.
        #[serde(default)]
        from: Option<Vec<String>>,
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
    /// The hook in observe mode (`hook_output = "observe"`): it changed
    /// nothing, and tells the daemon what it saw, for the journal. Kinds and
    /// counts, never a value.
    OutputObserved {
        tool: String,
        kinds: Vec<String>,
        likely: usize,
        possible: usize,
    },
    /// The hook refused (or, in observe mode, would have refused) something an
    /// agent tried, and tells the daemon what kind of thing it was, for the
    /// journal and the injection alarm. Fire and forget: the hook does not
    /// wait for the answer beyond its usual limit, and writes the report to
    /// the spool (`spool.rs`) when no daemon runs. Never a value, never the
    /// command text: a category, a rule id, a file path.
    HookReport {
        /// The harness's own session id, when its payload has one.
        session: Option<String>,
        harness: String,
        cwd: String,
        signal: Signal,
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
        /// `--vault DIR`: use the vault whose project root is `DIR` from this
        /// directory (remote use; see `docs/daemon.md`). `None`: the vault of
        /// the project holding `cwd`, as always.
        #[serde(default)]
        vault: Option<String>,
    },
    /// The hook asks, before a tool call runs, whether its text carries a
    /// value the daemon holds for this agent, in any of the forms it knows
    /// (raw, base64, hex, URL-encoded, reversed). The reply is `Ok` or
    /// `ToolDeny`. The text is the agent's and travels only to the daemon, on
    /// this user's socket; the daemon never journals it. `session` is the
    /// harness's own session id, when its payload has one.
    ToolCheck {
        session: Option<String>,
        cwd: String,
        text: String,
    },
    /// The hook asks, before a `vahta run` runs, whether the command inside it
    /// passes every named secret's own rules, so the harness need not ask the
    /// person. No window, no password, no session, nothing journaled: the vault
    /// is only peeked at. `names` empty means the project's `vahta.toml` list,
    /// as for `Run`; `path` is the caller's `PATH`, which finds the program.
    /// The reply is `Allowed` or `NoOpinion`, never a refusal: the run itself
    /// says why it will not go.
    CheckRun {
        cwd: String,
        argv: Vec<String>,
        names: Vec<String>,
        path: Option<String>,
        /// `--vault DIR`: as for `Run`; the hook asks about a run that uses the vault whose project root is `DIR` from this
        /// directory (remote use; see `docs/daemon.md`). `None`: the vault of
        /// the project holding `cwd`, as always.
        #[serde(default)]
        vault: Option<String>,
    },
    /// The same question for a `vahta http`: would a request to `url` with
    /// these secrets pass their approved host lists? Replies `Allowed` only if
    /// every name is a session-tier secret whose rule set lists a host that
    /// matches `url`; anything else is `NoOpinion`. No window, no journal.
    CheckHttp {
        cwd: String,
        url: String,
        names: Vec<String>,
        /// `--vault DIR`: use the vault whose project root is `DIR` from this
        /// directory (remote use; see `docs/daemon.md`). `None`: the vault of
        /// the project holding `cwd`, as always.
        #[serde(default)]
        vault: Option<String>,
    },
    /// `vahta hooks pause`: take Vahta's hook entries out of these harnesses
    /// (all that have them, when empty) for `secs` (at most 8 hours). A window
    /// asks the person, with the password; `reason` is the caller's, shown as
    /// unverified. The watchdog puts the entries back when the time is up.
    HooksPause {
        cwd: String,
        harnesses: Vec<String>,
        secs: u64,
        reason: Option<String>,
    },
    /// `vahta hooks resume`: put the entries back now (all harnesses, when
    /// empty). No password: it only restores protection.
    HooksResume {
        harnesses: Vec<String>,
    },
    /// The watchdog found Vahta's hooks tampered with and asks the person,
    /// through the daemon's window, what to do. Replies
    /// [`ClientReply::GuardChoice`].
    GuardAsk {
        harness: String,
        file: String,
        what: String,
    },
    /// `vahta remote on|off`: turn the vault's opt-in to be used from other
    /// projects on or off. A window shows the vault and asks for the master
    /// password; nothing changes without it. `on = None` only reports.
    Remote {
        cwd: String,
        on: Option<bool>,
    },
    /// `vahta devices`: the phones this vault has paired. No password: the
    /// list is in the signed plain part of the file.
    DevicesList {
        cwd: String,
    },
    /// `vahta devices pair NAME --for DURATION`: pair a phone. The window asks
    /// for the master password; the phone then pairs over the link.
    DevicesPair {
        cwd: String,
        name: String,
        /// How long the phone's access lasts.
        secs: u64,
    },
    /// `vahta devices extend ID --for DURATION`: the master password gives a
    /// device access for `secs` from now.
    DevicesExtend {
        cwd: String,
        id: String,
        secs: u64,
    },
    /// `vahta devices revoke ID`: remove a device and its slot.
    DevicesRevoke {
        cwd: String,
        id: String,
    },
    /// `vahta devices lost ID`: revoke, and change the vault key so that a
    /// copy of the vault file that the phone could open is of no use to
    /// whoever has it. Shows a new recovery key.
    DevicesLost {
        cwd: String,
        id: String,
    },
    /// `vahta recover`: the password is forgotten; the recovery key opens the
    /// vault and a new password is chosen.
    Recover {
        cwd: String,
    },
    /// The watchdog tells the daemon what it did, for the journal.
    GuardNote {
        harness: String,
        file: String,
        event: GuardEvent,
    },
    /// The team commands (`id`, `members`, `grant`, `revoke`, `share`,
    /// `join`); see [`crate::members::MemberOp`].
    Members {
        cwd: String,
        what: crate::members::MemberOp,
    },
    /// `vahta unlock --role NAME`: open a session limited to an approved agent
    /// role. The window names the role; the session covers the role's secrets
    /// (or the `names` among them) and allows only what the role allows.
    UnlockRole {
        cwd: String,
        role: String,
        names: Option<Vec<String>>,
        duration: DurationSpec,
        label: Option<String>,
        #[serde(default)]
        vault: Option<String>,
    },
    /// `vahta delegate --role NAME`: narrow the caller's session to an
    /// approved agent role. With no `names`, the scope is the role's secrets
    /// the caller's session covers; the deadline is the shortest of the
    /// requested one, the role's longest and the parent's. Refused without a
    /// window when it would widen anything.
    DelegateRole {
        cwd: String,
        role: String,
        names: Vec<String>,
        duration: DurationSpec,
        label: Option<String>,
        #[serde(default)]
        vault: Option<String>,
    },
    /// `vahta role`: propose an agent role from `vahta.toml` for the person's
    /// approval, or with `remove` take one away. A role wider than one of its
    /// secrets' approved rules is refused before any window.
    Role {
        cwd: String,
        name: Option<String>,
        remove: bool,
        reason: Option<String>,
        /// The caller's `PATH`, where programs named in `allow` are looked up.
        path: Option<String>,
    },
    /// The connectors vault (`--connector`): one per user, in Vahta's own data
    /// directory, never found by a working directory. See [`ConnectorCmd`].
    Connector {
        cmd: ConnectorCmd,
    },
}

/// What `--connector` asks of the connectors vault. The vault is not looked up
/// from a directory: there is one, and these are the only requests that reach
/// it. As everywhere, no field holds a value or a password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectorCmd {
    /// Create the vault.
    Init {},
    /// Add a secret; its value is typed in the window. The rules and the
    /// harnesses are shown after the value and stored in the same save.
    Add {
        name: String,
        tier: Option<Tier>,
        rules: RuleArgs,
    },
    Remove {
        name: String,
    },
    /// Propose the rules and the harnesses of a secret (the person approves).
    Bind {
        name: String,
        harnesses: Vec<String>,
        allow: Vec<String>,
        deny: Vec<String>,
        clear: bool,
        reason: Option<String>,
        path: Option<String>,
        category: Option<String>,
        dirs: Vec<String>,
        net: Option<String>,
    },
    /// Open the connectors session: the password once, then
    /// `vahta run --connector` needs no window until it ends.
    Unlock {
        duration: DurationSpec,
        label: Option<String>,
    },
    /// Run the server of one connector. The reply is `RunStarted`, then the
    /// connection carries [`RunInput`] and [`RunOutput`] as for `Run`.
    Run {
        /// Where the client is; checked against the kernel.
        cwd: String,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        name: String,
        /// `(secret, variable)`: the server reads its key from a variable that
        /// is not the secret's name.
        #[serde(default)]
        renames: Vec<(String, String)>,
        label: Option<String>,
    },
}

/// A launch of a connector's server that was refused, as `vahta status`
/// shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorRefusal {
    pub name: String,
    /// Unix seconds.
    pub at: u64,
    pub kind: RefusalKind,
    /// What the person does about it.
    pub hint: String,
}

/// What the person chose when the watchdog asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GuardChoice {
    /// Put the hooks back.
    Restore,
    /// Leave them off for `secs`, then put them back.
    KeepOff { secs: u64 },
    /// Stop the watchdog and its autostart for good.
    TurnOff,
}

/// What the watchdog did, as it tells the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardEvent {
    /// Put the hooks back after the person's choice, or with no answer.
    Restored,
    /// Put the hooks back because a pause ran out.
    RestoredAfterPause,
    /// Tried to put them back and could not.
    RestoreFailed,
    /// Turned itself off at the person's word.
    TurnedOff,
    /// Found tampering and could not ask (no daemon, no window).
    Unasked,
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

/// What the hook saw an agent try. Each variant is one kind of evidence the
/// daemon weighs; none carries a value or the text it was found in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case", deny_unknown_fields)]
pub enum Signal {
    /// A secret-shaped value in a tool call, refused. `category` is what the
    /// agent was told ("an API token"), `rule` the detector rule that fired
    /// (for the person only), `evasion` how the value was hidden, if it was.
    Blocked {
        category: String,
        rule: String,
        evasion: Option<Evasion>,
    },
    /// The same find in observe mode: the call was let through.
    Observed {
        category: String,
        rule: String,
        evasion: Option<Evasion>,
    },
    /// A tool call that reads, changes or names one of Vahta's own files.
    VahtaFileTouch { path: String },
    /// A command for the person only (`vahta reveal`, `copy`, `_surface`).
    AgentGuard { command: String },
    /// A change to a harness's hook settings that would weaken Vahta's hooks.
    HookTamper { file: String, what: String },
    /// A tool call carried a value Vahta holds, written as `form`. Made by
    /// the daemon when a `ToolCheck` hits; the hook never sends it.
    KnownValue { form: String },
}

impl Signal {
    /// The variant's name, as the journal records it.
    pub fn kind(&self) -> &'static str {
        match self {
            Signal::Blocked { .. } => "blocked",
            Signal::Observed { .. } => "observed",
            Signal::VahtaFileTouch { .. } => "vahta_file_touch",
            Signal::AgentGuard { .. } => "agent_guard",
            Signal::HookTamper { .. } => "hook_tamper",
            Signal::KnownValue { .. } => "known_value",
        }
    }
}

/// How a secret-shaped value was hidden from a plain look at the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evasion {
    Base64,
    /// Joined from string pieces (`'ab''cd'`, `"a" + "b"`).
    Concat,
    Hex,
    Reversed,
    /// Another encoding (URL-encoding and the like).
    Encoded,
}

impl Evasion {
    pub fn as_str(self) -> &'static str {
        match self {
            Evasion::Base64 => "base64",
            Evasion::Concat => "concatenation",
            Evasion::Hex => "hex",
            Evasion::Reversed => "reversed",
            Evasion::Encoded => "encoded",
        }
    }
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
    /// The project the session was opened from, when that is not the
    /// vault's own (remote use); the session covers only that pair.
    #[serde(default)]
    pub used_from: Option<String>,
    pub names: Vec<String>,
    /// Always `runner`: a session runs commands and does nothing else.
    pub role: String,
    pub anchor_exe: String,
    pub anchor_pid: u32,
    /// Seconds left, or `None` for one that lasts until revoked.
    pub remaining_secs: Option<u64>,
    pub uses: u64,
    pub label: Option<String>,
    /// The agent role the session is limited to, if any.
    #[serde(default)]
    pub agent_role: Option<String>,
    /// The connectors session that lasts until the machine reboots.
    #[serde(default)]
    pub until_reboot: bool,
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
    /// The secret has approved command rules and this command is not allowed by
    /// them (or is denied by them).
    CommandNotAllowed,
    /// The secret has no approved rules, so no command may use it until some
    /// are proposed (`vahta bind NAME --category ...`) and approved.
    NoRules,
    /// `vahta http`: the secret is not bound to the host the request goes to
    /// (no host list, the app's own network, or another host).
    HostNotAllowed,
    /// Remote use of a vault that does not allow it from here. Sent only once
    /// the vault has been found and has opted in; a vault that has not looks
    /// exactly like a path with no vault (`NoVault`).
    NotFromHere,
    /// The caller's session belongs to an agent role, and the role does not
    /// give this request (an action it is not for, or a command or network
    /// that the role does not allow).
    RoleForbids,
    /// A proposed role is wider than one of its secrets' approved rules.
    RoleTooWide,
    /// The role's uses are all spent.
    RoleExhausted,
    /// No such role is approved in this vault.
    UnknownRole,
    /// `vahta run --connector` whose direct parent is not one of the harnesses
    /// the connector is bound to.
    NotFromHarness,
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
        /// When the injection alarm last went off (Unix seconds), until the
        /// next unlock.
        #[serde(default)]
        alarm_at: Option<u64>,
    },
    /// An `Http` request got a response; the body follows as `RunOutput`
    /// frames. Everything here has had the values taken out.
    HttpResponse {
        status: u16,
        /// Lowercase names; credentials-carrying headers are left out.
        headers: Vec<(String, String)>,
        /// The body was cut at the size cap.
        truncated: bool,
        /// A redirect was not followed, and why.
        redirect_stopped: Option<String>,
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
    /// The answer to a `CheckRun` or `CheckHttp`: every named secret exists, is session-tier,
    /// and its approved rules allow this command.
    Allowed {},
    /// The answer to a `CheckRun` or `CheckHttp` for anything else.
    NoOpinion {},
    /// The answer to a `ToolCheck` that found a held value: the tool call
    /// must be refused. `form` is how the value was written (`base64`,
    /// `hex`, `raw`...), which the agent may be told; `name` is the secret's
    /// name, for the person only.
    ToolDeny {
        form: String,
        name: String,
    },
    /// The answer to a [`ClientRequest::GuardAsk`].
    GuardChoice {
        choice: GuardChoice,
    },
    /// The answer to [`ClientRequest::DevicesList`].
    Devices {
        devices: Vec<DeviceInfo>,
        unlock: UnlockInfo,
    },
    /// The answer to [`crate::members::MemberOp::List`]: the owner's six
    /// verification words (what a new member compares on joining) and the
    /// members.
    Members {
        owner_words: String,
        members: Vec<crate::members::MemberInfo>,
    },
}

/// Which unlock method this vault tries first, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockInfo {
    /// The setting in force: `last`, `password` or `device:NAME`.
    pub setting: String,
    /// Where it comes from: `this vault`, `all vaults` or `default`.
    pub source: String,
    /// The method that setting makes current now: `master password` or
    /// `device NAME`.
    pub current: String,
}

/// A paired device as `vahta devices` shows it. No key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInfo {
    /// The id in hex.
    pub id: String,
    pub name: String,
    pub paired_at: u64,
    /// When its access ends (Unix seconds); `None` does not end.
    pub expires_at: Option<u64>,
    /// The last time it opened the vault or approved something, from the
    /// daemon's journal.
    pub last_used: Option<u64>,
    /// `active` or `expired`.
    pub state: String,
    pub transports: Vec<String>,
    /// Whether this is the current unlock method (tried first).
    pub current: bool,
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
    /// When the injection alarm last went off (Unix seconds), until the next
    /// unlock.
    #[serde(default)]
    pub alarm_at: Option<u64>,
    /// The last refused launches of connector servers, newest last.
    #[serde(default)]
    pub connector_refusals: Vec<ConnectorRefusal>,
    /// A connectors session is open.
    #[serde(default)]
    pub connectors_session: bool,
    /// That session lasts until the machine reboots.
    #[serde(default)]
    pub connectors_until_reboot: bool,
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
        /// With no choice in this time, the window cancels.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_secs: Option<u64>,
    },
    /// A line of plain text, typed in the open: a name, never a value.
    Text {
        panel: Panel,
        prompt: String,
        /// With no line in this time, the window cancels.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_secs: Option<u64>,
    },
    /// Show something secret until a key is pressed, or `seconds` pass.
    Show {
        panel: Panel,
        what: String,
        value: Secret,
        seconds: Option<u32>,
        /// Ask for an explicit acknowledgement, as for a recovery key.
        acknowledge: bool,
    },
    /// A pairing code to scan, shown until the phone connects (the daemon then
    /// sends `PairStop`), the person presses Enter, or `seconds` pass. Answered
    /// with `Done` when stopped by the daemon, `Cancel` otherwise. The code is
    /// single-use and short-lived, but it is what lets a phone pair, so it
    /// goes over this connection like a password does.
    Pair {
        panel: Panel,
        /// The code as lines of Unicode blocks.
        qr: String,
        /// The same code as text, for a phone that cannot scan.
        text: String,
        seconds: u32,
    },
    /// The phone has connected: ends a pending `Pair` (answered `Done`). With
    /// none pending it does nothing.
    PairStop {},
    /// The daemon is waiting for the person's phone to answer (an unlock) and
    /// the window says so, until the daemon sends `DeviceWaitStop` (the phone
    /// answered), the person presses Enter to use the password instead, or
    /// `seconds` pass. Answered with `Done` when stopped by the daemon or timed
    /// out, `Choice { index: 0 }` for the password, `Cancel` when the person
    /// closed the window.
    DeviceWait {
        panel: Panel,
        /// The phone's name, as the person gave it at pairing.
        device: String,
        seconds: u32,
    },
    /// The phone has answered: ends a pending `DeviceWait` (answered `Done`).
    /// With none pending it does nothing.
    DeviceWaitStop {},
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
        for op in ["add", "reset"] {
            let good =
                format!(r#"{{"op":"{op}","cwd":"/p","name":"A","tier":"Session","file":null}}"#);
            let ok: Result<Option<ClientRequest>, _> =
                read_frame(&mut Cursor::new(frame(good.as_bytes())));
            assert!(
                matches!(
                    ok,
                    Ok(Some(
                        ClientRequest::Add { .. } | ClientRequest::Reset { .. }
                    ))
                ),
                "{op}"
            );
            for extra in ["value", "secret", "password", "typed", "plaintext"] {
                let bad = format!(
                    r#"{{"op":"{op}","cwd":"/p","name":"A","tier":"Session","file":null,"{extra}":"fake-one"}}"#
                );
                let r: Result<Option<ClientRequest>, _> =
                    read_frame(&mut Cursor::new(frame(bad.as_bytes())));
                assert!(r.is_err(), "{op}: {extra} was accepted");
            }
        }
        // The old `set` is gone: a client that sends it is told so, not obeyed.
        let old = r#"{"op":"set","cwd":"/p","name":"A","tier":"Session","file":null}"#;
        let r: Result<Option<ClientRequest>, _> =
            read_frame(&mut Cursor::new(frame(old.as_bytes())));
        assert!(r.is_err());
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
