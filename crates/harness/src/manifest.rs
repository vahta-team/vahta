//! The manifest schema: what one harness's `harness.toml` may say.
//!
//! A manifest is data, not code. Adding a harness is adding a folder with one
//! of these files; nothing in the hook changes unless the harness needs a
//! shape the schema cannot yet express.

use serde::Deserialize;
use serde_json::Value;

/// The five things the hook can be asked about, whatever the harness calls them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A tool call is about to run.
    BeforeTool,
    /// A file is about to be read.
    BeforeRead,
    /// The user's message is about to be sent to the model.
    Prompt,
    /// A tool finished and its output is about to reach the model.
    AfterTool,
    /// A session has begun. Used to say that the installed setup is outdated.
    SessionStart,
}

impl Kind {
    /// The spelling used on the hook's command line (`--event <kind>`).
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::BeforeTool => "before_tool",
            Kind::BeforeRead => "before_read",
            Kind::Prompt => "prompt",
            Kind::AfterTool => "after_tool",
            Kind::SessionStart => "session_start",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "before_tool" => Some(Kind::BeforeTool),
            "before_read" => Some(Kind::BeforeRead),
            "prompt" => Some(Kind::Prompt),
            "after_tool" => Some(Kind::AfterTool),
            "session_start" => Some(Kind::SessionStart),
            _ => None,
        }
    }
}

/// A tool family. Policy keys on the family, never on a harness's tool name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    Shell,
    Write,
    Mcp,
    Read,
}

/// One string or a list of alternatives, so a field that a harness spells two
/// ways can be read either way.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        let (one, many): (Option<&str>, &[String]) = match self {
            OneOrMany::One(s) => (Some(s.as_str()), &[]),
            OneOrMany::Many(v) => (None, v.as_slice()),
        };
        one.into_iter().chain(many.iter().map(String::as_str))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    /// How the harness is written in prose ("Claude Code").
    pub title: String,
    /// Bumped whenever what `vahta setup` writes for this harness changes.
    /// The hook command carries the version it was installed at (`--setup N`).
    pub setup_version: u32,
    /// Something the person must do in the harness itself after setup writes,
    /// which setup cannot and should not do for them (Codex's hook trust).
    #[serde(default)]
    pub setup_notice: Option<String>,
    pub config: Config,
    /// How `vahta setup` decides the harness is installed.
    pub detect: Detect,
    #[serde(default)]
    pub events: Vec<EventSpec>,
    #[serde(default)]
    pub tool_groups: Vec<ToolGroup>,
    /// Group used when a payload names no tool at all.
    pub unnamed_tool_group: Option<Group>,
    #[serde(default)]
    pub replies: Replies,
}

/// Where the harness keeps its hook configuration. Used by `vahta setup`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `json` or `toml`.
    pub format: String,
    /// User-scope config path per OS; `~` is the home directory, `$VAR` an
    /// environment variable. Candidates are tried in order; one whose variable
    /// is unset is skipped.
    pub path: Paths,
    /// How hook entries are laid out in the file.
    pub shape: Shape,
    /// A field the file must carry, e.g. Cursor's `version: 1`.
    pub require: Option<Require>,
}

/// The two layouts of a hook registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shape {
    /// Claude and Codex: `hooks.<Event>[] = {matcher?, hooks: [{type, command}]}`.
    Grouped,
    /// Cursor: `hooks.<event>[] = {command, matcher?}`.
    Flat,
}

/// Evidence that a harness is installed. Found means any rule matches.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// Config directories (`~` and `$VAR` as in `config.path`; one whose
    /// variable is unset is skipped). Found when one exists.
    #[serde(default)]
    pub dirs: Vec<String>,
    /// Executable names looked up on `PATH`.
    #[serde(default)]
    pub binaries: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    pub linux: Vec<String>,
    pub macos: Vec<String>,
    pub windows: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Require {
    pub key: String,
    pub value: i64,
}

/// A harness event and how to read its payload. Field paths are dotted
/// (`tool_input.file_path`); a list means "first one present wins".
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSpec {
    /// The harness's own name for the event, as written in its config.
    pub name: String,
    pub kind: Kind,
    /// The harness's own tool matcher for this event. Used by setup only.
    pub matcher: Option<String>,
    pub tool_name: Option<OneOrMany>,
    pub tool_input: Option<OneOrMany>,
    pub prompt: Option<OneOrMany>,
    pub tool_output: Option<OneOrMany>,
    pub cwd: Option<OneOrMany>,
    /// `before_read`: the file's path, and (Cursor only) its content.
    pub file_path: Option<OneOrMany>,
    pub content: Option<OneOrMany>,
}

/// A family of tools: which names belong to it and where its text lives.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGroup {
    pub group: Group,
    /// Exact tool names, compared case-insensitively.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Name prefixes (case-insensitive); the name must be longer than the prefix.
    #[serde(default)]
    pub prefixes: Vec<String>,
    /// Payload fields whose presence marks a call as this group's even when
    /// the name carries no hint (Cursor's `beforeMCPExecution`).
    #[serde(default)]
    pub marker_fields: Vec<String>,
    /// Keys of `tool_input` holding the text to scan, in priority order. Empty
    /// means every string in `tool_input` is scanned.
    #[serde(default)]
    pub text_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replies {
    pub before_tool: Option<KindReplies>,
    pub before_read: Option<KindReplies>,
    pub prompt: Option<KindReplies>,
    pub after_tool: Option<KindReplies>,
    pub session_start: Option<KindReplies>,
}

/// What may be said for one kind of event. A missing `allow` means silence.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindReplies {
    pub allow: Option<Reply>,
    pub deny: Option<Reply>,
    /// Neither allow nor deny: tell the model and the user, change nothing.
    pub notice: Option<Reply>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Style {
    /// A JSON document on stdout.
    Json,
    /// A message on stderr and a non-zero exit code (unused in v1).
    ExitCode,
    /// Delivered by a plugin in the harness's own language (reserved).
    Plugin,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub style: Style,
    #[serde(default)]
    pub exit_code: i32,
    /// `json`: the document. String leaves may use `{reason}`, `{user_message}`
    /// and `{agent_message}`.
    pub body: Option<Value>,
    /// `exit_code`: the stderr text, same placeholders.
    pub stderr: Option<String>,
}

impl Manifest {
    pub fn parse(src: &str) -> Result<Manifest, String> {
        toml::from_str(src).map_err(|e| e.to_string())
    }

    pub fn event(&self, kind: Kind) -> Option<&EventSpec> {
        self.events.iter().find(|e| e.kind == kind)
    }
}
