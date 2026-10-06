//! Per-harness manifests, payload normalisation and reply rendering.
//!
//! A hook binary asks three things of this crate: which harness is calling
//! ([`manifest`]), what the payload means ([`Manifest::normalise`]) and how to
//! phrase the answer ([`Manifest::render`]). Everything harness-specific lives
//! in `harnesses/<name>/harness.toml`, embedded at build time.

mod manifest;
mod normalise;
mod reply;

pub use manifest::{
    Config, DenyRules, Detect, EventSpec, Group, Kind, KindReplies, Manifest, OneOrMany, Paths,
    Replies, Reply, Require, Shape, Style, ToolGroup,
};
pub use normalise::Event;
pub use reply::{Decision, Output};

const CLAUDE: &str = include_str!("../harnesses/claude/harness.toml");
const CODEX: &str = include_str!("../harnesses/codex/harness.toml");
const CURSOR: &str = include_str!("../harnesses/cursor/harness.toml");

/// Names of the harnesses with an embedded manifest.
pub const HARNESSES: [&str; 3] = ["claude", "codex", "cursor"];

/// The embedded manifest of a harness, parsed. `None` for an unknown name.
pub fn manifest(name: &str) -> Option<Result<Manifest, String>> {
    let src = match name {
        "claude" => CLAUDE,
        "codex" => CODEX,
        "cursor" => CURSOR,
        _ => return None,
    };
    Some(Manifest::parse(src))
}
