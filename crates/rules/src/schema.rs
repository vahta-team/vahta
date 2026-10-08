//! The enums of the rule files, shared by the build script, which reads them,
//! and the library.

use serde::Deserialize;

/// What a credential guards; steers advice, not detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    /// Moves money.
    Payment,
    /// Opens a cloud account.
    Cloud,
    #[default]
    Other,
}

/// What the hook does when the rule hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Refuse the tool call.
    #[default]
    Block,
    /// Let it through and only tell the daemon.
    Observe,
}

/// What an allow-list regex is tried against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    /// The captured value.
    #[default]
    Value,
    /// The whole regex match.
    Matched,
    /// The line the match is on.
    Line,
}
