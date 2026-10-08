//! Finds plaintext credentials an agent can read.
//!
//! It began as a port of key-amnesia's `scan_py`. Like the detector, this
//! crate is now the specification, pinned by its own tests.
//!
//! **Never carries secret values.** A finding holds a path, a kind, the
//! *names* of what was found and how many — never what was found.
//!
//! Covers the project scan and the `--deep` scan (home-directory candidates
//! and agent session transcripts for three harnesses). The transcript path
//! reads JSON, and Python's `json.loads` is the spec for what that accepts, so
//! [`json`] is a parser written to agree with it rather than a general one.
//! `cargo tree -p vahta-scan` shows two path dependencies, `vahta-detect` and `vahta-json`.

pub mod content;
pub mod deep;
pub mod filenames;
pub mod finding;
pub use vahta_json as json;
pub mod par;
pub mod report;
pub mod walk;

pub use finding::{Confidence, Finding};

/// Content beyond this is not scanned. Matches `_MAX_CONTENT_BYTES`.
pub const MAX_CONTENT_BYTES: usize = 256_000;

pub const STRICT_CERTAIN: &str = "certain";
pub const STRICT_HIGH: &str = "high";
pub const STRICT_PARANOID: &str = "paranoid";
