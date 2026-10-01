//! Finds plaintext credentials an agent can read.
//!
//! A port of `key_amnesia.scan_py`, which remains the specification. The same
//! rule as the detector applies: this must agree with Python, including where
//! Python is arguably wrong, and the proof is the existing Python test suite
//! run against this implementation rather than a corpus written to suit it.
//!
//! **Never carries secret values.** A finding holds a path, a kind, the
//! *names* of what was found and how many — never what was found.
//!
//! Covers the project scan and the `--deep` scan (home-directory candidates
//! and agent session transcripts for three harnesses). The transcript path
//! reads JSON, and Python's `json.loads` is the spec for what that accepts, so
//! [`json`] is a parser written to agree with it rather than a general one.
//! `cargo tree -p vahta-scan` shows one dependency, `vahta-detect`.

pub mod content;
pub mod deep;
pub mod filenames;
pub mod finding;
pub mod json;
pub mod report;
pub mod walk;

pub use finding::{Confidence, Finding};

/// Content beyond this is not scanned. Matches `_MAX_CONTENT_BYTES`.
pub const MAX_CONTENT_BYTES: usize = 256_000;

pub const STRICT_CERTAIN: &str = "certain";
pub const STRICT_HIGH: &str = "high";
pub const STRICT_PARANOID: &str = "paranoid";
