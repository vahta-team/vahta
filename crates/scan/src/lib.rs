//! Finds plaintext credentials an agent can read.
//!
//! A port of `key_amnesia.scan`, which remains the specification. The same
//! rule as the detector applies: this must agree with Python, including where
//! Python is arguably wrong, and the proof is the existing Python test suite
//! run against this implementation rather than a corpus written to suit it.
//!
//! **Never carries secret values.** A finding holds a path, a kind, the
//! *names* of what was found and how many — never what was found.
//!
//! Scope, deliberately: the project scan. The `--deep` path — agent transcript
//! formats for three harnesses, and the home-directory candidate list — is
//! 395 of `scan.py`'s 1194 lines, is a moving target tied to other vendors'
//! file layouts, and stays in Python for now.

pub mod filenames;
pub mod finding;

pub use finding::{Confidence, Finding};

/// Content beyond this is not scanned. Matches `_MAX_CONTENT_BYTES`.
pub const MAX_CONTENT_BYTES: usize = 256_000;

pub const STRICT_CERTAIN: &str = "certain";
pub const STRICT_HIGH: &str = "high";
pub const STRICT_PARANOID: &str = "paranoid";
