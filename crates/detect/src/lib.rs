//! Secret-shape detector for Vahta.
//!
//! A port of `key_amnesia.detect_py`, which remains the specification: the
//! measured evidence behind every threshold — why the likely-floor sits at
//! 0.50 rather than 0.60, why hex is an explicit exception instead of a
//! lowered floor, why length >= 20 was rejected — lives in that module's
//! docstring and is not restated here.
//!
//! The port is proven by running the Python test suite against this
//! implementation through the extension module, not by a corpus written for
//! the occasion. Behaviour is frozen: this crate must agree with Python,
//! including where Python is arguably wrong.
//!
//! Never returns or logs secret *values*.

pub mod classify;
pub mod hits;
pub mod matchers;
pub mod primitives;
#[rustfmt::skip]
mod pyunicode;

pub use classify::{
    Confidence, HEX_LIKELY_MIN_LEN, LIKELY_TRANSITION_FLOOR, MIN_VALUE_LEN,
    MIN_VOWEL_SEGMENTS_FOR_POSSIBLE, NAMED_WEAKENING_FUNCTION_CALL, NAMED_WEAKENING_IDENTIFIER,
    NAMED_WEAKENING_LOW_TRANSITION, NAMED_WEAKENING_TYPE_ANNOTATION,
    NAMED_WEAKENING_WORD_SHAPED_PASSPHRASE, NAMED_WEAKENINGS, REASON_UNCONFIRMED_MCP, REASON_UUID,
    SHANNON_POSSIBLE_FLOOR, STRIPPED_UUID_LEN, assignment_is_secret, classify_value,
    is_placeholder, uuid_or_stripped_hex,
};
pub use hits::{HitSet, find_secret_kind, looks_like_json_container, scan_text_hits, scan_texts};
pub use matchers::{
    FLAG_FORM_FIRE_TIERS, REASON_FLAG_FORM, classify_bearer_capture, find_prefix_kind,
    is_secret_name, iter_assignments, iter_flag_values,
};
pub use primitives::{
    CharClass, char_class, entropy, fold_ci, has_vowel, is_digit_python, is_python_space,
    is_word_python, transition_rate, vowel_bearing_segments, word_segments,
};
