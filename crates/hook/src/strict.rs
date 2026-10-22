//! The prompt check when the daemon cannot be reached.
//!
//! With the daemon up, the person is asked about a secret in a prompt and
//! the detector's rules are enough. Without it the hook cannot ask, so a prompt
//! the detector let pass is looked at again with a lower threshold: any long
//! string that looks like a key (a run of the characters keys are written in,
//! at least [`MIN_LEN`] of them, with letters and digits, and the spread of
//! characters that random text has and words do not) holds the prompt. This
//! errs towards holding: a git commit id or a UUID is let through (they are
//! written in prompts all the time and are not secrets), anything else key-like
//! is not.

use vahta_detect::entropy;

/// The shortest string the strict check looks at.
pub const MIN_LEN: usize = 20;
/// The least Shannon entropy, in bits per character, of a key-like string.
/// Random base64 and hex are above it; words, identifiers and paths are not.
const MIN_ENTROPY: f64 = 3.5;

/// The characters a key is written in: base64 and its URL form, hex. (The `=`
/// of base64 padding is not one: it ends a key, and `NAME=value` has one in the
/// middle.)
fn key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/')
}

/// `s` is a 40-character git object name or an 8-4-4-4-12 UUID.
fn is_id(s: &str) -> bool {
    let hex = |p: &str| p.chars().all(|c| c.is_ascii_hexdigit());
    if s.len() == 40 && hex(s) {
        return true;
    }
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && hex(p))
}

fn looks_like_a_key(token: &str) -> bool {
    if token.chars().count() < MIN_LEN || is_id(token) {
        return false;
    }
    let digits = token.chars().any(|c| c.is_ascii_digit());
    let letters = token.chars().any(|c| c.is_ascii_alphabetic());
    // Words joined by `-` or `_` (an identifier, a slug): several separators
    // and no long run between them. A random key has about one in thirty.
    let parts: Vec<&str> = token.split(['-', '_']).collect();
    let words = parts.len() > 3 && parts.iter().all(|p| p.len() <= 12);
    digits && letters && !words && entropy(token) >= MIN_ENTROPY
}

/// The length of the first key-like string in `text`, if there is one. Only the
/// length is returned: what it is stays out of every message.
pub fn long_token(text: &str) -> Option<usize> {
    for word in text.split(|c: char| !key_char(c)) {
        let token = word.trim_matches(|c| matches!(c, '-' | '_' | '+' | '/'));
        if token.matches('/').count() >= 3 {
            // Probably a path or a URL: judge its parts.
            if let Some(n) = token
                .split('/')
                .map(str::len)
                .zip(token.split('/'))
                .find_map(|(n, part)| looks_like_a_key(part).then_some(n))
            {
                return Some(n);
            }
        } else if looks_like_a_key(token) {
            return Some(token.len());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built from pieces: no key-shaped string sits in this file.
    fn base64ish() -> String {
        ["wJ7r", "Xu9t", "nFEM", "I2Kd", "Mq7Q", "bPxR"].concat()
    }

    fn hex32() -> String {
        [
            "3f9a", "c07e", "5b21", "d84a", "96e0", "71bc", "2a58", "f4d3",
        ]
        .concat()
    }

    #[test]
    fn a_long_random_string_in_a_key_alphabet_is_found() {
        assert_eq!(long_token(&format!("use {} for it", base64ish())), Some(24));
        assert_eq!(long_token(&format!("k={}", hex32())), Some(32));
        // Url-safe base64 with its separators, in quotes.
        let urlsafe = ["Ab3_", "xY9-", "Qw7e", "R2tP", "z8Lm"].concat();
        assert!(long_token(&format!("\"{urlsafe}\"")).is_some());
        // With the padding and the plus and slash of base64.
        let padded = ["dGhp", "cyBp", "cyBh", "IGtl", "eTEy", "Mw+/", "Zm9v", "=="].concat();
        assert!(long_token(&padded).is_some());
    }

    #[test]
    fn words_identifiers_ids_and_short_strings_are_not() {
        for text in [
            "please summarise the readme and fix the failing tests",
            "call someVeryLongFunctionNameForTheParser please",
            "rename my_very_long_snake_case_identifier_2 everywhere",
            "see /usr/lib/python3/dist-packages/some_package/module.py",
            "commit 9fceb02d0ae598e95dc970b74767f19372d61af8 broke it",
            "id 123e4567-e89b-12d3-a456-426614174000 is stale",
            "https://example.com/docs/guide/getting-started-v2",
            "token abc123XYZ",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            "",
        ] {
            assert_eq!(long_token(text), None, "{text}");
        }
    }

    #[test]
    fn a_key_inside_a_path_or_url_is_still_found() {
        let url = format!("https://example.com/hooks/{}/send", base64ish());
        assert_eq!(long_token(&url), Some(24));
    }
}
