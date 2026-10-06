//! Numeric and lexical primitives underneath the tier decision.
//!
//! Ported from `key_amnesia.detect_py`, which stays the specification: the
//! measured evidence for every threshold lives in its module docstring. This
//! layer must be *behaviourally identical*, not merely similar, so the places
//! where Python and Rust do not agree by default are called out where they
//! occur rather than discovered later.

use crate::pyunicode;

/// Character class used by [`transition_rate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharClass {
    Upper,
    Lower,
    Digit,
    Other,
}

/// Python's `str.isspace()`, which is also exactly what `re`'s `\s` matches
/// on `str` — checked over every code point, not assumed.
///
/// Rust's `char::is_whitespace` is the Unicode `White_Space` property. Python
/// additionally counts U+001C..U+001F, the ASCII file, group, record and unit
/// separators, and nothing goes the other way. The difference is not
/// cosmetic: `API_KEY\x1c=\x1c"<value>"` is a likely finding to Python and was
/// nothing at all to the port, which makes it a way to walk a credential past
/// the hook.
#[inline]
pub fn is_python_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// Python's `\w` on `str`: `str.isalnum()` or `_`.
///
/// Not `char::is_alphanumeric`, which also admits `Other_Alphabetic`
/// combining marks, circled letters, and code points a newer Unicode version
/// assigned — about six thousand characters Python does not treat as word
/// characters, each of which moves a `\b`. The non-ASCII set is a table
/// generated from the interpreter; see `tools/gen_unicode_tables.py`.
#[inline]
pub fn is_word_python(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '_';
    }
    pyunicode::contains(&pyunicode::WORD, c)
}

/// One character as Python's `re` sees it under `(?i)`, when the pattern side
/// is ASCII.
///
/// `re.IGNORECASE` on `str` folds by Unicode rules, so four non-ASCII
/// characters match ASCII letters: `İ` (U+0130) and `ı` (U+0131) match `i`,
/// `ſ` (U+017F) matches `s`, and the Kelvin sign `K` (U+212A) matches `k`.
/// Enumerated over every code point against every ASCII letter, digit, `_`
/// and `-`; these four are the complete list. Everything else non-ASCII is
/// returned unchanged, so it can never equal an ASCII literal.
///
/// A port comparing with `to_ascii_lowercase` misses `paſſword = "<value>"`
/// entirely where Python reports it, which is again a way past the hook.
#[inline]
pub fn fold_ci(c: char) -> char {
    match c {
        '\u{130}' | '\u{131}' => 'i',
        '\u{17f}' => 's',
        '\u{212a}' => 'k',
        _ => c.to_ascii_lowercase(),
    }
}

/// Classify one character, as Python's `str.isupper` / `islower` /
/// `isdigit` would.
///
/// Rust's `char::is_uppercase` / `is_lowercase` / `is_numeric` are
/// Unicode-aware too, but not by identical definitions or the same Unicode
/// version, so non-ASCII answers come from tables generated out of the
/// interpreter (`tools/gen_unicode_tables.py`). Checked over every code point.
#[inline]
pub fn char_class(c: char) -> CharClass {
    if c.is_ascii() {
        return if c.is_ascii_uppercase() {
            CharClass::Upper
        } else if c.is_ascii_lowercase() {
            CharClass::Lower
        } else if c.is_ascii_digit() {
            CharClass::Digit
        } else {
            CharClass::Other
        };
    }
    if pyunicode::contains(&pyunicode::UPPER, c) {
        CharClass::Upper
    } else if pyunicode::contains(&pyunicode::LOWER, c) {
        CharClass::Lower
    } else if pyunicode::contains(&pyunicode::DIGIT, c) {
        CharClass::Digit
    } else {
        CharClass::Other
    }
}

/// `str.isdigit()` for a single character: Numeric_Type of Decimal or Digit.
///
/// Neither `char::is_numeric` (all of `N*`, so `'½'` too) nor `to_digit(10)`
/// (ASCII only) is this. An earlier hand-written list of five scripts was
/// wrong on 806 code points — NKo, Mongolian, Tai Tham and the rest — which
/// only an exhaustive comparison showed; a sampled one had passed.
#[inline]
pub fn is_digit_python(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_digit();
    }
    pyunicode::contains(&pyunicode::DIGIT, c)
}

/// Compensated summation, matching what CPython's `sum()` does to floats.
///
/// Since **Python 3.12** `sum()` no longer adds floats naively: it uses
/// Neumaier compensated summation, which tracks the rounding error each
/// addition throws away and folds it back at the end. A port that adds
/// left to right is therefore *more wrong* than Python, not merely different.
///
/// This was measured, not guessed. Over 4027 generated inputs a naive sum
/// disagreed with Python on 2179 of them — always in the last one or two
/// digits, which is exactly the size of error that decides a tier at the
/// `SHANNON_POSSIBLE_FLOOR` boundary while being invisible everywhere else.
#[derive(Default)]
struct Neumaier {
    sum: f64,
    compensation: f64,
}

impl Neumaier {
    #[inline]
    fn add(&mut self, x: f64) {
        let t = self.sum + x;
        if self.sum.abs() >= x.abs() {
            self.compensation += (self.sum - t) + x;
        } else {
            self.compensation += (x - t) + self.sum;
        }
        self.sum = t;
    }

    fn finish(&self) -> f64 {
        self.sum + self.compensation
    }
}

/// Shannon entropy in bits.
///
/// # Summation is part of the contract
///
/// Floating-point addition is neither associative nor lossless, so two
/// implementations summing the same terms can land on opposite sides of
/// `SHANNON_POSSIBLE_FLOOR`. Two things have to match Python, not just one:
///
/// * the **order** — Python iterates `Counter(s).values()`, which in CPython
///   is insertion order, so first occurrence. Reproduced here rather than
///   sorted, because sorting would mean changing the Python side too, and
///   this milestone changes no behaviour.
/// * the **algorithm** — see [`Neumaier`].
pub fn entropy(s: &str) -> f64 {
    if s.is_ascii() {
        return entropy_ascii(s.as_bytes());
    }
    entropy_general(s)
}

/// [`entropy`] for ASCII input, with no allocation and no linear search.
///
/// The general path finds each character's slot with a scan of the distinct
/// characters seen so far, which on a 40-character key with ~35 distinct
/// characters is most of the cost of classifying it. Here the counts live in a
/// table indexed by the byte, and a separate list records first-occurrence
/// order, because the order the terms are summed in is part of the contract
/// (see above). Same terms, same order, same arithmetic: the same bits out.
fn entropy_ascii(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 128];
    let mut order = [0u8; 128];
    let mut distinct = 0usize;
    for &b in bytes {
        let slot = &mut counts[b as usize];
        if *slot == 0 {
            order[distinct] = b;
            distinct += 1;
        }
        *slot += 1;
    }
    let n = bytes.len() as f64;
    // `p * log2(p)` depends only on the count (n is fixed), and counts repeat
    // heavily — most characters of a random key occur once or twice — so each
    // small count's term is computed once, by the very same expression.
    let mut memo = [0.0f64; 64];
    let mut seen = 0u64;
    let mut acc = Neumaier::default();
    for &b in &order[..distinct] {
        let count = counts[b as usize] as usize;
        let term = if count < 64 {
            if seen & (1 << count) == 0 {
                let p = count as f64 / n;
                memo[count] = p * p.log2();
                seen |= 1 << count;
            }
            memo[count]
        } else {
            let p = count as f64 / n;
            p * p.log2()
        };
        acc.add(term);
    }
    -acc.finish()
}

fn entropy_general(s: &str) -> f64 {
    let mut counts: Vec<(char, usize)> = Vec::new();
    let mut total: usize = 0;

    for c in s.chars() {
        total += 1;
        match counts.iter_mut().find(|(seen, _)| *seen == c) {
            Some((_, n)) => *n += 1,
            None => counts.push((c, 1)),
        }
    }

    if total == 0 {
        return 0.0;
    }

    let n = total as f64;
    // Same terms, same order, same compensated sum as `neumaier_sum` — just
    // fed one at a time instead of through a temporary `Vec<f64>`.
    let mut acc = Neumaier::default();
    for (_, count) in &counts {
        let p = *count as f64 / n;
        acc.add(p * p.log2());
    }
    -acc.finish()
}

/// Fraction of adjacent character pairs that change class.
///
/// Identifiers measure 0.18-0.45, JWT-shaped 0.71, random fixtures 1.00,
/// hex-32 0.42 — see the Python module docstring for how those were obtained
/// and why the likely-floor sits at 0.50.
///
/// Length is counted in **characters, not bytes**: Python's `len()` on a
/// `str` counts code points, and using `str::len()` here would make every
/// non-ASCII input disagree.
pub fn transition_rate(s: &str) -> f64 {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return 0.0;
    };

    let mut prev = char_class(first);
    let mut changes: usize = 0;
    let mut pairs: usize = 0;

    for c in chars {
        let class = char_class(c);
        pairs += 1;
        if class != prev {
            changes += 1;
        }
        prev = class;
    }

    if pairs == 0 {
        return 0.0;
    }
    changes as f64 / pairs as f64
}

/// Split a value into word-ish segments.
///
/// # Why this is hand-rolled
///
/// Python uses `re.split(r"[^A-Za-z0-9]+", value)` and then
/// `[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+` over each part. That second pattern
/// contains a **negative lookahead**, which Rust's `regex` crate does not
/// support at all. The alternation is small enough to implement directly, and
/// doing so avoids taking on a backtracking regex engine for one pattern.
///
/// The three alternatives, in order, are: an optional capital followed by
/// lowercase (`Foo`, `foo`); a run of capitals not followed by a lowercase
/// (`HTTP` in `HTTPServer`, which must stop before the `S` that begins
/// `Server`); and a run of digits.
pub fn word_segments(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    for_each_segment(value, |seg| out.push(seg.to_string()));
    out
}

/// [`word_segments`] without allocating: each segment is handed to `f` as a
/// slice of `value`. The vowel-segment count, which runs for every candidate
/// value, uses this directly.
fn for_each_segment(value: &str, mut f: impl FnMut(&str)) {
    for part in value.split(|c: char| !c.is_ascii_alphanumeric()) {
        if part.is_empty() {
            continue;
        }
        let mut found = false;
        camel_segments(part, |seg| {
            found = true;
            f(seg);
        });
        if !found {
            f(part);
        }
    }
}

/// `part` holds ASCII alphanumerics only (it came out of the split above), so
/// byte offsets are character offsets and every slice is on a boundary.
fn camel_segments(part: &str, mut emit: impl FnMut(&str)) {
    let chars = part.as_bytes();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];

        // `[A-Z]?[a-z]+`, with the capital.
        if c.is_ascii_uppercase() && i + 1 < chars.len() && chars[i + 1].is_ascii_lowercase() {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                i += 1;
            }
            emit(&part[start..i]);
            continue;
        }
        // `[a-z]+`
        if c.is_ascii_lowercase() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                i += 1;
            }
            emit(&part[start..i]);
            continue;
        }

        // `[A-Z]+(?![a-z])`: a run of capitals, giving back the last one if a
        // lowercase letter follows it (it belongs to the next word).
        if c.is_ascii_uppercase() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_uppercase() {
                i += 1;
            }
            if i < chars.len() && chars[i].is_ascii_lowercase() && i - start > 1 {
                i -= 1;
            }
            if i > start {
                emit(&part[start..i]);
                continue;
            }
            i += 1;
            continue;
        }

        // `[0-9]+`
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            emit(&part[start..i]);
            continue;
        }

        i += 1;
    }
}

#[cfg(test)]
const VOWELS: &str = "aeiouAEIOUyY";

/// True if the segment carries a vowel. `y` counts, as in Python.
pub fn has_vowel(seg: &str) -> bool {
    // Membership in `VOWELS`, spelled out so it compiles to a byte test.
    seg.chars().any(|c| {
        matches!(
            c,
            'a' | 'e' | 'i' | 'o' | 'u' | 'A' | 'E' | 'I' | 'O' | 'U' | 'y' | 'Y'
        )
    })
}

/// Number of vowel-bearing segments in a value.
pub fn vowel_bearing_segments(value: &str) -> usize {
    let mut n = 0usize;
    for_each_segment(value, |seg| n += usize::from(has_vowel(seg)));
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(entropy(""), 0.0);
    }

    #[test]
    fn entropy_of_four_distinct_is_two_bits() {
        assert_eq!(entropy("abcd"), 2.0);
    }

    #[test]
    fn entropy_of_one_repeated_character_is_zero() {
        assert_eq!(entropy("aaaaaa"), 0.0);
    }

    #[test]
    fn entropy_counts_code_points_not_bytes() {
        // Two distinct characters, four bytes. Byte-counting would give a
        // different answer.
        assert_eq!(entropy("ЯЯ"), 0.0);
        assert_eq!(entropy("Яб"), 1.0);
    }

    #[test]
    fn transition_rate_of_short_input_is_zero() {
        assert_eq!(transition_rate(""), 0.0);
        assert_eq!(transition_rate("a"), 0.0);
    }

    #[test]
    fn transition_rate_of_uniform_case_is_zero() {
        assert_eq!(transition_rate("abcdef"), 0.0);
    }

    #[test]
    fn transition_rate_of_alternating_classes_is_one() {
        assert_eq!(transition_rate("aA1b"), 1.0);
    }

    #[test]
    fn vulgar_fraction_is_other_not_digit() {
        // Rust's is_numeric would call this a digit; Python's isdigit does not.
        assert_eq!(char_class('½'), CharClass::Other);
        assert_eq!(char_class('²'), CharClass::Digit);
        assert_eq!(char_class('٣'), CharClass::Digit);
    }

    /// Every expectation here was read out of the Python implementation
    /// rather than reasoned about. The boundary cases are the ones where a
    /// hand-rolled splitter and the original alternation come apart: a run of
    /// capitals must give its last character back to a following lowercase
    /// segment, but only when that leaves something behind.
    #[test]
    fn camel_case_splits_the_way_the_regex_does() {
        assert_eq!(word_segments("summerVineyard"), vec!["summer", "Vineyard"]);
        assert_eq!(word_segments("HTTPServer"), vec!["HTTP", "Server"]);
        assert_eq!(
            word_segments("XMLHttpRequest"),
            vec!["XML", "Http", "Request"]
        );
        assert_eq!(
            word_segments("getToken2Cache"),
            vec!["get", "Token", "2", "Cache"]
        );
        assert_eq!(
            word_segments("correct-horse-battery"),
            vec!["correct", "horse", "battery"]
        );
        assert_eq!(word_segments("A1b2"), vec!["A", "1", "b", "2"]);
        assert_eq!(word_segments("ABCdef"), vec!["AB", "Cdef"]);
        assert_eq!(word_segments("abcDEF"), vec!["abc", "DEF"]);
        assert_eq!(word_segments("A"), vec!["A"]);
        assert_eq!(word_segments("AB"), vec!["AB"]);
        assert_eq!(word_segments("ABc"), vec!["A", "Bc"]);
    }

    /// Non-ASCII characters are *separators* to the Python splitter, not
    /// content: `re.split(r"[^A-Za-z0-9]+", …)` consumes them, so a value made
    /// only of them yields no segments at all rather than one segment holding
    /// the whole string.
    #[test]
    fn non_ascii_is_a_separator_and_yields_no_segment() {
        assert_eq!(word_segments("___"), Vec::<String>::new());
        assert_eq!(word_segments("Я"), Vec::<String>::new());
        assert_eq!(word_segments("ЯблокоTest"), vec!["Test"]);
    }

    #[test]
    fn has_vowel_matches_the_vowel_string_for_every_char() {
        for cp in 0..=0x2FFu32 {
            let c = char::from_u32(cp).unwrap();
            assert_eq!(has_vowel(&c.to_string()), VOWELS.contains(c), "{cp:#x}");
        }
    }

    #[test]
    fn entropy_fast_path_is_bit_identical_to_the_general_one() {
        // Deterministic mixed inputs, including counts above the memo size.
        let mut x = 0x2545F4914F6CDD1Du64;
        for len in 1..300usize {
            let mut s = String::new();
            for _ in 0..len {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let span = 1 + (len as u64 % 90);
                s.push((33 + (x % span)) as u8 as char);
            }
            assert_eq!(
                entropy_ascii(s.as_bytes()).to_bits(),
                entropy_general(&s).to_bits()
            );
        }
    }

    #[test]
    fn vowel_counting_includes_y() {
        assert!(has_vowel("myth"));
        assert!(!has_vowel("xkcd"));
        assert_eq!(vowel_bearing_segments("summerVineyard"), 2);
    }
}
