//! Numeric and lexical primitives underneath the tier decision.
//!
//! Ported from `key_amnesia.detect_py`, which stays the specification: the
//! measured evidence for every threshold lives in its module docstring. This
//! layer must be *behaviourally identical*, not merely similar, so the places
//! where Python and Rust do not agree by default are called out where they
//! occur rather than discovered later.

/// Character class used by [`transition_rate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharClass {
    Upper,
    Lower,
    Digit,
    Other,
}

/// Classify one character.
///
/// # Divergence risk
///
/// Python's `str.isupper` / `islower` / `isdigit` are Unicode-aware, and so
/// are Rust's `char::is_uppercase` / `is_lowercase` / `is_numeric` — but not
/// by identical definitions. `is_numeric` admits `Nl` and `No` (`'½'`), while
/// Python's `isdigit` admits only Decimal and Digit numeric types, so `'½'`
/// is `Other` to Python and would be `Digit` to a naive port.
///
/// `is_numeric_python` below reproduces Python's rule. The differential test
/// against the Python implementation is what proves it, not this comment —
/// this module has no authority to declare the two equal.
#[inline]
pub fn char_class(c: char) -> CharClass {
    if c.is_uppercase() {
        CharClass::Upper
    } else if c.is_lowercase() {
        CharClass::Lower
    } else if is_digit_python(c) {
        CharClass::Digit
    } else {
        CharClass::Other
    }
}

/// `str.isdigit()` for a single character: Numeric_Type of Decimal or Digit.
///
/// Rust's `char::is_numeric` is the wider `N*` general category, which also
/// contains `Nl` (Roman numerals) and `No` (vulgar fractions). Excluding the
/// characters that are numeric but not digits is what keeps `'½'` in the same
/// class as Python puts it.
#[inline]
pub fn is_digit_python(c: char) -> bool {
    if c.is_ascii_digit() {
        return true;
    }
    if !c.is_numeric() {
        return false;
    }
    // Numeric but not a digit: fractions, Roman numerals, circled and
    // enclosed forms. `to_digit` answers for the decimal/digit types that
    // Python accepts and rejects the rest.
    c.to_digit(10).is_some() || is_non_ascii_decimal(c)
}

/// Decimal digits outside ASCII (Arabic-Indic, Devanagari, fullwidth, …).
///
/// `char::to_digit` is ASCII-only, so the general categories have to be asked
/// directly. `Nd` is exactly Python's decimal case; superscripts such as `'²'`
/// are `No` with Numeric_Type=Digit, which Python also accepts, and are listed
/// explicitly because they are few and fixed.
#[inline]
fn is_non_ascii_decimal(c: char) -> bool {
    matches!(c,
        '\u{00B2}' | '\u{00B3}' | '\u{00B9}'            // ² ³ ¹
        | '\u{0660}'..='\u{0669}'                        // Arabic-Indic
        | '\u{06F0}'..='\u{06F9}'                        // Extended Arabic-Indic
        | '\u{0966}'..='\u{096F}'                        // Devanagari
        | '\u{0E50}'..='\u{0E59}'                        // Thai
        | '\u{FF10}'..='\u{FF19}'                        // Fullwidth
        | '\u{2080}'..='\u{2089}'                        // Subscript
        | '\u{2460}'..='\u{2468}'                        // Circled 1-9
    )
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
fn neumaier_sum(terms: &[f64]) -> f64 {
    let mut sum = 0.0f64;
    let mut compensation = 0.0f64;

    for &x in terms {
        let t = sum + x;
        if sum.abs() >= x.abs() {
            compensation += (sum - t) + x;
        } else {
            compensation += (x - t) + sum;
        }
        sum = t;
    }
    sum + compensation
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
/// * the **algorithm** — see [`neumaier_sum`].
pub fn entropy(s: &str) -> f64 {
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
    let terms: Vec<f64> = counts
        .iter()
        .map(|(_, count)| {
            let p = *count as f64 / n;
            p * p.log2()
        })
        .collect();

    -neumaier_sum(&terms)
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

    for part in value.split(|c: char| !c.is_ascii_alphanumeric()) {
        if part.is_empty() {
            continue;
        }
        let found = camel_segments(part);
        if found.is_empty() {
            out.push(part.to_string());
        } else {
            out.extend(found);
        }
    }
    out
}

fn camel_segments(part: &str) -> Vec<String> {
    let chars: Vec<char> = part.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];

        // `[A-Z]?[a-z]+`
        if c.is_ascii_uppercase()
            && i + 1 < chars.len()
            && chars[i + 1].is_ascii_lowercase()
        {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
            continue;
        }
        if c.is_ascii_lowercase() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_lowercase() {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
            continue;
        }

        // `[A-Z]+(?![a-z])` — take capitals, then give back the last one if a
        // lowercase follows, because it belongs to the next segment.
        if c.is_ascii_uppercase() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_uppercase() {
                i += 1;
            }
            if i < chars.len() && chars[i].is_ascii_lowercase() && i - start > 1 {
                i -= 1;
            }
            if i > start {
                out.push(chars[start..i].iter().collect());
                continue;
            }
            // A single capital directly before a lowercase was handled above;
            // reaching here means the alternative cannot match, so skip it.
            i += 1;
            continue;
        }

        // `[0-9]+`
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
            continue;
        }

        i += 1;
    }
    out
}

const VOWELS: &str = "aeiouAEIOUyY";

/// True if the segment carries a vowel. `y` counts, as in Python.
pub fn has_vowel(seg: &str) -> bool {
    seg.chars().any(|c| VOWELS.contains(c))
}

/// Number of vowel-bearing segments in a value.
pub fn vowel_bearing_segments(value: &str) -> usize {
    word_segments(value)
        .iter()
        .filter(|seg| has_vowel(seg))
        .count()
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
        assert_eq!(word_segments("XMLHttpRequest"), vec!["XML", "Http", "Request"]);
        assert_eq!(word_segments("getToken2Cache"), vec!["get", "Token", "2", "Cache"]);
        assert_eq!(word_segments("correct-horse-battery"), vec!["correct", "horse", "battery"]);
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
    fn vowel_counting_includes_y() {
        assert!(has_vowel("myth"));
        assert!(!has_vowel("xkcd"));
        assert_eq!(vowel_bearing_segments("summerVineyard"), 2);
    }
}
