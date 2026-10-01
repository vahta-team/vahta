//! Dump primitive outputs for a list of inputs, one per line on stdin.
//!
//! Exists so the Python implementation and this one can be compared over many
//! inputs instead of over the handful a person thinks to write down. The
//! format is deliberately dumb: tab-separated, shortest round-trip floats, so
//! a byte-for-byte diff is the comparison.

use std::io::{self, Read, Write};
use vahta_detect::{classify_value, entropy, transition_rate, vowel_bearing_segments, word_segments};

fn main() -> io::Result<()> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let out = io::stdout();
    let mut out = out.lock();

    for line in raw.lines() {
        // Inputs are escaped by the generator so a tab or newline inside a
        // case cannot corrupt the record separator.
        let value = unescape(line);
        let (tier, reason) = classify_value(&value);
        writeln!(
            out,
            "{}\t{:?}\t{:?}\t{}\t{:?}\t{}\t{}",
            line,
            entropy(&value),
            transition_rate(&value),
            vowel_bearing_segments(&value),
            word_segments(&value),
            tier.as_str(),
            reason.unwrap_or("-"),
        )?;
    }
    Ok(())
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}
