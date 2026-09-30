//! Dump full detector output for inputs read from stdin, one escaped line each.
//!
//! The companion to `benchmarks/diff_hits.py`. Together they answer the only
//! question that matters for the port: does this implementation say exactly
//! what Python says, on inputs nobody hand-picked?

use std::io::{self, Read, Write};
use vahta_detect::{find_secret_kind, scan_text_hits};

fn main() -> io::Result<()> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let out = io::stdout();
    let mut out = out.lock();

    for line in raw.lines() {
        let value = unescape(line);
        let h = scan_text_hits(&value);
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            line,
            list(&h.likely_names),
            list(&h.possible_names),
            h.prefix.unwrap_or("-"),
            h.bearer_likely,
            h.bearer_possible,
            list(&h.likely_reasons),
            list(&h.possible_reasons),
            list(&h.flag_names),
            find_secret_kind(&value).unwrap_or_else(|| "-".to_string()),
        )?;
    }
    Ok(())
}

fn list(items: &[String]) -> String {
    format!("[{}]", items.join(","))
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
