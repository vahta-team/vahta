//! Reading a `.env` file for `vahta import --dotenv`.
//!
//! The daemon reads the file itself, so its values never pass through the
//! command line. The format is the common one: `NAME=value` lines, an optional
//! `export `, blank lines and `#` comments, single-quoted values taken as they
//! are, double-quoted values with the usual escapes, and unquoted values ending
//! at an inline ` #` comment. A line that is not that, or a name that is not a
//! valid secret name, refuses the whole file, naming the line number and never
//! its content.

use vahta_vault::{SecretValue, valid_name};

/// The largest file read.
pub const MAX_DOTENV: u64 = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct Parsed {
    pub items: Vec<(String, Vec<u8>)>,
    /// Names with an empty value, which are skipped: an empty value cannot be
    /// scrubbed from output and is not a secret.
    pub skipped_empty: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DotenvError {
    pub line: usize,
    pub what: &'static str,
}

impl std::fmt::Display for DotenvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.what)
    }
}

pub fn parse(text: &str) -> Result<Parsed, DotenvError> {
    let mut items: Vec<(String, Vec<u8>)> = Vec::new();
    let mut skipped_empty = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line_no = n + 1;
        let err = |what| DotenvError {
            line: line_no,
            what,
        };
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let (name, value) = line.split_once('=').ok_or_else(|| err("not NAME=value"))?;
        let name = name.trim();
        if !valid_name(name) {
            return Err(err("not a valid secret name"));
        }
        let value = value.trim_start();
        let value = match value.chars().next() {
            Some('\'') => {
                let rest = &value[1..];
                let end = rest.find('\'').ok_or_else(|| err("unterminated quote"))?;
                if !rest[end + 1..].trim().is_empty() && !rest[end + 1..].trim().starts_with('#') {
                    return Err(err("text after the closing quote"));
                }
                rest[..end].to_string()
            }
            Some('"') => {
                let mut out = String::new();
                let mut chars = value[1..].chars();
                let mut closed = false;
                let mut tail = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => {
                            closed = true;
                            tail = chars.collect();
                            break;
                        }
                        '\\' => match chars.next() {
                            Some('n') => out.push('\n'),
                            Some('r') => out.push('\r'),
                            Some('t') => out.push('\t'),
                            Some(other) => out.push(other),
                            None => return Err(err("unterminated quote")),
                        },
                        c => out.push(c),
                    }
                }
                if !closed {
                    return Err(err("unterminated quote"));
                }
                if !tail.trim().is_empty() && !tail.trim().starts_with('#') {
                    return Err(err("text after the closing quote"));
                }
                out
            }
            _ => {
                // Unquoted: up to an inline comment, trimmed.
                let end = value.find(" #").unwrap_or(value.len());
                value[..end].trim_end().to_string()
            }
        };
        if value.is_empty() {
            skipped_empty.push(name.to_string());
            continue;
        }
        // A name repeated later replaces the earlier one, as a shell sourcing
        // the file would.
        items.retain(|(n, _)| n != name);
        items.push((name.to_string(), value.into_bytes()));
    }
    Ok(Parsed {
        items,
        skipped_empty,
    })
}

impl Parsed {
    pub fn into_secrets(self) -> Vec<(String, SecretValue)> {
        self.items
            .into_iter()
            .map(|(n, v)| (n, SecretValue::new(v)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Parsed {
        parse(text).unwrap()
    }

    fn get<'a>(parsed: &'a Parsed, name: &str) -> &'a [u8] {
        &parsed.items.iter().find(|(n, _)| n == name).unwrap().1
    }

    #[test]
    fn the_common_forms() {
        let parsed = p(
            "# a comment\n\nA=fake-one\nexport B = fake two # inline\nC='fa#ke \"three\"'\nD=\"line\\nbreak \\\"q\\\"\"\nE=\n",
        );
        assert_eq!(get(&parsed, "A"), b"fake-one");
        assert_eq!(get(&parsed, "B"), b"fake two");
        assert_eq!(get(&parsed, "C"), b"fa#ke \"three\"");
        assert_eq!(get(&parsed, "D"), b"line\nbreak \"q\"");
        assert_eq!(parsed.skipped_empty, ["E"]);
        assert_eq!(parsed.items.len(), 4);
    }

    #[test]
    fn a_later_definition_wins_and_a_hash_without_a_space_stays() {
        let parsed = p("A=one\nA=two\nB=x#y\n");
        assert_eq!(get(&parsed, "A"), b"two");
        assert_eq!(get(&parsed, "B"), b"x#y");
        assert_eq!(parsed.items.len(), 2);
    }

    #[test]
    fn a_bad_line_refuses_the_file_without_quoting_it() {
        for (bad, line) in [
            ("A=ok\nnot an assignment\n", 2),
            ("1BAD=x\n", 1),
            ("A='open\n", 1),
            ("A=\"open\n", 1),
            ("A='x' y\n", 1),
            ("bad name=x\n", 1),
        ] {
            let e = parse(bad).unwrap_err();
            assert_eq!(e.line, line, "{bad}");
            assert!(!e.to_string().contains("open"));
        }
    }
}
