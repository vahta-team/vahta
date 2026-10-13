//! A typed value that has whitespace where a secret never does.
//!
//! A pasted token often carries a trailing line break or a space, and then
//! every use fails with a 401 that explains nothing. [`check`] says which
//! problems a value has, and [`describe`] names them in words. Neither ever
//! returns or prints any part of the value.

/// What is wrong with a value, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Problems {
    /// Whitespace (a space, a tab or a line break) before the first character.
    pub leading: bool,
    /// Whitespace after the last character.
    pub trailing: bool,
    /// A line break between the first and last character.
    pub line_break: bool,
    /// A tab or another control character between the first and last character.
    pub control: bool,
}

impl Problems {
    pub fn any(&self) -> bool {
        self.leading || self.trailing || self.line_break || self.control
    }

    /// Trimming the ends fixes all of it.
    pub fn only_edges(&self) -> bool {
        !self.line_break && !self.control
    }
}

/// Whether `value` looks like a PEM block, which is legitimately many lines.
pub(crate) fn looks_like_pem(value: &str) -> bool {
    value.contains("-----BEGIN ") && value.contains("-----END ")
}

/// The problems of `value`. With `multiline` (a file secret, or a PEM block)
/// line breaks are expected: those inside are not reported, and line breaks at
/// the end are not either (files end with one).
pub(crate) fn check(value: &str, multiline: bool) -> Problems {
    let is_break = |c: char| c == '\n' || c == '\r';
    let end = if multiline {
        value.trim_end_matches(is_break)
    } else {
        value
    };
    let trimmed = end.trim();
    let mut p = Problems {
        leading: end.starts_with(char::is_whitespace),
        trailing: end.len() > end.trim_end().len(),
        ..Problems::default()
    };
    for c in trimmed.chars() {
        if is_break(c) {
            p.line_break |= !multiline;
        } else if c.is_control() {
            p.control = true;
        }
    }
    p
}

/// The problems in plain words, one sentence each, never the value.
pub(crate) fn describe(p: &Problems) -> String {
    let mut parts = Vec::new();
    if p.leading {
        parts.push("starts with a space, a tab or a line break");
    }
    if p.trailing {
        parts.push("ends with a space, a tab or a line break");
    }
    if p.line_break {
        parts.push("has a line break inside it");
    }
    if p.control {
        parts.push("has a tab or another invisible character inside it");
    }
    let joined = match parts.as_slice() {
        [] => String::new(),
        [one] => one.to_string(),
        [init @ .., last] => format!("{}, and {last}", init.join(", ")),
    };
    format!(
        "The value you typed {joined}. A key almost never does, and one that does is usually refused when used."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word() -> String {
        ["ab", "cd", "12"].concat()
    }

    #[test]
    fn a_clean_value_has_no_problems() {
        assert!(!check(&word(), false).any());
        assert!(!check("two words", false).line_break);
    }

    #[test]
    fn edges_are_found() {
        let w = word();
        let p = check(&format!("{w} "), false);
        assert!(p.trailing && !p.leading && p.only_edges());
        let p = check(&format!("\n{w}"), false);
        assert!(p.leading && !p.trailing);
        let p = check(&format!(" {w}\r\n"), false);
        assert!(p.leading && p.trailing && p.only_edges());
        assert!(check(&format!("{w}\t"), false).trailing);
    }

    #[test]
    fn inner_problems_are_found_and_cannot_be_trimmed() {
        let w = word();
        let p = check(&format!("{w}\n{w}"), false);
        assert!(p.line_break && !p.only_edges());
        let p = check(&format!("{w}\t{w}"), false);
        assert!(p.control && !p.line_break);
        let p = check(&format!("{w}\u{7}{w}"), false);
        assert!(p.control);
    }

    #[test]
    fn multiline_values_are_not_nagged_for_their_lines() {
        let w = word();
        let pem = format!("-----BEGIN X-----\n{w}\n{w}\n-----END X-----\n");
        assert!(looks_like_pem(&pem));
        assert!(!check(&pem, true).any());
        assert!(!check(&pem.replace('\n', "\r\n"), true).any());
        // Still caught: spaces around it, or a stray invisible character.
        assert!(check(&format!(" {pem}"), true).leading);
        assert!(check(&format!("{pem}  "), true).trailing);
        assert!(check(&format!("{w}\u{7}\n{w}"), true).control);
        // A plain value still is nagged.
        assert!(check(&format!("{w}\n"), false).trailing);
    }

    #[test]
    fn the_words_name_the_problem_and_not_the_value() {
        let w = word();
        let said = describe(&check(&format!("{w} "), false));
        assert!(said.contains("ends with") && !said.contains(&w));
        let said = describe(&check(&format!(" {w}\n{w}\t"), false));
        assert!(said.contains("starts with") && said.contains("line break inside"));
    }
}
