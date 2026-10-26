//! Source code that talks about passwords without holding one: a QML lock
//! screen, written out the way an agent sends it (as a Python string with
//! spelled-out `\n` and `\"`). Every line is built from pieces at run time.

use vahta_detect::find_secret;

fn word() -> String {
    ["Pass", "word"].concat()
}

/// The lock screen lines, with the word in the cases QML uses.
fn lines() -> Vec<String> {
    let p = word();
    let l = p.to_lowercase();
    vec![
        format!("pending{p} = {l}"),
        format!("pending{p} = {p}"),
        format!("{l} = pending{p}"),
        format!("pending{p}: {l}Field.text"),
        format!("root.{l} = field.text"),
        format!("if (!lockRequested || authenticating{p} || {l}.length === 0) return"),
        format!("readonly property string placeholderText: \"Enter {p}\""),
        format!("{l}Label: \"Enter your {p} here\""),
        format!("if (submitted.length > 0) root.submit{p}(submitted)"),
        format!("echoMode: TextInput.{p}"),
    ]
}

/// A file as source code carries it inside a string: newlines and quotes spelled out.
fn escaped(lines: &[String]) -> String {
    lines
        .join("\n    ")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[test]
fn qml_lines_are_not_findings_alone_or_together() {
    let lines = lines();
    for line in &lines {
        assert!(find_secret(line).is_none(), "plain: {line:?}");
        let one = escaped(std::slice::from_ref(line));
        assert!(find_secret(&one).is_none(), "escaped: {one:?}");
        let with_next = escaped(&[line.clone(), "signal unlocked()".to_string()]);
        assert!(
            find_secret(&with_next).is_none(),
            "escaped+next: {with_next:?}"
        );
    }
    assert!(find_secret(&lines.join("\n")).is_none());
    assert!(find_secret(&escaped(&lines)).is_none());
}

#[test]
fn a_literal_value_is_still_a_finding() {
    let p = word();
    let l = p.to_lowercase();
    let value = ["hunt", "er2x", "Yz9Q", "kLm4"].concat();
    for text in [
        format!("{l} = \"{value}\""),
        format!("pending{p} = '{value}'"),
        format!("{l}: {value}"),
        format!("{}={value}", l.to_uppercase()),
        format!("{}: s3cr3t-value-123", l.to_uppercase()),
        format!("{l} = {value}\\n    next"),
    ] {
        let f = find_secret(&text);
        assert!(f.is_some(), "missed: {text:?}");
        assert_eq!(f.unwrap().rule, "vahta.assignment", "{text:?}");
    }
    // A bare camelCase word with no space before the separator may be the value.
    let phrase = ["correct", "Horse", "Battery", "Staple"].concat();
    for text in [
        format!("{}={phrase}", l.to_uppercase()),
        format!("{l}: {phrase}"),
    ] {
        assert!(find_secret(&text).is_some(), "missed: {text:?}");
    }
}

#[test]
fn connection_strings_and_flags_are_still_findings() {
    let value = ["hunt", "er2x", "Yz9Q", "kLm4"].concat();
    let dsn = format!("postgres://app:{value}@db.example/x");
    assert_eq!(find_secret(&dsn).unwrap().rule, "vahta.connection-string");
    let flag = format!("mysql -u root -p{value} -h db");
    assert!(find_secret(&flag).is_some());
}
