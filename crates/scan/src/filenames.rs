//! Classifying a file by its name alone, before anything is read.
//!
//! Ported from `key_amnesia.scan_py`. Paths are handled as `/`-separated strings
//! rather than platform paths, because the Python side compares
//! `path.as_posix()` and matching that exactly matters more than looking
//! idiomatic.

/// `.env`, `.env.local`, `.env.production` — but not `.environment`, and not
/// a `.imported` leftover from a previous migration.
pub fn is_dotenv_filename(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    if let Some(rest) = name.strip_prefix(".env.") {
        let _ = rest;
        return !name.ends_with(".imported");
    }
    false
}

const SSH_PRIVATE_NAMES: [&str; 4] = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

const MCP_BASENAMES: [&str; 2] = ["mcp.json", "claude_desktop_config.json"];

const HISTORY_BASENAMES: [&str; 6] = [
    ".bash_history",
    ".zsh_history",
    ".zhistory",
    ".python_history",
    ".node_repl_history",
    ".lesshst",
];

/// Text-ish extensions worth content-scanning for assignment patterns.
///
/// The empty string is in the list on purpose: an extensionless file such as
/// `Dockerfile` or a shell script without a suffix is exactly where a
/// credential gets pasted.
const CONTENT_SCAN_SUFFIXES: [&str; 33] = [
    "",
    ".env",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".txt",
    ".md",
    ".properties",
    ".xml",
    ".rb",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".php",
];

/// The kind a filename alone implies, or `None`.
///
/// `posix_path` is the whole path with `/` separators, as Python's
/// `path.as_posix()` produces; `name` is its final component. Both are passed
/// because the `mcp.json` rule looks at the path and everything else at the
/// name, and deriving one from the other here would only invite them to
/// disagree.
pub fn filename_kind(posix_path: &str, name: &str) -> Option<&'static str> {
    if is_dotenv_filename(name) {
        return Some("dotenv");
    }
    if name == "credentials.json" {
        return Some("credentials.json");
    }
    if name == ".npmrc" {
        return Some(".npmrc");
    }
    if name == ".pypirc" {
        return Some(".pypirc");
    }
    if SSH_PRIVATE_NAMES.contains(&name) {
        return Some("ssh_private_key");
    }
    if MCP_BASENAMES.contains(&name) || name == "mcp.json" || posix_path.ends_with("/mcp.json") {
        return Some("mcp_config");
    }
    if HISTORY_BASENAMES.contains(&name) || name.ends_with("_history") {
        return Some("shell_history");
    }
    if name == ".gitconfig" || name == ".git-credentials" {
        return Some("git_config");
    }
    None
}

/// Python's `Path.suffix`.
///
/// Not a plain `rsplit('.')`. A name that *begins* with a dot and has no other
/// one — `.env`, `.npmrc`, `.gitconfig` — has **no** suffix in pathlib's
/// model, and treating `.npmrc` as the suffix `.npmrc` would change which
/// files get content-scanned. A trailing dot does yield `"."`, verified
/// against the interpreter rather than assumed.
///
/// `.` and `..` are deliberately not special-cased: they are directory names,
/// and this is only ever asked about a file the walker reached.
pub fn suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[i..],
        _ => "",
    }
}

/// Names that are content-scanned despite their suffix.
const CONTENT_SCAN_NAMES: [&str; 3] = ["Dockerfile", "Makefile", "Jenkinsfile"];

/// Is this file worth reading for inline assignments?
pub fn is_content_scannable(name: &str) -> bool {
    // `path.suffix.lower()` is Unicode: a suffix spelled with the Kelvin
    // sign, `.\u{212a}t`, lowers to `.kt` and is scanned. `to_lowercase`
    // agrees with Python on it; `to_ascii_lowercase` did not.
    let s = suffix(name).to_lowercase();
    CONTENT_SCAN_SUFFIXES.contains(&s.as_str()) || CONTENT_SCAN_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_variants() {
        assert!(is_dotenv_filename(".env"));
        assert!(is_dotenv_filename(".env.local"));
        assert!(is_dotenv_filename(".env.production"));
        assert!(!is_dotenv_filename(".env.local.imported"));
        assert!(!is_dotenv_filename(".environment"));
        assert!(!is_dotenv_filename("env"));
    }

    /// Every expectation read out of the interpreter, not reasoned about.
    #[test]
    fn suffix_matches_pathlib() {
        assert_eq!(suffix("a.py"), ".py");
        assert_eq!(suffix("archive.tar.gz"), ".gz");
        assert_eq!(suffix("Dockerfile"), "");
        assert_eq!(suffix("logo.PNG"), ".PNG");
        // Leading-dot names have no suffix in pathlib's model.
        assert_eq!(suffix(".env"), "");
        assert_eq!(suffix(".npmrc"), "");
        assert_eq!(suffix(".gitconfig"), "");
        assert_eq!(suffix(".env.local"), ".local");
        assert_eq!(suffix(".env.local.imported"), ".imported");
        // A trailing dot does yield a suffix.
        assert_eq!(suffix("x."), ".");
    }

    #[test]
    fn kinds_by_name() {
        assert_eq!(filename_kind("/p/.env", ".env"), Some("dotenv"));
        assert_eq!(
            filename_kind("/p/id_rsa", "id_rsa"),
            Some("ssh_private_key")
        );
        assert_eq!(filename_kind("/p/.npmrc", ".npmrc"), Some(".npmrc"));
        assert_eq!(filename_kind("/p/mcp.json", "mcp.json"), Some("mcp_config"));
        assert_eq!(
            filename_kind("/p/.bash_history", ".bash_history"),
            Some("shell_history")
        );
        assert_eq!(
            filename_kind("/p/my_history", "my_history"),
            Some("shell_history")
        );
        assert_eq!(filename_kind("/p/main.py", "main.py"), None);
    }

    #[test]
    fn extensionless_files_are_content_scanned() {
        assert!(is_content_scannable("Dockerfile"));
        assert!(is_content_scannable("main.py"));
        assert!(is_content_scannable(".env"));
        assert!(!is_content_scannable("logo.png"));
        assert!(!is_content_scannable("archive.tar.gz"));
    }
}
