//! `vahta.toml`: the committed contract of secret *names* a project expects.
//!
//! The schema is ka's `amnesia.toml`:
//!
//! ```toml
//! [secrets.OPENAI_API_KEY]
//! required = true
//! description = "OpenAI API key"
//! env = "OPENAI_API_KEY"
//! ```
//!
//! `required` defaults to true, `description` to empty and `env` to the name.
//! It never holds a value or a tier. It may hold `allow` and `deny` lists of
//! command rules (see [`crate::rules`]), but those are a **proposal**: the
//! file is in the repository, so anyone who can push can edit it. What the
//! daemon enforces is the approved copy in the signed vault, which changes
//! only when the person approves it in a window with the password. So the
//! invariant holds: nothing in this file changes what the vault does.
//! Unknown keys are refused rather than ignored, so a typo such as
//! `requried` cannot silently turn a check off.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::rules::{self, ParsedRule};
use crate::{Error, valid_name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEntry {
    pub name: String,
    pub required: bool,
    pub description: String,
    pub env: String,
    /// Proposed `allow` rules, in file order. Not enforced until approved.
    pub allow: Vec<ParsedRule>,
    /// Proposed `deny` rules, in file order. Not enforced until approved.
    pub deny: Vec<ParsedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub path: PathBuf,
    pub secrets: BTreeMap<String, SecretEntry>,
}

/// The largest `vahta.toml` read; a contract of names is small.
const MAX_MANIFEST: u64 = 1 << 20;

pub fn load(path: &Path) -> Result<Manifest, Error> {
    let shown = path.display();
    let len = std::fs::metadata(path)
        .map_err(|e| Error::Manifest(format!("cannot read {shown}: {e}")))?
        .len();
    if len > MAX_MANIFEST {
        return Err(Error::Manifest(format!("{shown} is too large")));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Manifest(format!("cannot read {shown}: {e}")))?;
    parse(&text, path)
}

pub fn parse(text: &str, path: &Path) -> Result<Manifest, Error> {
    let shown = path.display();
    let bad = |msg: String| Error::Manifest(format!("{msg} in {shown}"));
    let root: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| bad(format!("invalid TOML ({})", e.message())))?;

    let mut secrets = BTreeMap::new();
    for (key, value) in &root {
        if key != "secrets" {
            return Err(bad(format!("unknown top-level key `{key}`")));
        }
        let toml::Value::Table(table) = value else {
            return Err(bad("[secrets] must be a table of named entries".to_string()));
        };
        for (name, body) in table {
            if !valid_name(name) {
                return Err(bad(format!("invalid secret name `{name}`")));
            }
            let toml::Value::Table(body) = body else {
                return Err(bad(format!("[secrets.{name}] must be a table")));
            };
            let mut entry = SecretEntry {
                name: name.clone(),
                required: true,
                description: String::new(),
                env: name.clone(),
                allow: Vec::new(),
                deny: Vec::new(),
            };
            for (k, v) in body {
                match (k.as_str(), v) {
                    ("required", toml::Value::Boolean(b)) => entry.required = *b,
                    ("description", toml::Value::String(s)) => entry.description = s.clone(),
                    ("env", toml::Value::String(s)) if !s.is_empty() => entry.env = s.clone(),
                    ("allow", toml::Value::Array(items)) => {
                        entry.allow = rule_list(items, name, "allow", true).map_err(&bad)?;
                    }
                    ("deny", toml::Value::Array(items)) => {
                        entry.deny = rule_list(items, name, "deny", false).map_err(&bad)?;
                    }
                    ("allow" | "deny", _) => {
                        return Err(bad(format!(
                            "[secrets.{name}].{k} must be a list of strings"
                        )));
                    }
                    ("required", _) => {
                        return Err(bad(format!("[secrets.{name}].required must be a boolean")));
                    }
                    ("description", _) => {
                        return Err(bad(format!(
                            "[secrets.{name}].description must be a string"
                        )));
                    }
                    ("env", _) => {
                        return Err(bad(format!(
                            "[secrets.{name}].env must be a non-empty string"
                        )));
                    }
                    (other, _) => {
                        return Err(bad(format!("unknown key `{other}` in [secrets.{name}]")));
                    }
                }
            }
            secrets.insert(name.clone(), entry);
        }
    }
    Ok(Manifest {
        path: path.to_path_buf(),
        secrets,
    })
}

fn rule_list(
    items: &[toml::Value],
    name: &str,
    key: &str,
    allow: bool,
) -> Result<Vec<ParsedRule>, String> {
    if items.len() > 64 {
        return Err(format!("[secrets.{name}].{key} has too many rules"));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let toml::Value::String(text) = item else {
            return Err(format!("[secrets.{name}].{key} must be a list of strings"));
        };
        let rule =
            rules::parse_rule(text, allow).map_err(|e| format!("[secrets.{name}].{key}: {e}"))?;
        out.push(rule);
    }
    Ok(out)
}

/// The outcome of comparing a manifest with the names in a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub ok: bool,
    pub required: Vec<String>,
    pub present: Vec<String>,
    pub missing: Vec<String>,
    /// Optional names the vault does not have: reported, never a failure.
    pub optional_absent: Vec<String>,
}

pub fn check_against_names(manifest: &Manifest, present_names: &[String]) -> CheckResult {
    let has = |n: &String| present_names.contains(n);
    let required: Vec<String> = manifest
        .secrets
        .values()
        .filter(|e| e.required)
        .map(|e| e.name.clone())
        .collect();
    let present: Vec<String> = required.iter().filter(|n| has(n)).cloned().collect();
    let missing: Vec<String> = required.iter().filter(|n| !has(n)).cloned().collect();
    let optional_absent = manifest
        .secrets
        .values()
        .filter(|e| !e.required && !has(&e.name))
        .map(|e| e.name.clone())
        .collect();
    CheckResult {
        ok: missing.is_empty(),
        required,
        present,
        missing,
        optional_absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Result<Manifest, Error> {
        parse(text, Path::new("vahta.toml"))
    }

    #[test]
    fn defaults_and_check() {
        let m = p("[secrets.A]\n[secrets.B]\nrequired = false\nenv = \"B_ENV\"\ndescription = \"d\"\n[secrets.C]\n").unwrap();
        assert!(m.secrets["A"].required);
        assert_eq!(m.secrets["A"].env, "A");
        assert_eq!(m.secrets["B"].env, "B_ENV");
        let r = check_against_names(&m, &["A".to_string()]);
        assert!(!r.ok);
        assert_eq!(r.missing, vec!["C"]);
        assert_eq!(r.optional_absent, vec!["B"]);
        assert_eq!(r.present, vec!["A"]);
    }

    #[test]
    fn reads_allow_and_deny() {
        let m = p(
            "[secrets.A]\nallow = [\"stripe\", \"git push\"]\ndeny = [\"@network\", \"@shells\"]\n",
        )
        .unwrap();
        let a = &m.secrets["A"];
        assert_eq!(a.allow.len(), 2);
        assert_eq!(a.allow[1].args, vec!["push"]);
        assert_eq!(a.deny[0].text, "@network");
        assert!(p("[secrets.B]\n").unwrap().secrets["B"].allow.is_empty());
    }

    #[test]
    fn refuses_what_it_cannot_trust() {
        for bad in [
            "[secrets.A]\nrequried = false\n",
            "[secrets.A]\nrequired = \"yes\"\n",
            "[secrets.\"not a name\"]\n",
            "[secrets.A]\nenv = \"\"\n",
            "[secrets.A]\nallow = \"curl\"\n",
            "[secrets.A]\nallow = [3]\n",
            "[secrets.A]\nallow = [\"@shells\"]\n",
            "[secrets.A]\ndeny = [\"@nope\"]\n",
            "[secrets.A]\nallow = [\"\"]\n",
            "[secrets.A]\nallow = [\"git 'push'\"]\n",
            "secrets = 3\n",
            "[other]\n",
            "= broken",
        ] {
            assert!(matches!(p(bad), Err(Error::Manifest(_))), "{bad}");
        }
        assert!(p("").unwrap().secrets.is_empty());
    }
}
