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
//! command rules (see [`crate::rules`]) and the rest of a rule set (`category`,
//! `dirs`, `from`, `harnesses`, `network` = "none" | "app" | "hosts" with `hosts`), but those are a
//! **proposal**: the
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
    /// Proposed category id (checked against the built-in ones at approval).
    pub category: Option<String>,
    /// Proposed directories, as written (`PATH`, optionally `:ro` or `:rw`).
    pub dirs: Vec<String>,
    /// Proposed network: `none`, `app` or `hosts`. `None` is the file saying
    /// nothing, which proposes `app`.
    pub network: Option<String>,
    /// Proposed hosts, for `network = "hosts"`.
    pub hosts: Vec<crate::HostRule>,
    /// Proposed project roots this secret may be used from, outside the
    /// vault's own project (absolute paths, as written).
    pub from: Vec<String>,
    /// Proposed harnesses (`claude`, `codex`, `cursor`), for a connectors vault.
    pub harnesses: Vec<String>,
}

/// The rule-set part of a secret's entry, as texts, to write into the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesText {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub category: Option<String>,
    pub dirs: Vec<String>,
    /// `Some("none")` or `Some("hosts")`; `None` is `app`, the default, which
    /// is not written.
    pub network: Option<String>,
    pub hosts: Vec<String>,
    /// Project roots the secret may be used from, outside the vault's own.
    pub from: Vec<String>,
    /// Harnesses the secret is bound to, in a connectors vault.
    pub harnesses: Vec<String>,
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
                category: None,
                dirs: Vec::new(),
                network: None,
                hosts: Vec::new(),
                from: Vec::new(),
                harnesses: Vec::new(),
            };
            for (k, v) in body {
                match (k.as_str(), v) {
                    ("required", toml::Value::Boolean(b)) => entry.required = *b,
                    ("description", toml::Value::String(s)) => entry.description = s.clone(),
                    ("env", toml::Value::String(s)) if !s.is_empty() => entry.env = s.clone(),
                    ("allow", toml::Value::Array(items)) => {
                        entry.allow = rule_list(items, name, "allow", true).map_err(bad)?;
                    }
                    ("deny", toml::Value::Array(items)) => {
                        entry.deny = rule_list(items, name, "deny", false).map_err(bad)?;
                    }
                    ("category", toml::Value::String(s))
                        if !s.is_empty()
                            && s.len() <= 64
                            && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') =>
                    {
                        entry.category = Some(s.clone());
                    }
                    ("network", toml::Value::String(s))
                        if matches!(s.as_str(), "none" | "app" | "hosts") =>
                    {
                        entry.network = Some(s.clone());
                    }
                    ("dirs", toml::Value::Array(items)) => {
                        entry.dirs = string_list(items, name, "dirs").map_err(bad)?;
                    }
                    ("hosts", toml::Value::Array(items)) => {
                        entry.hosts = string_list(items, name, "hosts")
                            .map_err(bad)?
                            .iter()
                            .map(|h| rules::parse_host(h))
                            .collect::<Result<_, _>>()
                            .map_err(|e| bad(format!("[secrets.{name}].hosts: {e}")))?;
                    }
                    ("from", toml::Value::Array(items)) => {
                        entry.from = string_list(items, name, "from").map_err(bad)?;
                        if entry.from.len() > crate::MAX_FROM
                            || !entry.from.iter().all(|p| crate::portable_absolute(p))
                        {
                            return Err(bad(format!(
                                "[secrets.{name}].from must be at most {} absolute project paths",
                                crate::MAX_FROM
                            )));
                        }
                    }
                    ("harnesses", toml::Value::Array(items)) => {
                        entry.harnesses = string_list(items, name, "harnesses").map_err(bad)?;
                        if !crate::valid_harnesses(&entry.harnesses) {
                            return Err(bad(format!(
                                "[secrets.{name}].harnesses must be some of \"claude\", \"codex\", \"cursor\", each once"
                            )));
                        }
                    }
                    ("allow" | "deny" | "dirs" | "hosts" | "from" | "harnesses", _) => {
                        return Err(bad(format!(
                            "[secrets.{name}].{k} must be a list of strings"
                        )));
                    }
                    ("category", _) => {
                        return Err(bad(format!(
                            "[secrets.{name}].category must be a category id such as \"ordinary\""
                        )));
                    }
                    ("network", _) => {
                        return Err(bad(format!(
                            "[secrets.{name}].network must be \"none\", \"app\" or \"hosts\""
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
            let hosts_given = !entry.hosts.is_empty();
            match entry.network.as_deref() {
                Some("hosts") if !hosts_given => {
                    return Err(bad(format!(
                        "[secrets.{name}] has network = \"hosts\" and no hosts"
                    )));
                }
                Some("hosts") => {}
                _ if hosts_given => {
                    return Err(bad(format!(
                        "[secrets.{name}].hosts needs network = \"hosts\""
                    )));
                }
                _ => {}
            }
            secrets.insert(name.clone(), entry);
        }
    }
    Ok(Manifest {
        path: path.to_path_buf(),
        secrets,
    })
}

fn string_list(items: &[toml::Value], name: &str, key: &str) -> Result<Vec<String>, String> {
    if items.len() > 64 {
        return Err(format!("[secrets.{name}].{key} has too many entries"));
    }
    items
        .iter()
        .map(|item| match item {
            toml::Value::String(t) if !t.is_empty() && t.len() <= 512 => Ok(t.clone()),
            _ => Err(format!(
                "[secrets.{name}].{key} must be a list of non-empty strings"
            )),
        })
        .collect()
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

// --- Editing the file ------------------------------------------------------------------

fn edit_error(path: &Path, why: impl std::fmt::Display) -> Error {
    Error::Manifest(format!("cannot update {}: {why}", path.display()))
}

fn parse_doc(text: &str) -> Result<toml_edit::DocumentMut, String> {
    text.parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("invalid TOML ({})", e.message()))
}

/// `[secrets.NAME]` of `doc`, created (as a table with the header only on
/// itself, not on `[secrets]`) when it is not there.
fn secret_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    name: &str,
) -> Result<&'a mut toml_edit::Table, String> {
    use toml_edit::{Item, Table};
    let secrets = doc
        .entry("secrets")
        .or_insert_with(|| {
            let mut t = Table::new();
            t.set_implicit(true);
            Item::Table(t)
        })
        .as_table_mut()
        .ok_or("`secrets` is not a table")?;
    secrets
        .entry(name)
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| format!("[secrets.{name}] is not a table"))
}

fn rules_key(allow: bool) -> &'static str {
    if allow { "allow" } else { "deny" }
}

/// `text` (the contents of `vahta.toml`, possibly empty) with `rule` appended
/// to `[secrets.NAME].allow` or `.deny`. Comments and order are kept; a rule
/// already there is not repeated.
pub fn add_rule(text: &str, name: &str, allow: bool, rule: &str) -> Result<String, Error> {
    let path = Path::new("vahta.toml");
    let mut doc = parse_doc(text).map_err(|e| edit_error(path, e))?;
    let table = secret_table(&mut doc, name).map_err(|e| edit_error(path, e))?;
    let key = rules_key(allow);
    let item = table
        .entry(key)
        .or_insert_with(|| toml_edit::value(toml_edit::Array::new()));
    let array = item
        .as_array_mut()
        .ok_or_else(|| edit_error(path, format!("[secrets.{name}].{key} is not a list")))?;
    if !array.iter().any(|v| v.as_str() == Some(rule)) {
        array.push(rule);
    }
    Ok(doc.to_string())
}

/// `text` with `[secrets.NAME]`'s rule keys (`allow`, `deny`, `category`,
/// `dirs`, `network`, `hosts`, `from`, `harnesses`) set to exactly these (a key with nothing to say
/// is removed). Everything else is kept.
pub fn set_rules(text: &str, name: &str, rules: &RulesText) -> Result<String, Error> {
    let path = Path::new("vahta.toml");
    let mut doc = parse_doc(text).map_err(|e| edit_error(path, e))?;
    // Nothing to write and no table to write it in: leave the file alone.
    if rules == &RulesText::default() && doc.get("secrets").and_then(|s| s.get(name)).is_none() {
        return Ok(text.to_string());
    }
    let table = secret_table(&mut doc, name).map_err(|e| edit_error(path, e))?;
    let list = |items: &[String]| -> toml_edit::Item {
        toml_edit::value(
            items
                .iter()
                .map(String::as_str)
                .collect::<toml_edit::Array>(),
        )
    };
    for (key, items) in [
        ("allow", &rules.allow),
        ("deny", &rules.deny),
        ("dirs", &rules.dirs),
        ("hosts", &rules.hosts),
        ("from", &rules.from),
        ("harnesses", &rules.harnesses),
    ] {
        if items.is_empty() {
            table.remove(key);
        } else {
            table.insert(key, list(items));
        }
    }
    match &rules.category {
        Some(c) => {
            table.insert("category", toml_edit::value(c.as_str()));
        }
        None => {
            table.remove("category");
        }
    }
    match &rules.network {
        Some(n) => {
            table.insert("network", toml_edit::value(n.as_str()));
        }
        None => {
            table.remove("network");
        }
    }
    Ok(doc.to_string())
}

/// Replace the contents of `path` with `text`, through a temporary file in the
/// same directory and a rename, keeping the file's permissions (it belongs to
/// the repository, so it is not made private).
pub fn write_text(path: &Path, text: &str) -> Result<(), Error> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let suffix = crate::hex_encode(&crate::crypto::random::<8>()?);
    let tmp = dir.join(format!(".vahta.toml.tmp-{suffix}"));
    let io = |what: &str, e: std::io::Error| edit_error(path, format!("{what}: {e}"));
    let result = (|| {
        std::fs::write(&tmp, text).map_err(|e| io("write", e))?;
        if let Ok(meta) = std::fs::metadata(path) {
            std::fs::set_permissions(&tmp, meta.permissions()).map_err(|e| io("permissions", e))?;
        }
        std::fs::rename(&tmp, path).map_err(|e| io("replace", e))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The network of an approved rule set as the file spells it.
pub fn network_word(network: &crate::Network) -> &'static str {
    match network {
        crate::Network::None => "none",
        crate::Network::Hosts(_) => "hosts",
        crate::Network::App => "app",
    }
}

/// Whether the rules `vahta.toml` proposes for `entry` are the ones the vault
/// has approved: the same texts, in the same order, in the command lists, the
/// same category, directories, network and hosts. A file that says nothing
/// about network proposes `app`. A file that proposes no rules for the secret
/// never differs: only a proposal can be pending, and clearing is `bind --clear`.
pub fn rules_in_sync(entry: Option<&SecretEntry>, approved: Option<&crate::RuleSet>) -> bool {
    rules_in_sync_with(entry, approved, |_| None)
}

/// What a category adds to a proposal that does not spell it out: its deny
/// groups (put in front, as `bind` does) and its default network word.
pub type Implied = (Vec<String>, &'static str);

/// [`rules_in_sync`] on the effective rules: `implied` maps a category id to
/// what `bind` would add to the proposal, so a file that leaves out the
/// category's own denies or network still matches what was approved.
pub fn rules_in_sync_with(
    entry: Option<&SecretEntry>,
    approved: Option<&crate::RuleSet>,
    implied: impl Fn(&str) -> Option<Implied>,
) -> bool {
    let texts = |rules: &[ParsedRule]| rules.iter().map(|r| r.text.clone()).collect::<Vec<_>>();
    let approved_texts =
        |rules: &[crate::ApprovedRule]| rules.iter().map(|r| r.text.clone()).collect::<Vec<_>>();
    // A file that says nothing about a secret's rules (no entry, or an entry
    // with none of the rule keys) proposes nothing, so it differs from
    // nothing: the approved rules stand.
    let Some(e) = entry else {
        return true;
    };
    let proposes_nothing = e.allow.is_empty()
        && e.deny.is_empty()
        && e.category.is_none()
        && e.dirs.is_empty()
        && e.network.is_none()
        && e.hosts.is_empty()
        && e.from.is_empty()
        && e.harnesses.is_empty();
    if proposes_nothing {
        return true;
    }
    let Some(b) = approved else {
        return false;
    };
    let hosts_have = match &b.network {
        crate::Network::Hosts(h) => h.iter().map(|h| h.text.clone()).collect(),
        _ => Vec::new(),
    };
    let (deny, default_net) = match e.category.as_deref().and_then(&implied) {
        Some((groups, net)) => {
            let mut deny = groups.clone();
            deny.extend(texts(&e.deny).into_iter().filter(|t| !groups.contains(t)));
            (deny, net)
        }
        None => (texts(&e.deny), "app"),
    };
    texts(&e.allow) == approved_texts(&b.allow)
        && deny == approved_texts(&b.deny)
        && e.category == b.category
        && e.dirs == b.dirs.iter().map(|d| d.text.clone()).collect::<Vec<_>>()
        && e.network.as_deref().unwrap_or(default_net) == network_word(&b.network)
        && e.hosts.iter().map(|h| h.text.clone()).collect::<Vec<_>>() == hosts_have
        && e.from == b.from
        && e.harnesses == b.harnesses
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
    fn adding_a_rule_keeps_comments_and_order() {
        let text = "# project secrets\n[secrets.A]\n# the key\ndescription = \"d\"\nallow = [\"x\"]\n\n[secrets.B]\n";
        let got = add_rule(text, "A", true, "stripe").unwrap();
        assert!(
            got.contains("# project secrets") && got.contains("# the key"),
            "{got}"
        );
        assert!(got.contains("\"x\", \"stripe\""), "{got}");
        assert!(got.find("[secrets.A]").unwrap() < got.find("[secrets.B]").unwrap());
        // The same rule twice is once.
        let again = add_rule(&got, "A", true, "stripe").unwrap();
        assert_eq!(again, got);
        // It parses back as the proposal.
        let m = p(&got).unwrap();
        assert_eq!(m.secrets["A"].allow.len(), 2);
        // A name the file lacks gets a table, in an empty file too.
        let new = add_rule("", "K", false, "@network").unwrap();
        assert_eq!(new, "[secrets.K]\ndeny = [\"@network\"]\n");
        assert!(add_rule("secrets = 3\n", "K", true, "x").is_err());
        assert!(add_rule("= broken", "K", true, "x").is_err());
    }

    #[test]
    fn setting_rules_replaces_both_lists_and_removes_empty_ones() {
        let text = "[secrets.A]\nallow = [\"x\"]\ndeny = [\"@shells\"]\nenv = \"E\"\n";
        let rules = RulesText {
            allow: vec!["y".to_string()],
            ..RulesText::default()
        };
        let got = set_rules(text, "A", &rules).unwrap();
        let m = p(&got).unwrap();
        assert_eq!(m.secrets["A"].allow[0].text, "y");
        assert!(m.secrets["A"].deny.is_empty());
        assert_eq!(m.secrets["A"].env, "E");
        // Clearing a name the file does not have changes nothing.
        assert_eq!(set_rules("", "Z", &RulesText::default()).unwrap(), "");
    }

    #[test]
    fn category_dirs_network_and_hosts_round_trip_and_are_compared() {
        use crate::{DirRule, Network, RuleSet};
        let rules = RulesText {
            allow: vec!["stripe".into()],
            deny: vec!["@shells".into()],
            category: Some("payment".into()),
            dirs: vec!["./scripts".into()],
            network: Some("hosts".into()),
            hosts: vec!["api.stripe.com".into(), "*.stripe.com:443".into()],
            from: vec!["/work/app".into()],
            harnesses: vec!["claude".into(), "cursor".into()],
        };
        let text = set_rules("", "K", &rules).unwrap();
        let m = p(&text).unwrap();
        let e = &m.secrets["K"];
        assert_eq!(e.category.as_deref(), Some("payment"));
        assert_eq!(e.dirs, ["./scripts"]);
        assert_eq!(e.network.as_deref(), Some("hosts"));
        assert_eq!(e.hosts.len(), 2);
        assert!(e.hosts[1].subdomains && e.hosts[1].port == Some(443));
        assert_eq!(e.from, ["/work/app"]);
        assert_eq!(e.harnesses, ["claude", "cursor"]);
        // The vault's copy matches when it says the same; any difference shows.
        let mut approved = RuleSet {
            name: "K".into(),
            category: Some("payment".into()),
            allow: e
                .allow
                .iter()
                .map(|r| r.to_allow("/usr/bin/stripe".into()))
                .collect(),
            deny: e.deny.iter().map(ParsedRule::to_deny).collect(),
            dirs: vec![DirRule {
                text: "./scripts".into(),
                path: "/p/scripts".into(),
                write: true,
            }],
            network: Network::Hosts(e.hosts.clone()),
            from: vec!["/work/app".into()],
            harnesses: vec!["claude".into(), "cursor".into()],
            ..RuleSet::default()
        };
        assert!(rules_in_sync(Some(e), Some(&approved)));
        // So are the harnesses.
        approved.harnesses = vec!["claude".into()];
        assert!(!rules_in_sync(Some(e), Some(&approved)));
        approved.harnesses = vec!["claude".into(), "cursor".into()];
        // Where it may be used from is part of what is compared.
        approved.from = vec!["/work/other".into()];
        assert!(!rules_in_sync(Some(e), Some(&approved)));
        approved.from.clear();
        assert!(!rules_in_sync(Some(e), Some(&approved)));
        approved.from = vec!["/work/app".into()];
        approved.network = Network::App;
        assert!(!rules_in_sync(Some(e), Some(&approved)));
        approved.network = Network::Hosts(e.hosts.clone());
        approved.category = None;
        assert!(!rules_in_sync(Some(e), Some(&approved)));
        // A file that only lists commands proposes the default network.
        let old = p("[secrets.K]\nallow = [\"x\"]\n").unwrap();
        let v1 = RuleSet {
            name: "K".into(),
            allow: vec![old.secrets["K"].allow[0].to_allow("/bin/x".into())],
            network: Network::App,
            ..RuleSet::default()
        };
        assert!(rules_in_sync(Some(&old.secrets["K"]), Some(&v1)));
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
            "[secrets.A]\nnetwork = \"hosts\"\n",
            "[secrets.A]\nhosts = [\"a.com\"]\n",
            "[secrets.A]\nnetwork = \"hosts\"\nhosts = [\"https://a.com\"]\n",
            "[secrets.A]\nnetwork = \"everything\"\n",
            "[secrets.A]\ncategory = \"Pay ment\"\n",
            "[secrets.A]\ndirs = \"x\"\n",
            "[secrets.A]\nfrom = \"/x\"\n",
            "[secrets.A]\nfrom = [\"relative/dir\"]\n",
            "[secrets.A]\nharnesses = [\"vim\"]\n",
            "[secrets.A]\nharnesses = [\"claude\", \"claude\"]\n",
            "[secrets.A]\nharnesses = \"claude\"\n",
            "secrets = 3\n",
            "[other]\n",
            "= broken",
        ] {
            assert!(matches!(p(bad), Err(Error::Manifest(_))), "{bad}");
        }
        assert!(p("").unwrap().secrets.is_empty());
    }
}
