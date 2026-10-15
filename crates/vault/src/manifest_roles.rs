//! `[roles.NAME]` in `vahta.toml`: the proposal of an agent role.
//!
//! ```toml
//! [roles.deploy-check]
//! secrets = ["STRIPE_KEY"]
//! allow = ["stripe balance"]
//! deny = ["@shells"]
//! network = "hosts"
//! hosts = ["api.stripe.com"]
//! dirs = ["."]
//! for = "2h"
//! uses = 20
//! actions = ["run", "http"]
//! ask = false
//! ```
//!
//! Like a secret's rules this is a **proposal**: the file is in the repository,
//! so anyone who can push can edit it. What the daemon enforces is the role the
//! person approved, stored signed in the vault; `vahta role NAME` shows the
//! person what the file proposes and, on approval, stores it. A role whose
//! file text differs from the approved one takes no effect as written: the
//! vault's copy stands.
//!
//! Role names are shaped like secret names. Unknown keys are refused.

use std::collections::BTreeMap;

use crate::manifest::{network_word, parse_doc};
use crate::rules::{self, ParsedRule};
use crate::{Action, AgentRole, Error, HostRule, MAX_ROLE_SECRETS, MAX_ROLES, valid_name};

/// One role as the file proposes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleEntry {
    pub name: String,
    /// The secrets the role covers, in file order.
    pub secrets: Vec<String>,
    pub allow: Vec<ParsedRule>,
    pub deny: Vec<ParsedRule>,
    /// `none`, `app` or `hosts`; `None` is the file saying nothing, which
    /// leaves each secret's own network.
    pub network: Option<String>,
    pub hosts: Vec<HostRule>,
    /// Directories as written (`PATH`, optionally `:ro` or `:rw`).
    pub dirs: Vec<String>,
    /// The longest one grant lasts, in seconds.
    pub max_for_secs: Option<u64>,
    /// The most uses one grant gives.
    pub max_uses: Option<u32>,
    /// `run` and/or `http`; a file that says nothing proposes `run` only.
    pub actions: Vec<Action>,
    pub ask_each_use: bool,
}

/// The longest duration a role may name: a year.
const MAX_SPAN: u64 = 366 * 24 * 3600;

/// `90s`, `30m`, `2h`, `1h30m`, `2d`: units only.
pub fn parse_span(text: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut any = false;
    for c in text.trim().chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit: u64 = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => return None,
        };
        let n: u64 = digits.parse().ok()?;
        digits.clear();
        total = total.checked_add(n.checked_mul(unit)?)?;
        any = true;
    }
    (digits.is_empty() && any && total > 0 && total <= MAX_SPAN).then_some(total)
}

fn strings(items: &[toml::Value], name: &str, key: &str) -> Result<Vec<String>, String> {
    if items.len() > 64 {
        return Err(format!("[roles.{name}].{key} has too many entries"));
    }
    items
        .iter()
        .map(|item| match item {
            toml::Value::String(t) if !t.is_empty() && t.len() <= 512 => Ok(t.clone()),
            _ => Err(format!(
                "[roles.{name}].{key} must be a list of non-empty strings"
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
    strings(items, name, key)?
        .iter()
        .map(|t| rules::parse_rule(t, allow).map_err(|e| format!("[roles.{name}].{key}: {e}")))
        .collect()
}

/// The `[roles]` table of a manifest. The error is a sentence without the
/// file name (the caller adds it).
pub(crate) fn parse_roles(value: &toml::Value) -> Result<BTreeMap<String, RoleEntry>, String> {
    let toml::Value::Table(table) = value else {
        return Err("[roles] must be a table of named entries".to_string());
    };
    if table.len() > MAX_ROLES {
        return Err(format!("at most {MAX_ROLES} roles"));
    }
    let mut out = BTreeMap::new();
    for (name, body) in table {
        if !valid_name(name) {
            return Err(format!("invalid role name `{name}`"));
        }
        let toml::Value::Table(body) = body else {
            return Err(format!("[roles.{name}] must be a table"));
        };
        let mut e = RoleEntry {
            name: name.clone(),
            secrets: Vec::new(),
            allow: Vec::new(),
            deny: Vec::new(),
            network: None,
            hosts: Vec::new(),
            dirs: Vec::new(),
            max_for_secs: None,
            max_uses: None,
            actions: vec![Action::Run],
            ask_each_use: false,
        };
        for (k, v) in body {
            match (k.as_str(), v) {
                ("secrets", toml::Value::Array(items)) => {
                    e.secrets = strings(items, name, "secrets")?;
                    if e.secrets.len() > MAX_ROLE_SECRETS
                        || !e
                            .secrets
                            .iter()
                            .enumerate()
                            .all(|(i, s)| valid_name(s) && !e.secrets[..i].contains(s))
                    {
                        return Err(format!(
                            "[roles.{name}].secrets must be at most {MAX_ROLE_SECRETS} secret \
                             names, each once"
                        ));
                    }
                }
                ("allow", toml::Value::Array(items)) => {
                    e.allow = rule_list(items, name, "allow", true)?;
                }
                ("deny", toml::Value::Array(items)) => {
                    e.deny = rule_list(items, name, "deny", false)?;
                }
                ("dirs", toml::Value::Array(items)) => e.dirs = strings(items, name, "dirs")?,
                ("hosts", toml::Value::Array(items)) => {
                    e.hosts = strings(items, name, "hosts")?
                        .iter()
                        .map(|h| rules::parse_host(h))
                        .collect::<Result<_, _>>()
                        .map_err(|err| format!("[roles.{name}].hosts: {err}"))?;
                }
                ("network", toml::Value::String(s))
                    if matches!(s.as_str(), "none" | "app" | "hosts") =>
                {
                    e.network = Some(s.clone());
                }
                ("for", toml::Value::String(s)) => {
                    e.max_for_secs = Some(parse_span(s).ok_or_else(|| {
                        format!(
                            "[roles.{name}].for must be a duration such as \"30m\", \"2h\" or \
                             \"1h30m\" (at most a year)"
                        )
                    })?);
                }
                ("uses", toml::Value::Integer(n)) if (1..=i64::from(u32::MAX)).contains(n) => {
                    e.max_uses = u32::try_from(*n).ok();
                }
                ("actions", toml::Value::Array(items)) => {
                    let words = strings(items, name, "actions")?;
                    let mut actions = Vec::new();
                    for w in &words {
                        let a = match w.as_str() {
                            "run" => Action::Run,
                            "http" => Action::Http,
                            _ => {
                                return Err(format!(
                                    "[roles.{name}].actions holds \"run\" and/or \"http\""
                                ));
                            }
                        };
                        if actions.contains(&a) {
                            return Err(format!("[roles.{name}].actions names `{w}` twice"));
                        }
                        actions.push(a);
                    }
                    if actions.is_empty() {
                        return Err(format!("[roles.{name}].actions must not be empty"));
                    }
                    e.actions = actions;
                }
                ("ask", toml::Value::Boolean(b)) => e.ask_each_use = *b,
                ("secrets" | "allow" | "deny" | "dirs" | "hosts" | "actions", _) => {
                    return Err(format!("[roles.{name}].{k} must be a list of strings"));
                }
                ("network", _) => {
                    return Err(format!(
                        "[roles.{name}].network must be \"none\", \"app\" or \"hosts\""
                    ));
                }
                ("for", _) => {
                    return Err(format!("[roles.{name}].for must be a duration string"));
                }
                ("uses", _) => {
                    return Err(format!(
                        "[roles.{name}].uses must be a whole number from 1 up"
                    ));
                }
                ("ask", _) => return Err(format!("[roles.{name}].ask must be a boolean")),
                (other, _) => return Err(format!("unknown key `{other}` in [roles.{name}]")),
            }
        }
        match e.network.as_deref() {
            Some("hosts") if e.hosts.is_empty() => {
                return Err(format!(
                    "[roles.{name}] has network = \"hosts\" and no hosts"
                ));
            }
            Some("hosts") => {}
            _ if !e.hosts.is_empty() => {
                return Err(format!("[roles.{name}].hosts needs network = \"hosts\""));
            }
            _ => {}
        }
        if e.secrets.is_empty() {
            return Err(format!("[roles.{name}] names no secrets"));
        }
        out.insert(name.clone(), e);
    }
    Ok(out)
}

/// Whether the role `vahta.toml` proposes is the approved one: the same
/// secrets (in any order), command rules (in order), network and hosts,
/// directories, limits, actions (in any order) and ask setting. A file with no
/// entry for a role never differs from it: only a proposal can be pending,
/// and removing is `vahta role --remove`.
pub fn role_in_sync(entry: Option<&RoleEntry>, approved: Option<&AgentRole>) -> bool {
    let Some(e) = entry else {
        return true;
    };
    let Some(a) = approved else {
        return false;
    };
    let texts = |r: &[ParsedRule]| r.iter().map(|r| r.text.clone()).collect::<Vec<_>>();
    let approved_texts =
        |r: &[crate::ApprovedRule]| r.iter().map(|r| r.text.clone()).collect::<Vec<_>>();
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    let approved_hosts = match &a.network {
        Some(crate::Network::Hosts(h)) => h.iter().map(|h| h.text.clone()).collect(),
        _ => Vec::new(),
    };
    let mut actions = e.actions.clone();
    let mut approved_actions = a.actions.clone();
    actions.sort_by_key(|x| matches!(x, Action::Http));
    approved_actions.sort_by_key(|x| matches!(x, Action::Http));
    sorted(e.secrets.clone()) == sorted(a.secrets.clone())
        && texts(&e.allow) == approved_texts(&a.allow)
        && texts(&e.deny) == approved_texts(&a.deny)
        && e.network.as_deref() == a.network.as_ref().map(network_word)
        && e.hosts.iter().map(|h| h.text.clone()).collect::<Vec<_>>() == approved_hosts
        && e.dirs == a.dirs.iter().map(|d| d.text.clone()).collect::<Vec<_>>()
        && e.max_for_secs == a.max_for_secs
        && e.max_uses == a.max_uses
        && actions == approved_actions
        && e.ask_each_use == a.ask_each_use
}

/// `text` (the contents of `vahta.toml`) without `[roles.NAME]`. Everything
/// else is kept; a file with no such role is returned as it is.
pub fn remove_role_text(text: &str, name: &str) -> Result<String, Error> {
    let mut doc =
        parse_doc(text).map_err(|e| Error::Manifest(format!("cannot update vahta.toml: {e}")))?;
    let Some(roles) = doc.get_mut("roles").and_then(|r| r.as_table_mut()) else {
        return Ok(text.to_string());
    };
    if roles.remove(name).is_none() {
        return Ok(text.to_string());
    }
    if roles.is_empty() {
        doc.remove("roles");
    }
    Ok(doc.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse;
    use std::path::Path;

    fn roles(text: &str) -> Result<BTreeMap<String, RoleEntry>, String> {
        parse(text, Path::new("vahta.toml"))
            .map(|m| m.roles)
            .map_err(|e| e.to_string())
    }

    const FULL: &str = r#"
[roles.deploy-ok]
secrets = ["A", "B"]
allow = ["git push"]
deny = ["@shells"]
network = "hosts"
hosts = ["api.example.com"]
dirs = ["."]
for = "1h30m"
uses = 20
actions = ["http", "run"]
ask = true
"#;

    #[test]
    fn a_role_name_is_shaped_like_a_secret_name() {
        assert!(roles("[roles.deploy-ok]\nsecrets = [\"A\"]\n").is_err());
        assert!(roles("[roles.deploy_ok]\nsecrets = [\"A\"]\n").is_ok());
    }

    #[test]
    fn a_full_role_parses_and_defaults_are_the_narrow_ones() {
        let full = roles(&FULL.replace("deploy-ok", "deploy_ok")).unwrap();
        let r = &full["deploy_ok"];
        assert_eq!(r.secrets, ["A", "B"]);
        assert_eq!(r.allow[0].text, "git push");
        assert_eq!(r.network.as_deref(), Some("hosts"));
        assert_eq!(r.max_for_secs, Some(5400));
        assert_eq!(r.max_uses, Some(20));
        assert_eq!(r.actions, [Action::Http, Action::Run]);
        assert!(r.ask_each_use);
        let bare = roles("[roles.r]\nsecrets = [\"A\"]\n").unwrap();
        let r = &bare["r"];
        assert_eq!(r.actions, [Action::Run], "run only unless asked");
        assert!(r.network.is_none() && r.max_for_secs.is_none() && !r.ask_each_use);
    }

    #[test]
    fn what_cannot_be_a_role_is_refused() {
        for bad in [
            "[roles.r]\n",
            "[roles.r]\nsecrets = []\n",
            "[roles.r]\nsecrets = [\"A\", \"A\"]\n",
            "[roles.r]\nsecrets = [\"not a name\"]\n",
            "[roles.r]\nsecrets = [\"A\"]\ntypo = 1\n",
            "[roles.r]\nsecrets = [\"A\"]\nfor = \"0s\"\n",
            "[roles.r]\nsecrets = [\"A\"]\nfor = \"soon\"\n",
            "[roles.r]\nsecrets = [\"A\"]\nfor = \"9999d\"\n",
            "[roles.r]\nsecrets = [\"A\"]\nuses = 0\n",
            "[roles.r]\nsecrets = [\"A\"]\nuses = \"3\"\n",
            "[roles.r]\nsecrets = [\"A\"]\nactions = [\"reveal\"]\n",
            "[roles.r]\nsecrets = [\"A\"]\nactions = []\n",
            "[roles.r]\nsecrets = [\"A\"]\nactions = [\"run\", \"run\"]\n",
            "[roles.r]\nsecrets = [\"A\"]\nnetwork = \"hosts\"\n",
            "[roles.r]\nsecrets = [\"A\"]\nhosts = [\"a.com\"]\n",
            "[roles.r]\nsecrets = [\"A\"]\nallow = [\"@shells\"]\n",
            "[roles.r]\nsecrets = [\"A\"]\nask = \"yes\"\n",
            "roles = 3\n",
        ] {
            assert!(roles(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn spans() {
        assert_eq!(parse_span("90s"), Some(90));
        assert_eq!(parse_span("2h"), Some(7200));
        assert_eq!(parse_span("1d2h"), Some(93_600));
        for bad in ["", "5", "m", "1x", "-5m", "1.5h", "0m"] {
            assert_eq!(parse_span(bad), None, "{bad}");
        }
    }

    fn approved(entry: &RoleEntry) -> AgentRole {
        AgentRole {
            name: entry.name.clone(),
            secrets: entry.secrets.clone(),
            allow: entry
                .allow
                .iter()
                .map(|r| r.to_allow("/usr/bin/git".into()))
                .collect(),
            deny: entry.deny.iter().map(ParsedRule::to_deny).collect(),
            network: Some(crate::Network::Hosts(entry.hosts.clone())),
            dirs: Vec::new(),
            max_for_secs: entry.max_for_secs,
            max_uses: entry.max_uses,
            actions: entry.actions.clone(),
            ask_each_use: entry.ask_each_use,
            approved_at: 1,
        }
    }

    #[test]
    fn the_toml_is_in_sync_only_with_what_was_approved() {
        let all = roles(
            &FULL
                .replace("deploy-ok", "deploy_ok")
                .replace("dirs = [\".\"]\n", ""),
        )
        .unwrap();
        let e = &all["deploy_ok"];
        let a = approved(e);
        assert!(role_in_sync(Some(e), Some(&a)));
        // Order of secrets and actions does not matter.
        let mut reordered = e.clone();
        reordered.secrets.reverse();
        reordered.actions.reverse();
        assert!(role_in_sync(Some(&reordered), Some(&a)));
        // Anything else does.
        let mut wider = e.clone();
        wider.secrets.push("C".into());
        assert!(!role_in_sync(Some(&wider), Some(&a)));
        let mut more = e.clone();
        more.max_uses = Some(21);
        assert!(!role_in_sync(Some(&more), Some(&a)));
        let mut net = e.clone();
        net.network = Some("app".into());
        net.hosts.clear();
        assert!(!role_in_sync(Some(&net), Some(&a)));
        let mut ask = e.clone();
        ask.ask_each_use = false;
        assert!(!role_in_sync(Some(&ask), Some(&a)));
        // Not approved at all; and a file with no entry never differs.
        assert!(!role_in_sync(Some(e), None));
        assert!(role_in_sync(None, Some(&a)));
    }

    #[test]
    fn removing_a_role_keeps_the_rest_of_the_file() {
        let text = "# keep\n[secrets.A]\nrequired = true\n\n[roles.one]\nsecrets = [\"A\"]\n\n[roles.two]\nsecrets = [\"A\"]\n";
        let out = remove_role_text(text, "one").unwrap();
        assert!(out.contains("# keep") && out.contains("[secrets.A]") && out.contains("roles.two"));
        assert!(!out.contains("roles.one"));
        let out = remove_role_text(&out, "two").unwrap();
        assert!(!out.contains("roles"), "{out}");
        assert_eq!(remove_role_text(&out, "none").unwrap(), out);
    }
}
