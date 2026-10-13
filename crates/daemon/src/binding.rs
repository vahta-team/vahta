//! How the approved rules of a secret are shown to the person, and which files
//! the agent could change.
//!
//! The check itself (deny, allow, directories, network) is
//! `vahta_policy::evaluate`; this module only words rules for windows and
//! messages. The rules are the **approved copy in the signed vault**
//! (`Peek::bindings`), never `vahta.toml`.

use std::path::Path;

use vahta_vault::{ApprovedRule, Network, RuleSet};

/// The rules as the person reads them: `category: c; allow: a, b; deny: d;
/// dirs: e; network: none`.
pub(crate) fn rules_text(binding: &RuleSet) -> String {
    let list = |rules: &[ApprovedRule]| {
        rules
            .iter()
            .map(|r| r.text.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut parts = Vec::new();
    if !binding.allow.is_empty() {
        parts.push(format!("allow: {}", list(&binding.allow)));
    }
    if !binding.deny.is_empty() {
        parts.push(format!("deny: {}", list(&binding.deny)));
    }
    if !binding.dirs.is_empty() {
        let dirs: Vec<&str> = binding.dirs.iter().map(|d| d.text.as_str()).collect();
        parts.push(format!("dirs: {}", dirs.join(", ")));
    }
    match &binding.network {
        Network::None => parts.push("network: none".to_string()),
        Network::Hosts(h) => {
            let hosts: Vec<&str> = h.iter().map(|h| h.text.as_str()).collect();
            parts.push(format!("network: only {}", hosts.join(", ")));
        }
        Network::App => {}
    }
    let mut text = parts.join("; ");
    if let Some(c) = &binding.category {
        text = if text.is_empty() {
            format!("category: {c}")
        } else {
            format!("category: {c}; {text}")
        };
    }
    text
}

/// Why the agent could change the file at `resolved`: it is inside the project
/// or in a temp directory. `None` for anywhere else.
pub(crate) fn agent_writable(resolved: &Path, project_root: &Path) -> Option<&'static str> {
    let root =
        crate::pathfind::canonical(project_root).unwrap_or_else(|| project_root.to_path_buf());
    if resolved.starts_with(&root) {
        return Some("this file is inside the project, so the agent can change it");
    }
    #[cfg(unix)]
    let temps = vec![
        std::env::temp_dir(),
        "/tmp".into(),
        "/var/tmp".into(),
        "/dev/shm".into(),
    ];
    #[cfg(not(unix))]
    let temps = vec![std::env::temp_dir()];
    for t in temps {
        let t = crate::pathfind::canonical(&t).unwrap_or(t);
        if resolved.starts_with(&t) {
            return Some("this file is in a temporary directory, so the agent can change it");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use vahta_vault::rules::parse_rule;

    fn allow(rule: &str, path: &str) -> ApprovedRule {
        parse_rule(rule, true).unwrap().to_allow(path.to_string())
    }

    fn deny(rule: &str) -> ApprovedRule {
        parse_rule(rule, false).unwrap().to_deny()
    }

    #[test]
    fn the_rules_read_back() {
        let b = RuleSet {
            name: "K".into(),
            allow: vec![allow("git push", "/g")],
            deny: vec![deny("@network")],
            network: Network::App,
            ..RuleSet::default()
        };
        assert_eq!(rules_text(&b), "allow: git push; deny: @network");
        let c = RuleSet {
            category: Some("local-only".into()),
            network: Network::None,
            ..b
        };
        assert_eq!(
            rules_text(&c),
            "category: local-only; allow: git push; deny: @network; network: none"
        );
    }
}
