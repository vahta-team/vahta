//! The compiled-in categories and what can be said about a rule set in terms of
//! one.

use vahta_vault::rules::{in_group, normalize_program_name};
use vahta_vault::{ApprovedRule, Class, Network, Program, RuleSet, Tier};

/// The three network shapes a rule set can have, without the hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetKind {
    /// No network (a fresh network namespace on Linux).
    None,
    /// Only the listed hosts, and only through `vahta http`.
    Hosts,
    /// Whatever the application does.
    App,
}

impl NetKind {
    /// The word used in `--net` and `vahta.toml`.
    pub fn word(self) -> &'static str {
        match self {
            NetKind::None => "none",
            NetKind::Hosts => "hosts",
            NetKind::App => "app",
        }
    }

    pub fn of(network: &Network) -> NetKind {
        match network {
            Network::None => NetKind::None,
            Network::Hosts(_) => NetKind::Hosts,
            Network::App => NetKind::App,
        }
    }
}

/// A starting set of rules for a kind of key.
#[derive(Debug)]
pub struct Category {
    /// Short id: what `--category` takes and what the vault stores.
    pub id: &'static str,
    /// The name the window shows.
    pub name: &'static str,
    pub description: &'static str,
    /// See the crate docs.
    pub rank: u8,
    /// The tier a secret of this category gets unless the person says otherwise.
    pub tier: Tier,
    /// The network shapes allowed for this category.
    pub networks: &'static [NetKind],
    pub default_network: NetKind,
    /// Deny groups every rule set of this category carries.
    pub deny: &'static [&'static str],
    /// Whether directories may be named.
    pub dirs: bool,
    /// Whether at least one `allow` rule is required.
    pub allow_required: bool,
    /// Programs the default set offers (those found on the caller's PATH).
    pub programs: &'static [&'static str],
    /// Words in a secret's name that point at this category.
    pub words: &'static [&'static str],
    /// The detected class that points at this category.
    pub class: Option<Class>,
    /// What the agent should think through before it proposes rules.
    pub checklist: &'static [&'static str],
}

include!(concat!(env!("OUT_DIR"), "/categories_data.rs"));

/// Every category, in a fixed order.
pub fn all() -> &'static [Category] {
    &CATEGORIES
}

/// The category with this id.
pub fn category(id: &str) -> Option<&'static Category> {
    CATEGORIES.iter().find(|c| c.id == id)
}

/// The category a secret looks like, from the class its value showed (a
/// vendor prefix) and the words of its name. The agent chose the name, but the
/// result is only a suggestion and a floor for downgrade detection; of the
/// categories that apply, the highest-ranked wins. With no sign, `ordinary`.
pub fn suggest(class: Option<Class>, name: &str) -> &'static Category {
    let words: Vec<String> = name
        .split(['_', '-', '.'])
        .map(str::to_ascii_uppercase)
        .collect();
    CATEGORIES
        .iter()
        .filter(|c| {
            class.is_some() && c.class == class
                || c.words.iter().any(|w| words.iter().any(|x| x == w))
        })
        .max_by_key(|c| c.rank)
        .unwrap_or_else(|| default_category())
}

fn default_category() -> &'static Category {
    // `ordinary` is part of the data and a test pins it.
    CATEGORIES
        .iter()
        .find(|c| c.id == "ordinary")
        .unwrap_or(&CATEGORIES[0])
}

/// Whether choosing `chosen` where `detected` was expected lowers the oversight.
pub fn is_downgrade(chosen: &Category, detected: &Category) -> bool {
    chosen.rank < detected.rank
}

impl Category {
    /// This category's deny groups as rules.
    pub fn required_deny(&self) -> Vec<ApprovedRule> {
        self.deny
            .iter()
            .map(|g| ApprovedRule {
                text: (*g).to_string(),
                program: Program::Group((*g).to_string()),
                args: Vec::new(),
            })
            .collect()
    }

    /// `deny` with this category's groups added in front where missing.
    pub fn with_required_deny(&self, deny: Vec<ApprovedRule>) -> Vec<ApprovedRule> {
        let mut out = self.required_deny();
        out.extend(
            deny.into_iter()
                .filter(|r| !self.deny.contains(&r.text.as_str())),
        );
        out
    }

    /// Whether `rule_set` meets what this category requires. The error is a
    /// sentence for the agent that proposed it.
    pub fn check(&self, rule_set: &RuleSet) -> Result<(), String> {
        let kind = NetKind::of(&rule_set.network);
        if !self.networks.contains(&kind) {
            let allowed: Vec<&str> = self.networks.iter().map(|n| n.word()).collect();
            return Err(format!(
                "a {} cannot have network `{}` (allowed: {}){}",
                self.name,
                kind.word(),
                allowed.join(", "),
                match self.networks {
                    [NetKind::Hosts] =>
                        "; name the hosts it may reach, e.g. --net hosts:api.vendor.com",
                    _ => "",
                }
            ));
        }
        if matches!(&rule_set.network, Network::Hosts(h) if h.is_empty()) {
            return Err("network `hosts` needs at least one host".to_string());
        }
        if !self.dirs && !rule_set.dirs.is_empty() {
            return Err(format!(
                "a {} cannot be given directories: a script in a directory the agent can write \
                 is a way to use the key",
                self.name
            ));
        }
        if self.allow_required && rule_set.allow.is_empty() {
            return Err(format!(
                "a {} needs at least one --allow PROGRAM (for example: {})",
                self.name,
                self.programs
                    .iter()
                    .take(4)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for g in self.deny {
            if !rule_set.deny.iter().any(|r| r.text == *g) {
                return Err(format!("a {} always denies {g}", self.name));
            }
        }
        for rule in &rule_set.allow {
            if let Program::Path(p) = &rule.program {
                let file = p.rsplit(['/', '\\']).next().unwrap_or(p);
                let name = normalize_program_name(file);
                if let Some(g) = self.deny.iter().find(|g| in_group(g, &name)) {
                    return Err(format!(
                        "`{}` is in {g}, which a {} always denies, so it can never run; choose a \
                         different category if it must",
                        rule.text, self.name
                    ));
                }
            }
        }
        Ok(())
    }
}

/// A rule set in the words the person reads, one short paragraph:
/// `Payment key. Works only through Vahta with api.stripe.com. Asks you every
/// time.` `tier` is the secret's tier, which is not part of a rule set.
pub fn describe(rule_set: &RuleSet, tier: Tier) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(
        rule_set
            .category
            .as_deref()
            .and_then(category)
            .map_or("Custom rules", |c| c.name)
            .to_string(),
    );
    parts.push(match &rule_set.network {
        Network::None => "Cannot use the network at all".to_string(),
        Network::Hosts(h) => format!(
            "Works only through Vahta with {}",
            h.iter()
                .map(|h| h.text.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Network::App => "The program uses the network itself".to_string(),
    });
    if rule_set.allow.is_empty() {
        parts.push("Any program may use it".to_string());
    } else {
        parts.push(format!(
            "Only these may run: {}",
            rule_set
                .allow
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !rule_set.dirs.is_empty() {
        parts.push(format!(
            "Folders: {}",
            rule_set
                .dirs
                .iter()
                .map(|d| d.text.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !rule_set.deny.is_empty() {
        parts.push(format!(
            "Never: {}",
            rule_set
                .deny
                .iter()
                .map(|r| r.text.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    parts.push(
        match tier {
            Tier::EachUse => "Asks you every time",
            Tier::Session => "Asks once per session",
        }
        .to_string(),
    );
    format!("{}.", parts.join(". "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vahta_vault::HostRule;

    #[test]
    fn the_six_categories_are_there_with_distinct_ranks() {
        let ids: Vec<&str> = all().iter().map(|c| c.id).collect();
        for want in [
            "payment",
            "server",
            "ordinary",
            "database",
            "publish",
            "local-only",
        ] {
            assert!(ids.contains(&want), "{want}");
        }
        assert_eq!(all().len(), 6);
        let mut ranks: Vec<u8> = all().iter().map(|c| c.rank).collect();
        ranks.sort_unstable();
        ranks.dedup();
        assert_eq!(ranks.len(), 6);
        // The two that ask every time.
        for c in all() {
            assert_eq!(
                c.tier == Tier::EachUse,
                matches!(c.id, "payment" | "publish"),
                "{}",
                c.id
            );
            assert!(c.networks.contains(&c.default_network));
            assert!(c.deny.contains(&"@shells"));
        }
        assert_eq!(category("payment").unwrap().networks, [NetKind::Hosts]);
        assert!(!category("payment").unwrap().dirs);
        assert_eq!(default_category().id, "ordinary");
    }

    #[test]
    fn a_class_and_the_words_of_a_name_suggest_a_category() {
        let s = |c, n| suggest(c, n).id;
        assert_eq!(s(Some(Class::Payment), "ANYTHING"), "payment");
        assert_eq!(s(Some(Class::Cloud), "ANYTHING"), "server");
        assert_eq!(s(Some(Class::Other), "OPENAI_API_KEY"), "ordinary");
        assert_eq!(s(None, "DATABASE_URL"), "database");
        assert_eq!(s(None, "npm-token"), "publish");
        assert_eq!(s(None, "GPG_PASSPHRASE"), "local-only");
        // The highest rank of what applies.
        assert_eq!(s(Some(Class::Cloud), "PROD_DB_PASSWORD"), "server");
        assert_eq!(s(Some(Class::Payment), "GITHUB_TOKEN"), "payment");
        // A word inside another word is not the word.
        assert_eq!(s(None, "PAGE_TOKEN"), "ordinary");
        assert_eq!(s(None, "DBX"), "ordinary");
    }

    #[test]
    fn downgrades_follow_rank() {
        let (p, o, l) = (
            category("payment").unwrap(),
            category("ordinary").unwrap(),
            category("local-only").unwrap(),
        );
        assert!(is_downgrade(o, p) && is_downgrade(l, p));
        assert!(!is_downgrade(p, o) && !is_downgrade(p, p));
    }

    fn rules(texts: &[&str], allow: bool) -> Vec<ApprovedRule> {
        texts
            .iter()
            .map(|t| {
                let r = vahta_vault::rules::parse_rule(t, allow).unwrap();
                if allow {
                    r.to_allow(format!("/usr/bin/{t}"))
                } else {
                    r.to_deny()
                }
            })
            .collect()
    }

    fn host(h: &str) -> HostRule {
        vahta_vault::rules::parse_host(h).unwrap()
    }

    #[test]
    fn a_category_checks_what_a_proposal_may_be() {
        let pay = category("payment").unwrap();
        let ok = RuleSet {
            name: "K".into(),
            category: Some("payment".into()),
            deny: pay.required_deny(),
            network: Network::Hosts(vec![host("api.stripe.com")]),
            ..RuleSet::default()
        };
        assert!(pay.check(&ok).is_ok());
        let app = RuleSet {
            network: Network::App,
            ..ok.clone()
        };
        let err = pay.check(&app).unwrap_err();
        assert!(err.contains("--net hosts:"), "{err}");
        let dirs = RuleSet {
            dirs: vec![vahta_vault::DirRule {
                text: "./x".into(),
                path: "/p/x".into(),
                write: true,
            }],
            ..ok.clone()
        };
        assert!(pay.check(&dirs).unwrap_err().contains("directories"));
        let no_deny = RuleSet {
            deny: vec![],
            ..ok.clone()
        };
        assert!(pay.check(&no_deny).unwrap_err().contains("@shells"));
        let python = RuleSet {
            allow: rules(&["python3"], true),
            ..ok
        };
        assert!(pay.check(&python).unwrap_err().contains("@interpreters"));
        // A server key needs a program.
        let srv = category("server").unwrap();
        let bare = RuleSet {
            name: "K".into(),
            deny: srv.required_deny(),
            network: Network::App,
            ..RuleSet::default()
        };
        assert!(srv.check(&bare).unwrap_err().contains("--allow"));
    }

    #[test]
    fn required_deny_groups_are_added_once() {
        let o = category("ordinary").unwrap();
        let merged = o.with_required_deny(rules(&["@network", "git push"], false));
        let texts: Vec<&str> = merged.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(texts, ["@shells", "@network", "git push"]);
    }

    #[test]
    fn a_rule_set_reads_in_plain_words() {
        let pay = category("payment").unwrap();
        let rs = RuleSet {
            name: "K".into(),
            category: Some("payment".into()),
            deny: pay.required_deny(),
            network: Network::Hosts(vec![host("api.stripe.com")]),
            ..RuleSet::default()
        };
        let said = describe(&rs, Tier::EachUse);
        assert!(
            said.starts_with("Payment key. Works only through Vahta with api.stripe.com."),
            "{said}"
        );
        assert!(said.ends_with("Asks you every time."), "{said}");
    }
}
