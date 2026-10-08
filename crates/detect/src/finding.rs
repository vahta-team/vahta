//! The hook's question, answered with what the agent and the person each need:
//! [`find_secret`].
//!
//! The order, first hit wins:
//!
//! 1. the vendor prefixes (certain, and specific);
//! 2. the data rules of `vahta-rules` (a rule may be `observe`: its find is
//!    kept only if nothing blocks);
//! 3. the structural rules (connection strings, command-line passwords, a PEM
//!    header);
//! 4. a Bearer value, then names that mean "secret" (`API_KEY=...`,
//!    `--password ...`), likely before possible;
//! 5. the evasion pass, only when nothing else hit: a base64, hex or
//!    piece-by-piece spelling of any of the above.
//!
//! A [`Finding`] carries a `category` for the agent (what it was, never which
//! rule) and a `rule` and `description` for the person. It never carries a
//! value.

use crate::classify::Confidence;
use crate::evasion;
use crate::hits::scan_text_hits;
use crate::structural::find_structural;
pub use vahta_rules::{Mode, Truncated};

/// How a value was hidden from a plain look at the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evasion {
    Base64,
    /// Pieces joined by the shell or the language (`'ab''cd'`, `"a" + "b"`).
    Concat,
    Hex,
}

impl Evasion {
    pub fn as_str(self) -> &'static str {
        match self {
            Evasion::Base64 => "base64",
            Evasion::Concat => "concatenation",
            Evasion::Hex => "hex",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// What the agent is told it was, with its article: "an API token".
    pub category: String,
    /// The rule that fired; for the person and the journal, not the agent.
    pub rule: String,
    /// What the rule looks for; for the person.
    pub description: String,
    pub confidence: Confidence,
    /// Set when the value was hidden. An evasion hit always blocks.
    pub evasion: Option<Evasion>,
    pub mode: Mode,
}

/// A [`Finding`], or none, and whether the rules ran in full.
#[derive(Debug)]
pub struct Detection {
    pub finding: Option<Finding>,
    pub truncated: Option<Truncated>,
}

/// What kind of secret is in `text`, if any.
pub fn find_secret(text: &str) -> Option<Finding> {
    detect(text).finding
}

/// [`find_secret`], and whether a limit of the rules cut the scan short.
pub fn detect(text: &str) -> Detection {
    let mut truncated = None;
    let finding = match find_plain(text, &mut truncated) {
        Some(f) => Some(f),
        None => {
            evasion::find(text, &|decoded| find_plain(decoded, &mut None)).map(|(mut f, how)| {
                f.evasion = Some(how);
                f.mode = Mode::Block;
                f.confidence = Confidence::Likely;
                f
            })
        }
    };
    Detection { finding, truncated }
}

/// Steps 1 to 4: the text as it is.
fn find_plain(text: &str, truncated: &mut Option<Truncated>) -> Option<Finding> {
    let hits = scan_text_hits(text);
    if let Some(kind) = hits.prefix {
        return Some(prefix_finding(kind));
    }

    // Rules: a blocking hit wins; an observe-only one waits for the others.
    let scan = vahta_rules::scan(text);
    if scan.truncated.is_some() {
        *truncated = scan.truncated;
    }
    let mut observed = None;
    for hit in &scan.hits {
        let rule = hit.rule();
        let f = Finding {
            category: rule.category.to_string(),
            rule: rule.id.to_string(),
            description: rule.description.to_string(),
            confidence: Confidence::Likely,
            evasion: None,
            mode: rule.mode,
        };
        if rule.mode == Mode::Block {
            return Some(f);
        }
        observed.get_or_insert(f);
    }

    if let Some(s) = find_structural(text) {
        return Some(Finding {
            category: s.category.to_string(),
            rule: s.rule.to_string(),
            description: s.description.to_string(),
            confidence: s.confidence,
            evasion: None,
            mode: Mode::Block,
        });
    }

    // Order is behaviour, not taste: a Bearer whose value is likely outranks
    // a likely name, and both outrank anything merely possible.
    let by_name = |name: &str, confidence| {
        let flag = hits.flag_names.iter().any(|n| n.eq_ignore_ascii_case(name));
        Some(name_finding(name, flag, confidence))
    };
    if hits.bearer_likely {
        return Some(bearer_finding(Confidence::Likely));
    }
    if let Some(name) = hits.likely_names.first() {
        return by_name(name, Confidence::Likely);
    }
    if hits.bearer_possible {
        return Some(bearer_finding(Confidence::Possible));
    }
    if let Some(name) = hits.possible_names.first() {
        return by_name(name, Confidence::Possible);
    }
    observed
}

fn bearer_finding(confidence: Confidence) -> Finding {
    Finding {
        category: "a Bearer token".to_string(),
        rule: "vahta.bearer".to_string(),
        description: "A Bearer value in an Authorization header".to_string(),
        confidence,
        evasion: None,
        mode: Mode::Block,
    }
}

fn name_finding(name: &str, flag: bool, confidence: Confidence) -> Finding {
    let (category, rule, description) = if flag {
        (
            format!("a secret passed as the --{} flag", name.to_lowercase()),
            "vahta.flag-value",
            "A value given to a flag named like a secret (--token, --password, --api-key, ...)",
        )
    } else {
        (
            format!("a secret assigned to {}", name.to_uppercase()),
            "vahta.assignment",
            "A value assigned to a name that means secret (api_key, access_key, token, secret, password, private_key)",
        )
    };
    Finding {
        category,
        rule: rule.to_string(),
        description: description.to_string(),
        confidence,
        evasion: None,
        mode: Mode::Block,
    }
}

/// The 11 vendor prefixes: kind (as the matcher names it), rule slug, category.
const PREFIX_FINDINGS: &[(&str, &str, &str)] = &[
    (
        "Anthropic-style key",
        "anthropic",
        "an Anthropic-style API key",
    ),
    ("OpenAI-style key", "openai", "an OpenAI-style API key"),
    (
        "AWS access key id",
        "aws-access-key-id",
        "an AWS access key id",
    ),
    (
        "GitHub fine-grained PAT",
        "github-fine-grained-pat",
        "a GitHub access token",
    ),
    ("GitHub PAT", "github-pat", "a GitHub access token"),
    ("GitLab PAT", "gitlab-pat", "a GitLab access token"),
    ("Slack token", "slack-token", "a Slack token"),
    ("Google API key", "google-api-key", "a Google API key"),
    (
        "Stripe secret key",
        "stripe-secret-key",
        "a Stripe secret key",
    ),
    (
        "Stripe restricted key",
        "stripe-restricted-key",
        "a Stripe restricted key",
    ),
    ("npm token", "npm-token", "an npm token"),
];

fn prefix_finding(kind: &str) -> Finding {
    let (slug, category) = PREFIX_FINDINGS
        .iter()
        .find(|(k, _, _)| *k == kind)
        .map_or(("prefix", "an API token"), |(_, s, c)| (*s, *c));
    Finding {
        category: category.to_string(),
        rule: format!("vahta.prefix.{slug}"),
        description: format!("Vendor prefix match: {kind}"),
        confidence: Confidence::Likely,
        evasion: None,
        mode: Mode::Block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_prefix_kind_has_a_category() {
        for kind in crate::matchers::PREFIX_KINDS {
            assert!(
                PREFIX_FINDINGS.iter().any(|(k, _, _)| k == &kind),
                "no category for {kind}"
            );
        }
    }

    #[test]
    fn a_plain_command_finds_nothing() {
        let d = detect("ls -la && cargo build --release");
        assert!(d.finding.is_none());
        assert!(d.truncated.is_none());
    }
}
