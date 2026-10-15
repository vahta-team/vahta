//! Agent roles against secret rules.
//!
//! A role only narrows. Two things are decided here, both pure:
//!
//! * [`too_wide`]: before the person is asked to approve a role, is it wider
//!   than one of its secrets' own approved rules? Each answer is a sentence
//!   that says exactly what is wider, so the proposer can fix it.
//! * [`narrowing`]: the role as a rule set to evaluate a command against, in
//!   addition to the secret's own. A command passes only if both allow it, so
//!   what a role session may do is `secret ∩ role`.
//!
//! The network is ordered `none` < `hosts` < `app`. A role says nothing about
//! it (`None`) or names a network no wider than the secret's; at run time the
//! stricter of the two is used.

use std::path::Path;

use vahta_vault::{AgentRole, ApprovedRule, DirRule, HostRule, Network, Program, RuleSet};

fn inside(path: &Path, dir: &Path) -> bool {
    !path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
        && path.starts_with(dir)
}

/// Whether the secret's allow rules (or, failing them, its folders) cover
/// the role's allow rule `r`.
fn allow_covered(secret: &RuleSet, r: &ApprovedRule) -> bool {
    if secret.allow.is_empty() && secret.dirs.is_empty() {
        // The secret is open: any program is within it.
        return true;
    }
    let Program::Path(program) = &r.program else {
        return false;
    };
    let by_rule = secret.allow.iter().any(|s| match &s.program {
        // The role's rule names the same program, with at least the
        // arguments the secret's rule fixes.
        Program::Path(p) => p == program && r.args.starts_with(&s.args),
        _ => false,
    });
    by_rule
        || secret
            .dirs
            .iter()
            .any(|d| inside(Path::new(program), Path::new(&d.path)))
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Whether every destination host rule `r` allows is also allowed by `s`.
fn host_covered(s: &HostRule, r: &HostRule) -> bool {
    if s.port.is_some() && s.port != r.port {
        return false;
    }
    let beneath = |a: &HostRule, b: &HostRule| a.host.ends_with(&format!(".{}", b.host));
    if r.subdomains && !is_ip(&r.host) {
        s.subdomains && !is_ip(&s.host) && (r.host == s.host || beneath(r, s))
    } else {
        r.host == s.host || (s.subdomains && !is_ip(&s.host) && beneath(r, s))
    }
}

fn dir_covered(secret: &RuleSet, d: &DirRule) -> bool {
    secret
        .dirs
        .iter()
        .any(|s| inside(Path::new(&d.path), Path::new(&s.path)) && (s.write || !d.write))
}

/// What the role asks for that `secret`'s approved rules do not give, one
/// sentence each. Empty: the role is no wider. `name` is the secret's name.
pub fn too_wide(role: &AgentRole, name: &str, secret: &RuleSet) -> Vec<String> {
    let mut out = Vec::new();
    for r in &role.allow {
        if !allow_covered(secret, r) {
            out.push(format!(
                "allow `{}` is wider than {name}'s own rules: they do not allow that program{}",
                r.text,
                if r.args.is_empty() {
                    ""
                } else {
                    " with those arguments"
                }
            ));
        }
    }
    match (&role.network, &secret.network) {
        (None, _) | (Some(Network::None), _) => {}
        (Some(Network::Hosts(_)), Network::None) => out.push(format!(
            "network hosts is wider than {name}'s network (none)"
        )),
        (Some(Network::Hosts(r)), Network::Hosts(s)) => {
            for h in r {
                if !s.iter().any(|sh| host_covered(sh, h)) {
                    out.push(format!(
                        "host `{}` is wider than {name}'s hosts ({})",
                        h.text,
                        s.iter()
                            .map(|h| h.text.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
        }
        (Some(Network::Hosts(_)), Network::App) | (Some(Network::App), Network::App) => {}
        (Some(Network::App), other) => out.push(format!(
            "network app is wider than {name}'s network ({})",
            match other {
                Network::None => "none",
                _ => "only listed hosts",
            }
        )),
    }
    if !secret.dirs.is_empty() {
        for d in &role.dirs {
            if dir_covered(secret, d) {
                continue;
            }
            let in_one = secret
                .dirs
                .iter()
                .any(|s| inside(Path::new(&d.path), Path::new(&s.path)));
            out.push(if in_one {
                format!(
                    "dir `{}` is read-write, and {name}'s directory there is read-only",
                    d.text
                )
            } else {
                format!(
                    "dir `{}` is not inside {name}'s directories ({})",
                    d.text,
                    secret
                        .dirs
                        .iter()
                        .map(|d| d.text.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
        }
    }
    out
}

/// The role as rules to evaluate a command against, in addition to the
/// secret's: its allow, deny and directories, and its network (the
/// application's own when the role says nothing, which narrows nothing).
pub fn narrowing(role: &AgentRole) -> RuleSet {
    RuleSet {
        name: role.name.clone(),
        allow: role.allow.clone(),
        deny: role.deny.clone(),
        dirs: role.dirs.clone(),
        network: role.network.clone().unwrap_or(Network::App),
        ..RuleSet::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vahta_vault::rules::{parse_host, parse_rule};

    fn allow(text: &str, path: &str) -> ApprovedRule {
        parse_rule(text, true).unwrap().to_allow(path.to_string())
    }

    fn host(t: &str) -> HostRule {
        parse_host(t).unwrap()
    }

    fn dir(path: &str, write: bool) -> DirRule {
        DirRule {
            text: path.into(),
            path: path.into(),
            write,
        }
    }

    fn secret() -> RuleSet {
        RuleSet {
            name: "K".into(),
            allow: vec![allow("git", "/usr/bin/git"), allow("curl", "/usr/bin/curl")],
            network: Network::App,
            ..RuleSet::default()
        }
    }

    fn role() -> AgentRole {
        AgentRole {
            name: "r".into(),
            secrets: vec!["K".into()],
            allow: vec![],
            deny: vec![],
            network: None,
            dirs: vec![],
            max_for_secs: None,
            max_uses: None,
            actions: vec![vahta_vault::Action::Run],
            ask_each_use: false,
            approved_at: 0,
        }
    }

    #[test]
    fn allow_must_be_covered_by_the_secrets_allow() {
        let mut r = role();
        r.allow = vec![allow("git push", "/usr/bin/git")];
        assert!(too_wide(&r, "K", &secret()).is_empty(), "more arguments");
        r.allow = vec![allow("wget", "/usr/bin/wget")];
        assert_eq!(too_wide(&r, "K", &secret()).len(), 1);
        // A secret rule that fixes arguments is not covered by fewer.
        let mut s = secret();
        s.allow = vec![allow("git push", "/usr/bin/git")];
        r.allow = vec![allow("git", "/usr/bin/git")];
        assert_eq!(too_wide(&r, "K", &s).len(), 1);
        r.allow = vec![allow("git push origin", "/usr/bin/git")];
        assert!(too_wide(&r, "K", &s).is_empty());
        // An open secret covers anything.
        r.allow = vec![allow("wget", "/usr/bin/wget")];
        assert!(too_wide(&r, "K", &RuleSet::default()).is_empty());
        // A folder covers the programs in it.
        let d = RuleSet {
            dirs: vec![dir("/work/bin", true)],
            ..RuleSet::default()
        };
        r.allow = vec![allow("tool", "/work/bin/tool")];
        assert!(too_wide(&r, "K", &d).is_empty());
        r.allow = vec![allow("tool", "/work/other/tool")];
        assert_eq!(too_wide(&r, "K", &d).len(), 1);
    }

    #[test]
    fn network_is_ordered_none_hosts_app() {
        let mut r = role();
        let mut s = secret();
        for (role_net, secret_net, wide) in [
            (None, Network::None, false),
            (Some(Network::None), Network::None, false),
            (
                Some(Network::Hosts(vec![host("a.com")])),
                Network::None,
                true,
            ),
            (Some(Network::App), Network::None, true),
            (
                Some(Network::App),
                Network::Hosts(vec![host("a.com")]),
                true,
            ),
            (Some(Network::App), Network::App, false),
            (Some(Network::None), Network::App, false),
            (
                Some(Network::Hosts(vec![host("a.com")])),
                Network::App,
                false,
            ),
            (
                Some(Network::Hosts(vec![host("a.com")])),
                Network::Hosts(vec![host("a.com"), host("b.com")]),
                false,
            ),
            (
                Some(Network::Hosts(vec![host("c.com")])),
                Network::Hosts(vec![host("a.com")]),
                true,
            ),
            (
                Some(Network::Hosts(vec![host("api.a.com")])),
                Network::Hosts(vec![host("*.a.com")]),
                false,
            ),
            (
                Some(Network::Hosts(vec![host("*.a.com")])),
                Network::Hosts(vec![host("a.com")]),
                true,
            ),
            (
                Some(Network::Hosts(vec![host("a.com:8443")])),
                Network::Hosts(vec![host("a.com:443")]),
                true,
            ),
            (
                Some(Network::Hosts(vec![host("a.com:443")])),
                Network::Hosts(vec![host("a.com")]),
                false,
            ),
        ] {
            r.network = role_net.clone();
            s.network = secret_net.clone();
            assert_eq!(
                !too_wide(&r, "K", &s).is_empty(),
                wide,
                "{role_net:?} under {secret_net:?}"
            );
        }
    }

    #[test]
    fn dirs_stay_inside_and_never_gain_write() {
        let mut s = secret();
        s.dirs = vec![dir("/work", false)];
        let mut r = role();
        r.dirs = vec![dir("/work/sub", false)];
        assert!(too_wide(&r, "K", &s).is_empty());
        r.dirs = vec![dir("/work/sub", true)];
        assert_eq!(too_wide(&r, "K", &s).len(), 1, "read-only to read-write");
        r.dirs = vec![dir("/elsewhere", false)];
        assert_eq!(too_wide(&r, "K", &s).len(), 1);
        r.dirs = vec![dir("/work/../etc", false)];
        assert_eq!(too_wide(&r, "K", &s).len(), 1);
        // A secret with no directories puts no limit.
        s.dirs.clear();
        assert!(too_wide(&r, "K", &s).is_empty());
    }

    #[test]
    fn deny_only_adds() {
        let mut r = role();
        r.deny = vec![parse_rule("@shells", false).unwrap().to_deny()];
        assert!(too_wide(&r, "K", &secret()).is_empty());
    }
}
