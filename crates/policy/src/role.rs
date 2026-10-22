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

use std::path::{Path, PathBuf};

use vahta_vault::rules::{
    expand_project_path, is_project_path, place_inside, place_key, same_place,
};
use vahta_vault::{AgentRole, ApprovedRule, DirRule, HostRule, Network, Program, RuleSet};

/// How the places of both sides are written before they are compared. A role is
/// written with `$PROJECT/...` or resolved to an absolute path, a secret's rule
/// is stored in either form, and the same place must not look like two. Both
/// are expanded from the project root (the canonical one, as the evaluator uses
/// it) and, where the place exists, resolved through links.
struct Places {
    root: PathBuf,
}

impl Places {
    fn new(project_root: &Path) -> Places {
        Places {
            root: dunce::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf()),
        }
    }

    fn path(&self, stored: &str) -> PathBuf {
        let expanded = expand_project_path(stored, &self.root);
        let p = Path::new(expanded.as_ref());
        dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    }

    /// An argument of a rule: a place in its comparable form (on Windows case,
    /// separators and the `\\?\` prefix do not matter), any other word as it is.
    fn word(&self, w: &str) -> String {
        if is_project_path(w) || Path::new(w).is_absolute() {
            place_key(&self.path(w).to_string_lossy())
        } else {
            w.to_string()
        }
    }

    fn words(&self, args: &[String]) -> Vec<String> {
        args.iter().map(|a| self.word(a)).collect()
    }
}

/// Whether the secret's allow rules (or, failing them, its folders) cover
/// the role's allow rule `r`.
fn allow_covered(secret: &RuleSet, r: &ApprovedRule, places: &Places) -> bool {
    if secret.allow.is_empty() && secret.dirs.is_empty() {
        // The secret is open: any program is within it.
        return true;
    }
    let Program::Path(program) = &r.program else {
        return false;
    };
    let (program, args) = (places.path(program), places.words(&r.args));
    let by_rule = secret.allow.iter().any(|s| match &s.program {
        // The role's rule names the same program, with at least the
        // arguments the secret's rule fixes.
        Program::Path(p) => {
            same_place(&places.path(p), &program) && args.starts_with(&places.words(&s.args))
        }
        _ => false,
    });
    by_rule
        || secret
            .dirs
            .iter()
            .any(|d| place_inside(&program, &places.path(&d.path)))
}

fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Whether every destination host rule `r` allows is also allowed by `s`.
fn host_covered(s: &HostRule, r: &HostRule) -> bool {
    // A role that may reach private addresses needs a secret rule that may.
    if r.allows_private() && !s.allows_private() {
        return false;
    }
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

fn dir_covered(secret: &RuleSet, d: &DirRule, places: &Places) -> bool {
    let dir = places.path(&d.path);
    secret
        .dirs
        .iter()
        .any(|s| place_inside(&dir, &places.path(&s.path)) && (s.write || !d.write))
}

/// What the role asks for that `secret`'s approved rules do not give, one
/// sentence each. Empty: the role is no wider. `name` is the secret's name;
/// `project_root` is what `$PROJECT` stands for, on both sides.
pub fn too_wide(
    role: &AgentRole,
    name: &str,
    secret: &RuleSet,
    project_root: &Path,
) -> Vec<String> {
    let places = Places::new(project_root);
    let mut out = Vec::new();
    for r in &role.allow {
        if !allow_covered(secret, r, &places) {
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
            if dir_covered(secret, d, &places) {
                continue;
            }
            let dir = places.path(&d.path);
            let in_one = secret
                .dirs
                .iter()
                .any(|s| place_inside(&dir, &places.path(&s.path)));
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

    fn root() -> &'static Path {
        Path::new("/work/proj")
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
        assert!(
            too_wide(&r, "K", &secret(), root()).is_empty(),
            "more arguments"
        );
        r.allow = vec![allow("wget", "/usr/bin/wget")];
        assert_eq!(too_wide(&r, "K", &secret(), root()).len(), 1);
        // A secret rule that fixes arguments is not covered by fewer.
        let mut s = secret();
        s.allow = vec![allow("git push", "/usr/bin/git")];
        r.allow = vec![allow("git", "/usr/bin/git")];
        assert_eq!(too_wide(&r, "K", &s, root()).len(), 1);
        r.allow = vec![allow("git push origin", "/usr/bin/git")];
        assert!(too_wide(&r, "K", &s, root()).is_empty());
        // An open secret covers anything.
        r.allow = vec![allow("wget", "/usr/bin/wget")];
        assert!(too_wide(&r, "K", &RuleSet::default(), root()).is_empty());
        // A folder covers the programs in it.
        let d = RuleSet {
            dirs: vec![dir("/work/bin", true)],
            ..RuleSet::default()
        };
        r.allow = vec![allow("tool", "/work/bin/tool")];
        assert!(too_wide(&r, "K", &d, root()).is_empty());
        r.allow = vec![allow("tool", "/work/other/tool")];
        assert_eq!(too_wide(&r, "K", &d, root()).len(), 1);
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
                !too_wide(&r, "K", &s, root()).is_empty(),
                wide,
                "{role_net:?} under {secret_net:?}"
            );
        }
    }

    #[test]
    fn a_role_cannot_allow_private_resolution_the_secret_does_not() {
        let mut r = role();
        let mut s = secret();
        for (role_host, secret_host, wide) in [
            ("private:db.corp", "db.corp", true),
            ("private:db.corp", "private:db.corp", false),
            ("db.corp", "private:db.corp", false),
            ("db.corp", "db.corp", false),
            ("private:db.corp", "private:*.corp", false),
        ] {
            r.network = Some(Network::Hosts(vec![host(role_host)]));
            s.network = Network::Hosts(vec![host(secret_host)]);
            assert_eq!(
                !too_wide(&r, "K", &s, root()).is_empty(),
                wide,
                "{role_host} under {secret_host}"
            );
        }
    }

    #[test]
    fn dirs_stay_inside_and_never_gain_write() {
        let mut s = secret();
        s.dirs = vec![dir("/work", false)];
        let mut r = role();
        r.dirs = vec![dir("/work/sub", false)];
        assert!(too_wide(&r, "K", &s, root()).is_empty());
        r.dirs = vec![dir("/work/sub", true)];
        assert_eq!(
            too_wide(&r, "K", &s, root()).len(),
            1,
            "read-only to read-write"
        );
        r.dirs = vec![dir("/elsewhere", false)];
        assert_eq!(too_wide(&r, "K", &s, root()).len(), 1);
        r.dirs = vec![dir("/work/../etc", false)];
        assert_eq!(too_wide(&r, "K", &s, root()).len(), 1);
        // A secret with no directories puts no limit.
        s.dirs.clear();
        assert!(too_wide(&r, "K", &s, root()).is_empty());
    }

    #[test]
    fn deny_only_adds() {
        let mut r = role();
        r.deny = vec![parse_rule("@shells", false).unwrap().to_deny()];
        assert!(too_wide(&r, "K", &secret(), root()).is_empty());
    }

    // On Windows the same script is the same script in any case and with either
    // separator (the comparison itself is tested on every system in
    // `vahta_vault::rules`).
    #[cfg(windows)]
    #[test]
    fn windows_places_in_a_role_and_a_secret_differ_only_in_spelling() {
        let mut r = role();
        let mut s = secret();
        let rule = |p: &str| parse_rule("tool", true).unwrap().to_allow(p.to_string());
        r.allow = vec![rule(r"c:/work/proj/bin/TOOL.exe")];
        s.allow = vec![rule(r"C:\Work\Proj\bin\tool.exe")];
        let root = Path::new(r"C:\Work\Proj");
        assert!(too_wide(&r, "K", &s, root).is_empty());
        r.allow = vec![rule(r"c:/work/proj/bin/other.exe")];
        assert_eq!(too_wide(&r, "K", &s, root).len(), 1);
    }

    #[test]
    fn project_forms_and_absolute_paths_name_the_same_place() {
        let root = Path::new("/work/proj");
        let mut r = role();
        let mut s = secret();
        let rel =
            |text: &str, path: &str| parse_rule(text, true).unwrap().to_allow(path.to_string());
        // Role relative, secret absolute.
        r.allow = vec![rel("tool", "$PROJECT/bin/tool")];
        s.allow = vec![rel("tool", "/work/proj/bin/tool")];
        assert!(too_wide(&r, "K", &s, root).is_empty());
        // Role absolute, secret relative.
        std::mem::swap(&mut r.allow, &mut s.allow);
        assert!(too_wide(&r, "K", &s, root).is_empty());
        // Arguments that are places compare the same way.
        r.allow = vec![rel("tool $PROJECT/a.sh", "$PROJECT/bin/tool")];
        r.allow[0].args = vec!["$PROJECT/a.sh".into(), "--x".into()];
        s.allow = vec![rel("tool", "/work/proj/bin/tool")];
        s.allow[0].args = vec!["/work/proj/a.sh".into()];
        assert!(too_wide(&r, "K", &s, root).is_empty());
        // A genuinely wider role is still refused: another program, fewer
        // arguments, a place outside the project.
        r.allow = vec![rel("tool", "$PROJECT/bin/other")];
        assert_eq!(too_wide(&r, "K", &s, root).len(), 1);
        r.allow = vec![rel("tool", "$PROJECT/bin/tool")];
        assert_eq!(too_wide(&r, "K", &s, root).len(), 1, "fewer arguments");
        r.allow = vec![rel("tool", "/work/elsewhere/bin/tool")];
        s.allow[0].args.clear();
        assert_eq!(too_wide(&r, "K", &s, root).len(), 1);
        // Folders: relative inside absolute is narrower, the reverse is wider.
        let mut d = RuleSet {
            dirs: vec![dir("/work/proj/src", true)],
            ..RuleSet::default()
        };
        r.allow.clear();
        r.dirs = vec![dir("$PROJECT/src/gen", true)];
        assert!(too_wide(&r, "K", &d, root).is_empty());
        r.dirs = vec![dir("$PROJECT", true)];
        assert_eq!(too_wide(&r, "K", &d, root).len(), 1);
        r.dirs = vec![dir("/work/proj/src/gen", false)];
        d.dirs = vec![dir("$PROJECT/src", true)];
        assert!(too_wide(&r, "K", &d, root).is_empty());
        r.dirs = vec![dir("/work/proj/other", false)];
        assert_eq!(too_wide(&r, "K", &d, root).len(), 1);
        r.dirs = vec![dir("$PROJECT/src/../other", false)];
        assert_eq!(too_wide(&r, "K", &d, root).len(), 1, "a `..` is not inside");
    }

    #[cfg(unix)]
    #[test]
    fn a_project_reached_through_a_link_is_the_same_project() {
        let tmp = std::env::temp_dir().join(format!("vahta-role-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let real = tmp.join("real");
        std::fs::create_dir_all(real.join("bin")).unwrap();
        std::fs::write(real.join("bin/tool"), "").unwrap();
        let link = tmp.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canon = dunce::canonicalize(&real).unwrap();
        let mut r = role();
        let mut s = secret();
        r.allow = vec![
            parse_rule("tool", true)
                .unwrap()
                .to_allow("$PROJECT/bin/tool".to_string()),
        ];
        s.allow = vec![
            parse_rule("tool", true)
                .unwrap()
                .to_allow(canon.join("bin/tool").to_string_lossy().into_owned()),
        ];
        // The project is named through the link, the secret's rule by the real
        // path: the same place.
        assert!(too_wide(&r, "K", &s, &link).is_empty());
        assert!(too_wide(&r, "K", &s, &real).is_empty());
        // A secret rule written through the link, the project by the real path.
        s.allow = vec![
            parse_rule("tool", true)
                .unwrap()
                .to_allow(link.join("bin/tool").to_string_lossy().into_owned()),
        ];
        assert!(too_wide(&r, "K", &s, &real).is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
