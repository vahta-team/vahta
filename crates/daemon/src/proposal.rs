//! A rule set as an agent proposes it (`vahta add`, `vahta bind`): parsed,
//! resolved against the file system and checked against its category, ready for
//! the window. Nothing here changes anything.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use vahta_policy::{Category, NetKind};
use vahta_vault::manifest::RulesText;
use vahta_vault::rules::{self, ParsedRule, ProgramSpec};
use vahta_vault::{ApprovedRule, DirRule, Network, RuleSet};

use crate::binding;
use crate::pathfind;

/// The text a client sent.
#[derive(Debug, Clone, Default)]
pub(crate) struct Args {
    pub category: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub dirs: Vec<String>,
    pub net: Option<String>,
    pub path: Option<OsString>,
    /// Project roots the secret may be used from, outside the vault's own.
    pub from: Vec<String>,
}

impl Args {
    /// Nothing but (at most) a category: the default set is wanted.
    pub fn is_bare(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.dirs.is_empty()
            && self.net.is_none()
            && self.from.is_empty()
    }
}

/// A proposal, resolved.
#[derive(Debug, Clone)]
pub(crate) struct Built {
    pub rule_set: RuleSet,
    /// `(rule text, program it resolved to)` for each allow rule.
    pub resolved: Vec<(String, PathBuf)>,
    /// Things the person should weigh (agent-writable programs and folders).
    pub warnings: Vec<String>,
}

/// The ids, for messages.
pub(crate) fn category_ids() -> String {
    vahta_policy::all()
        .iter()
        .map(|c| c.id)
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn find_category(id: &str) -> Result<&'static Category, String> {
    vahta_policy::category(id)
        .ok_or_else(|| format!("unknown category `{id}` (known: {})", category_ids()))
}

/// `none`, `app` or `hosts:H[,H...]`.
pub(crate) fn parse_net(text: &str) -> Result<Network, String> {
    let t = text.trim();
    match t {
        "none" => Ok(Network::None),
        "app" => Ok(Network::App),
        _ => match t.strip_prefix("hosts:") {
            Some(list) => parse_hosts(list.split(',')).map(Network::Hosts),
            None => Err(format!(
                "`{t}` is not a network: use none, app or hosts:HOST[,HOST...]"
            )),
        },
    }
}

pub(crate) fn parse_hosts<'a>(
    items: impl Iterator<Item = &'a str>,
) -> Result<Vec<vahta_vault::HostRule>, String> {
    let hosts: Vec<_> = items.map(rules::parse_host).collect::<Result<_, _>>()?;
    if hosts.is_empty() || hosts.len() > 64 {
        return Err("name between 1 and 64 hosts".to_string());
    }
    Ok(hosts)
}

/// `PATH`, `PATH:ro` or `PATH:rw`, resolved against the project root.
fn parse_dir(text: &str, root: &Path) -> Result<DirRule, String> {
    let shown = text.trim();
    let (path_text, write) = if let Some(p) = shown.strip_suffix(":ro") {
        (p, false)
    } else if let Some(p) = shown.strip_suffix(":rw") {
        (p, true)
    } else {
        (shown, true)
    };
    if path_text.is_empty() || path_text.contains('\0') || shown.chars().any(char::is_control) {
        return Err(format!("directory `{shown}` is not a path"));
    }
    let given = Path::new(path_text);
    let full = if given.is_absolute() {
        given.to_path_buf()
    } else {
        root.join(given)
    };
    let canon = pathfind::canonical(&full)
        .filter(|p| p.is_dir())
        .ok_or_else(|| format!("directory `{shown}` does not exist"))?;
    if canon.parent().is_none() {
        return Err("a rule for the whole file system is no rule".to_string());
    }
    Ok(DirRule {
        text: shown.to_string(),
        path: canon.to_string_lossy().into_owned(),
        write,
    })
}

/// An absolute project root a secret may be used from: it must exist, and is
/// stored canonical (symlinks resolved, no `..`). The whole file system is no
/// project.
pub(crate) fn parse_from(text: &str) -> Result<String, String> {
    let shown = text.trim();
    if shown.is_empty() || shown.contains('\0') || shown.chars().any(char::is_control) {
        return Err(format!("`{shown}` is not a project path"));
    }
    let given = Path::new(shown);
    if !given.is_absolute() {
        return Err(format!(
            "--from `{shown}` must be an absolute path to a project folder"
        ));
    }
    let canon = pathfind::canonical(given)
        .filter(|p| p.is_dir())
        .ok_or_else(|| format!("project folder `{shown}` does not exist"))?;
    if canon.parent().is_none() {
        return Err("a project folder of `/` is no project".to_string());
    }
    Ok(canon.to_string_lossy().into_owned())
}

/// The `from` list of a proposal, canonical, in order, without repeats.
pub(crate) fn parse_froms(texts: &[String]) -> Result<Vec<String>, String> {
    if texts.len() > vahta_vault::MAX_FROM {
        return Err(format!(
            "too many --from folders (at most {})",
            vahta_vault::MAX_FROM
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for t in texts {
        let p = parse_from(t)?;
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

fn parse_all(texts: &[String], allow: bool) -> Result<Vec<ParsedRule>, String> {
    if texts.len() > 64 {
        return Err("too many rules".to_string());
    }
    texts.iter().map(|t| rules::parse_rule(t, allow)).collect()
}

type Resolved = (Vec<ApprovedRule>, Vec<(String, PathBuf)>);

/// Resolve and approve `allow` rules: each program is found once and fixed by
/// its canonical path.
fn resolve_allow(
    allow: &[ParsedRule],
    path: Option<&OsString>,
    root: &Path,
) -> Result<Resolved, String> {
    let mut resolved = Vec::new();
    let mut approved = Vec::new();
    for rule in allow {
        let word = match &rule.program {
            ProgramSpec::Bare(w) | ProgramSpec::Path(w) => w,
            ProgramSpec::Group(g) => return Err(format!("`{g}` is a group; groups are for deny")),
        };
        let Some(found) = pathfind::locate(word, path, root) else {
            return Err(format!(
                "cannot find the program of the rule `{}` (bare names are looked up in your PATH, \
                 paths are relative to the project root)",
                rule.text
            ));
        };
        resolved.push((rule.text.clone(), found.clone()));
        approved.push(rule.to_allow(found.to_string_lossy().into_owned()));
    }
    Ok((approved, resolved))
}

fn warnings_for(resolved: &[(String, PathBuf)], dirs: &[DirRule], root: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (text, program) in resolved {
        if let Some(w) = binding::agent_writable(program, root) {
            let w = format!("{}: {w}", program.display());
            if !out.contains(&w) {
                out.push(w);
            }
        }
        let file = program
            .file_name()
            .map(|n| rules::normalize_program_name(&n.to_string_lossy()))
            .unwrap_or_default();
        if rules::runs_anything(&file) {
            out.push(format!(
                "`{text}` runs other programs (a shell, interpreter or launcher): allowing it \
                 lets the agent run anything with this secret"
            ));
        }
    }
    for d in dirs {
        if binding::agent_writable(Path::new(&d.path), root).is_some() {
            out.push(format!(
                "{}: the agent can put files in this folder, and anything in it may use the secret",
                d.text
            ));
        }
    }
    out
}

/// Parse and resolve `args` into a rule set for `name`, checked against
/// `category` (`None`: no category, `app` network, no further checks).
pub(crate) fn build(
    name: &str,
    category: Option<&'static Category>,
    args: &Args,
    root: &Path,
) -> Result<Built, String> {
    let allow = parse_all(&args.allow, true)?;
    let deny = parse_all(&args.deny, false)?;
    let (approved, resolved) = resolve_allow(&allow, args.path.as_ref(), root)?;
    if args.dirs.len() > 64 {
        return Err("too many directories".to_string());
    }
    let dirs: Vec<DirRule> = args
        .dirs
        .iter()
        .map(|d| parse_dir(d, root))
        .collect::<Result<_, _>>()?;
    let network = match (&args.net, category) {
        (Some(n), _) => parse_net(n)?,
        (None, Some(c)) => match c.default_network {
            NetKind::None => Network::None,
            NetKind::App => Network::App,
            NetKind::Hosts => {
                return Err(format!(
                    "a {} must name the hosts it may reach: add --net hosts:HOST[,HOST...] \
                     (the vendor's API host)",
                    c.name
                ));
            }
        },
        (None, None) => Network::App,
    };
    let mut denied: Vec<ApprovedRule> = deny.iter().map(ParsedRule::to_deny).collect();
    if let Some(c) = category {
        denied = c.with_required_deny(denied);
    }
    let rule_set = RuleSet {
        name: name.to_string(),
        category: category.map(|c| c.id.to_string()),
        downgraded_from: None,
        allow: approved,
        deny: denied,
        dirs,
        network,
        from: parse_froms(&args.from)?,
    };
    if let Some(c) = category {
        c.check(&rule_set)?;
    }
    let warnings = warnings_for(&resolved, &rule_set.dirs, root);
    Ok(Built {
        rule_set,
        resolved,
        warnings,
    })
}

/// Why a default set could not be built.
#[derive(Debug)]
pub(crate) enum DefaultErr {
    /// The category needs hosts and the proposal named none: ask the person.
    NeedHosts,
    Other(String),
}

/// The category's own rules: its deny groups and network. The agent's programs
/// are kept when the category can take them (a category that requires a
/// program and gets none is an error: Vahta does not guess programs). Folders
/// and custom denies are dropped. `hosts` are
/// used when the category's network is `hosts`.
pub(crate) fn default_set(
    name: &str,
    cat: &'static Category,
    agent: &Args,
    hosts: Option<Vec<vahta_vault::HostRule>>,
    root: &Path,
) -> Result<Built, DefaultErr> {
    let mut args = Args {
        category: Some(cat.id.to_string()),
        path: agent.path.clone(),
        ..Args::default()
    };
    if cat.default_network == NetKind::Hosts {
        let agent_hosts = agent
            .net
            .as_deref()
            .and_then(|n| parse_net(n).ok())
            .and_then(|n| match n {
                Network::Hosts(h) => Some(h),
                _ => None,
            });
        match hosts.or(agent_hosts) {
            Some(h) => {
                args.net = Some(format!(
                    "hosts:{}",
                    h.iter()
                        .map(|h| h.text.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                ));
            }
            None => return Err(DefaultErr::NeedHosts),
        }
    }
    // The agent's programs, minus any the category always denies.
    for text in &agent.allow {
        let mut trial = args.clone();
        trial.allow.push(text.clone());
        if build(name, Some(cat), &trial, root).is_ok() {
            args.allow.push(text.clone());
        }
    }
    build(name, Some(cat), &args, root).map_err(DefaultErr::Other)
}

/// The rule set as `vahta.toml` spells it.
pub(crate) fn texts_of(rs: &RuleSet) -> RulesText {
    RulesText {
        allow: rs.allow.iter().map(|r| r.text.clone()).collect(),
        deny: rs.deny.iter().map(|r| r.text.clone()).collect(),
        category: rs.category.clone(),
        dirs: rs.dirs.iter().map(|d| d.text.clone()).collect(),
        network: match &rs.network {
            Network::None => Some("none".to_string()),
            Network::Hosts(_) => Some("hosts".to_string()),
            Network::App => None,
        },
        hosts: match &rs.network {
            Network::Hosts(h) => h.iter().map(|h| h.text.clone()).collect(),
            _ => Vec::new(),
        },
        from: rs.from.clone(),
    }
}

/// The loud line for a category below the detected one.
pub(crate) fn downgrade_line(
    chosen: &Category,
    detected: &Category,
    who: &str,
    subject: &str,
) -> String {
    format!(
        "This asks to downgrade: {subject} looks like a {}, whose default category is {}; {who} \
         proposes {}.",
        detected.name.to_lowercase(),
        detected.id,
        chosen.id
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn networks_and_hosts_parse() {
        assert_eq!(parse_net("none").unwrap(), Network::None);
        assert_eq!(parse_net("app").unwrap(), Network::App);
        match parse_net("hosts:api.a.com, *.b.org:443").unwrap() {
            Network::Hosts(h) => assert_eq!(h.len(), 2),
            other => panic!("{other:?}"),
        }
        for bad in ["", "hosts:", "hosts:x y", "open", "hosts:https://a.com"] {
            assert!(parse_net(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dirs_resolve_and_the_root_is_refused() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("scripts")).unwrap();
        let d = parse_dir("./scripts:ro", t.path()).unwrap();
        assert!(!d.write && d.path.ends_with("scripts") && d.text == "./scripts:ro");
        assert!(parse_dir("nope", t.path()).is_err());
        assert!(parse_dir("/", t.path()).is_err());
    }

    #[test]
    fn a_payment_default_needs_hosts_and_a_category_check_runs() {
        let t = tempfile::tempdir().unwrap();
        let pay = vahta_policy::category("payment").unwrap();
        assert!(matches!(
            default_set("K", pay, &Args::default(), None, t.path()),
            Err(DefaultErr::NeedHosts)
        ));
        let hosts = parse_hosts(["api.stripe.com"].into_iter()).unwrap();
        let b = default_set("K", pay, &Args::default(), Some(hosts), t.path()).unwrap();
        assert_eq!(b.rule_set.category.as_deref(), Some("payment"));
        assert!(matches!(b.rule_set.network, Network::Hosts(_)));
        assert_eq!(b.rule_set.deny.len(), 3);
        let args = Args {
            net: Some("app".into()),
            ..Args::default()
        };
        assert!(build("K", Some(pay), &args, t.path()).is_err());
    }
}
