//! Converts upstream rule files into `rules/imported.toml`.
//!
//! ```text
//! cargo run -p vahta-rules --example import -- \
//!     --gitleaks DIR --kingfisher DIR --out crates/rules/rules/imported.toml
//! ```
//!
//! * `--gitleaks DIR` holds `gitleaks.toml` and `COMMIT` (the pinned commit).
//! * `--kingfisher DIR` holds `betterleaks.yml`, `veles.yml` and `COMMIT`: the
//!   rules as Kingfisher converted them.
//!
//! The files are read as data and never run. What comes out:
//!
//! * gitleaks rules first (MIT). `generic-api-key` and every rule without
//!   keywords are left out: our own name-based matcher covers those.
//! * then the Betterleaks and Veles rules Kingfisher carries, but only those
//!   that add coverage gitleaks lacks: a rule whose keywords overlap a
//!   gitleaks rule's is dropped as a duplicate. Their keywords are derived from
//!   the regex (the longest literal every match must contain), since the
//!   Kingfisher form has none; a regex with no such literal of at least
//!   [`MIN_KEYWORD`] characters is a keyword-free generic rule and is dropped.
//! * a rule bound to a file path, one that needs another rule to fire, and one
//!   whose regex the Rust `regex` crate refuses are dropped, and reported.
//!
//! A rule for an identifier that is no secret alone (`*-client-id`,
//! `*-tenant-id`, an account name, a public key) is written with
//! `mode = "observe"`.
//!
//! Each rule keeps its true origin in `source`. Ids are prefixed `gitleaks.`,
//! `betterleaks.` or `veles.`.
//!
//! The report (counts and the reason for every drop) goes to stdout.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use regex::RegexBuilder;
use regex_syntax::hir::{Class, Hir, HirKind};

/// A keyword shorter than this would wake the rule on ordinary text.
const MIN_KEYWORD: usize = 3;
/// Rules our structural code in `vahta-detect` does better: it can tell a
/// placeholder or a `${VAR}` from a password.
const SUPERSEDED: &[&str] = &["generic-credential-uri", "mongodb-connection-string"];
/// Rules whose own keyword is too short to prefilter on, with one that is not.
const KEYWORD_OVERRIDE: &[(&str, &[&str])] = &[("jwt", &["eyj"])];
/// Rules for an identifier that is not a secret by itself (a client id, a tenant
/// id, an account name, a public key): they are imported in `observe` mode, so
/// the daemon hears of them and the agent is not stopped by them.
const IDENTIFIER_SUFFIXES: &[&str] = &[
    "-client-id",
    "-tenant-id",
    "-app-id",
    "-application-id",
    "-application-key",
    "-account-name",
    "-account-host",
    "-username",
    "-public-key",
    "-instance-url",
    "-project-url",
    "-rest-url",
    "-address",
    "-access-id",
    "-key-id",
    "-auth-id",
    "-user-api-id",
    "-service-account-id",
    "-token-name",
];
/// Same as `vahta_rules::REGEX_SIZE_LIMIT`.
const SIZE_LIMIT: usize = 1 << 20;

struct Imported {
    id: String,
    source: String,
    description: String,
    regex: String,
    keywords: Vec<String>,
    secret_group: usize,
    entropy: Option<f64>,
    allow: Vec<AllowOut>,
}

struct AllowOut {
    stopwords: Vec<String>,
    regexes: Vec<String>,
    target: &'static str,
}

#[derive(Default)]
struct Report {
    kept: BTreeMap<&'static str, usize>,
    dropped: Vec<(String, String)>,
}

impl Report {
    fn drop(&mut self, id: &str, why: impl Into<String>) {
        self.dropped.push((id.to_string(), why.into()));
    }
}

fn main() {
    let mut gitleaks = None;
    let mut kingfisher = None;
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--gitleaks" => gitleaks = args.next().map(PathBuf::from),
            "--kingfisher" => kingfisher = args.next().map(PathBuf::from),
            "--out" => out = args.next().map(PathBuf::from),
            _ => fail(&format!("unknown argument {a}")),
        }
    }
    let (Some(gitleaks), Some(kingfisher), Some(out)) = (gitleaks, kingfisher, out) else {
        fail("usage: import --gitleaks DIR --kingfisher DIR --out FILE");
    };
    let mut report = Report::default();

    // --- gitleaks ---------------------------------------------------------
    let gl_commit = read(&gitleaks.join("COMMIT")).trim().to_string();
    let gl_text = read(&gitleaks.join("gitleaks.toml"));
    let gl: toml::Table = gl_text
        .parse()
        .unwrap_or_else(|e| fail(&format!("gitleaks.toml: {e}")));
    let (common_regexes, common_stopwords) = common_allow(&gl);
    let mut rules: Vec<Imported> = Vec::new();
    let gl_source = format!("gitleaks@{}", short(&gl_commit));
    for r in gl
        .get("rules")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let Some(t) = r.as_table() else { continue };
        let id = t
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let Some(regex) = t.get("regex").and_then(|v| v.as_str()) else {
            report.drop(&id, "path-only rule");
            continue;
        };
        if t.contains_key("path") {
            report.drop(&id, "bound to a file path (the hook sees text, not paths)");
            continue;
        }
        if SUPERSEDED.contains(&id.as_str()) {
            report.drop(&id, "superseded by the structural connection-string rule");
            continue;
        }
        if id == "generic-api-key" {
            report.drop(
                &id,
                "keyword-free generic rule (our name matcher covers it)",
            );
            continue;
        }
        let keywords: Vec<String> = t
            .get("keywords")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str())
                    .map(str::to_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        if keywords.is_empty() {
            report.drop(&id, "no keywords (generic)");
            continue;
        }
        let keywords = usable_keywords(&id, keywords);
        if keywords.is_empty() {
            report.drop(&id, "keywords too short to prefilter on");
            continue;
        }
        let regex = &to_rust(regex);
        if let Err(e) = compiles(regex) {
            report.drop(&id, format!("regex refused: {e}"));
            continue;
        }
        let allow = gitleaks_allow(t);
        rules.push(Imported {
            id: format!("gitleaks.{id}"),
            source: gl_source.clone(),
            description: t
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or(&id)
                .to_string(),
            regex: regex.to_string(),
            keywords,
            secret_group: t
                .get("secretGroup")
                .and_then(|v| v.as_integer())
                .unwrap_or(0) as usize,
            entropy: t
                .get("entropy")
                .and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64))),
            allow,
        });
    }
    *report.kept.entry("gitleaks").or_default() = rules.len();

    // --- kingfisher -------------------------------------------------------
    let kf_commit = read(&kingfisher.join("COMMIT")).trim().to_string();
    let gl_keywords: Vec<String> = rules.iter().flat_map(|r| r.keywords.clone()).collect();
    let mut seen_keywords = gl_keywords.clone();
    for (file, tag, origin) in [
        ("betterleaks.yml", "betterleaks", "betterleaks@b3b4cbb"),
        ("veles.yml", "veles", "veles@e8621f1"),
    ] {
        let text = read(&kingfisher.join(file));
        let source = format!("{origin} via kingfisher@{}", short(&kf_commit));
        let mut kept = 0;
        for k in parse_kingfisher(&text) {
            let bare =
                k.id.split_once('.')
                    .map_or(k.id.as_str(), |x| x.1)
                    .to_string();
            let id = format!("{tag}.{}", bare.trim_start_matches("secrets/"));
            if SUPERSEDED.contains(&bare.as_str()) {
                report.drop(&id, "superseded by the structural connection-string rule");
                continue;
            }
            if k.has_path {
                report.drop(&id, "bound to a file path");
                continue;
            }
            if k.depends {
                report.drop(&id, "needs another rule to fire");
                continue;
            }
            let k = KRule {
                pattern: to_rust(&k.pattern),
                ..k
            };
            if let Err(e) = compiles(&k.pattern) {
                report.drop(&id, format!("regex refused: {e}"));
                continue;
            }
            let Some(keywords) = derive_keywords(&k.pattern)
                .map(|ks| usable_keywords(&bare, ks))
                .filter(|ks| !ks.is_empty())
            else {
                report.drop(
                    &id,
                    "no literal of at least 3 characters in every match (generic)",
                );
                continue;
            };
            if keywords.iter().any(|kw| overlaps(&seen_keywords, kw)) {
                report.drop(&id, "duplicate: an imported rule already has this keyword");
                continue;
            }
            seen_keywords.extend(keywords.iter().cloned());
            rules.push(Imported {
                id,
                source: source.clone(),
                description: k.name.clone(),
                regex: k.pattern,
                keywords,
                secret_group: k.secret_group,
                entropy: k.entropy,
                allow: Vec::new(),
            });
            kept += 1;
        }
        *report.kept.entry(tag).or_default() = kept;
    }

    // --- write ------------------------------------------------------------
    let mut o = String::new();
    o.push_str("# Generated by `cargo run -p vahta-rules --example import`. Do not edit.\n");
    o.push_str("# Licences and attribution are in crates/rules/NOTICE.\n");
    o.push_str("#\n# Sources, pinned:\n");
    let _ = writeln!(o, "#   gitleaks   {gl_commit} (MIT)");
    let _ = writeln!(
        o,
        "#   kingfisher {kf_commit} (Apache-2.0), carrying Betterleaks b3b4cbb (MIT) and Veles/OSV-SCALIBR e8621f1 (Apache-2.0)"
    );
    o.push_str("\n[meta]\n");
    let _ = writeln!(o, "gitleaks = \"{gl_commit}\"");
    let _ = writeln!(o, "kingfisher = \"{kf_commit}\"");
    o.push_str("\n[common]\n");
    let _ = writeln!(o, "stopwords = [{}]", join_strs(&common_stopwords));
    let _ = writeln!(
        o,
        "regexes = [\n{}]",
        common_regexes
            .iter()
            .map(|r| format!("  {},\n", ts(r)))
            .collect::<String>()
    );
    for r in &rules {
        o.push('\n');
        o.push_str("[[rules]]\n");
        let _ = writeln!(o, "id = {}", ts(&r.id));
        let _ = writeln!(o, "source = {}", ts(&r.source));
        let _ = writeln!(o, "description = {}", ts(&r.description));
        let _ = writeln!(o, "category = {}", ts(&category(&r.id, &r.description)));
        let _ = writeln!(o, "class = {}", ts(class(&r.id, &r.description)));
        if is_identifier(&r.id) {
            let _ = writeln!(o, "mode = 'observe'");
        }
        let _ = writeln!(o, "keywords = [{}]", join_strs(&r.keywords));
        let _ = writeln!(o, "regex = {}", ts(&r.regex));
        if r.secret_group != 0 {
            let _ = writeln!(o, "secret_group = {}", r.secret_group);
        }
        if let Some(e) = r.entropy {
            let _ = writeln!(o, "entropy = {e:?}");
        }
        for a in &r.allow {
            o.push_str("[[rules.allow]]\n");
            if !a.stopwords.is_empty() {
                let _ = writeln!(o, "stopwords = [{}]", join_strs(&a.stopwords));
            }
            if !a.regexes.is_empty() {
                let _ = writeln!(o, "regexes = [{}]", join_strs(&a.regexes));
            }
            if a.target != "value" {
                let _ = writeln!(o, "target = {}", ts(a.target));
            }
        }
    }
    std::fs::write(&out, o).unwrap_or_else(|e| fail(&format!("{}: {e}", out.display())));

    println!("kept: {:?}", report.kept);
    println!("total rules written: {}", rules.len());
    println!("dropped: {}", report.dropped.len());
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for (_, why) in &report.dropped {
        let key = why.split(':').next().unwrap_or(why).to_string();
        *by_reason.entry(key).or_default() += 1;
    }
    for (why, n) in by_reason {
        println!("  {n:4}  {why}");
    }
    if std::env::var_os("IMPORT_VERBOSE").is_some() {
        for (id, why) in &report.dropped {
            println!("  - {id}: {why}");
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("import: {msg}");
    std::process::exit(2);
}

fn read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(&format!("{}: {e}", path.display())))
}

/// Keywords that would wake the rule on ordinary text ("ey" is in "key", "s." in
/// every sentence) are removed; a two-character one with `_`, `~` or `-` stays.
fn usable_keywords(id: &str, keywords: Vec<String>) -> Vec<String> {
    if let Some((_, over)) = KEYWORD_OVERRIDE.iter().find(|(i, _)| *i == id) {
        return over.iter().map(|s| s.to_string()).collect();
    }
    keywords
        .into_iter()
        .filter(|k| k.len() >= MIN_KEYWORD || k.contains(['_', '~', '-']))
        .collect()
}

fn short(commit: &str) -> &str {
    &commit[..commit.len().min(7)]
}

fn compiles(pattern: &str) -> Result<(), String> {
    RegexBuilder::new(pattern)
        .size_limit(SIZE_LIMIT)
        .build()
        .map(|_| ())
        .map_err(|e| e.to_string().lines().last().unwrap_or("").to_string())
}

// --- gitleaks ---------------------------------------------------------------

fn common_allow(gl: &toml::Table) -> (Vec<String>, Vec<String>) {
    let list = |key: &str| -> Vec<String> {
        gl.get("allowlist")
            .and_then(|a| a.get(key))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let regexes = list("regexes").iter().map(|r| to_rust(r)).collect();
    (regexes, list("stopwords"))
}

/// A rule's own allow-lists. One that also names paths is skipped: the hook
/// has no path to test it against, and the path condition is part of it.
fn gitleaks_allow(rule: &toml::Table) -> Vec<AllowOut> {
    let mut out = Vec::new();
    for a in rule
        .get("allowlists")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let Some(a) = a.as_table() else { continue };
        if a.contains_key("paths") {
            continue;
        }
        let list = |key: &str| -> Vec<String> {
            a.get(key)
                .and_then(|v| v.as_array())
                .map(|x| {
                    x.iter()
                        .filter_map(|s| s.as_str())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let target = match a.get("regexTarget").and_then(|v| v.as_str()) {
            Some("match") => "matched",
            Some("line") => "line",
            _ => "value",
        };
        let stopwords: Vec<String> = list("stopwords").iter().map(|s| s.to_lowercase()).collect();
        // One the engine cannot compile would be skipped there; say so here
        // by keeping only the ones that do.
        let regexes: Vec<String> = list("regexes")
            .iter()
            .map(|r| to_rust(r))
            .filter(|r| compiles(r).is_ok())
            .collect();
        if !stopwords.is_empty() || !regexes.is_empty() {
            out.push(AllowOut {
                stopwords,
                regexes,
                target,
            });
        }
    }
    out
}

// --- kingfisher YAML (the narrow shape it writes) ---------------------------

struct KRule {
    name: String,
    id: String,
    pattern: String,
    secret_group: usize,
    entropy: Option<f64>,
    has_path: bool,
    depends: bool,
}

/// Top-level scalars of each `- name:` item under `rules:`; nested blocks
/// (validation, filters) are skipped, except the entropy floor in a filter.
fn parse_kingfisher(text: &str) -> Vec<KRule> {
    let mut rules = Vec::new();
    let mut cur: Option<KRule> = None;
    let mut in_rules = false;
    let mut saw_entropy_call = false;
    let mut want_float = false;
    for line in text.lines() {
        if !in_rules {
            in_rules = line == "rules:";
            continue;
        }
        if let Some(rest) = line.strip_prefix("- ") {
            if let Some(done) = cur.take() {
                rules.push(done);
            }
            cur = Some(KRule {
                name: String::new(),
                id: String::new(),
                pattern: String::new(),
                secret_group: 0,
                entropy: None,
                has_path: false,
                depends: false,
            });
            saw_entropy_call = false;
            want_float = false;
            set_key(cur.as_mut(), rest);
            continue;
        }
        let Some(k) = cur.as_mut() else { continue };
        if let Some(rest) = line.strip_prefix("  ")
            && !rest.starts_with(' ')
            && !rest.starts_with('-')
        {
            set_key(Some(k), rest);
            continue;
        }
        let t = line.trim();
        if t == "value: entropy" {
            saw_entropy_call = true;
        } else if saw_entropy_call && t == "kind: float" {
            want_float = true;
        } else if want_float && let Some(v) = t.strip_prefix("value: ") {
            k.entropy = v.trim_matches('\'').parse().ok();
            saw_entropy_call = false;
            want_float = false;
        }
    }
    if let Some(done) = cur.take() {
        rules.push(done);
    }
    rules
}

fn set_key(rule: Option<&mut KRule>, line: &str) {
    let Some(rule) = rule else { return };
    let Some((key, value)) = line.split_once(':') else {
        return;
    };
    let value = scalar(value.trim());
    match key {
        "name" => rule.name = value,
        "id" => rule.id = value,
        "pattern" => rule.pattern = value,
        "betterleaks_secret_group" => rule.secret_group = value.parse().unwrap_or(0),
        "path" => rule.has_path = true,
        "depends_on_rule" => rule.depends = true,
        _ => {}
    }
}

/// A YAML flow scalar: plain, 'single' (with `''`) or "double".
fn scalar(v: &str) -> String {
    if let Some(inner) = v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')) {
        return inner.replace("''", "'");
    }
    if let Some(inner) = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(o) => out.push(o),
                    None => {}
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    v.to_string()
}

// --- RE2 to Rust regex --------------------------------------------------------

/// RE2 (Go) reads `\w`, `\d` and `\s` as ASCII sets; the Rust `regex` crate reads
/// them as Unicode, which makes `[\w.-]{0,50}` thousands of states and the
/// vendor rules built on it blow the size limit. Spelled out, they are tiny.
/// The negated forms are rewritten outside a bracket class only.
fn to_rust(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let mut in_class = false;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' if i + 1 < chars.len() => {
                let n = chars[i + 1];
                let set = match n {
                    'w' => Some(("0-9A-Za-z_", false)),
                    'd' => Some(("0-9", false)),
                    's' => Some(("\\t\\n\\f\\r ", false)),
                    'W' if !in_class => Some(("0-9A-Za-z_", true)),
                    'D' if !in_class => Some(("0-9", true)),
                    'S' if !in_class => Some(("\\t\\n\\f\\r ", true)),
                    _ => None,
                };
                match set {
                    Some((body, negated)) if in_class => {
                        let _ = negated;
                        out.push_str(body);
                    }
                    Some((body, negated)) => {
                        out.push('[');
                        if negated {
                            out.push('^');
                        }
                        out.push_str(body);
                        out.push(']');
                    }
                    None => {
                        out.push(c);
                        out.push(n);
                    }
                }
                i += 2;
                continue;
            }
            '[' if !in_class => {
                in_class = true;
                out.push(c);
                i += 1;
                if chars.get(i) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                // A `]` first in the class is a literal.
                if chars.get(i) == Some(&']') {
                    out.push_str("\\]");
                    i += 1;
                }
                continue;
            }
            '[' if in_class && chars.get(i + 1) == Some(&':') => {
                // `[:alpha:]` inside a class: copy through `:]`.
                while i < chars.len() {
                    out.push(chars[i]);
                    if chars[i] == ']' && chars[i - 1] == ':' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            ']' if in_class => in_class = false,
            _ => {}
        }
        out.push(c);
        i += 1;
    }
    out
}

// --- keywords from a regex --------------------------------------------------

/// Lowercase literals of which every match contains at least one, each at
/// least [`MIN_KEYWORD`] long; `None` when the regex has no such set.
fn derive_keywords(pattern: &str) -> Option<Vec<String>> {
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(pattern)
        .ok()?;
    let set = required(&hir)?;
    let min = set.iter().map(String::len).min()?;
    (min >= MIN_KEYWORD && set.len() <= 8).then_some(set)
}

fn score(set: &[String]) -> (usize, usize) {
    (
        set.iter().map(String::len).min().unwrap_or(0),
        usize::MAX - set.len(),
    )
}

/// A set of lowercase ASCII literals, one of which every match contains.
fn required(h: &Hir) -> Option<Vec<String>> {
    match h.kind() {
        HirKind::Literal(l) => {
            let s = std::str::from_utf8(&l.0).ok()?;
            s.is_ascii().then(|| vec![s.to_ascii_lowercase()])
        }
        HirKind::Class(c) => letter_of(c).map(|c| vec![c.to_string()]),
        HirKind::Capture(c) => required(&c.sub),
        HirKind::Repetition(r) if r.min >= 1 => required(&r.sub),
        HirKind::Alternation(alts) => {
            let mut all: Vec<String> = Vec::new();
            for a in alts {
                for k in required(a)? {
                    if !all.contains(&k) {
                        all.push(k);
                    }
                }
            }
            Some(all)
        }
        HirKind::Concat(items) => {
            let mut best: Option<Vec<String>> = None;
            let mut run = String::new();
            let consider = |cand: Vec<String>, best: &mut Option<Vec<String>>| {
                if best.as_ref().is_none_or(|b| score(&cand) > score(b)) {
                    *best = Some(cand);
                }
            };
            for item in items {
                match item.kind() {
                    HirKind::Literal(l)
                        if std::str::from_utf8(&l.0).is_ok_and(|s| s.is_ascii()) =>
                    {
                        run.push_str(&String::from_utf8_lossy(&l.0).to_ascii_lowercase());
                        continue;
                    }
                    HirKind::Class(c) if letter_of(c).is_some() => {
                        run.extend(letter_of(c));
                        continue;
                    }
                    HirKind::Look(_) => continue,
                    _ => {}
                }
                if !run.is_empty() {
                    consider(vec![std::mem::take(&mut run)], &mut best);
                }
                if let Some(cand) = required(item) {
                    consider(cand, &mut best);
                }
            }
            if !run.is_empty() {
                consider(vec![run], &mut best);
            }
            best
        }
        _ => None,
    }
}

/// The lowercase ASCII letter a class stands for, when it is just the two cases
/// of one letter (what `(?i)a` becomes), ignoring non-ASCII fold partners.
fn letter_of(c: &Class) -> Option<char> {
    let Class::Unicode(u) = c else { return None };
    let mut letters: Vec<char> = Vec::new();
    for r in u.iter() {
        for ch in r.start()..=r.end() {
            if ch.is_ascii() {
                letters.push(ch);
            }
            if letters.len() > 2 {
                return None;
            }
        }
    }
    match letters.as_slice() {
        [a, b] if a.is_ascii_alphabetic() && a.eq_ignore_ascii_case(b) => {
            Some(a.to_ascii_lowercase())
        }
        _ => None,
    }
}

fn overlaps(seen: &[String], kw: &str) -> bool {
    seen.iter().any(|s| {
        s == kw || (s.len() >= 4 && kw.len() >= 4 && (s.contains(kw) || kw.contains(s.as_str())))
    })
}

// --- classification ---------------------------------------------------------

/// What the agent is told the value was. Never the vendor, never the rule id.
fn is_identifier(id: &str) -> bool {
    // `auth0-client-id.1` is the first of several rules for one name.
    let base = id
        .trim_end_matches(|c: char| c.is_ascii_digit())
        .trim_end_matches('.');
    IDENTIFIER_SUFFIXES.iter().any(|s| base.ends_with(s))
}

fn category(id: &str, description: &str) -> String {
    let text = format!("{id} {description}").to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    let c = if is_identifier(id) {
        "an account or client identifier"
    } else if has(&["private-key", "private key", "privatekey", "private_key"]) {
        "a private key"
    } else if has(&["password", "passwd"]) {
        "a password"
    } else if has(&["webhook"]) {
        "a webhook URL with an embedded secret"
    } else if has(&["client-secret", "client secret", "client_secret", "oauth"]) {
        "an OAuth client secret"
    } else if has(&[
        "access-key",
        "access key",
        "accesskey",
        "secret-key",
        "secret key",
        "secretkey",
    ]) {
        "an access key"
    } else if has(&["token", "-pat", " pat ", "bearer", "jwt", "session"]) {
        "an API token"
    } else if has(&["api-key", "apikey", "api key", "api_key"]) {
        "an API key"
    } else if has(&["credential", "creds"]) {
        "a credential"
    } else {
        "an API credential"
    };
    c.to_string()
}

fn class(id: &str, description: &str) -> &'static str {
    let text = format!("{id} {description}").to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    if has(&[
        "stripe",
        "paypal",
        "square",
        "braintree",
        "razorpay",
        "adyen",
        "plaid",
        "coinbase",
        "flutterwave",
        "paystack",
        "mollie",
        "gocardless",
        "lemon",
        "checkout",
        "payment",
    ]) {
        "payment"
    } else if has(&[
        "aws",
        "amazon",
        "gcp",
        "google",
        "azure",
        "alibaba",
        "tencent",
        "digitalocean",
        "heroku",
        "cloudflare",
        "linode",
        "vultr",
        "oracle",
        "scaleway",
        "ibm",
    ]) {
        "cloud"
    } else {
        "other"
    }
}

// --- TOML output ------------------------------------------------------------

fn join_strs(items: &[String]) -> String {
    items.iter().map(|s| ts(s)).collect::<Vec<_>>().join(", ")
}

/// A TOML string: literal when it can be, escaped otherwise.
fn ts(s: &str) -> String {
    if !s.contains('\'') && !s.chars().any(char::is_control) {
        return format!("'{s}'");
    }
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            '\r' => o.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(o, "\\u{:04X}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
