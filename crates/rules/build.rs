//! Turns `rules/vahta.toml` and `rules/imported.toml` into Rust statics, so
//! the hook, which starts afresh for every tool call, parses nothing at run
//! time. A file that does not parse fails the build.

#[path = "src/schema.rs"]
mod schema;

use std::fmt::Write as _;
use std::path::Path;

use schema::{Class, Mode, Target};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAllow {
    #[serde(default)]
    pub stopwords: Vec<String>,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub target: Target,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSample {
    pub hit: bool,
    pub parts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRuleSample {
    pub rule: String,
    pub hit: bool,
    pub parts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    pub source: String,
    pub description: String,
    pub category: String,
    #[serde(default)]
    pub class: Class,
    pub keywords: Vec<String>,
    pub regex: String,
    #[serde(default)]
    pub secret_group: usize,
    pub entropy: Option<f64>,
    #[serde(default)]
    pub allow: Vec<RawAllow>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub tests: Vec<RawSample>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCommon {
    #[serde(default)]
    pub stopwords: Vec<String>,
    #[serde(default)]
    pub regexes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawFile {
    /// Provenance notes; not used.
    #[serde(default)]
    pub meta: Option<toml::Table>,
    #[serde(default)]
    pub common: RawCommon,
    #[serde(default)]
    pub rules: Vec<RawRule>,
    #[serde(default)]
    pub samples: Vec<RawRuleSample>,
}

fn q(s: &str) -> String {
    format!("{s:?}")
}

fn strs(items: &[String]) -> String {
    items.iter().map(|s| q(s)).collect::<Vec<_>>().join(", ")
}

fn class(c: Class) -> &'static str {
    match c {
        Class::Payment => "Class::Payment",
        Class::Cloud => "Class::Cloud",
        Class::Other => "Class::Other",
    }
}

fn mode(m: Mode) -> &'static str {
    match m {
        Mode::Block => "Mode::Block",
        Mode::Observe => "Mode::Observe",
    }
}

fn target(t: Target) -> &'static str {
    match t {
        Target::Value => "Target::Value",
        Target::Matched => "Target::Matched",
        Target::Line => "Target::Line",
    }
}

fn allow(a: &RawAllow) -> String {
    format!(
        "Allow {{ stopwords: &[{}], regexes: &[{}], target: {} }}",
        strs(&a.stopwords),
        strs(&a.regexes),
        target(a.target)
    )
}

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    let mut stopwords = Vec::new();
    let mut regexes = Vec::new();
    let mut rules = String::new();
    let mut samples = String::new();
    let (mut n_rules, mut n_samples) = (0, 0);
    for name in ["vahta.toml", "imported.toml"] {
        let path = Path::new(&dir).join("rules").join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let file: RawFile = toml::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        stopwords.extend(file.common.stopwords);
        regexes.extend(file.common.regexes);
        for r in file.rules {
            n_rules += 1;
            let entropy = r
                .entropy
                .map_or("None".to_string(), |e| format!("Some({e:?})"));
            let allows: Vec<String> = r.allow.iter().map(allow).collect();
            let tests: Vec<String> = r
                .tests
                .iter()
                .map(|t| format!("Sample {{ hit: {}, parts: &[{}] }}", t.hit, strs(&t.parts)))
                .collect();
            let _ = writeln!(
                rules,
                "    Rule {{ id: {}, source: {}, description: {}, category: {}, class: {}, \
                 keywords: &[{}], regex: {}, secret_group: {}, entropy: {}, allow: &[{}], \
                 mode: {}, tests: &[{}], compiled: OnceLock::new(), allow_compiled: OnceLock::new() }},",
                q(&r.id),
                q(&r.source),
                q(&r.description),
                q(&r.category),
                class(r.class),
                strs(&r.keywords),
                q(&r.regex),
                r.secret_group,
                entropy,
                allows.join(", "),
                mode(r.mode),
                tests.join(", ")
            );
        }
        for s in file.samples {
            n_samples += 1;
            let _ = writeln!(
                samples,
                "    RuleSample {{ rule: {}, hit: {}, parts: &[{}] }},",
                q(&s.rule),
                s.hit,
                strs(&s.parts)
            );
        }
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "pub(crate) static RULES: [Rule; {n_rules}] = [\n{rules}];"
    );
    let _ = writeln!(
        out,
        "pub(crate) static SAMPLES: [RuleSample; {n_samples}] = [\n{samples}];"
    );
    let _ = writeln!(
        out,
        "pub(crate) static COMMON_STOPWORDS: &[&str] = &[{}];",
        strs(&stopwords)
    );
    let _ = writeln!(
        out,
        "pub(crate) static COMMON_REGEXES: &[&str] = &[{}];",
        strs(&regexes)
    );
    let dest = Path::new(&std::env::var("OUT_DIR").expect("out dir")).join("rules_data.rs");
    std::fs::write(dest, out).expect("write generated rules");
}
