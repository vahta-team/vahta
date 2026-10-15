//! Turns `categories/*.toml` into a Rust static, so the categories are part of
//! the binary: nothing on the machine, an agent included, can rewrite them at
//! run time. A file that does not parse, or that breaks a rule of the format
//! (a duplicate id, a default network the category does not allow), fails the
//! build.

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    id: String,
    name: String,
    description: String,
    rank: u8,
    tier: String,
    networks: Vec<String>,
    default_network: String,
    deny: Vec<String>,
    dirs: bool,
    allow_required: bool,
    programs: Vec<String>,
    words: Vec<String>,
    class: Option<String>,
    checklist: Vec<String>,
    /// Present: a run gets only these variables, the injected ones and the
    /// safe core. Absent: the caller's environment, as always.
    env_keep: Option<Vec<String>>,
}

fn q(s: &str) -> String {
    format!("{s:?}")
}

fn strs(items: &[String]) -> String {
    items.iter().map(|s| q(s)).collect::<Vec<_>>().join(", ")
}

fn net(word: &str, file: &str) -> &'static str {
    match word {
        "none" => "NetKind::None",
        "hosts" => "NetKind::Hosts",
        "app" => "NetKind::App",
        other => panic!("{file}: unknown network `{other}`"),
    }
}

fn main() {
    let dir =
        Path::new(&std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir")).join("categories");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("categories dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .collect();
    files.sort();
    let mut seen: Vec<String> = Vec::new();
    let mut body = String::new();
    for path in &files {
        println!("cargo:rerun-if-changed={}", path.display());
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{file}: {e}"));
        let c: Raw = toml::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert!(
            c.id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') && !c.id.is_empty(),
            "{file}: id is lowercase letters and hyphens"
        );
        assert!(
            format!("{}.toml", c.id) == file,
            "{file}: id must match the file name"
        );
        assert!(!seen.contains(&c.id), "{file}: duplicate id");
        assert!(!c.networks.is_empty(), "{file}: networks must not be empty");
        assert!(
            c.networks.contains(&c.default_network),
            "{file}: default_network must be one of networks"
        );
        assert!(
            c.checklist.len() >= 3,
            "{file}: a checklist has at least 3 items"
        );
        for g in &c.deny {
            assert!(
                matches!(g.as_str(), "@network" | "@shells" | "@interpreters"),
                "{file}: unknown group {g}"
            );
        }
        // The list is how a category keeps a run from being steered by the
        // environment, so a name that redirects a program must never be on it.
        for v in c.env_keep.iter().flatten() {
            let upper = v.to_ascii_uppercase();
            assert!(
                !v.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'*')
                    && v.find('*').is_none_or(|i| i == v.len() - 1),
                "{file}: env_keep entry `{v}` is a variable name, or a prefix ending in *"
            );
            for bad in [
                "NPM_CONFIG",
                "CARGO_REGISTR",
                "TWINE_",
                "PIP_",
                "UV_",
                "LD_",
                "DYLD_",
                "VAHTA_",
                "NODE_OPTIONS",
                "RUSTFLAGS",
                "GIT_",
                "HTTP_PROXY",
                "HTTPS_PROXY",
            ] {
                assert!(
                    !upper.starts_with(bad),
                    "{file}: env_keep must not keep `{v}` (it can redirect or load code)"
                );
            }
        }
        let env_keep = match &c.env_keep {
            None => "None".to_string(),
            Some(list) => format!("Some(&[{}])", strs(list)),
        };
        let tier = match c.tier.as_str() {
            "each-use" => "Tier::EachUse",
            "session" => "Tier::Session",
            other => panic!("{file}: unknown tier `{other}`"),
        };
        let class = match c.class.as_deref() {
            None => "None",
            Some("payment") => "Some(Class::Payment)",
            Some("cloud") => "Some(Class::Cloud)",
            Some(other) => panic!("{file}: unknown class `{other}`"),
        };
        let nets: Vec<&str> = c.networks.iter().map(|n| net(n, &file)).collect();
        let _ = writeln!(
            body,
            "    Category {{ id: {}, name: {}, description: {}, rank: {}, tier: {tier}, \
             networks: &[{}], default_network: {}, deny: &[{}], dirs: {}, allow_required: {}, \
             programs: &[{}], words: &[{}], class: {class}, checklist: &[{}], env_keep: {env_keep} }},",
            q(&c.id),
            q(&c.name),
            q(&c.description),
            c.rank,
            nets.join(", "),
            net(&c.default_network, &file),
            strs(&c.deny),
            c.dirs,
            c.allow_required,
            strs(&c.programs),
            strs(&c.words),
            strs(&c.checklist),
        );
        seen.push(c.id);
    }
    let out = format!(
        "static CATEGORIES: [Category; {}] = [\n{body}];\n",
        files.len()
    );
    let dest = Path::new(&std::env::var("OUT_DIR").expect("out dir")).join("categories_data.rs");
    std::fs::write(dest, out).expect("write generated categories");
}
