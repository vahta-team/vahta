//! Throughput bench for the detector hot path (single-threaded).
//!
//! Usage: `cargo run --release -p vahta-detect --example bench -- [repo-root] [rounds]`
//!
//! Corpus: the repo's own `src/`, `tests/` and `crates/` text files (one blob per
//! file, as the scanner feeds them) plus generated assignment-heavy text whose
//! secret-shaped values are assembled at runtime from pieces, so no literal
//! credential ever sits in the source. Prints MB/s for the whole entry point
//! and per-matcher timings, which is what to read to find the hotspot.

use std::path::Path;
use std::time::Instant;
use vahta_detect::{
    classify_bearer_capture, classify_value, find_prefix_kind, iter_assignments, iter_flag_values,
    scan_text_hits,
};

fn collect(dir: &Path, out: &mut Vec<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if matches!(name, "target" | "__pycache__" | ".git" | "fixtures") {
                continue;
            }
            collect(&p, out);
        } else if let Ok(s) = std::fs::read_to_string(&p) {
            if s.len() < 400_000 {
                out.push(s);
            }
        }
    }
}

/// Deterministic xorshift, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[(self.next() % xs.len() as u64) as usize]
    }
}

fn generated(bytes: usize) -> String {
    let mut r = Rng(0x9E3779B97F4A7C15);
    let names = [
        "api_key",
        "DB_PASSWORD",
        "auth-token",
        "client_secret",
        "passwd",
        "PRIVATE_KEY",
        "host",
        "name",
    ];
    let heads = ["sk", "ghp", "AKIA", "xoxb", "plain", "Zx", "", "AIza"];
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut s = String::with_capacity(bytes + 200);
    while s.len() < bytes {
        let name = r.pick(&names);
        let mut v = String::new();
        let h = r.pick(&heads);
        if !h.is_empty() {
            v.push_str(h);
            v.push(if h == "AKIA" { 'X' } else { '_' });
        }
        for _ in 0..(8 + r.next() % 30) {
            v.push(alphabet[(r.next() % 62) as usize] as char);
        }
        match r.next() % 5 {
            0 => s.push_str(&format!("{name} = \"{v}\"\n")),
            1 => s.push_str(&format!("export {name}={v}\n")),
            2 => s.push_str(&format!("  \"{name}\": \"{v}\",\n")),
            3 => s.push_str(&format!(
                "run --{} {v} --verbose # héllo\n",
                name.to_lowercase().replace('_', "-")
            )),
            _ => s.push_str(&format!(
                "curl -H 'Authorization: Bearer {v}' https://example.test/{name}\n"
            )),
        }
    }
    s
}

fn time<F: FnMut()>(rounds: usize, mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..rounds {
        f();
    }
    t.elapsed().as_secs_f64() / rounds as f64
}

fn report(label: &str, bytes: usize, secs: f64) {
    println!(
        "  {label:<22} {:>8.2} ms  {:>7.1} MB/s",
        secs * 1e3,
        bytes as f64 / secs / 1e6
    );
}

fn run(label: &str, files: &[String], rounds: usize) {
    let bytes: usize = files.iter().map(|f| f.len()).sum();
    println!(
        "{label}: {} files, {:.2} MB",
        files.len(),
        bytes as f64 / 1e6
    );
    let mut sink = 0usize;
    report(
        "scan_text_hits",
        bytes,
        time(rounds, || {
            for f in files {
                sink += scan_text_hits(f).likely_names.len();
            }
        }),
    );
    report(
        "  (chars collect)",
        bytes,
        time(rounds, || {
            for f in files {
                sink += f.chars().collect::<Vec<char>>().len();
            }
        }),
    );
    report(
        "  find_prefix_kind",
        bytes,
        time(rounds, || {
            for f in files {
                sink += find_prefix_kind(f).is_some() as usize;
            }
        }),
    );
    report(
        "  bearer",
        bytes,
        time(rounds, || {
            for f in files {
                sink += classify_bearer_capture(f) as usize;
            }
        }),
    );
    report(
        "  iter_assignments",
        bytes,
        time(rounds, || {
            for f in files {
                sink += iter_assignments(f).len();
            }
        }),
    );
    let pairs: Vec<(String, String)> = files
        .iter()
        .flat_map(|f| iter_assignments(f).into_iter().chain(iter_flag_values(f)))
        .collect();
    report(
        "  classify_value",
        bytes,
        time(rounds, || {
            for (_, v) in &pairs {
                sink += classify_value(v).0 as usize;
            }
        }),
    );
    report(
        "    entropy",
        bytes,
        time(rounds, || {
            for (_, v) in &pairs {
                sink += vahta_detect::entropy(v) as usize;
            }
        }),
    );
    report(
        "    vowel_segments",
        bytes,
        time(rounds, || {
            for (_, v) in &pairs {
                sink += vahta_detect::vowel_bearing_segments(v);
            }
        }),
    );
    report(
        "    transition_rate",
        bytes,
        time(rounds, || {
            for (_, v) in &pairs {
                sink += vahta_detect::transition_rate(v) as usize;
            }
        }),
    );
    report(
        "    is_placeholder",
        bytes,
        time(rounds, || {
            for (_, v) in &pairs {
                sink += vahta_detect::is_placeholder(v) as usize;
            }
        }),
    );
    println!("    ({} candidate values)", pairs.len());
    report(
        "  iter_flag_values",
        bytes,
        time(rounds, || {
            for f in files {
                sink += iter_flag_values(f).len();
            }
        }),
    );
    if sink == usize::MAX {
        println!("{sink}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = args.get(1).map(String::as_str).unwrap_or(".");
    let rounds: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let mut files = Vec::new();
    for d in ["src", "tests", "crates"] {
        collect(&Path::new(root).join(d), &mut files);
    }
    run("repo text", &files, rounds);
    let synthetic = vec![generated(2_000_000)];
    run("generated", &synthetic, rounds);
}
