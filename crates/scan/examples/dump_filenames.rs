//! Dump filename classification for paths read from stdin, one per line.

use std::io::{self, Read, Write};
use vahta_scan::filenames::{filename_kind, is_content_scannable, suffix};

fn main() -> io::Result<()> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let out = io::stdout();
    let mut out = out.lock();
    for path in raw.lines() {
        let name = path.rsplit('/').next().unwrap_or(path);
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            path,
            suffix(name),
            filename_kind(path, name).unwrap_or("-"),
            is_content_scannable(name),
        )?;
    }
    Ok(())
}
