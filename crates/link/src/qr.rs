//! The terminal rendering of a pairing code.

use qrcode::{Color, EcLevel, QrCode};

/// A QR code of `text` as Unicode half blocks, two module rows per text line,
/// with a 2-module quiet zone. Dark modules print as spaces on the light
/// background of the block characters, so it scans on dark terminals too.
pub fn render_qr(text: &str) -> Result<String, String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map_err(|e| e.to_string())?;
    let w = code.width();
    let quiet = 2usize;
    let side = w + 2 * quiet;
    let dark = |x: usize, y: usize| {
        x >= quiet
            && y >= quiet
            && x < w + quiet
            && y < w + quiet
            && code[(x - quiet, y - quiet)] == Color::Dark
    };
    let mut out = String::new();
    let mut y = 0;
    while y < side {
        for x in 0..side {
            // The block is "lit" where the module is light (the code is drawn
            // as dark-on-light).
            let top = !dark(x, y);
            let bottom = y + 1 >= side || !dark(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::PairOffer;

    #[test]
    fn dimensions_match_the_symbol() {
        let o = PairOffer::new([1; 32], [2; 16], "laptop", 0, 60).unwrap();
        let qr = render_qr(&o.to_qr_string()).unwrap();
        let lines: Vec<&str> = qr.lines().collect();
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert_eq!(lines.len(), width.div_ceil(2));
        // A version-9ish symbol: well within a terminal.
        assert!((29..=70).contains(&width), "width {width}");
        // Quiet zone: the first line is all light.
        assert!(lines[0].chars().all(|c| c == '\u{2588}'));
    }

    #[test]
    fn too_long_is_an_error_not_a_panic() {
        assert!(render_qr(&"x".repeat(5000)).is_err());
    }
}
