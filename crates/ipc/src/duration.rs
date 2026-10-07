//! Durations as people type them, shared by `vahta unlock --for` and the
//! window that extends a session: units (`90s`, `15m`, `1h30m`, `2d`) or a
//! clock (`0:02:30`, `1:30:00`, `2:30` for minutes and seconds).

/// The seconds `text` stands for, or `None` when it is not a duration. Zero is
/// returned as zero; whether that is allowed is the caller's business.
pub fn parse_secs(text: &str) -> Option<u64> {
    let text = text.trim().to_ascii_lowercase();
    if text.contains(':') {
        return parse_clock(&text);
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut any = false;
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit: u64 = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => return None,
        };
        let n: u64 = digits.parse().ok()?;
        digits.clear();
        total = total.checked_add(n.checked_mul(unit)?)?;
        any = true;
    }
    (digits.is_empty() && any).then_some(total)
}

/// `h:mm:ss` or `m:ss`. The parts after the first are below 60.
fn parse_clock(text: &str) -> Option<u64> {
    let parts: Vec<&str> = text.split(':').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let nums: Vec<u64> = parts
        .iter()
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    if nums[1..].iter().any(|n| *n >= 60) {
        return None;
    }
    let (h, m, s) = match nums[..] {
        [m, s] => (0, m, s),
        [h, m, s] => (h, m, s),
        _ => return None,
    };
    h.checked_mul(3600)?
        .checked_add(m.checked_mul(60)?)?
        .checked_add(s)
}

/// A duration for a person to read: `45s`, `2m30s`, `30m`, `1h30m`, `2h`,
/// `1d2h`. Units that are zero are left out.
pub fn human(secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }
    let parts = [
        (secs / 86_400, "d"),
        (secs % 86_400 / 3600, "h"),
        (secs % 3600 / 60, "m"),
        (secs % 60, "s"),
    ];
    parts
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, u)| format!("{n}{u}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_and_clocks_both_parse() {
        for (text, secs) in [
            ("90s", 90),
            ("15m", 900),
            ("1h30m", 5400),
            ("2d", 172_800),
            (" 2M30S ", 150),
            ("0:02:30", 150),
            ("1:30:00", 5400),
            ("2:30", 150),
            ("26:00:00", 93_600),
        ] {
            assert_eq!(parse_secs(text), Some(secs), "{text}");
        }
    }

    #[test]
    fn nonsense_is_refused() {
        for text in [
            "", "m", "15", "1h30", "15x", "1:60", "1:00:60", "1::00", ":30", "1:2:3:4", "-5m",
            "1.5h", "forever",
        ] {
            assert_eq!(parse_secs(text), None, "{text}");
        }
        assert_eq!(parse_secs("99999999999999999999d"), None);
        assert_eq!(parse_secs("18446744073709551615d"), None);
        assert_eq!(parse_secs("18446744073709551615:00:00"), None);
    }

    #[test]
    fn human_leaves_out_the_zero_units() {
        assert_eq!(human(45), "45s");
        assert_eq!(human(150), "2m30s");
        assert_eq!(human(1800), "30m");
        assert_eq!(human(5400), "1h30m");
        assert_eq!(human(7200), "2h");
        assert_eq!(human(93_600), "1d2h");
    }
}
