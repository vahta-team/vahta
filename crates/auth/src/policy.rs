//! The factor policy, as data: `policy/factors.toml`, turned into statics by
//! the build script.

use crate::factor::Need;

mod gen_ {
    include!(concat!(env!("OUT_DIR"), "/factors_gen.rs"));
}

fn parse(text: &str) -> Need {
    // The build script checked every value; the default is the safe reading
    // of one it did not.
    Need::parse(text).unwrap_or(Need::Knowledge)
}

/// What `action` (a [`crate::Action::key`]) needs, for a secret of
/// `category` if it has one.
pub fn need(action: &str, category: Option<&str>) -> Need {
    if let Some(c) = category
        && let Some((_, _, n)) = gen_::CATEGORIES
            .iter()
            .find(|(cat, a, _)| *cat == c && *a == action)
    {
        return parse(n);
    }
    match gen_::ACTIONS.iter().find(|(a, _)| *a == action) {
        Some((_, n)) => parse(n),
        None => parse(gen_::DEFAULT),
    }
}

/// The strictest need over several categories (an action on several secrets).
pub fn need_for(action: &str, categories: &[String]) -> Need {
    let mut need = self::need(action, None);
    for c in categories {
        need = need.strictest(self::need(action, Some(c)));
    }
    need
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Factor;

    #[test]
    fn the_file_says_what_the_actions_need() {
        assert_eq!(need("extend", None), Need::Presence);
        assert_eq!(need("unlock", None), Need::Knowledge);
        assert_eq!(need("devices", None), Need::PasswordOnly);
        // A category overrides, another one does not.
        assert_eq!(
            need("run_each_use", Some("payment")),
            Need::PossessionBiometric
        );
        assert_eq!(need("run_each_use", Some("llm")), Need::Knowledge);
        assert_eq!(need("nonsense", None), Need::Knowledge);
        assert_eq!(
            need_for("run_each_use", &["llm".into(), "payment".into()]),
            Need::PossessionBiometric
        );
    }

    #[test]
    fn the_password_satisfies_everything_but_a_phone_alone_does_not_manage_devices() {
        for n in [
            Need::Presence,
            Need::Knowledge,
            Need::PossessionBiometric,
            Need::PasswordOnly,
        ] {
            assert!(n.satisfied_by(Factor::Knowledge));
        }
        assert!(Need::Knowledge.satisfied_by(Factor::PossessionBiometric));
        assert!(Need::PossessionBiometric.satisfied_by(Factor::PossessionBiometric));
        assert!(!Need::PasswordOnly.satisfied_by(Factor::PossessionBiometric));
        assert!(!Need::Knowledge.satisfied_by(Factor::Presence));
        assert!(!Need::PossessionBiometric.satisfied_by(Factor::Presence));
        assert!(Need::Presence.satisfied_by(Factor::Presence));
    }
}
