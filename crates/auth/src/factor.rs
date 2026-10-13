use serde::{Deserialize, Serialize};

/// What kind of proof an approver or unlocker gives. Ordered by strength:
/// someone is at the machine; they know the secret; they hold the paired
/// phone and passed its biometric check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Factor {
    Presence,
    Knowledge,
    PossessionBiometric,
}

/// What an action asks for. Not a bare minimum factor: the master password
/// (Knowledge) satisfies every need but `PasswordOnly`, so the password window
/// is always a way through, and a phone satisfies `Knowledge` because it is
/// two factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Need {
    Presence,
    Knowledge,
    PossessionBiometric,
    /// The master password and nothing else.
    PasswordOnly,
}

impl Need {
    pub fn parse(text: &str) -> Option<Need> {
        Some(match text {
            "presence" => Need::Presence,
            "knowledge" => Need::Knowledge,
            "possession_biometric" => Need::PossessionBiometric,
            "password_only" => Need::PasswordOnly,
            _ => return None,
        })
    }

    pub fn satisfied_by(self, have: Factor) -> bool {
        match self {
            Need::PasswordOnly => have == Factor::Knowledge,
            _ if have == Factor::Knowledge => true,
            Need::Presence => true,
            Need::Knowledge => have >= Factor::Knowledge,
            Need::PossessionBiometric => have == Factor::PossessionBiometric,
        }
    }

    /// The stricter of two (for an action on secrets of several categories).
    pub fn strictest(self, other: Need) -> Need {
        let rank = |n: Need| match n {
            Need::Presence => 0,
            Need::Knowledge => 1,
            Need::PossessionBiometric => 2,
            Need::PasswordOnly => 3,
        };
        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }
}
