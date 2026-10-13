//! What a secret's approved rules allow.
//!
//! * [`category`] data: the secret categories (`payment`, `server`, `ordinary`,
//!   `database`, `publish`, `local-only`) as they are compiled in from
//!   `categories/*.toml`. They are code-reviewed data in the repository and
//!   part of the binary: there is no file or setting that changes them on a
//!   machine, so an agent cannot rewrite them to suit itself.
//! * [`evaluate`]: one command against one secret's [`RuleSet`], the check that
//!   runs before a command gets the secret. Pure: it reads no file and starts no
//!   process; the caller resolves the program and the directories first.
//!
//! # Category ranks
//!
//! A rank says how much a leaked or misused key costs and how much oversight
//! its defaults ask for, highest first: `payment` 6, `publish` 5, `server` 4,
//! `database` 3, `local-only` 2, `ordinary` 1. Distinct on purpose, so a
//! proposal can never tie with what the key looks like. A category whose rank is
//! below the one detected from the value and the name is a **downgrade**: it is
//! allowed, but the window says so loudly and the journal records it.
//! `local-only` ranks low although it is strict, since it is strict about the
//! network and its default tier is a session.

mod category;
mod evaluate;

pub use category::{Category, NetKind, all, category, describe, is_downgrade, suggest};
pub use evaluate::{Ctx, Verdict, evaluate};
