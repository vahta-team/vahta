//! The wire types of `vahta members`, `grant`, `revoke`, `share` and `join`.
//!
//! One request carries them all ([`crate::protocol::ClientRequest::Members`]),
//! so the protocol has one new request and one new reply for the whole team
//! feature. Nothing here is a secret: a member's public key string, names, the
//! file paths the person typed, and what a window will ask. Passwords and the
//! verification words are typed in the window, never sent by the client.

use serde::{Deserialize, Serialize};

/// What the person asked of the team commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "member_op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemberOp {
    /// `vahta id`: make this person's own key (the window asks for a password).
    Id {},
    /// `vahta members add NAME --role R --key vh1... [--for D]`.
    Add {
        name: String,
        /// `runner`, `editor` or `admin`.
        role: String,
        /// The `vh1...` key string the member sent.
        key: String,
        /// How long the membership lasts, in seconds.
        secs: Option<u64>,
    },
    /// `vahta members list`.
    List {},
    /// `vahta members extend NAME --for D`.
    Extend { name: String, secs: u64 },
    /// `vahta members remove NAME`.
    Remove { name: String },
    /// `vahta grant NAME MEMBER`.
    Grant { name: String, member: String },
    /// `vahta revoke NAME MEMBER`.
    Revoke { name: String, member: String },
    /// `vahta share MEMBER -o FILE`: the package for a member. `out` is an
    /// absolute path.
    Share { member: String, out: String },
    /// `vahta share --to owner NAME -o FILE`: one secret for the owner.
    SendToOwner { name: String, out: String },
    /// `vahta join FILE`: install a package, or import a secret an editor
    /// sent. `file` is an absolute path.
    Join { file: String },
}

/// One member as `vahta members list` shows it. No key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberInfo {
    pub name: String,
    pub role: String,
    /// When the membership ends (Unix seconds); `None` does not end.
    pub expires_at: Option<u64>,
    /// `active` or `expired`.
    pub state: String,
    /// The secrets this member holds.
    pub secrets: Vec<String>,
    /// Twelve hex digits of a hash of the member's public keys.
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ClientRequest, read_frame, write_frame};
    use std::io::Cursor;

    #[test]
    fn a_team_request_round_trips_and_has_no_place_for_a_password_or_words() {
        let req = ClientRequest::Members {
            cwd: "/p".into(),
            what: MemberOp::Add {
                name: "ann".into(),
                role: "runner".into(),
                key: "vh1abc".into(),
                secs: Some(60),
            },
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let back: Option<ClientRequest> = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, Some(req));
        for extra in ["password", "words", "value"] {
            let bad = format!(
                r#"{{"op":"members","cwd":"/p","what":{{"member_op":"list","{extra}":"x"}}}}"#
            );
            let mut f = (bad.len() as u32).to_le_bytes().to_vec();
            f.extend_from_slice(bad.as_bytes());
            let r: Result<Option<ClientRequest>, _> = read_frame(&mut Cursor::new(f));
            assert!(r.is_err(), "{extra}");
        }
    }
}
