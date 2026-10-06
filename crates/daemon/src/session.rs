//! Sessions: what a person's one password buys.
//!
//! A session is opened by `vahta unlock`, once, with the password typed in the
//! window. It belongs to an **anchor** process (pid and start time) and to
//! everything that process starts, and it lets `vahta run` from there use the
//! secrets it covers with no window. It keeps only the data keys of those
//! secrets, the store's MAC key and the pinned owner key and generation (see
//! `vahta_vault::SessionKeys`); the vault key is gone.
//!
//! * **Role.** Always a runner: `run` only. `reveal`, `copy`, `export` and
//!   every write need a fresh password and never enter a session.
//! * **Scope.** Session-tier secrets only. An each-use secret is never in one.
//! * **Deadline.** A time, or none (`forever`, until revoked). Two minutes
//!   before a root session ends, the person is asked in a window whether to
//!   extend it by 30 minutes; with no answer it ends at its deadline.
//! * **Delegation.** A child session narrows its parent's: a subset of its
//!   secrets, no later a deadline, anchored to the process that runs the
//!   sub-agent. Anything else is refused. The deepest matching session is the
//!   one a command uses.
//! * **Ending.** At the deadline, when the anchor exits, on `lock`, on
//!   `sessions kill`, when the daemon stops, on sleep. Ending a session ends
//!   every session below it and overwrites its keys. It cannot take a value back
//!   from a command that is already running; the docs say so.
//! * **Children inherit.** The daemon remembers the processes it launched and
//!   under which session, so a `vahta run` from inside one uses that session.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use vahta_os::ProcessId;
use vahta_vault::SessionKeys;

use crate::protocol::SessionInfo;

/// How long a person's "yes" extends a session.
pub const EXTEND_BY: Duration = Duration::from_secs(30 * 60);
/// How long before the end the person is asked.
pub const EXTEND_LEAD: Duration = Duration::from_secs(2 * 60);

/// What a session may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// `run` only.
    Runner,
}

pub struct Session {
    pub id: String,
    /// Whose daemon this is; one tenant, `local`, until there is a cloud.
    pub tenant: &'static str,
    pub vault_id: [u8; 16],
    pub vault_path: PathBuf,
    pub project: PathBuf,
    /// The names the session covers.
    pub scope: Vec<String>,
    pub keys: SessionKeys,
    pub role: Role,
    pub anchor: ProcessId,
    pub anchor_exe: String,
    pub parent: Option<String>,
    /// `None` lasts until revoked.
    pub deadline: Option<Instant>,
    /// When the person is asked about extending.
    pub ask_at: Option<Instant>,
    pub extension_pending: bool,
    pub label: Option<String>,
    pub uses: u64,
}

/// A session that has ended, its keys already overwritten.
pub struct Ended {
    pub session: Session,
    pub reason: &'static str,
}

/// A root session whose end is near enough to ask about.
pub struct ExtensionAsk {
    pub id: String,
    pub deadline: Instant,
    pub scope: Vec<String>,
    pub project: PathBuf,
    pub anchor_exe: String,
    pub anchor_pid: u32,
}

#[derive(Default)]
pub struct Sweep {
    pub ended: Vec<Ended>,
    pub ask: Vec<ExtensionAsk>,
}

/// Why a delegated session was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegateRefusal {
    /// Names the parent session does not cover.
    NotASubset(Vec<String>),
    /// A deadline later than the parent's (or none, under a parent that has one).
    LaterDeadline,
}

/// When to ask about extending a session that ends at `deadline`: two minutes
/// before, or halfway for one shorter than four minutes.
pub fn ask_time(now: Instant, deadline: Instant) -> Instant {
    let left = deadline.saturating_duration_since(now);
    deadline - EXTEND_LEAD.min(left / 2)
}

#[derive(Default)]
pub struct Sessions {
    items: Vec<Session>,
    /// Processes the daemon launched, and the session each runs under.
    launched: HashMap<ProcessId, String>,
}

impl Sessions {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn add(&mut self, session: Session) {
        self.items.push(session);
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.items.iter().find(|s| s.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Session> {
        self.items.iter_mut().find(|s| s.id == id)
    }

    /// How many sessions are above `id`: 0 for a root.
    pub fn depth(&self, id: &str) -> usize {
        let mut depth = 0;
        let mut current = self.get(id).and_then(|s| s.parent.as_deref());
        while let Some(parent) = current {
            depth += 1;
            if depth > self.items.len() {
                break;
            }
            current = self.get(parent).and_then(|s| s.parent.as_deref());
        }
        depth
    }

    /// Remember that `child` was launched under session `id`.
    pub fn note_launch(&mut self, child: ProcessId, id: &str) {
        self.launched.insert(child, id.to_string());
    }

    pub fn forget_launch(&mut self, child: &ProcessId) {
        self.launched.remove(child);
    }

    /// The session a caller belongs to for `vault_id`: one whose anchor is in
    /// the caller's chain of ancestors (the caller included), or one under
    /// which a process in the chain was launched. The deepest, that is the
    /// narrowest, wins; of equals the newest.
    pub fn find(&self, chain: &[ProcessId], vault_id: &[u8; 16]) -> Option<&Session> {
        let mut best: Option<(usize, &Session)> = None;
        for s in self.items.iter().filter(|s| &s.vault_id == vault_id) {
            let matches = chain.contains(&s.anchor)
                || chain
                    .iter()
                    .any(|p| self.launched.get(p).is_some_and(|id| id == &s.id));
            if matches {
                let depth = self.depth(&s.id);
                if best.is_none_or(|(d, _)| depth >= d) {
                    best = Some((depth, s));
                }
            }
        }
        best.map(|(_, s)| s)
    }

    /// Every session, of any vault, that a caller with this `chain` belongs
    /// to: by anchor or by a process the daemon launched under it. For the
    /// hook, which asks about values in a tool's output, not about one vault.
    pub fn covering(&self, chain: &[ProcessId]) -> Vec<&Session> {
        self.items
            .iter()
            .filter(|s| {
                chain.contains(&s.anchor)
                    || chain
                        .iter()
                        .any(|p| self.launched.get(p).is_some_and(|id| id == &s.id))
            })
            .collect()
    }

    /// Whether a child with `names` and `deadline` may be made under `parent`.
    pub fn check_delegate(
        parent: &Session,
        names: &[String],
        deadline: Option<Instant>,
    ) -> Result<(), DelegateRefusal> {
        let missing: Vec<String> = names
            .iter()
            .filter(|n| !parent.scope.contains(n))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(DelegateRefusal::NotASubset(missing));
        }
        match (parent.deadline, deadline) {
            (None, _) => Ok(()),
            (Some(p), Some(c)) if c <= p => Ok(()),
            _ => Err(DelegateRefusal::LaterDeadline),
        }
    }

    /// End session `id` and every session below it. `reason` is the root's;
    /// the others end with `parent_ended`.
    pub fn end_tree(&mut self, id: &str, reason: &'static str) -> Vec<Ended> {
        if self.get(id).is_none() {
            return Vec::new();
        }
        let mut doomed = vec![id.to_string()];
        let mut i = 0;
        while i < doomed.len() {
            let current = doomed[i].clone();
            for s in &self.items {
                if s.parent.as_deref() == Some(current.as_str()) && !doomed.contains(&s.id) {
                    doomed.push(s.id.clone());
                }
            }
            i += 1;
        }
        let mut ended = Vec::new();
        for (n, gone) in doomed.iter().enumerate() {
            if let Some(pos) = self.items.iter().position(|s| &s.id == gone) {
                let mut session = self.items.remove(pos);
                session.keys.zeroize();
                ended.push(Ended {
                    session,
                    reason: if n == 0 { reason } else { "parent_ended" },
                });
            }
        }
        self.launched.retain(|_, sid| !doomed.contains(sid));
        ended
    }

    /// End every session for which `pred` holds, and what is below them.
    pub fn end_where(
        &mut self,
        pred: impl Fn(&Session) -> bool,
        reason: &'static str,
    ) -> Vec<Ended> {
        let ids: Vec<String> = self
            .items
            .iter()
            .filter(|s| pred(s))
            .map(|s| s.id.clone())
            .collect();
        let mut ended = Vec::new();
        for id in ids {
            ended.extend(self.end_tree(&id, reason));
        }
        ended
    }

    pub fn end_all(&mut self, reason: &'static str) -> Vec<Ended> {
        self.end_where(|_| true, reason)
    }

    /// End what has run out (a deadline, an anchor that is gone) and say which
    /// root sessions are due to be asked about extending.
    pub fn sweep(&mut self, now: Instant, alive: &dyn Fn(&ProcessId) -> bool) -> Sweep {
        let mut sweep = Sweep::default();
        let expired: Vec<String> = self
            .items
            .iter()
            .filter(|s| s.deadline.is_some_and(|d| d <= now))
            .map(|s| s.id.clone())
            .collect();
        for id in expired {
            sweep.ended.extend(self.end_tree(&id, "expired"));
        }
        let orphaned: Vec<String> = self
            .items
            .iter()
            .filter(|s| !alive(&s.anchor))
            .map(|s| s.id.clone())
            .collect();
        for id in orphaned {
            sweep.ended.extend(self.end_tree(&id, "anchor_exited"));
        }
        self.launched.retain(|p, _| alive(p));
        for s in self.items.iter_mut() {
            if s.parent.is_none()
                && !s.extension_pending
                && let (Some(deadline), Some(ask_at)) = (s.deadline, s.ask_at)
                && ask_at <= now
                && now < deadline
            {
                s.extension_pending = true;
                sweep.ask.push(ExtensionAsk {
                    id: s.id.clone(),
                    deadline,
                    scope: s.scope.clone(),
                    project: s.project.clone(),
                    anchor_exe: s.anchor_exe.clone(),
                    anchor_pid: s.anchor.pid,
                });
            }
        }
        sweep
    }

    /// Push `id`'s deadline out by `by`. False for a session that is gone or
    /// has no deadline.
    pub fn extend(&mut self, id: &str, now: Instant, by: Duration) -> bool {
        let Some(s) = self.get_mut(id) else {
            return false;
        };
        let Some(deadline) = s.deadline else {
            return false;
        };
        let new = deadline.max(now) + by;
        s.deadline = Some(new);
        s.ask_at = Some(ask_time(now, new));
        s.extension_pending = false;
        true
    }

    pub fn infos(&self, now: Instant) -> Vec<SessionInfo> {
        self.items.iter().map(|s| info_of(s, now)).collect()
    }
}

pub fn info_of(s: &Session, now: Instant) -> SessionInfo {
    SessionInfo {
        id: s.id.clone(),
        tenant: s.tenant.to_string(),
        parent: s.parent.clone(),
        project: s.project.display().to_string(),
        vault: s.vault_path.display().to_string(),
        names: s.scope.clone(),
        role: match s.role {
            Role::Runner => "runner".to_string(),
        },
        anchor_exe: s.anchor_exe.clone(),
        anchor_pid: s.anchor.pid,
        remaining_secs: s
            .deadline
            .map(|d| d.saturating_duration_since(now).as_secs()),
        uses: s.uses,
        label: s.label.clone(),
    }
}

/// A short random id for a session.
pub fn new_id() -> Option<String> {
    let bytes = vahta_vault::crypto::random::<6>().ok()?;
    Some(vahta_vault::hex_encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vahta_vault::store::LocalStore;
    use vahta_vault::{KdfParams, Kind, Tier, Vault};

    struct Fixture {
        _dir: tempfile::TempDir,
        keys_for: Vec<(String, SessionKeys)>,
        vault_id: [u8; 16],
    }

    fn pid(n: u32) -> ProcessId {
        ProcessId {
            pid: n,
            start_time: u64::from(n) * 100,
        }
    }

    /// A vault with A, B and C, and session keys for each subset asked for.
    fn keys(names: &[&str]) -> (SessionKeys, [u8; 16]) {
        let fx = fixture(&[names]);
        let (_, k) = fx.keys_for.into_iter().next().unwrap();
        (k, fx.vault_id)
    }

    fn fixture(subsets: &[&[&str]]) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.vht");
        let store = LocalStore::new(dir.path().join("store"));
        let (mut v, _) = Vault::create(b"correct horse", KdfParams::TEST).unwrap();
        for (n, value) in [("A", "fake-a"), ("B", "fake-b"), ("C", "fake-c")] {
            v.set(n, value.as_bytes(), Kind::Env, Tier::Session)
                .unwrap();
        }
        v.save(&path, &store).unwrap();
        let vault_id = v.vault_id();
        let keys_for = subsets
            .iter()
            .map(|names| {
                let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
                (names.join(","), v.session_keys(&names).unwrap())
            })
            .collect();
        Fixture {
            _dir: dir,
            keys_for,
            vault_id,
        }
    }

    fn session(
        id: &str,
        names: &[&str],
        anchor: u32,
        parent: Option<&str>,
        deadline: Option<Instant>,
    ) -> Session {
        let (k, vault_id) = keys(names);
        // Every test vault has its own id, so a fixed one is stamped on for the
        // lookups that need sessions of "one vault".
        let _ = vault_id;
        Session {
            id: id.to_string(),
            tenant: "local",
            vault_id: [7; 16],
            vault_path: PathBuf::from("/p/.vahta/vault.vht"),
            project: PathBuf::from("/p"),
            scope: names.iter().map(|n| n.to_string()).collect(),
            keys: k,
            role: Role::Runner,
            anchor: pid(anchor),
            anchor_exe: "claude".to_string(),
            parent: parent.map(str::to_string),
            deadline,
            ask_at: deadline.map(|d| ask_time(Instant::now(), d)),
            extension_pending: false,
            label: None,
            uses: 0,
        }
    }

    #[test]
    fn a_subset_is_accepted_and_a_superset_refused() {
        let now = Instant::now();
        let parent = session(
            "p",
            &["A", "B"],
            10,
            None,
            Some(now + Duration::from_secs(600)),
        );
        let names = |v: &[&str]| v.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let later = Some(now + Duration::from_secs(60));
        assert_eq!(
            Sessions::check_delegate(&parent, &names(&["A"]), later),
            Ok(())
        );
        assert_eq!(
            Sessions::check_delegate(&parent, &names(&["A", "B"]), later),
            Ok(())
        );
        assert_eq!(
            Sessions::check_delegate(&parent, &names(&["A", "C"]), later),
            Err(DelegateRefusal::NotASubset(names(&["C"])))
        );
        assert_eq!(
            Sessions::check_delegate(&parent, &names(&["D", "C"]), later),
            Err(DelegateRefusal::NotASubset(names(&["D", "C"])))
        );
    }

    #[test]
    fn a_later_deadline_is_refused() {
        let now = Instant::now();
        let end = now + Duration::from_secs(600);
        let parent = session("p", &["A"], 10, None, Some(end));
        let a = vec!["A".to_string()];
        assert_eq!(Sessions::check_delegate(&parent, &a, Some(end)), Ok(()));
        assert_eq!(
            Sessions::check_delegate(&parent, &a, Some(end + Duration::from_secs(1))),
            Err(DelegateRefusal::LaterDeadline)
        );
        // "Forever" under a parent that has an end is later than it.
        assert_eq!(
            Sessions::check_delegate(&parent, &a, None),
            Err(DelegateRefusal::LaterDeadline)
        );
        // A parent that lasts until revoked allows any.
        let forever = session("f", &["A"], 11, None, None);
        assert_eq!(Sessions::check_delegate(&forever, &a, None), Ok(()));
        assert_eq!(Sessions::check_delegate(&forever, &a, Some(end)), Ok(()));
    }

    #[test]
    fn the_deepest_matching_session_wins_and_unrelated_ones_do_not_match() {
        let mut s = Sessions::default();
        s.add(session("root", &["A", "B"], 10, None, None));
        s.add(session("child", &["A"], 20, Some("root"), None));
        s.add(session("other", &["A", "B"], 99, None, None));
        let vault = [7u8; 16];
        assert_eq!(s.depth("root"), 0);
        assert_eq!(s.depth("child"), 1);
        // A caller under the child (whose chain includes both anchors).
        let chain = [pid(30), pid(20), pid(10), pid(5)];
        assert_eq!(s.find(&chain, &vault).unwrap().id, "child");
        // A caller under the root only.
        assert_eq!(s.find(&[pid(31), pid(10)], &vault).unwrap().id, "root");
        // A caller under neither, and one for another vault.
        assert!(s.find(&[pid(31), pid(77)], &vault).is_none());
        assert!(s.find(&chain, &[8u8; 16]).is_none());
        // A recycled pid (same number, another start time) is not the anchor.
        let recycled = ProcessId {
            pid: 10,
            start_time: 1,
        };
        assert!(s.find(&[pid(31), recycled], &vault).is_none());
        // A process the daemon launched under the root carries the session.
        s.note_launch(pid(40), "root");
        assert_eq!(s.find(&[pid(41), pid(40)], &vault).unwrap().id, "root");
        // Launched under the child, it is the child's.
        s.note_launch(pid(50), "child");
        assert_eq!(
            s.find(&[pid(51), pid(50), pid(40)], &vault).unwrap().id,
            "child"
        );
    }

    #[test]
    fn killing_a_parent_kills_its_children_and_wipes_their_keys() {
        let mut s = Sessions::default();
        s.add(session("root", &["A", "B"], 10, None, None));
        s.add(session("child", &["A"], 20, Some("root"), None));
        s.add(session("grandchild", &["A"], 30, Some("child"), None));
        s.add(session("other", &["B"], 40, None, None));
        s.note_launch(pid(60), "child");
        let ended = s.end_tree("root", "killed");
        let ids: Vec<&str> = ended.iter().map(|e| e.session.id.as_str()).collect();
        assert_eq!(ids, ["root", "child", "grandchild"]);
        assert_eq!(ended[0].reason, "killed");
        assert_eq!(ended[1].reason, "parent_ended");
        assert!(ended.iter().all(|e| e.session.keys.is_wiped()));
        assert_eq!(s.len(), 1);
        assert!(s.get("other").is_some_and(|o| !o.keys.is_wiped()));
        // What was launched under the dead sessions is forgotten.
        assert!(s.find(&[pid(60)], &[7u8; 16]).is_none());
        assert!(s.end_tree("root", "killed").is_empty());
    }

    #[test]
    fn expiry_ends_the_session_and_zeroises_its_keys() {
        let now = Instant::now();
        let mut s = Sessions::default();
        s.add(session(
            "short",
            &["A"],
            10,
            None,
            Some(now + Duration::from_secs(5)),
        ));
        s.add(session(
            "long",
            &["A"],
            11,
            None,
            Some(now + Duration::from_secs(500)),
        ));
        s.add(session("forever", &["A"], 12, None, None));
        s.add(session("kid", &["A"], 13, Some("short"), None));
        let alive = |_: &ProcessId| true;
        let none = s.sweep(now + Duration::from_secs(1), &alive);
        assert!(none.ended.is_empty());
        let swept = s.sweep(now + Duration::from_secs(6), &alive);
        let ids: Vec<&str> = swept.ended.iter().map(|e| e.session.id.as_str()).collect();
        assert_eq!(ids, ["short", "kid"]);
        assert_eq!(swept.ended[0].reason, "expired");
        assert!(swept.ended.iter().all(|e| e.session.keys.is_wiped()));
        assert_eq!(s.len(), 2);
        // A session whose anchor is gone ends too, with its own reason.
        let gone = |p: &ProcessId| p.pid != 11;
        let swept = s.sweep(now + Duration::from_secs(7), &gone);
        assert_eq!(swept.ended.len(), 1);
        assert_eq!(swept.ended[0].reason, "anchor_exited");
        assert_eq!(s.len(), 1);
        assert!(s.get("forever").is_some());
    }

    #[test]
    fn the_extension_is_asked_once_near_the_end_and_granted_or_not() {
        let now = Instant::now();
        let mut s = Sessions::default();
        s.add(session(
            "a",
            &["A"],
            10,
            None,
            Some(now + Duration::from_secs(600)),
        ));
        // A delegated child is never asked.
        s.add(session(
            "c",
            &["A"],
            11,
            Some("a"),
            Some(now + Duration::from_secs(300)),
        ));
        let alive = |_: &ProcessId| true;
        assert!(
            s.sweep(now + Duration::from_secs(100), &alive)
                .ask
                .is_empty()
        );
        let near = s.sweep(now + Duration::from_secs(490), &alive);
        assert_eq!(near.ask.len(), 1);
        assert_eq!(near.ask[0].id, "a");
        // Not asked again while the question stands.
        assert!(
            s.sweep(now + Duration::from_secs(500), &alive)
                .ask
                .is_empty()
        );
        // Yes: thirty more minutes from the old end, and a fresh question later.
        assert!(s.extend("a", now + Duration::from_secs(500), EXTEND_BY));
        let left = s.infos(now + Duration::from_secs(500))[0]
            .remaining_secs
            .unwrap();
        assert_eq!(left, 600 + 1800 - 500);
        assert!(
            s.sweep(now + Duration::from_secs(700), &alive)
                .ask
                .is_empty()
        );
        let again = s.sweep(now + Duration::from_secs(600 + 1800 - 100), &alive);
        assert_eq!(again.ask.len(), 1);
        // A forever session has nothing to extend.
        s.add(session("f", &["A"], 12, None, None));
        assert!(!s.extend("f", now, EXTEND_BY));
        assert!(!s.extend("nope", now, EXTEND_BY));
    }

    #[test]
    fn a_short_session_is_asked_halfway() {
        let now = Instant::now();
        let end = now + Duration::from_secs(4);
        assert_eq!(ask_time(now, end), now + Duration::from_secs(2));
        let long = now + Duration::from_secs(3600);
        assert_eq!(ask_time(now, long), long - EXTEND_LEAD);
    }

    #[test]
    fn what_a_client_sees_has_no_key() {
        let now = Instant::now();
        let mut s = Sessions::default();
        s.add(session(
            "a",
            &["A", "B"],
            10,
            None,
            Some(now + Duration::from_secs(90)),
        ));
        let info = &s.infos(now)[0];
        assert_eq!(info.role, "runner");
        assert_eq!(info.names, ["A", "B"]);
        assert_eq!(info.remaining_secs, Some(90));
        let shown = serde_json::to_string(info).unwrap();
        assert!(!shown.contains("fake-"));
    }
}
