//! What a session keeps of a vault, and how it reads one secret.
//!
//! A session is opened with the password, once. It then keeps only the data
//! keys of the secrets it covers (session-tier ones, never each-use), the
//! store's MAC key, and the owner key and generation the vault had at that
//! moment. The vault key, which opens everything, is dropped right after.
//!
//! Every read goes back to the file: it is read again and verified, its owner
//! key and generation are compared with the pins, the local store's record is
//! checked, and the one sealed entry is opened with its data key. A secret that
//! has been changed since the session was opened was re-sealed under a new data
//! key, so the old key opens nothing: the read fails with
//! [`Error::SessionStale`] ("changed since this session was opened; unlock
//! again"), and so does one that was removed or moved to the each-use tier.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::KEY_LEN;
use crate::format::{self, CURRENT, current};
use crate::store::{LocalStore, StateKey};
use crate::{Error, SecretValue, hex_encode};

struct SessionKey {
    name: String,
    secret_id: [u8; 16],
    dek: Zeroizing<[u8; KEY_LEN]>,
}

pub struct SessionKeys {
    vault_id: [u8; 16],
    pinned_owner_sign_pk: [u8; 32],
    generation: u64,
    mac_key: Zeroizing<[u8; 32]>,
    keys: Vec<SessionKey>,
}

impl SessionKeys {
    pub(crate) fn new(
        vault_id: [u8; 16],
        pinned_owner_sign_pk: [u8; 32],
        generation: u64,
        mac_key: [u8; 32],
        keys: Vec<(String, [u8; 16], Zeroizing<[u8; KEY_LEN]>)>,
    ) -> SessionKeys {
        SessionKeys {
            vault_id,
            pinned_owner_sign_pk,
            generation,
            mac_key: Zeroizing::new(mac_key),
            keys: keys
                .into_iter()
                .map(|(name, secret_id, dek)| SessionKey {
                    name,
                    secret_id,
                    dek,
                })
                .collect(),
        }
    }

    pub fn vault_id(&self) -> [u8; 16] {
        self.vault_id
    }

    /// The generation the vault had when the session was opened.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The names these keys open.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|k| k.name.as_str())
    }

    pub fn covers(&self, name: &str) -> bool {
        self.keys.iter().any(|k| k.name == name)
    }

    /// A copy limited to `names`, which must all be covered: what a delegated
    /// child session keeps of its parent's keys.
    pub fn narrowed(&self, names: &[String]) -> Result<SessionKeys, Error> {
        let mut keys = Vec::with_capacity(names.len());
        for name in names {
            let k = self
                .keys
                .iter()
                .find(|k| &k.name == name)
                .ok_or(Error::NoAccess)?;
            keys.push((name.clone(), k.secret_id, k.dek.clone()));
        }
        Ok(SessionKeys::new(
            self.vault_id,
            self.pinned_owner_sign_pk,
            self.generation,
            *self.mac_key,
            keys,
        ))
    }

    /// Overwrite every key with zeros now. Dropping does the same; this is for
    /// the moment a session ends while something still holds the struct.
    pub fn zeroize(&mut self) {
        for k in &mut self.keys {
            k.dek.zeroize();
        }
        self.mac_key.zeroize();
    }

    /// Whether [`SessionKeys::zeroize`] has run.
    pub fn is_wiped(&self) -> bool {
        self.mac_key.iter().all(|b| *b == 0)
            && self.keys.iter().all(|k| k.dek.iter().all(|b| *b == 0))
    }

    /// Read `name` from the vault file's `bytes`. The checks are in the module
    /// documentation.
    pub fn open(&self, bytes: &[u8], name: &str, store: &LocalStore) -> Result<SecretValue, Error> {
        let key = self
            .keys
            .iter()
            .find(|k| k.name == name)
            .ok_or(Error::NoAccess)?;
        let loaded = format::decode(bytes)?;
        // A file in an older format has not been upgraded by an unlock of this
        // build; its keys are not these.
        if loaded.format() != CURRENT {
            return Err(Error::SessionStale);
        }
        let m = loaded.model();
        if m.header.vault_id != self.vault_id {
            return Err(Error::SessionStale);
        }
        if m.owner.sign_pk != self.pinned_owner_sign_pk {
            return Err(Error::OwnerChanged);
        }
        if m.header.generation < self.generation {
            return Err(Error::RolledBack {
                found: m.header.generation,
                seen: self.generation,
            });
        }
        // The machine's own record, authenticated with the key kept for it.
        store.check(
            &self.vault_id,
            &StateKey::owner_from_mac(*self.mac_key),
            &m.owner.sign_pk,
            m.header.generation,
        )?;
        let i = m
            .index
            .iter()
            .position(|e| e.name == name)
            .ok_or_else(|| Error::not_found(name))?;
        let entry = &m.index[i];
        if entry.secret_id != key.secret_id || entry.tier != current::Tier::Session {
            return Err(Error::SessionStale);
        }
        match current::value_with_dek(CURRENT, &self.vault_id, &key.dek, &m.secrets[i]) {
            Ok(v) => Ok(v),
            // The data key of a changed secret is new, so the old one opens
            // nothing: that is the signal, not a damaged file.
            Err(Error::Unlock) => Err(Error::SessionStale),
            Err(e) => Err(e),
        }
    }
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("vault", &hex_encode(&self.vault_id))
            .field("generation", &self.generation)
            .field("secrets", &self.keys.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::{KdfParams, Kind, Tier, Vault};

    const PW: &[u8] = b"correct horse";

    struct T {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        store: LocalStore,
    }

    fn t() -> T {
        let dir = tempfile::tempdir().unwrap();
        T {
            path: dir.path().join("vault.vht"),
            store: LocalStore::new(dir.path().join("store")),
            _dir: dir,
        }
    }

    fn saved(t: &T) {
        let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
        v.set("A", b"fake-one", Kind::Env, Tier::Session).unwrap();
        v.set("B", b"fake-two", Kind::Env, Tier::Session).unwrap();
        v.set("E", b"fake-each", Kind::Env, Tier::EachUse).unwrap();
        v.save(&t.path, &t.store).unwrap();
    }

    fn keys(t: &T, names: &[&str]) -> SessionKeys {
        let v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        v.session_keys(&names).unwrap()
    }

    fn read(t: &T, k: &SessionKeys, name: &str) -> Result<SecretValue, Error> {
        k.open(&fs::read(&t.path).unwrap(), name, &t.store)
    }

    #[test]
    fn a_session_reads_what_it_covers_and_nothing_else() {
        let t = t();
        saved(&t);
        let k = keys(&t, &["A"]);
        assert_eq!(read(&t, &k, "A").unwrap().expose(), b"fake-one");
        assert!(matches!(read(&t, &k, "B"), Err(Error::NoAccess)));
        assert!(k.covers("A") && !k.covers("B"));
        assert_eq!(k.names().collect::<Vec<_>>(), ["A"]);
        // The debug output has no key and no value.
        let shown = format!("{k:?}");
        assert!(!shown.contains("fake") && shown.contains("secrets: 1"));
    }

    #[test]
    fn it_survives_unrelated_writes_and_fails_closed_on_a_changed_secret() {
        let t = t();
        saved(&t);
        let k = keys(&t, &["A", "B"]);
        // Another secret is added: the generation moves, A still reads.
        let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
        v.set("C", b"fake-three", Kind::Env, Tier::Session).unwrap();
        v.save(&t.path, &t.store).unwrap();
        assert_eq!(read(&t, &k, "A").unwrap().expose(), b"fake-one");
        // A is replaced: a new data key, the old one opens nothing.
        let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
        v.set("A", b"fake-new", Kind::Env, Tier::Session).unwrap();
        v.save(&t.path, &t.store).unwrap();
        let err = read(&t, &k, "A").unwrap_err();
        assert!(matches!(err, Error::SessionStale));
        assert!(err.to_string().contains("unlock again"));
        assert_eq!(read(&t, &k, "B").unwrap().expose(), b"fake-two");
        // B moves to the each-use tier, C was never covered.
        let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
        v.set_tier("B", Tier::EachUse).unwrap();
        v.remove("A").unwrap();
        v.save(&t.path, &t.store).unwrap();
        assert!(matches!(read(&t, &k, "B"), Err(Error::SessionStale)));
        assert!(matches!(read(&t, &k, "A"), Err(Error::NotFound(_))));
    }

    #[test]
    fn a_rolled_back_or_swapped_file_is_refused() {
        let t = t();
        saved(&t);
        let old = fs::read(&t.path).unwrap();
        let k = keys(&t, &["A"]);
        let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
        v.set("C", b"fake-three", Kind::Env, Tier::Session).unwrap();
        v.save(&t.path, &t.store).unwrap();
        let newer = fs::read(&t.path).unwrap();
        // The older file restored: below what the machine has seen.
        assert!(matches!(
            k.open(&old, "A", &t.store),
            Err(Error::RolledBack { .. })
        ));
        // Another vault's file in its place.
        let other = tempfile::tempdir().unwrap();
        let (mut ov, _) = Vault::create(PW, KdfParams::TEST).unwrap();
        ov.set("A", b"fake-other", Kind::Env, Tier::Session)
            .unwrap();
        let op = other.path().join("vault.vht");
        ov.save(&op, &LocalStore::new(other.path().join("s")))
            .unwrap();
        assert!(matches!(
            k.open(&fs::read(&op).unwrap(), "A", &t.store),
            Err(Error::SessionStale)
        ));
        // Garbage is not a vault.
        assert!(k.open(b"not a vault", "A", &t.store).is_err());
        assert!(k.open(&newer, "A", &t.store).is_ok());
    }

    #[test]
    fn a_tampered_machine_record_is_refused() {
        let t = t();
        saved(&t);
        let k = keys(&t, &["A"]);
        let vault_id = hex_encode(&k.vault_id());
        let state = t.store.root().join("vaults").join(vault_id).join("state");
        let text = fs::read_to_string(&state).unwrap();
        fs::write(
            &state,
            text.replace("max_generation = 1", "max_generation = 0"),
        )
        .unwrap();
        assert!(matches!(read(&t, &k, "A"), Err(Error::StoreTampered)));
    }

    #[test]
    fn narrowing_keeps_a_subset_and_zeroizing_wipes() {
        let t = t();
        saved(&t);
        let mut k = keys(&t, &["A", "B"]);
        let child = k.narrowed(&["A".to_string()]).unwrap();
        assert_eq!(child.names().collect::<Vec<_>>(), ["A"]);
        assert_eq!(read(&t, &child, "A").unwrap().expose(), b"fake-one");
        assert!(matches!(
            k.narrowed(&["C".to_string()]),
            Err(Error::NoAccess)
        ));
        assert!(!k.is_wiped());
        k.zeroize();
        assert!(k.is_wiped());
        // Wiped keys open nothing.
        assert!(read(&t, &k, "A").is_err());
        assert!(!child.is_wiped());
    }

    #[test]
    fn only_the_owner_can_make_session_keys() {
        let t = t();
        saved(&t);
        let mut v = Vault::unlock_password(&t.path, PW, &t.store).unwrap();
        let keys = crate::RecipientSecret::generate().unwrap();
        let id = v
            .add_recipient(
                "run",
                crate::RecipientKind::Person,
                crate::Role::Runner,
                &keys.public().unwrap(),
            )
            .unwrap();
        v.grant("A", &id).unwrap();
        v.save(&t.path, &t.store).unwrap();
        let r = Vault::open_as_recipient(&t.path, &id, &keys, &t.store).unwrap();
        assert!(matches!(
            r.session_keys(&["A".to_string()]),
            Err(Error::NotOwner)
        ));
    }
}
