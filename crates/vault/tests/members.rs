//! Team members: identity, key strings, packages and the editor's transfer,
//! through the public API, in temp directories only. Secret values are made up.

use std::path::PathBuf;

use tempfile::TempDir;
use vahta_vault::member::{self, ProposedRules, file_info, is_transfer};
use vahta_vault::store::LocalStore;
use vahta_vault::{
    Error, KdfParams, Kind, RecipientKind, RecipientSecret, Role, Tier, Vault, identity,
};

const PW: &[u8] = b"correct horse";

struct Owner {
    _dir: TempDir,
    path: PathBuf,
    store: LocalStore,
}

fn owner() -> Owner {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    let store = LocalStore::new(dir.path().join("store"));
    Owner {
        _dir: dir,
        path,
        store,
    }
}

/// A vault with secrets ALPHA, BETA and GAMMA and a member holding only ALPHA
/// and BETA. Returns the vault (saved), the member's id and keys.
fn team(role: Role) -> (Owner, Vault, [u8; 16], RecipientSecret) {
    let o = owner();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    for (n, val) in [("ALPHA", "fake-a"), ("BETA", "fake-b"), ("GAMMA", "fake-g")] {
        v.set(n, val.as_bytes(), Kind::Env, Tier::Session).unwrap();
    }
    let keys = RecipientSecret::generate().unwrap();
    let id = v
        .add_recipient("ann", RecipientKind::Person, role, &keys.public().unwrap())
        .unwrap();
    v.grant("ALPHA", &id).unwrap();
    v.grant("BETA", &id).unwrap();
    v.save(&o.path, &o.store).unwrap();
    (o, v, id, keys)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_package_holds_one_member_and_only_their_secrets() {
    let (_o, v, id, keys) = team(Role::Runner);
    let other = RecipientSecret::generate().unwrap();
    let mut v = v;
    let oid = v
        .add_recipient(
            "bob",
            RecipientKind::Person,
            Role::Editor,
            &other.public().unwrap(),
        )
        .unwrap();
    v.grant("GAMMA", &oid).unwrap();
    v.save(&_o.path, &_o.store).unwrap();

    let pkg = v.package_for(&id, &[]).unwrap();
    // Nothing of what the member does not hold is in the bytes.
    for hidden in [&b"GAMMA"[..], b"bob", b"fake-g"] {
        assert!(!contains(&pkg, hidden));
    }
    let info = file_info(&pkg).unwrap();
    assert!(info.package && info.signed_by_owner);
    assert_eq!(info.vault_id, v.vault_id());
    assert_eq!(info.generation, v.generation());
    assert_eq!(info.owner_generation, v.generation());
    assert_eq!(info.recipients.len(), 1);
    assert_eq!(info.recipients[0].name, "ann");
    let peek = Vault::peek_bytes(&pkg).unwrap();
    let names: Vec<&str> = peek.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["ALPHA", "BETA"]);
    assert_eq!(peek.recipient_count, 1);
    assert!(peek.devices.is_empty() && peek.bindings.is_empty());

    // The member opens it and reads what it holds.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    std::fs::write(&path, &pkg).unwrap();
    let store = LocalStore::new(dir.path().join("store"));
    let r = Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    assert_eq!(r.get("ALPHA").unwrap().expose(), b"fake-a");
    assert_eq!(r.get("BETA").unwrap().expose(), b"fake-b");
    assert!(matches!(r.get("GAMMA"), Err(Error::NotFound(_))));
}

#[test]
fn a_package_is_not_a_vault() {
    let (o, v, id, _keys) = team(Role::Runner);
    let pkg = v.package_for(&id, &[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    std::fs::write(&path, &pkg).unwrap();
    let store = LocalStore::new(dir.path().join("store"));
    // No password opens it, not even the owner's.
    assert!(matches!(
        Vault::unlock_password(&path, PW, &store),
        Err(Error::Package)
    ));
    // The owner's vault is never written over it.
    let mut again = Vault::unlock_password(&o.path, PW, &o.store).unwrap();
    again
        .set("DELTA", b"fake-d", Kind::Env, Tier::Session)
        .unwrap();
    assert!(again.save(&path, &o.store).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), pkg);
    // A package cannot be packaged again.
    assert!(!file_info(&std::fs::read(&o.path).unwrap()).unwrap().package);
}

#[test]
fn a_member_added_by_an_admin_still_gets_a_valid_package() {
    let o = owner();
    let (mut v, _) = Vault::create(PW, KdfParams::TEST).unwrap();
    v.set("ALPHA", b"fake-a", Kind::Env, Tier::Session).unwrap();
    let admin = RecipientSecret::generate().unwrap();
    let aid = v
        .add_recipient(
            "root",
            RecipientKind::Person,
            Role::Admin,
            &admin.public().unwrap(),
        )
        .unwrap();
    v.save(&o.path, &o.store).unwrap();
    let mut a = Vault::open_as_recipient(&o.path, &aid, &admin, &o.store).unwrap();
    let keys = RecipientSecret::generate().unwrap();
    let id = a
        .add_recipient(
            "ann",
            RecipientKind::Person,
            Role::Runner,
            &keys.public().unwrap(),
        )
        .unwrap();
    a.save(&o.path, &o.store).unwrap();
    let mut v = Vault::unlock_password(&o.path, PW, &o.store).unwrap();
    v.grant("ALPHA", &id).unwrap();
    v.save(&o.path, &o.store).unwrap();
    let pkg = v.package_for(&id, &[]).unwrap();
    assert!(!contains(&pkg, b"root"));
    assert_eq!(Vault::peek_bytes(&pkg).unwrap().entries.len(), 1);
}

#[test]
fn an_expired_membership_does_not_open() {
    let (o, mut v, id, keys) = team(Role::Runner);
    v.set_recipient_expiry(&id, Some(1)).unwrap();
    v.save(&o.path, &o.store).unwrap();
    let pkg = v.package_for(&id, &[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    std::fs::write(&path, &pkg).unwrap();
    let store = LocalStore::new(dir.path().join("store"));
    assert!(matches!(
        Vault::open_as_recipient(&path, &id, &keys, &store),
        Err(Error::MembershipExpired)
    ));
    // Extending it, which the owner's certificate covers, opens it again.
    v.set_recipient_expiry(&id, Some(u64::MAX / 2)).unwrap();
    v.save(&o.path, &o.store).unwrap();
    std::fs::write(&path, v.package_for(&id, &[]).unwrap()).unwrap();
    assert!(Vault::open_as_recipient(&path, &id, &keys, &store).is_ok());
}

#[test]
fn an_editor_sends_one_secret_and_the_owner_reads_it() {
    let (o, mut v, id, keys) = team(Role::Editor);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    std::fs::write(&path, v.package_for(&id, &[]).unwrap()).unwrap();
    let store = LocalStore::new(dir.path().join("store"));
    let mut e = Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    e.set("FRESH", b"fake-new", Kind::Env, Tier::EachUse)
        .unwrap();
    e.save(&path, &store).unwrap();

    let blob = e.make_transfer("FRESH", 1, None).unwrap();
    assert!(is_transfer(&blob));
    let t = v.read_transfer(&blob).unwrap();
    assert_eq!((t.name.as_str(), t.from.name.as_str()), ("FRESH", "ann"));
    assert_eq!(t.value().expose(), b"fake-new");
    assert!(!t.replaces);
    assert!(v.entries().iter().all(|x| x.name != "FRESH"));
    v.apply_transfer(&t).unwrap();
    v.save(&o.path, &o.store).unwrap();
    assert_eq!(v.get("FRESH").unwrap().expose(), b"fake-new");
    assert_eq!(v.held_by(&id), ["ALPHA", "BETA", "FRESH"]);
    // The same transfer again is not newer than what is there.
    assert!(v.read_transfer(&blob).is_err());

    // Not for another vault, not edited, not from a Runner.
    let (_o2, v2, _, _) = team(Role::Editor);
    assert!(v2.read_transfer(&blob).is_err());
    let mut bad = blob.clone();
    let last = bad.len() - 100;
    bad[last] ^= 1;
    assert!(v.read_transfer(&bad).is_err());
    assert!(matches!(
        e.make_transfer("NOPE", 2, None),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn a_runner_cannot_send_and_a_secret_it_does_not_hold_cannot_be_sent() {
    let (_o, v, id, keys) = team(Role::Runner);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    std::fs::write(&path, v.package_for(&id, &[]).unwrap()).unwrap();
    let store = LocalStore::new(dir.path().join("store"));
    let r = Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    assert!(matches!(
        r.make_transfer("ALPHA", 1, None),
        Err(Error::NotPermitted)
    ));
    assert!(matches!(
        v.make_transfer("ALPHA", 1, None),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn removing_a_member_names_what_to_rotate_and_the_old_package_is_stale() {
    let (o, mut v, id, _keys) = team(Role::Runner);
    let mut rotate = v.remove_recipient(&id).unwrap();
    rotate.sort();
    assert_eq!(rotate, ["ALPHA", "BETA"]);
    v.save(&o.path, &o.store).unwrap();
    assert!(matches!(
        v.package_for(&id, &[]),
        Err(Error::UnknownRecipient)
    ));
}

#[test]
fn identity_files_and_key_strings_work_together() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("identity.vht");
    let public = identity::create(&p, b"my password", KdfParams::TEST).unwrap();
    let shown = member::public_key_string(&identity::read_public(&p).unwrap());
    assert_eq!(member::parse_public_key(&shown).unwrap(), public);
    let keys = identity::open(&p, b"my password").unwrap();
    assert_eq!(keys.public().unwrap(), public);
    assert!(identity::open(&p, b"not it").is_err());
}

/// Install `bytes` as a member's file in a fresh directory.
fn installed(bytes: &[u8]) -> (tempfile::TempDir, PathBuf, LocalStore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.vht");
    std::fs::write(&path, bytes).unwrap();
    let store = LocalStore::new(dir.path().join("store"));
    (dir, path, store)
}

#[test]
fn an_editors_own_save_does_not_make_the_owners_next_package_look_old() {
    let (o, mut v, id, keys) = team(Role::Editor);
    let first = v.package_for(&id, &[]).unwrap();
    let (_dir, path, store) = installed(&first);
    let mut e = Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    // The editor changes its own copy three times: its file's generation runs
    // ahead of the owner's.
    for n in ["ONE", "TWO", "THREE"] {
        e.set(n, b"fake-x", Kind::Env, Tier::Session).unwrap();
        e.save(&path, &store).unwrap();
    }
    let local = file_info(&std::fs::read(&path).unwrap()).unwrap();
    assert!(local.generation > local.owner_generation);
    assert_eq!(
        local.owner_generation,
        file_info(&first).unwrap().owner_generation
    );

    // The owner saves once and sends the next package: its generation is
    // lower than the editor's file, and it is still the newer one.
    v.set("DELTA", b"fake-d", Kind::Env, Tier::Session).unwrap();
    v.grant("DELTA", &id).unwrap();
    v.save(&o.path, &o.store).unwrap();
    let next = v.package_for(&id, &[]).unwrap();
    let info = file_info(&next).unwrap();
    assert!(info.owner_generation > local.owner_generation);
    assert!(info.generation <= local.generation);
    std::fs::write(&path, &next).unwrap();
    let e = Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    assert_eq!(e.get("DELTA").unwrap().expose(), b"fake-d");
    // The old package is a rollback, whatever the local file reached.
    std::fs::write(&path, &first).unwrap();
    assert!(matches!(
        Vault::open_as_recipient(&path, &id, &keys, &store),
        Err(Error::RolledBack { .. })
    ));
}

#[test]
fn a_transfer_is_replayed_only_by_a_lower_or_equal_counter() {
    let (o, mut v, id, keys) = team(Role::Editor);
    let (_dir, path, store) = installed(&v.package_for(&id, &[]).unwrap());
    let mut e = Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    e.set("FRESH", b"fake-1", Kind::Env, Tier::Session).unwrap();
    let one = e.make_transfer("FRESH", 7, None).unwrap();
    e.set("FRESH", b"fake-2", Kind::Env, Tier::Session).unwrap();
    let two = e.make_transfer("FRESH", 8, None).unwrap();
    let zero = e.make_transfer("FRESH", 0, None).unwrap();

    let t = v.read_transfer(&one).unwrap();
    assert_eq!(t.counter, 7);
    // Reading changes nothing: it can be read again until it is applied.
    assert!(v.read_transfer(&one).is_ok());
    v.apply_transfer(&t).unwrap();
    v.save(&o.path, &o.store).unwrap();
    // The counter is in the signed file: it survives a reopen.
    let mut v = Vault::unlock_password(&o.path, PW, &o.store).unwrap();
    for stale in [&one, &zero] {
        assert!(matches!(v.read_transfer(stale), Err(Error::Invalid(_))));
    }
    let t = v.read_transfer(&two).unwrap();
    assert!(t.replaces);
    v.apply_transfer(&t).unwrap();
    v.save(&o.path, &o.store).unwrap();
    assert_eq!(v.get("FRESH").unwrap().expose(), b"fake-2");
    assert!(v.read_transfer(&two).is_err());
    // Removing the member drops the counter with them (the file still verifies).
    v.remove_recipient(&id).unwrap();
    v.save(&o.path, &o.store).unwrap();
    Vault::unlock_password(&o.path, PW, &o.store).unwrap();
}

#[test]
fn proposed_rules_ride_in_the_signed_transfer_and_apply_nothing() {
    let (_o, mut v, id, keys) = team(Role::Editor);
    let (_dir, path, store) = installed(&v.package_for(&id, &[]).unwrap());
    let mut e = Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    e.set("FRESH", b"fake-1", Kind::Env, Tier::Session).unwrap();
    let rules = ProposedRules {
        category: Some("ordinary".into()),
        allow: vec!["git push".into()],
        net: Some("none".into()),
        ..ProposedRules::default()
    };
    let blob = e.make_transfer("FRESH", 1, Some(rules.clone())).unwrap();
    // An empty proposal is not a proposal.
    assert!(
        e.make_transfer("FRESH", 2, Some(ProposedRules::default()))
            .is_err()
    );
    let t = v.read_transfer(&blob).unwrap();
    assert_eq!(t.proposed, Some(rules));
    assert!(!t.replaces);
    v.apply_transfer(&t).unwrap();
    // The vault took the secret and no rules.
    assert!(v.bindings().iter().all(|b| b.name != "FRESH"));
    // Changing the proposal in transit breaks the editor's signature.
    let mut bad = blob.clone();
    let at = bad
        .windows(8)
        .position(|w| w == b"git push")
        .expect("the proposal is in the file");
    bad[at] = b'G';
    assert!(v.read_transfer(&bad).is_err());
}

#[test]
fn a_package_carries_project_relative_rules_and_no_folders_of_the_owner() {
    use vahta_vault::rules::parse_rule;
    use vahta_vault::{DirRule, Network, RuleSet};
    let (o, mut v, id, keys) = team(Role::Runner);
    let root = std::path::Path::new("/home/owner/Projects/x");
    let allow =
        |rule: &str, program: &str| parse_rule(rule, true).unwrap().to_allow(program.into());
    v.set_bindings(
        "ALPHA",
        Some(RuleSet {
            name: "ALPHA".into(),
            allow: vec![
                allow(
                    "python3 /home/owner/Projects/x/lib/x.py",
                    "/usr/bin/python3",
                ),
                allow("./bin/tool", "/home/owner/Projects/x/bin/tool"),
            ],
            dirs: vec![DirRule {
                text: "/home/owner/Projects/x/scripts:ro".into(),
                path: "/home/owner/Projects/x/scripts".into(),
                write: false,
            }],
            network: Network::None,
            from: vec!["/home/owner/Projects/other".into()],
            ..RuleSet::default()
        }),
    )
    .unwrap();
    v.save(&o.path, &o.store).unwrap();
    let pkg = v.package_for(&id, &[root]).unwrap();
    assert!(!contains(&pkg, b"/home/owner"));
    let b = &Vault::peek_bytes(&pkg).unwrap().bindings[0];
    assert_eq!(b.allow[0].args, ["$PROJECT/lib/x.py"]);
    assert_eq!(b.allow[0].text, "python3 $PROJECT/lib/x.py");
    // Outside the project stays as it is.
    assert_eq!(
        b.allow[0].program,
        vahta_vault::Program::Path("/usr/bin/python3".into())
    );
    assert_eq!(
        b.allow[1].program,
        vahta_vault::Program::Path("$PROJECT/bin/tool".into())
    );
    assert_eq!(b.dirs[0].path, "$PROJECT/scripts");
    assert_eq!(b.dirs[0].text, "$PROJECT/scripts:ro");
    assert!(b.from.is_empty());
    assert_eq!(vahta_vault::rules::absolute_places(b), ["/usr/bin/python3"]);
    // The member opens it, and the vault the owner keeps is untouched.
    let (_dir, path, store) = installed(&pkg);
    Vault::open_as_recipient(&path, &id, &keys, &store).unwrap();
    let own = Vault::unlock_password(&o.path, PW, &o.store).unwrap();
    assert_eq!(
        own.bindings()[0].dirs[0].path,
        "/home/owner/Projects/x/scripts"
    );
}
