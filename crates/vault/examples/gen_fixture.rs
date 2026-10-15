//! Generates the golden vault of the current format, once, at release.
//!
//! ```text
//! cargo run -p vahta-vault --example gen_fixture --features test-kdf -- v1
//! ```
//!
//! writes `tests/fixtures/format/v1.vht` and `v1.expected.json`. A fixture is
//! committed and never regenerated after its format ships: the point of the
//! file is that a later build must still read what an earlier one wrote. It
//! is written with the cheap test KDF, so the test suite can unlock it without
//! a gibibyte per run; the real cost is exercised by a separate test.
//!
//! Test material only: the phrase and the values are made up.

use std::path::PathBuf;

use vahta_vault::rules::parse_rule;
use vahta_vault::store::LocalStore;
use vahta_vault::{
    Action, AgentRole, Class, Device, DirRule, HostRule, KdfParams, Kind, Network, NewSlot,
    RecipientKind, RecipientSecret, Role, RuleSet, Tier, Vault, seal_vault_key,
};

const PHRASE: &str = "correct horse";

fn main() {
    let Some(name) = std::env::args().nth(1) else {
        eprintln!("usage: gen_fixture <name>   (e.g. v1)");
        std::process::exit(2);
    };
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/format");
    let work = tempdir();
    let store = LocalStore::new(work.join("store"));
    // Saved in a temp dir (the lock file lives beside the vault), then copied.
    let saved = work.join("vault.vht");
    let path = dir.join(format!("{name}.vht"));

    let (mut vault, _recovery) = Vault::create(PHRASE.as_bytes(), KdfParams::TEST).expect("create");
    let items: [(&str, &[u8], Kind, Tier); 3] = [
        ("ALPHA", b"fake-one", Kind::Env, Tier::Session),
        (
            "BETA",
            b"fake two lines\nx",
            Kind::File {
                file_name: "beta.txt".into(),
            },
            Tier::EachUse,
        ),
        ("GAMMA", b"", Kind::Env, Tier::Session),
    ];
    for (n, v, k, t) in &items {
        vault.set(n, v, k.clone(), *t).expect("set");
    }
    // Format 1 also carries a class and approved command rules. BETA is bound
    // to an absolute path that need not exist: the vault only stores it.
    vault
        .set_class("ALPHA", Some(Class::Payment))
        .expect("class");
    let allow = parse_rule("beta-tool push", true)
        .expect("rule")
        .to_allow("/opt/fixture/beta-tool".to_string());
    let role_allow = allow.clone();
    let deny = parse_rule("@network", false).expect("rule").to_deny();
    vault
        .set_bindings(
            "BETA",
            Some(RuleSet {
                name: "BETA".into(),
                allow: vec![allow],
                deny: vec![deny],
                category: Some("package-manager".into()),
                dirs: vec![DirRule {
                    text: "/opt/fixture/work (read-write)".into(),
                    path: "/opt/fixture/work".into(),
                    write: true,
                }],
                network: Network::Hosts(vec![HostRule {
                    text: "registry.example.org".into(),
                    host: "registry.example.org".into(),
                    subdomains: false,
                    port: Some(443),
                }]),
                // Format 4 also carries `from` on a rule set and the vault's
                // remote-use flag.
                from: vec!["/opt/fixture/project".into()],
                ..Default::default()
            }),
        )
        .expect("bindings");
    vault.set_remote(true).expect("remote");
    // Format 5 also carries the vault kind (a project vault here), agent roles
    // and a member's expiry.
    vault
        .set_role(AgentRole {
            name: "READER".into(),
            secrets: vec!["BETA".into()],
            allow: vec![role_allow],
            deny: Vec::new(),
            network: Some(Network::None),
            dirs: Vec::new(),
            max_for_secs: Some(3600),
            max_uses: Some(5),
            actions: vec![Action::Run, Action::Http],
            ask_each_use: true,
            approved_at: 1_700_000_000,
        })
        .expect("role");
    let member = RecipientSecret::generate()
        .expect("keys")
        .public()
        .expect("public keys");
    let member_id = vault
        .add_recipient(
            "fixture member",
            RecipientKind::Person,
            Role::Runner,
            &member,
        )
        .expect("recipient");
    vault
        .set_recipient_expiry(&member_id, Some(1_900_000_000))
        .expect("expiry");
    // Format 2 also carries a paired device and slots of kinds beyond the two
    // this build knows: the second is a kind no build has defined, which every
    // later build must carry through untouched.
    vault
        .add_device(Device {
            device_id: [7; 16],
            name: "fixture phone".into(),
            sign_pub: [&[2u8][..], &[1; 32]].concat(),
            ecdh_pub: [&[3u8][..], &[2; 32]].concat(),
            paired_at: 1_700_000_000,
            expires_at: None,
            transports: vec!["lan".into()],
        })
        .expect("device");
    let kek = [9u8; 32];
    vault
        .add_slot(
            NewSlot {
                kind: 0x7001,
                slot_id: Some([7; 16]),
                label: "fixture future kind".into(),
                expires_at: None,
                params: vec![1, 2, 3],
            },
            |vk, aad| seal_vault_key(&kek, aad, vk),
        )
        .expect("slot");
    vault.save(&saved, &store).expect("save");
    std::fs::copy(&saved, &path).expect("copy the vault into the fixtures");

    let mut json = String::from("{\n  \"phrase\": \"correct horse\",\n  \"secrets\": [\n");
    for (i, (n, v, k, t)) in items.iter().enumerate() {
        let kind = match k {
            Kind::Env => "env".to_string(),
            Kind::File { file_name } => format!("file:{file_name}"),
        };
        let tier = match t {
            Tier::Session => "session",
            Tier::EachUse => "each_use",
        };
        let value = String::from_utf8_lossy(v).replace('\n', "\\n");
        let comma = if i + 1 < items.len() { "," } else { "" };
        json.push_str(&format!(
            "    {{\"name\": \"{n}\", \"value\": \"{value}\", \"kind\": \"{kind}\", \"tier\": \"{tier}\"}}{comma}\n"
        ));
    }
    json.push_str("  ],\n  \"classes\": {\"ALPHA\": \"payment\"},\n");
    json.push_str("  \"bindings\": {\"BETA\": {\"allow\": [\"beta-tool push\"], \"deny\": [\"@network\"], \"from\": [\"/opt/fixture/project\"]}},\n  \"remote\": true,\n  \"kind\": \"project\",\n  \"roles\": [\"READER\"],\n  \"member_expires_at\": 1900000000\n}\n");
    std::fs::write(dir.join(format!("{name}.expected.json")), json).expect("write expected");
    eprintln!("wrote {}", path.display());
}

fn tempdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("vahta-gen-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&p).expect("temp dir");
    p
}
