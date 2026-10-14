//! The phone's helpers against the desktop's own code: what a phone signs
//! from `decision_message` is what `Decision::verify` accepts. Also the
//! checked-in vectors for the Kotlin/Dart side
//! (`tests/helper_vectors.json`; regenerate with `VAHTA_UPDATE_VECTORS=1`).

use std::time::Duration;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use vahta_auth::{Action, Decision, Request, device_id_for};
use vahta_mobile::*;

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sec1(k: &SigningKey) -> Vec<u8> {
    k.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn spki(sec1: &[u8]) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    v.extend_from_slice(sec1);
    v
}

fn request() -> Request {
    Request::new(
        Action::RunEachUse {
            names: vec!["STRIPE_KEY".into()],
            command: "deploy --prod".into(),
        },
        "/home/me/shop",
        [0x42; 16],
        Duration::from_secs(60),
    )
    .unwrap()
    .with_options(&["Allow once".to_string(), "Deny".to_string()])
    .with_category(Some("payments".into()))
    .with_label(Some("deploying the shop".into()))
}

/// What Android does: SHA256withECDSA over the message, DER out.
fn android_sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(message);
    sig.to_der().as_bytes().to_vec()
}

#[test]
fn a_phone_signature_from_decision_message_verifies_on_the_desktop() {
    let key = SigningKey::random(&mut rand_core::OsRng);
    let ecdh = SigningKey::random(&mut rand_core::OsRng);
    let (sign_pub, ecdh_pub) = (sec1(&key), sec1(&ecdh));
    let id = device_id(sign_pub.clone(), ecdh_pub.clone());
    assert_eq!(id, device_id_for(&sign_pub, &ecdh_pub).to_vec());
    let device_id: [u8; 16] = id.clone().try_into().unwrap();

    let req = request();
    for choice in [0u8, 1] {
        let msg = decision_message(req.to_bytes(), choice, id.clone()).unwrap();
        let raw = signature_from_der(android_sign(&key, &msg)).unwrap();
        assert_eq!(raw.len(), 64);
        let decision = Decision {
            request_hash: req.hash(),
            choice,
            device_id,
            signature: raw,
        };
        decision.verify(&req, &device_id, &sign_pub).unwrap();
    }

    // The same bytes the desktop's own `Decision::sign` signs.
    let desktop_made = Decision::sign(&req, 1, device_id, &key);
    let msg = decision_message(req.to_bytes(), 1, id.clone()).unwrap();
    use p256::ecdsa::signature::Verifier;
    let sig = Signature::from_slice(&desktop_made.signature).unwrap();
    key.verifying_key().verify(&msg, &sig).unwrap();

    // A signature for one choice does not do for another, nor for another
    // request, nor for another device.
    let msg0 = decision_message(req.to_bytes(), 0, id.clone()).unwrap();
    let signed0 = signature_from_der(android_sign(&key, &msg0)).unwrap();
    let moved = Decision {
        request_hash: req.hash(),
        choice: 1,
        device_id,
        signature: signed0.clone(),
    };
    assert!(moved.verify(&req, &device_id, &sign_pub).is_err());
    let other = request();
    let replay = Decision {
        request_hash: other.hash(),
        choice: 0,
        device_id,
        signature: signed0,
    };
    assert!(replay.verify(&other, &device_id, &sign_pub).is_err());
}

#[test]
fn decision_message_refuses_what_it_should_not_sign() {
    let req = request();
    let id = vec![7u8; 16];
    // An option the request does not offer.
    assert!(decision_message(req.to_bytes(), 2, id.clone()).is_err());
    // Not a request; a request with trailing bytes (a different spelling of
    // the same value would hash differently).
    assert!(decision_message(b"hello".to_vec(), 0, id.clone()).is_err());
    let mut padded = req.to_bytes();
    padded.push(0);
    assert!(decision_message(padded, 0, id.clone()).is_err());
    // A device id of the wrong length.
    assert!(decision_message(req.to_bytes(), 0, vec![7; 15]).is_err());
    // A request with no options has one implicit choice, 0.
    let plain = Request::new(Action::AlarmLock, "/p", [0; 16], Duration::from_secs(5)).unwrap();
    assert!(decision_message(plain.to_bytes(), 0, id.clone()).is_ok());
    assert!(decision_message(plain.to_bytes(), 1, id).is_err());
}

#[test]
fn der_and_spki_conversions_are_strict() {
    let key = SigningKey::random(&mut rand_core::OsRng);
    let der = android_sign(&key, b"x");
    let raw = signature_from_der(der.clone()).unwrap();
    assert_eq!(raw, Signature::from_der(&der).unwrap().to_bytes().to_vec());
    assert!(signature_from_der(raw).is_err(), "raw is not DER");
    assert!(signature_from_der(vec![0x30, 0x03, 1, 2, 3]).is_err());
    let mut trailing = der;
    trailing.push(0);
    assert!(signature_from_der(trailing).is_err());

    let point = sec1(&key);
    assert_eq!(sec1_from_spki(spki(&point)).unwrap(), point);
    assert!(sec1_from_spki(point.clone()).is_err());
    let mut off_curve = spki(&point);
    let n = off_curve.len();
    off_curve[n - 1] ^= 1;
    assert!(sec1_from_spki(off_curve).is_err());
    let mut other_curve = spki(&point);
    other_curve[20] = 0x02; // secp256k1's OID tail is not prime256v1's
    assert!(sec1_from_spki(other_curve).is_err());
    assert!(sec1_from_spki(vec![]).is_err());
}

#[test]
fn adverts_follow_the_documented_format() {
    let key = generate_static_key().unwrap();
    let a = session_advert(key.public.clone()).unwrap();
    let tag = device_tag(key.public.clone()).unwrap();
    assert_eq!(tag.len(), 8);
    assert_eq!(a.service_data[..2], [1, 1]);
    assert_eq!(a.service_data[2..], tag[..]);
    assert_eq!(a.lan_instance, hx(&tag));
    assert_eq!(a.service_uuid, "11ca9b36-035f-4d80-8e4a-7819627ac4c0");

    let offer =
        vahta_link::PairOffer::new([1; 32], [2; 16], "desk", vahta_link::unix_now(), 60).unwrap();
    let p = pairing_advert(offer.to_qr_string()).unwrap();
    assert_eq!(p.service_data[..2], [1, 2]);
    assert_ne!(p.service_data[2..], tag[..]);
    assert!(pairing_advert("vahta-pair:nonsense".into()).is_err());
    assert!(device_tag(vec![0; 31]).is_err());
}

#[test]
fn the_summary_shows_what_the_request_says() {
    let v = request_summary(request().to_bytes()).unwrap();
    assert_eq!(v.kind, "run_each_use");
    assert_eq!(v.names, ["STRIPE_KEY"]);
    assert_eq!(v.command.as_deref(), Some("deploy --prod"));
    assert_eq!(v.project, "/home/me/shop");
    assert_eq!(v.category.as_deref(), Some("payments"));
    assert_eq!(v.agent_label.as_deref(), Some("deploying the shop"));
    assert!(!v.agent_label_verified);
    assert_eq!(v.options, ["Allow once", "Deny"]);
    assert!(request_summary(vec![1, 2, 3]).is_err());

    let mk = |a| Request::new(a, "/p", [0; 16], Duration::from_secs(9)).unwrap();
    let v = request_summary(
        mk(Action::Unlock {
            names: vec!["A".into(), "B".into()],
            duration_secs: Some(600),
        })
        .to_bytes(),
    )
    .unwrap();
    assert_eq!(
        (v.kind.as_str(), v.seconds, v.names.len()),
        ("unlock", Some(600), 2)
    );
    let v = request_summary(
        mk(Action::Http {
            names: vec!["K".into()],
            host: "api.example.com".into(),
        })
        .to_bytes(),
    )
    .unwrap();
    assert_eq!(v.host.as_deref(), Some("api.example.com"));
    let v = request_summary(
        mk(Action::RunAsk {
            names: vec!["K".into()],
            command: "x".into(),
            reason: Some("because".into()),
        })
        .to_bytes(),
    )
    .unwrap();
    assert_eq!(v.reason.as_deref(), Some("because"));
}

// --- vectors for the Kotlin/Dart side -----------------------------------------------------------

fn fixed_request() -> Request {
    Request {
        action: Action::RunEachUse {
            names: vec!["STRIPE_KEY".into()],
            command: "deploy --prod".into(),
        },
        project: "/home/me/shop".into(),
        vault_id: [0x42; 16],
        category: Some("payments".into()),
        agent_label: Some("deploying the shop".into()),
        options: vec!["Allow once".into(), "Deny".into()],
        nonce: [0x07; 16],
        expires_at: 2_000_000_000,
    }
}

fn build() -> Value {
    let req = fixed_request();
    let sign = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let ecdh = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let (sign_pub, ecdh_pub) = (sec1(&sign), sec1(&ecdh));
    let id = device_id(sign_pub.clone(), ecdh_pub.clone());
    let msg0 = decision_message(req.to_bytes(), 0, id.clone()).unwrap();
    let msg1 = decision_message(req.to_bytes(), 1, id.clone()).unwrap();
    // P-256 ECDSA with RFC 6979 nonces is deterministic.
    let der1 = android_sign(&sign, &msg1);
    let static_pub: Vec<u8> = (1..=32u8).collect();
    let session = session_advert(static_pub.clone()).unwrap();
    let offer = vahta_link::PairOffer {
        v: 1,
        desktop_static_pub: [3; 32],
        psk: [5; 32],
        vault_id: [0x42; 16],
        desktop_name: "desk".into(),
        expires_at: 2_000_000_000,
    };
    let pairing = pairing_advert(offer.to_qr_string()).unwrap();
    let view = request_summary(req.to_bytes()).unwrap();
    json!({
        "comment": "Test keys only. Generated by crates/mobile/tests/helpers.rs.",
        "request_bytes": hx(&req.to_bytes()),
        "request_hash": hx(&req.hash()),
        "device": {
            "sign_private": hx(&[0x11; 32]), "sign_pub": hx(&sign_pub),
            "ecdh_pub": hx(&ecdh_pub), "device_id": hx(&id),
        },
        "decision_message_choice_0": hx(&msg0),
        "decision_message_choice_1": hx(&msg1),
        "signature_der_choice_1": hx(&der1),
        "signature_raw_choice_1": hx(&signature_from_der(der1).unwrap()),
        "spki_to_sec1": { "spki": hx(&spki(&sign_pub)), "sec1": hx(&sign_pub) },
        "device_tag": { "static_pub": hx(&static_pub), "tag": hx(&device_tag(static_pub.clone()).unwrap()) },
        "session_advert": {
            "service_uuid": session.service_uuid, "service_data": hx(&session.service_data),
            "lan_instance": session.lan_instance,
            "write_characteristic": session.write_characteristic,
            "notify_characteristic": session.notify_characteristic,
        },
        "pairing_advert": {
            "qr": offer.to_qr_string(), "service_data": hx(&pairing.service_data),
            "lan_instance": pairing.lan_instance,
        },
        "request_summary": {
            "kind": view.kind, "names": view.names, "project": view.project,
            "command": view.command, "host": view.host, "reason": view.reason,
            "detail": view.detail, "seconds": view.seconds, "category": view.category,
            "agent_label": view.agent_label, "agent_label_verified": view.agent_label_verified,
            "options": view.options, "expires_at": view.expires_at,
            "nonce": hx(&view.nonce), "vault_id": hx(&view.vault_id),
        },
    })
}

fn canon(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut e: Vec<_> = m.into_iter().collect();
            e.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(e.into_iter().map(|(k, v)| (k, canon(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(canon).collect()),
        v => v,
    }
}

#[test]
fn helper_vectors_match_the_checked_in_file() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/helper_vectors.json");
    let got = serde_json::to_string_pretty(&canon(build())).unwrap() + "\n";
    if std::env::var_os("VAHTA_UPDATE_VECTORS").is_some() {
        std::fs::write(path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(path).expect("run with VAHTA_UPDATE_VECTORS=1 to create it");
    let got: Value = serde_json::from_str(&got).unwrap();
    let want: Value = serde_json::from_str(&want).unwrap();
    assert_eq!(
        got, want,
        "vectors changed; if intended, regenerate with VAHTA_UPDATE_VECTORS=1"
    );
}

#[test]
fn helper_vectors_are_deterministic() {
    assert_eq!(build(), build());
}
