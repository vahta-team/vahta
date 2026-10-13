//! The whole protocol in-process: pairing, a pinned session, request and
//! response, and what an attacker on the pipe can and cannot do.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vahta_link::channel::Handshake;
use vahta_link::memory::{MemoryTransport, memory_pipe};
use vahta_link::messages::*;
use vahta_link::pairing::{pair_desktop, pair_phone};
use vahta_link::{
    DeviceAddr, Keypair, LinkError, Message, PairAccept, PairOffer, Transport, reach_first,
};

const NOW: u64 = 1_000_000;
const VAULT: [u8; 16] = [0x11; 16];

fn accept_for(name: &str) -> PairAccept {
    PairAccept {
        phone_name: name.into(),
        phone_static_pub: [0; 32], // replaced by the responder
        sign_pub: [&[4u8][..], &[1; 64]].concat(),
        ecdh_pub: [&[4u8][..], &[2; 64]].concat(),
    }
}

fn run_pairing(
    desktop_offer: &PairOffer,
    phone_offer: &PairOffer,
    desktop: &Keypair,
    phone: &Keypair,
) -> (
    Result<vahta_link::pairing::PairedPhone, LinkError>,
    Result<vahta_link::pairing::PairedDesktop, LinkError>,
) {
    let (a, b) = memory_pipe();
    let (po, pk) = (phone_offer.clone(), phone.clone());
    let h = thread::spawn(move || pair_phone(Box::new(b), po, &pk, accept_for("pixel"), NOW));
    let mut a = a;
    a.set_recv_timeout_for_test();
    let d = pair_desktop(Box::new(a), desktop_offer, desktop, NOW);
    (d, h.join().unwrap())
}

trait T2 {
    fn set_recv_timeout_for_test(&mut self);
}
impl T2 for vahta_link::memory::MemoryPipe {
    fn set_recv_timeout_for_test(&mut self) {
        use vahta_link::Pipe;
        self.set_recv_timeout(Some(Duration::from_secs(5))).unwrap();
    }
}

fn keys() -> (Keypair, Keypair, PairOffer) {
    let desktop = Keypair::generate().unwrap();
    let phone = Keypair::generate().unwrap();
    let offer = PairOffer::new(desktop.public, VAULT, "desk", NOW, 120).unwrap();
    (desktop, phone, offer)
}

#[test]
fn pairing_succeeds_and_both_learn_the_other() {
    let (desktop, phone, offer) = keys();
    let (d, p) = run_pairing(&offer, &offer, &desktop, &phone);
    let d = d.unwrap();
    assert_eq!(d.accept.phone_static_pub, phone.public);
    assert_eq!(d.accept.phone_name, "pixel");
    let p = p.unwrap();
    assert_eq!(p.desktop_static_pub, desktop.public);
    assert_eq!(p.vault_id, VAULT);
}

#[test]
fn wrong_psk_fails_both_sides() {
    let (desktop, phone, offer) = keys();
    let mut other = offer.clone();
    other.psk[0] ^= 1;
    let (d, p) = run_pairing(&offer, &other, &desktop, &phone);
    assert!(d.is_err());
    assert!(matches!(p, Err(LinkError::Noise(_))), "{p:?}");
}

#[test]
fn phone_refuses_a_desktop_that_is_not_the_one_in_the_qr() {
    let (desktop, phone, offer) = keys();
    let impostor = Keypair::generate().unwrap();
    // Same PSK (the attacker saw the QR) but its own static key.
    let (d, p) = run_pairing(&offer, &offer, &impostor, &phone);
    assert!(p.is_err(), "pinning the QR key");
    assert!(d.is_err());
    let _ = desktop;
}

#[test]
fn expired_offer_is_refused_on_both_sides() {
    let (desktop, phone, offer) = keys();
    let (a, _b) = memory_pipe();
    let late = NOW + 121;
    assert!(matches!(
        pair_desktop(Box::new(a), &offer, &desktop, late),
        Err(LinkError::OfferExpired)
    ));
    let (_a, b) = memory_pipe();
    assert!(matches!(
        pair_phone(Box::new(b), offer, &phone, accept_for("x"), late),
        Err(LinkError::OfferExpired)
    ));
}

#[test]
fn replayed_handshake_does_not_pair() {
    let (desktop, phone, offer) = keys();
    // Record a real pairing as an eavesdropper sees it (desktop's frames).
    let log = Arc::new(Mutex::new(Vec::new()));
    let (a, b) = memory_pipe();
    let a = a.record_sends(log.clone());
    let (po, pk) = (offer.clone(), phone.clone());
    let h = thread::spawn(move || pair_phone(Box::new(b), po, &pk, accept_for("pixel"), NOW));
    pair_desktop(Box::new(a), &offer, &desktop, NOW).unwrap();
    h.join().unwrap().unwrap();
    let frames = log.lock().unwrap().clone();
    assert!(frames.len() >= 2);

    // A fresh responder (new ephemeral key) gets the recorded frames.
    let mut r = Handshake::pairing_responder(&phone, &offer, NOW).unwrap();
    r.read(&frames[0]).unwrap(); // message 1 only carries the old ephemeral
    let _reply = r.write().unwrap();
    assert!(
        r.read(&frames[1]).is_err(),
        "recorded message 3 must not verify"
    );
}

fn paired_session() -> (vahta_link::PipeChannel, vahta_link::PipeChannel) {
    let (desktop, phone, _) = keys();
    let (a, b) = memory_pipe();
    let (dp, pp) = (desktop.public, phone.public);
    let h = thread::spawn(move || {
        Handshake::session_responder(&phone, &dp, &VAULT)
            .unwrap()
            .run(Box::new(b))
            .unwrap()
    });
    let d = Handshake::session_initiator(&desktop, &pp, &VAULT)
        .unwrap()
        .run(Box::new(a))
        .unwrap();
    (d, h.join().unwrap())
}

#[test]
fn request_response_round_trip_over_kk() {
    let (mut d, mut p) = paired_session();
    assert_eq!(d.handshake_hash(), p.handshake_hash());
    let req = ApproveRequest::new(b"curl example.com".to_vec(), [7; 16], NOW + 30);
    d.send(&Message::ApproveRequest(req.clone())).unwrap();
    let Message::ApproveRequest(got) = p.recv().unwrap() else {
        panic!()
    };
    assert_eq!(got, req);
    p.send(&Message::Decision(Decision {
        request_hash: got.request_hash,
        choice: Choice::Approve,
        signature: vec![9; 64],
    }))
    .unwrap();
    let Message::Decision(dec) = d.recv().unwrap() else {
        panic!()
    };
    assert_eq!(dec.request_hash, req.request_hash);
    d.send(&Message::Ping(1)).unwrap();
    assert_eq!(p.recv().unwrap(), Message::Ping(1));
}

#[test]
fn large_messages_are_fragmented() {
    let (mut d, mut p) = paired_session();
    let big = vec![0xAB; 200_000];
    d.send_bytes(&big).unwrap();
    assert_eq!(p.recv_bytes().unwrap(), big);
    d.send_bytes(&[]).unwrap();
    assert!(p.recv_bytes().unwrap().is_empty());
    assert!(d.send_bytes(&vec![0; MAX_MESSAGE + 1]).is_err());
}

#[test]
fn session_with_the_wrong_pinned_key_fails() {
    let (desktop, phone, _) = keys();
    let stranger = Keypair::generate().unwrap();
    let (a, b) = memory_pipe();
    let dp = desktop.public;
    let h = thread::spawn(move || {
        Handshake::session_responder(&phone, &dp, &VAULT)
            .unwrap()
            .run(Box::new(b))
            .map(|_| ())
    });
    let mut a = a;
    a.set_recv_timeout_for_test();
    // The desktop thinks it dials someone else; and the phone does not know
    // this initiator's key either way.
    let r = Handshake::session_initiator(&desktop, &stranger.public, &VAULT)
        .unwrap()
        .run(Box::new(a));
    assert!(r.is_err());
    assert!(h.join().unwrap().is_err());
}

#[test]
fn session_for_another_vault_fails() {
    let (desktop, phone, _) = keys();
    let (a, b) = memory_pipe();
    let (dp, pp) = (desktop.public, phone.public);
    let h = thread::spawn(move || {
        Handshake::session_responder(&phone, &dp, &[0x22; 16])
            .unwrap()
            .run(Box::new(b))
            .map(|_| ())
    });
    let mut a = a;
    a.set_recv_timeout_for_test();
    let r = Handshake::session_initiator(&desktop, &pp, &VAULT)
        .unwrap()
        .run(Box::new(a));
    assert!(r.is_err());
    assert!(h.join().unwrap().is_err());
}

#[test]
fn bit_flip_in_transport_is_an_error_and_poisons_the_channel() {
    let (desktop, phone, _) = keys();
    let (a, b) = memory_pipe();
    // Frames 0 and 1 are the two handshake messages; corrupt from the first
    // data frame on.
    let a = a.corrupt_sends_from(1);
    let (dp, pp) = (desktop.public, phone.public);
    let h = thread::spawn(move || {
        let mut p = Handshake::session_responder(&phone, &dp, &VAULT)
            .unwrap()
            .run(Box::new(b))
            .unwrap();
        (p.recv(), p.recv())
    });
    let mut d = Handshake::session_initiator(&desktop, &pp, &VAULT)
        .unwrap()
        .run(Box::new(a))
        .unwrap();
    d.send(&Message::Ping(1)).unwrap();
    d.send(&Message::Ping(2)).unwrap();
    let (first, second) = h.join().unwrap();
    assert!(matches!(first, Err(LinkError::Noise(_))), "{first:?}");
    assert!(second.is_err(), "poisoned");
}

fn sans_io_pair() -> (vahta_link::Channel, vahta_link::Channel) {
    let (desktop, phone, _) = keys();
    let mut i = Handshake::session_initiator(&desktop, &phone.public, &VAULT).unwrap();
    let mut r = Handshake::session_responder(&phone, &desktop.public, &VAULT).unwrap();
    while !(i.is_finished() && r.is_finished()) {
        if i.is_my_turn() {
            r.read(&i.write().unwrap()).unwrap();
        } else {
            i.read(&r.write().unwrap()).unwrap();
        }
    }
    (i.finish().unwrap(), r.finish().unwrap())
}

#[test]
fn replayed_and_reordered_transport_frames_are_refused() {
    let one = |c: &mut vahta_link::Channel, m| c.seal_message(&m).unwrap().remove(0);
    let (mut d, mut p) = sans_io_pair();
    let (f1, f2) = (one(&mut d, Message::Ping(1)), one(&mut d, Message::Ping(2)));
    let mut part = vahta_link::Partial::default();
    assert_eq!(
        p.open_message(&mut part, &f1).unwrap(),
        Some(Message::Ping(1))
    );
    assert!(p.open_message(&mut part, &f1).is_err(), "replay");
    assert!(
        p.open_message(&mut part, &f2).is_err(),
        "poisoned after a failure"
    );

    let (mut d, mut p) = sans_io_pair();
    let (_f1, f2) = (one(&mut d, Message::Ping(1)), one(&mut d, Message::Ping(2)));
    assert!(p.open_message(&mut part, &f2).is_err(), "reordered");
}

#[test]
fn memory_transport_and_the_race() {
    let t = MemoryTransport::new();
    let phone = Keypair::generate().unwrap();
    let l = t.listen(phone.public);
    let dev = DeviceAddr {
        name: "p".into(),
        static_pub: phone.public,
        ble_address: None,
        lan_hint: None,
    };
    let t: Arc<dyn Transport> = Arc::new(t);
    let (name, mut pipe) =
        reach_first(&[t], &dev, Instant::now() + Duration::from_secs(2)).unwrap();
    assert_eq!(name, "memory");
    let mut other = l.accept(Duration::from_secs(1)).unwrap();
    pipe.send(b"x").unwrap();
    assert_eq!(other.recv().unwrap(), b"x");
    let nobody = DeviceAddr {
        static_pub: [9; 32],
        ..dev
    };
    let t2: Arc<dyn Transport> = Arc::new(MemoryTransport::new());
    assert!(reach_first(&[t2], &nobody, Instant::now() + Duration::from_secs(1)).is_err());
}
