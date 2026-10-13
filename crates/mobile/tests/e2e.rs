//! The phone API against the desktop side of vahta-link, frame by frame.

use vahta_link::channel::{Handshake, Keypair};
use vahta_link::messages::{ApproveRequest, Choice};
use vahta_link::{Message, PairOffer, Partial};
use vahta_mobile::*;

const NOW: u64 = 5000;
const VAULT: [u8; 16] = [3; 16];

fn sec1(b: u8) -> Vec<u8> {
    [&[4u8][..], &[b; 64]].concat()
}

#[test]
fn pair_then_session_then_approval() {
    let desktop = Keypair::generate().unwrap();
    let offer = PairOffer::new(desktop.public, VAULT, "desk", NOW, 60).unwrap();
    let qr = offer.to_qr_string();

    let scanned = parse_offer(qr.clone(), NOW).unwrap();
    assert_eq!(scanned.desktop_name, "desk");
    assert!(parse_offer(qr.clone(), NOW + 61).is_err());

    let key = generate_static_key().unwrap();
    let mut ph =
        PairingSession::start(qr, key.clone(), "pixel".into(), sec1(1), sec1(2), NOW).unwrap();
    let mut hs = Handshake::pairing_initiator(&desktop, &offer, NOW).unwrap();

    // Desktop handshake: msg1 ->, <- msg2, msg3 ->.
    let m2 = ph.handle_frame(hs.write().unwrap()).unwrap();
    assert_eq!(m2.len(), 1);
    hs.read(&m2[0]).unwrap();
    let m3 = hs.write().unwrap();
    assert!(hs.is_finished());
    let mut dchan = hs.finish().unwrap();
    // msg3 completes the phone's handshake and yields its sealed PairAccept.
    let accept_frames = ph.handle_frame(m3).unwrap();
    let mut partial = Partial::default();
    let mut accept = None;
    for f in &accept_frames {
        if let Some(Message::PairAccept(a)) = dchan.open_message(&mut partial, f).unwrap() {
            accept = Some(a);
        }
    }
    let accept = accept.expect("phone sent PairAccept");
    assert_eq!(accept.phone_static_pub.to_vec(), key.public);
    assert!(!ph.is_done());
    for f in dchan.seal_message(&Message::PairAck).unwrap() {
        assert!(ph.handle_frame(f).unwrap().is_empty());
    }
    assert!(ph.is_done());
    let paired = ph.result().unwrap();
    assert_eq!(paired.desktop_static_pub, desktop.public.to_vec());
    assert_eq!(paired.vault_id, VAULT.to_vec());

    // A session over the pinned keys.
    let mut link =
        LinkSession::start(key.clone(), paired.desktop_static_pub, paired.vault_id).unwrap();
    let mut d = Handshake::session_initiator(&desktop, &accept.phone_static_pub, &VAULT).unwrap();
    let out = link.handle_frame(d.write().unwrap()).unwrap();
    assert_eq!(out.frames.len(), 1);
    assert!(link.is_established());
    d.read(&out.frames[0]).unwrap();
    let mut dc = d.finish().unwrap();

    let req = ApproveRequest::new(b"do the thing".to_vec(), [1; 16], NOW + 30);
    let mut got = None;
    for f in dc
        .seal_message(&Message::ApproveRequest(req.clone()))
        .unwrap()
    {
        got = Some(link.handle_frame(f).unwrap().event);
    }
    let Some(LinkEvent::Approve(a)) = got else {
        panic!()
    };
    assert_eq!(a.request, req.request);
    assert_eq!(a.request_hash, req.request_hash.to_vec());

    let frames = link
        .reply_decision(a.request_hash, true, vec![7; 64])
        .unwrap();
    let mut p = Partial::default();
    let m = frames
        .iter()
        .filter_map(|f| dc.open_message(&mut p, f).unwrap())
        .next()
        .unwrap();
    let Message::Decision(dec) = m else { panic!() };
    assert_eq!(dec.choice, Choice::Approve);

    // Ping is answered by the session itself.
    let f = dc.seal_message(&Message::Ping(9)).unwrap().remove(0);
    let out = link.handle_frame(f).unwrap();
    assert_eq!(out.event, LinkEvent::Ping);
    let reply = dc
        .open_message(&mut Partial::default(), &out.frames[0])
        .unwrap();
    assert_eq!(reply, Some(Message::Pong(9)));

    // A tampered frame ends the session.
    let mut f = dc.seal_message(&Message::Ping(10)).unwrap().remove(0);
    f[3] ^= 1;
    assert!(link.handle_frame(f).is_err());
    assert!(
        link.handle_frame(vec![0; 40]).is_err(),
        "dead after an error"
    );
}

#[test]
fn wrong_desktop_key_in_the_qr_is_refused() {
    let desktop = Keypair::generate().unwrap();
    let impostor = Keypair::generate().unwrap();
    let offer = PairOffer::new(desktop.public, VAULT, "desk", NOW, 60).unwrap();
    let key = generate_static_key().unwrap();
    let mut ph =
        PairingSession::start(offer.to_qr_string(), key, "p".into(), sec1(1), sec1(2), NOW)
            .unwrap();
    // Same PSK, but the dialer holds a different static key.
    let mut hs = Handshake::pairing_initiator(&impostor, &offer, NOW).unwrap();
    let m2 = ph.handle_frame(hs.write().unwrap()).unwrap();
    hs.read(&m2[0]).unwrap();
    assert!(ph.handle_frame(hs.write().unwrap()).is_err());
}

#[test]
fn ble_helpers_round_trip() {
    let frame: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    let mut r = BleReassembler::new();
    let got: Vec<_> = ble_chunks(frame.clone(), 20)
        .unwrap()
        .into_iter()
        .flat_map(|c| r.push(c))
        .collect();
    assert_eq!(got, vec![frame]);
}
