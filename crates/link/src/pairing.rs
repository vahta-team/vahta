//! Pairing: the desktop shows a [`PairOffer`] as a QR code, the phone scans it
//! and both run `Noise_XXpsk3`. The phone then sends its [`PairAccept`] over
//! the fresh channel and the desktop acknowledges. The caller (which holds the
//! unlocked vault) records the device; nothing here persists anything.

use crate::channel::{Channel, Handshake, Keypair, Partial};
use crate::error::{LinkError, Result};
use crate::frame::Pipe;
use crate::messages::{Message, PairAccept, PairOffer};

/// What the desktop learns from a completed pairing.
#[derive(Debug, Clone)]
pub struct PairedPhone {
    pub accept: PairAccept,
}

/// Desktop side, over a pipe to the phone.
pub fn pair_desktop(
    pipe: Box<dyn Pipe>,
    offer: &PairOffer,
    key: &Keypair,
    now: u64,
) -> Result<PairedPhone> {
    let mut chan = Handshake::pairing_initiator(key, offer, now)?.run(pipe)?;
    let Message::PairAccept(accept) = chan.recv()? else {
        return Err(LinkError::Protocol("expected PairAccept".into()));
    };
    // The key that spoke Noise is the key the phone claims.
    if &accept.phone_static_pub != chan.remote_static() {
        return Err(LinkError::Protocol(
            "PairAccept key differs from the channel key".into(),
        ));
    }
    chan.send(&Message::PairAck)?;
    Ok(PairedPhone { accept })
}

/// What the phone learns: who it paired with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedDesktop {
    pub desktop_static_pub: [u8; 32],
    pub vault_id: [u8; 16],
    pub desktop_name: String,
}

enum State {
    Handshake(Box<Handshake>),
    AwaitAck(Box<Channel>),
    Done,
    Failed,
}

/// Phone side of pairing, without I/O: feed each frame received, send each
/// frame returned. `accept.phone_static_pub` is set from `key`.
pub struct PairResponder {
    state: State,
    accept: PairAccept,
    partial: Partial,
    offer: PairOffer,
}

impl PairResponder {
    pub fn new(offer: PairOffer, key: &Keypair, mut accept: PairAccept, now: u64) -> Result<Self> {
        accept.phone_static_pub = key.public;
        let hs = Handshake::pairing_responder(key, &offer, now)?;
        Ok(Self {
            state: State::Handshake(Box::new(hs)),
            accept,
            partial: Partial::default(),
            offer,
        })
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Who we paired with; available once done.
    pub fn result(&self) -> Option<PairedDesktop> {
        self.is_done().then(|| PairedDesktop {
            desktop_static_pub: self.offer.desktop_static_pub,
            vault_id: self.offer.vault_id,
            desktop_name: self.offer.desktop_name.clone(),
        })
    }

    pub fn on_frame(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>> {
        let r = self.step(frame);
        if r.is_err() {
            self.state = State::Failed;
        }
        r
    }

    fn step(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>> {
        match std::mem::replace(&mut self.state, State::Failed) {
            State::Handshake(mut hs) => {
                hs.read(frame)?;
                let mut out = Vec::new();
                while !hs.is_finished() && hs.is_my_turn() {
                    out.push(hs.write()?);
                }
                if hs.is_finished() {
                    let mut chan = hs.finish()?;
                    out.extend(chan.seal_message(&Message::PairAccept(self.accept.clone()))?);
                    self.state = State::AwaitAck(Box::new(chan));
                } else {
                    self.state = State::Handshake(hs);
                }
                Ok(out)
            }
            State::AwaitAck(mut chan) => match chan.open_message(&mut self.partial, frame)? {
                None => {
                    self.state = State::AwaitAck(chan);
                    Ok(vec![])
                }
                Some(Message::PairAck) => {
                    self.state = State::Done;
                    Ok(vec![])
                }
                Some(_) => Err(LinkError::Protocol("expected PairAck".into())),
            },
            State::Done | State::Failed => Err(LinkError::Protocol("pairing is over".into())),
        }
    }
}

/// Phone side over a pipe (tests, or a phone with a plain socket).
pub fn pair_phone(
    mut pipe: Box<dyn Pipe>,
    offer: PairOffer,
    key: &Keypair,
    accept: PairAccept,
    now: u64,
) -> Result<PairedDesktop> {
    let mut r = PairResponder::new(offer, key, accept, now)?;
    while !r.is_done() {
        let frame = pipe.recv()?;
        for out in r.on_frame(&frame)? {
            pipe.send(&out)?;
        }
    }
    r.result()
        .ok_or_else(|| LinkError::Protocol("pairing did not finish".into()))
}
