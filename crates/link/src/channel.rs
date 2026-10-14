//! The secure channel: Noise over any pipe.
//!
//! Pairing runs `Noise_XXpsk3_25519_ChaChaPoly_SHA256` with the PSK from the
//! QR code; afterwards every connection runs `Noise_KK_25519_ChaChaPoly_SHA256`
//! with both static keys pinned. The desktop is always the initiator (it dials
//! the phone). The vault id is the Noise prologue, so a channel for one vault
//! never completes for another.
//!
//! The state machines here do no I/O: bytes in, bytes out. `Handshake::run`
//! and `PipeChannel` drive them over a [`Pipe`]; the phone side drives them
//! from the app's own Bluetooth/TCP code.

use snow::{Builder, HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::error::{LinkError, Result};
use crate::frame::{MAX_FRAME, Pipe};
use crate::messages::{MAX_MESSAGE, Message, PairOffer};

pub const PAIRING_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA256";
pub const SESSION_PATTERN: &str = "Noise_KK_25519_ChaChaPoly_SHA256";

const TAG: usize = 16;
/// Plaintext per Noise message: one flag byte, then data.
const MAX_CHUNK_DATA: usize = MAX_FRAME - TAG - 1;
const FLAG_MORE: u8 = 0;
const FLAG_LAST: u8 = 1;

/// An X25519 static key pair. The caller decides where the private half lives.
#[derive(Clone)]
pub struct Keypair {
    pub public: [u8; 32],
    pub private: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keypair({:02x}{:02x}..)", self.public[0], self.public[1])
    }
}

impl Keypair {
    pub fn generate() -> Result<Self> {
        let kp = Builder::new(SESSION_PATTERN.parse()?).generate_keypair()?;
        Self::from_parts(&kp.public, &kp.private)
    }

    /// The pair for a given private key (the public half is derived).
    pub fn from_private(private: &[u8; 32]) -> Result<Self> {
        use snow::params::DHChoice;
        use snow::resolvers::{CryptoResolver, DefaultResolver};
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .ok_or_else(|| LinkError::Noise("no X25519".into()))?;
        dh.set(private);
        Self::from_parts(dh.pubkey(), private)
    }

    /// Restores a persisted pair. The two halves are trusted to match; a pair
    /// that does not fails its first handshake.
    pub fn from_parts(public: &[u8], private: &[u8]) -> Result<Self> {
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| LinkError::Protocol("public key must be 32 bytes".into()))?;
        let private: [u8; 32] = private
            .try_into()
            .map_err(|_| LinkError::Protocol("private key must be 32 bytes".into()))?;
        Ok(Self {
            public,
            private: Zeroizing::new(private),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Pairing,
    Session,
}

/// A Noise handshake in progress.
pub struct Handshake {
    hs: HandshakeState,
    kind: Kind,
    /// A remote static key the handshake must end with (pinning).
    expected_remote: Option<[u8; 32]>,
}

fn prologue(kind: Kind, vault_id: &[u8; 16]) -> Vec<u8> {
    let mut p = match kind {
        Kind::Pairing => b"vahta-link/1/pair|".to_vec(),
        Kind::Session => b"vahta-link/1/session|".to_vec(),
    };
    p.extend_from_slice(vault_id);
    p
}

impl Handshake {
    /// Desktop side of pairing. `now` is Unix seconds; an expired offer is refused.
    pub fn pairing_initiator(local: &Keypair, offer: &PairOffer, now: u64) -> Result<Self> {
        Self::pairing(local, offer, now, true, None)
    }

    /// Phone side of pairing, from a scanned offer. Ends only if the desktop
    /// proves the static key printed in the QR code.
    pub fn pairing_responder(local: &Keypair, offer: &PairOffer, now: u64) -> Result<Self> {
        Self::pairing(local, offer, now, false, None)
    }

    /// Fixed ephemeral key, for deterministic test vectors only.
    #[doc(hidden)]
    pub fn pairing_for_vectors(
        local: &Keypair,
        offer: &PairOffer,
        now: u64,
        initiator: bool,
        eph: &[u8; 32],
    ) -> Result<Self> {
        Self::pairing(local, offer, now, initiator, Some(eph))
    }

    fn pairing(
        local: &Keypair,
        offer: &PairOffer,
        now: u64,
        initiator: bool,
        eph: Option<&[u8; 32]>,
    ) -> Result<Self> {
        offer.check_fresh(now)?;
        let pro = prologue(Kind::Pairing, &offer.vault_id);
        let mut b = Builder::new(PAIRING_PATTERN.parse()?)
            .local_private_key(&local.private[..])?
            .psk(3, &offer.psk)?
            .prologue(&pro)?;
        if let Some(e) = eph {
            b = b.fixed_ephemeral_key_for_testing_only(e);
        }
        let hs = if initiator {
            b.build_initiator()?
        } else {
            b.build_responder()?
        };
        // The phone checks the desktop against the QR; the desktop learns the
        // phone's key here and checks it against PairAccept.
        let expected_remote = (!initiator).then_some(offer.desktop_static_pub);
        Ok(Self {
            hs,
            kind: Kind::Pairing,
            expected_remote,
        })
    }

    /// Initiator of a pinned session (the desktop).
    pub fn session_initiator(
        local: &Keypair,
        remote_pub: &[u8; 32],
        vault_id: &[u8; 16],
    ) -> Result<Self> {
        Self::session(local, remote_pub, vault_id, true, None)
    }

    /// Responder of a pinned session (the phone).
    pub fn session_responder(
        local: &Keypair,
        remote_pub: &[u8; 32],
        vault_id: &[u8; 16],
    ) -> Result<Self> {
        Self::session(local, remote_pub, vault_id, false, None)
    }

    #[doc(hidden)]
    pub fn session_for_vectors(
        local: &Keypair,
        remote_pub: &[u8; 32],
        vault_id: &[u8; 16],
        initiator: bool,
        eph: &[u8; 32],
    ) -> Result<Self> {
        Self::session(local, remote_pub, vault_id, initiator, Some(eph))
    }

    fn session(
        local: &Keypair,
        remote_pub: &[u8; 32],
        vault_id: &[u8; 16],
        initiator: bool,
        eph: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let pro = prologue(Kind::Session, vault_id);
        let mut b = Builder::new(SESSION_PATTERN.parse()?)
            .local_private_key(&local.private[..])?
            .remote_public_key(remote_pub)?
            .prologue(&pro)?;
        if let Some(e) = eph {
            b = b.fixed_ephemeral_key_for_testing_only(e);
        }
        let hs = if initiator {
            b.build_initiator()?
        } else {
            b.build_responder()?
        };
        Ok(Self {
            hs,
            kind: Kind::Session,
            expected_remote: Some(*remote_pub),
        })
    }

    pub fn is_my_turn(&self) -> bool {
        self.hs.is_my_turn()
    }

    pub fn is_finished(&self) -> bool {
        self.hs.is_handshake_finished()
    }

    /// The next handshake message to send.
    pub fn write(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_FRAME];
        let n = self.hs.write_message(&[], &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consumes a handshake message from the peer. A bad tag, a wrong PSK or a
    /// replayed message fails here.
    pub fn read(&mut self, msg: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; MAX_FRAME];
        let payload = self.hs.read_message(msg, &mut buf)?;
        if payload != 0 {
            return Err(LinkError::Protocol(
                "handshake payload is not expected".into(),
            ));
        }
        Ok(())
    }

    /// Ends a finished handshake into a transport channel, checking the pin.
    pub fn finish(self) -> Result<Channel> {
        if !self.hs.is_handshake_finished() {
            return Err(LinkError::Protocol("handshake is not finished".into()));
        }
        let hash = self.hs.get_handshake_hash().to_vec();
        let remote: [u8; 32] = self
            .hs
            .get_remote_static()
            .and_then(|r| r.try_into().ok())
            .ok_or_else(|| LinkError::Noise("no remote static key".into()))?;
        if let Some(want) = self.expected_remote
            && want != remote
        {
            return Err(LinkError::Noise(
                "the peer's key is not the pinned key".into(),
            ));
        }
        let _ = self.kind;
        Ok(Channel {
            state: self.hs.into_transport_mode()?,
            remote_static: remote,
            handshake_hash: hash,
            poisoned: false,
        })
    }

    /// Runs the handshake to the end over a pipe.
    pub fn run(mut self, mut pipe: Box<dyn Pipe>) -> Result<PipeChannel> {
        while !self.is_finished() {
            if self.is_my_turn() {
                pipe.send(&self.write()?)?;
            } else {
                self.read(&pipe.recv()?)?;
            }
        }
        Ok(PipeChannel {
            channel: self.finish()?,
            pipe,
        })
    }
}

/// An established channel, without I/O. Messages longer than one Noise message
/// are split; each fragment is a frame to send, and `open` reassembles.
pub struct Channel {
    state: TransportState,
    remote_static: [u8; 32],
    handshake_hash: Vec<u8>,
    poisoned: bool,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

/// Fragments of a message being received.
#[derive(Default)]
pub struct Partial(Vec<u8>);

impl Channel {
    pub fn remote_static(&self) -> &[u8; 32] {
        &self.remote_static
    }

    /// The handshake hash: both sides hold the same value (channel binding).
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    /// Seals one application message into one or more frames.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<Vec<u8>>> {
        if self.poisoned {
            return Err(LinkError::Noise("channel failed earlier".into()));
        }
        if plaintext.len() > MAX_MESSAGE {
            return Err(LinkError::Protocol("message too large".into()));
        }
        let mut frames = Vec::new();
        let mut chunks = plaintext.chunks(MAX_CHUNK_DATA).peekable();
        if chunks.peek().is_none() {
            frames.push(self.seal_chunk(FLAG_LAST, &[])?);
        }
        while let Some(c) = chunks.next() {
            let flag = if chunks.peek().is_some() {
                FLAG_MORE
            } else {
                FLAG_LAST
            };
            frames.push(self.seal_chunk(flag, c)?);
        }
        Ok(frames)
    }

    fn seal_chunk(&mut self, flag: u8, data: &[u8]) -> Result<Vec<u8>> {
        let mut pt = Vec::with_capacity(data.len() + 1);
        pt.push(flag);
        pt.extend_from_slice(data);
        let mut out = vec![0u8; pt.len() + TAG];
        let n = self
            .state
            .write_message(&pt, &mut out)
            .inspect_err(|_| self.poisoned = true)?;
        out.truncate(n);
        Ok(out)
    }

    /// Opens one frame. `Some(message)` when it completed a message. Any
    /// failure (tamper, replay, reorder, loss) poisons the channel: the caller
    /// drops it and reconnects.
    pub fn open(&mut self, partial: &mut Partial, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.poisoned {
            return Err(LinkError::Noise("channel failed earlier".into()));
        }
        let mut buf = vec![0u8; frame.len()];
        let n = match self.state.read_message(frame, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                self.poisoned = true;
                return Err(e.into());
            }
        };
        buf.truncate(n);
        let Some((&flag, data)) = buf.split_first() else {
            self.poisoned = true;
            return Err(LinkError::Protocol("empty fragment".into()));
        };
        if partial.0.len() + data.len() > MAX_MESSAGE {
            self.poisoned = true;
            return Err(LinkError::Protocol("message too large".into()));
        }
        partial.0.extend_from_slice(data);
        match flag {
            FLAG_MORE => Ok(None),
            FLAG_LAST => Ok(Some(std::mem::take(&mut partial.0))),
            _ => {
                self.poisoned = true;
                Err(LinkError::Protocol("bad fragment flag".into()))
            }
        }
    }

    pub fn seal_message(&mut self, m: &Message) -> Result<Vec<Vec<u8>>> {
        self.seal(&m.encode())
    }

    pub fn open_message(&mut self, partial: &mut Partial, frame: &[u8]) -> Result<Option<Message>> {
        self.open(partial, frame)?
            .map(|b| Message::decode(&b))
            .transpose()
    }
}

/// A channel with its pipe: blocking send and receive of whole messages.
pub struct PipeChannel {
    channel: Channel,
    pipe: Box<dyn Pipe>,
}

impl PipeChannel {
    pub fn remote_static(&self) -> &[u8; 32] {
        self.channel.remote_static()
    }

    pub fn handshake_hash(&self) -> &[u8] {
        self.channel.handshake_hash()
    }

    pub fn set_recv_timeout(&mut self, t: Option<std::time::Duration>) -> Result<()> {
        self.pipe.set_recv_timeout(t)
    }

    /// Where the peer was reached.
    pub fn peer_hint(&self) -> Option<crate::PeerHint> {
        self.pipe.peer_hint()
    }

    pub fn send_bytes(&mut self, plaintext: &[u8]) -> Result<()> {
        for f in self.channel.seal(plaintext)? {
            self.pipe.send(&f)?;
        }
        Ok(())
    }

    pub fn recv_bytes(&mut self) -> Result<Vec<u8>> {
        let mut partial = Partial::default();
        loop {
            let frame = self.pipe.recv()?;
            if let Some(m) = self.channel.open(&mut partial, &frame)? {
                return Ok(m);
            }
        }
    }

    pub fn send(&mut self, m: &Message) -> Result<()> {
        self.send_bytes(&m.encode())
    }

    pub fn recv(&mut self) -> Result<Message> {
        Message::decode(&self.recv_bytes()?)
    }
}
