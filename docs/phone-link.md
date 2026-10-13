# Phone link

How the desktop talks to a paired phone: one secure channel, any transport.
Code: `crates/link` (desktop, and the shared protocol), `crates/mobile` (the
phone side, shaped for a flutter_rust_bridge wrapper). Fixed-key test vectors
for the Kotlin/Dart side: `crates/link/tests/vectors.json`.

## Layers

1. **Transport** (`Transport::reach` gives a `Pipe`): an ordered, reliable carrier of
   whole frames, at most 65535 bytes. Untrusted.
   - **BLE** (Linux, BlueZ over D-Bus): the desktop is the GATT central, the phone the
     server. One service, one write characteristic (desktop to phone), one notify
     characteristic (phone to desktop); UUIDs are in `ble.rs`. A frame is sent as
     a 2-byte big-endian length plus the bytes, cut into chunks of ATT MTU minus 3
     (`ble_frame.rs`; the vectors pin it). The device is found by the address
     remembered at pairing, or by scanning for the service UUID.
   - **LAN**: mDNS `_vahta._tcp` (instance name: first 8 bytes of SHA-256 of the phone's
     static key, hex), then TCP, frames with a 2-byte length prefix.
   - The daemon tries every transport a device has in parallel (`reach_first`); the
     first connection wins, the rest are dropped.
2. **Noise** over the pipe. The desktop always dials, so it is always the initiator.
   - Pairing: `Noise_XXpsk3_25519_ChaChaPoly_SHA256`, PSK from the QR code.
   - Every later connection: `Noise_KK_25519_ChaChaPoly_SHA256`, both static keys pinned.
   - The prologue is `vahta-link/1/pair|` or `vahta-link/1/session|` plus the 16-byte
     vault id, so a channel for one vault never completes for another.
   - After the handshake each message is sealed with the Noise transport state
     (implicit counter nonces). A message longer than one Noise message is split
     into fragments (flag byte: 0 more, 1 last); a message is at most 1 MiB.
     Any decrypt failure (bit flip, replay, reorder, loss) poisons the channel;
     the caller drops it and reconnects.
3. **Messages**: `[version = 1]` then postcard (`messages.rs`). Decoding is strict: wrong
   version, unknown variant, trailing bytes, a request whose hash does not match,
   or a key that is not SEC1 P-256 is an error.

## Pairing

1. The desktop (vault open, password asked and journaled by the caller) makes a `PairOffer`
   `{ v, desktop_static_pub, psk, vault_id, desktop_name, expires_at }` and shows
   `vahta-pair:` + base64url(postcard) as a QR code (`render_qr`, Unicode blocks).
2. The phone scans it, rejects it if expired, and waits for the desktop to dial.
3. XXpsk3 handshake. The phone ends it only if the desktop's static key is the
   one printed in the QR; the PSK proves the dialer saw the screen.
4. The phone sends `PairAccept { phone_name, phone_static_pub, sign_pub, ecdh_pub }` (the
   last two are Android Keystore P-256 public keys, SEC1 bytes). The desktop checks
   that `phone_static_pub` is the key that just spoke Noise, then sends `PairAck`.
5. The caller stores the device record (the desktop's key pair, the phone's keys, the
   address hints). The link crate persists nothing and does not choose where
   keys live.

## Messages

`PairAccept`, `PairAck`, `ApproveRequest { request, request_hash, nonce, expires_at }`
(`request` is opaque bytes, the hash is SHA-256 of it), `Decision { request_hash,
choice, signature }`, `UnlockRequest { slot_id, eph_pub }`, `UnlockResponse`
(an ECDH output or an error text), `Ping`/`Pong`. They are data: the link
decides nothing about what a signature covers or what an ECDH result is for.

## Threat model

- **The transport is untrusted.** An eavesdropper or a man in the middle on
  Bluetooth, Wi-Fi or a future relay sees frame sizes and timing, and can drop,
  delay or cut the connection. Bluetooth link-layer pairing is not relied on.
- **Confidentiality and integrity** come from Noise. Tampering, replays within a
  connection, reordering and truncation all end in a decrypt error. Replaying a
  recorded handshake to a fresh responder fails (new ephemeral key).
- **Authentication** is by pinned static keys (KK). A stranger who knows the vault id cannot
  complete a session. At pairing, authentication of the desktop is the QR
  (its key), of the phone is the PSK; an attacker who photographs the QR within its
  lifetime can pair as the phone, which is why the offer is short-lived, the
  PSK single use, and pairing needs the open vault.
- **Not covered here:** that the person holding the phone approved *this* request
  (the Approver's signature, S5), that the phone is not stolen (biometrics in the
  Keystore, device expiry and revoke in the vault), and traffic analysis.
- Static keys and the offer's PSK are zeroized on drop where the crate holds
  them; persistence is the caller's decision.
