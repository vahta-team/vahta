# Phone link

How the desktop talks to a paired phone: one secure channel, any transport.
Code: `crates/link` (desktop, and the shared protocol), `crates/mobile` (the
phone side, shaped for a flutter_rust_bridge wrapper). Fixed-key test vectors
for the Kotlin/Dart side: `crates/link/tests/vectors.json` (channel, messages, tags)
and `crates/mobile/tests/helper_vectors.json` (what the phone signs, how a request
reads, what it advertises). The daemon side is `crates/daemon/src/link_devices.rs`.

## Layers

1. **Transport** (`Transport::reach` gives a `Pipe`): an ordered, reliable carrier of
   whole frames, at most 65535 bytes. Untrusted.
   - **BLE** (Linux, BlueZ over D-Bus; no other desktop OS yet): the desktop is the
     GATT central, the phone the GATT server. One service, one write characteristic
     (desktop to phone, write with response), one notify characteristic (phone to
     desktop); UUIDs (random v4, fixed forever): service
     `11ca9b36-035f-4d80-8e4a-7819627ac4c0`, write `0e1a6dcf-3ae7-4ba5-a24c-fc4c243d0629`,
     notify `5625b7a7-3f03-49f9-8d96-a25a49559adf` (constants in `ble_frame.rs`). A
     frame is sent as a 2-byte big-endian length plus the bytes, cut into chunks of
     ATT MTU minus 3 (`ble_frame.rs`; the vectors pin it). The phone must accept
     the notify subscription (CCCD) before the desktop writes. The desktop finds the
     phone by its advertisement (below), not by a remembered address.
   - **LAN** (all desktop OSes): the phone listens on a TCP port and registers
     `_vahta._tcp` over mDNS with the instance name below; the desktop browses,
     resolves the instance and connects. TCP carries the same frames, each with a
     2-byte big-endian length prefix. The desktop remembers the last address that
     worked and tries it first for 1.5 seconds. Multicast is often blocked on
     guest and corporate networks; then LAN does not work and BLE is the way.
   - **Other desktop OSes:** macOS and Windows get the LAN transport only for now;
     the BLE transport is absent there and the daemon does not try it.
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

## Advertising: how the desktop finds the phone

A phone is found by a **tag**, 8 bytes, never by an address (BLE addresses on
phones are random and rotate). There are two tags:

* **device tag** of a paired phone: the first 8 bytes of `SHA-256(phone static
  Noise public key)` (`device_tag`). It names the device without carrying its key.
* **pairing tag** while waiting to be paired: the first 8 bytes of
  `SHA-256("vahta/v1/pair-tag" || psk)` (`pairing_tag`), with the PSK from the
  QR code. Only someone who has seen the QR code can compute it, and it reveals
  nothing of the PSK.

**BLE.** The phone advertises with these two parts (an Android
`BluetoothLeAdvertiser` call with `setConnectable(true)`):

1. the advertising packet carries the 128-bit service UUID;
2. the scan response carries **service data** under the same 128-bit UUID,
   10 bytes: `[format = 1, kind, tag (8 bytes)]`, `kind` 1 for a paired phone
   (device tag) and 2 for a phone waiting to pair (pairing tag). A reader ignores
   any other format byte (a future format) and any other length.

The packets are not secret and not trusted: anyone can copy a tag. What the tag
buys is that the desktop connects to the right phone and not every Vahta phone
in the room; the Noise handshake that follows is what authenticates.

**LAN.** The mDNS instance name is the tag in lowercase hex (16 characters), the
service type `_vahta._tcp`, the port the phone's listener.

`mobile::session_advert(static_pub)` and `mobile::pairing_advert(qr)` return all
of it (`service_uuid`, `service_data`, `lan_instance`, characteristics), so the
Kotlin side copies bytes and computes nothing. The vectors pin the tags and the
service data.

The phone advertises only while it needs to be found: while the pairing screen
is up (pairing tag), and, for a paired phone, while the app's link service is
running (device tag). It must stop advertising the pairing tag once pairing is
done or the screen is left.

## Pairing

1. The person runs `vahta devices pair NAME`; the daemon opens the prompt window and
   asks for the master password (pairing is password-only, journaled).
2. The daemon makes a `PairOffer`
   `{ v, desktop_static_pub, psk, vault_id, desktop_name, expires_at }` and shows
   `vahta-pair:` + base64url(postcard) in the window as a Unicode QR code
   (`render_qr`) and, below it, as one line of text for a phone that cannot scan. The
   code lives 5 minutes (`MAX_OFFER_SECS`) and the window says so. The
   desktop's static key is made on first use and kept per vault (see Desktop
   state below).
3. The phone scans it (or takes the text), rejects it if expired, shows the
   desktop name and asks the person to confirm, then advertises the **pairing tag**
   over BLE and opens its LAN listener with the same tag as the instance name
   (`mobile::pairing_advert`).
4. The desktop dials as soon as the code is on screen, racing the transports
   (`reach_first`: BLE scan for the pairing tag and connect, LAN hint then mDNS),
   in tries of 4 seconds until the code expires or the person closes the window.
   The first pipe that connects runs `Noise_XXpsk3` as initiator with a 10 second
   limit per step. A connection that fails the handshake (wrong PSK, a stranger,
   garbage) is dropped and the wait goes on: the code is still good.
5. The phone ends the handshake only if the desktop's static key is the one printed
   in the QR; the PSK proves the dialer saw the screen.
6. The phone sends `PairAccept { phone_name, phone_static_pub, sign_pub, ecdh_pub }`
   (the last two are Android Keystore P-256 public keys, SEC1 uncompressed; from
   `PublicKey.getEncoded()` use `mobile::sec1_from_spki`). The desktop checks that
   `phone_static_pub` is the key that just spoke Noise, then sends `PairAck`. The
   phone treats pairing as done on `PairAck` and stores the desktop's key and the
   vault id (`PairedDesktop`).
7. The daemon keeps the phone's static key and where it was reached
   (`link/<vault id>/<device id>.json`), gives the window "Phone paired.", and
   records the device in the vault's signed list with a slot of its own.

## Sessions

Every later connection: the desktop finds the phone by the **device tag**
(BLE: scan, match service data; LAN: mDNS instance, or the remembered address),
connects, and runs `Noise_KK` with both static keys pinned and the vault id in the
prologue. The phone is the responder, one connection at a time is enough: the
desktop closes the connection when it has its answer or when another approver
answered first, and **the phone must dismiss any prompt that belongs to a
connection that closed**.

* **Approval** (`ApproveRequest`): the phone checks the request parses
  (`request_summary`; `LinkSession` already refuses bytes that are not a request
  and an envelope whose nonce or expiry differs from the request inside), draws its
  own screen from the structure, asks for biometrics, signs
  `decision_message(request, option, device_id)` with its Keystore signing key
  (SHA256withECDSA, then `signature_from_der`) and replies with
  `reply_decision(request_hash, approve, option, signature)`, or with a deny.
* **Unlock** (`UnlockRequest { slot_id, eph_pub, request }`): one biometric prompt
  both approves `request` and opens the vault. The phone signs
  `decision_message(request, 0, device_id)`, does the Keystore ECDH with `eph_pub`
  (raw 32-byte shared secret, the X coordinate), and answers
  `reply_unlock_ok(shared, signature)`. A no is `reply_unlock_denied`, a failure
  `reply_unlock_error`.
* **Timeouts.** The desktop tries to connect for at most 12 seconds (less if the
  request ends sooner), allows 10 seconds per handshake step, and then waits for the
  answer until the request's own `expires_at` (a few minutes for an unlock or a run
  question). An unanswered request ends with no answer; the desktop does not
  retry on its own. A phone that is slow to wake has the connect window to appear.
* **Pings.** Either side may send `Ping(n)`; the other answers `Pong(n)`.
  `LinkSession` answers pings itself; during a long biometric prompt the phone need
  not send anything.
* **Reachability** (`DeviceChannel::reachable`) is a cached guess made without
  blocking the caller: a successful contact or probe counts for 45 seconds, a failed
  one for 10, and a stale or missing entry starts a probe on a background thread
  (a BLE scan for the tag, or a LAN connect). A phone nothing has been tried with is
  assumed reachable. The password window is never held up by any of this.

## Desktop state

In the daemon's data directory (`<data>/link/<vault id hex>/`):

* `desktop.key`: this computer's static X25519 key for the link (hex, mode 0600,
  directory 0700), one per vault. It is a transport identity, not a vault secret:
  it lets a phone recognise this computer. Whoever reads it can open a Noise
  session to a paired phone as this computer, but cannot answer for the phone: an
  approval is checked against the keys in the vault's signed device list, and an
  unlock needs the phone's key-agreement key. The worst they can do is make the
  phone show prompts, which the person declines.
* `<device id hex>.json`: the phone's static Noise public key, its name, the last
  Bluetooth address and the last LAN address it was reached at. These are a pin and
  hints, not trust. They are kept here and not in the vault because a Bluetooth
  address changes, and because they are per computer: the phone pins *this*
  computer's key, so another computer holding a copy of the vault cannot reach the
  phone (it falls back to the password), and a phone can be paired with each
  computer separately.
* `revoke` and `lost` delete the phone's file. Losing the directory means pairing
  again; the vault and the password are unaffected.

## Messages

`PairAccept`, `PairAck`, `ApproveRequest { request, request_hash, nonce, expires_at }`
(`request` is the canonical `Request` bytes, `request_hash` is plain SHA-256 of them),
`Decision { request_hash, choice (Approve | Deny), option, signature }` (the option
index the person chose, and the 64-byte signature; empty on a deny),
`UnlockRequest { slot_id, eph_pub, request }`,
`UnlockResponse` (`Approved { shared, signature }`, `Denied`, `Error(text)`),
`Ping`/`Pong`. The link decides nothing about what a signature covers or what
an ECDH result is for; the phone-side helpers in `crates/mobile` and the
desktop's `vahta-auth` do, from the same code.

### What the phone signs

`Request` is the structure the person approves (action, secret names, project,
category, the agent's unverified label, the options, a nonce, an expiry), encoded
canonically with postcard; `Request::from_bytes` is strict (no trailing bytes, no
other spelling of the same value), so what the phone hashes is what it was shown.
The phone signs exactly

    "vahta/v1/decision" || SHA-256("vahta/v1/request" || request bytes) || option || device_id

where `device_id` is the first 16 bytes of
`SHA-256("vahta/v1/device-id" || sign_pub || ecdh_pub)`. That string comes from
one function (`Request::decision_message` in `vahta-auth`) that the desktop's
`Decision::sign` and `Decision::verify` and the phone's `decision_message` all call.
The daemon accepts a decision only for the request it sent, before it expires,
from the device the vault lists, for an option the request offers.

### What the Kotlin side calls (`crates/mobile`)

| Need | Call |
|---|---|
| Phone's channel key | `generate_static_key()` once; store encrypted |
| Keystore public keys to SEC1 | `sec1_from_spki(publicKey.encoded)` for both the signing and the ECDH key |
| Device id | `device_id(sign_pub, ecdh_pub)` |
| Scan | `parse_offer(qr, now)` for the confirmation screen, `PairingSession::start(...)`, `handle_frame` |
| Advertising | `pairing_advert(qr)` while pairing, `session_advert(static_pub)` after; `device_tag(static_pub)` |
| Draw an approval | `request_summary(request)` |
| Bytes to sign | `decision_message(request, option, device_id)`, sign with SHA256withECDSA |
| Signature to wire form | `signature_from_der(der)` (64 bytes, r then s) |
| Reply | `reply_decision`, `reply_unlock_ok(ecdh_result, signature)`, `reply_unlock_denied`, `reply_unlock_error` |
| BLE chunks | `ble_chunks`, `BleReassembler` |

### Phone key protection

The phone holds two Keystore keys: one signs decisions, one does the ECDH for
unlock. The signing key needs a fingerprint for every signature: the app signs
through a `BiometricPrompt` `CryptoObject`, so the signature cannot be made
without the person touching the sensor for that very operation. The ECDH key
cannot be held to that. On Android 13 a `KeyAgreement` cannot be bound to one
prompt, so the ECDH key is usable for 1 second after a fingerprint, and the app
runs the ECDH right after the signature, inside that second. Only the Vahta
app's own process can use these Keystore keys; other apps and the desktop
cannot, and the private keys never leave the secure hardware. What the 1 second
means: code running inside the Vahta app, in that window, could make one ECDH
without a second fingerprint. Binding every ECDH to its own prompt needs a newer
Android API or an RSA-OAEP key (which does support per-operation binding).
RSA-OAEP was considered and deferred.

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

## Testing without a phone

`vahta-mobile` has a `fake-phone` feature (never enabled by the app): a software
phone that makes exactly the helper calls the Kotlin side makes, with P-256 keys
that sign DER and do ECDH as the Keystore does. The daemon's tests pair with it,
approve and unlock over the memory transport (in `link_devices.rs`) and over the LAN
transport on loopback against the real daemon with the scripted prompt surface
(`crates/cli/tests/daemon.rs`, `VAHTA_TEST_PHONE_ADDR`). Nothing in the test suite
touches a Bluetooth adapter or a real network; the BLE transport is covered by unit
tests of its parsing and framing and by ignored tests that need a phone.
