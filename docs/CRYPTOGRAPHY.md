# Cryptography

This document covers ForgeVPN's cryptographic design: the X25519 key
exchange, the live handshake that provides forward secrecy, the
authenticated encryption wrapping every tunnel packet, and what's
deliberately still missing.

## Current state

Every data packet forwarded between two peers is encrypted and
authenticated with ChaCha20-Poly1305, using keys derived from a live
handshake run over UDP at startup -- not directly from each peer's
long-term key pair. That handshake mixes fresh, ephemeral X25519 keys
(generated per process, wiped from memory the moment they're no longer
needed) with each peer's static identity, so the data channel has
**forward secrecy**: even if a `PrivateKey` leaks later, past traffic
can't be decrypted from it, because the ephemeral private keys that
actually protected that traffic are gone.

What's still missing, deliberately deferred to later milestones (see
`docs/ROADMAP.md`):

* **No re-handshake or reconnection.** Each `session_t` supports exactly
  one handshake per process lifetime (see "Known limitations" below).
  There's no keepalive, and no recovery if a peer restarts mid-session.
* **No key rotation.** The forward-secret data keys derived at handshake
  time are used for the rest of the process's life.
* **Simplified replay protection.** A strict-monotonic counter check
  (see below), not a sliding window -- rejects legitimate out-of-order
  UDP delivery, not just replays.

## Why libsodium, not hand-rolled crypto

Every other module in this project is deliberately built from scratch --
raw `ioctl` calls for TUN, raw BSD sockets for UDP, a hand-written INI
parser for configuration -- because that's where writing it yourself
demonstrates systems programming knowledge. Cryptographic primitives are
the exception: implementing Curve25519 scalar multiplication or an AEAD
cipher by hand is a well-known way to introduce subtle, exploitable bugs
(timing side channels, incorrect constant-time comparisons, nonce
misuse), even for experienced engineers. **Knowing when not to write your
own crypto is itself the professional judgment call.** ForgeVPN uses
[libsodium](https://doc.libsodium.org/), a widely audited, industry
standard library, for every cryptographic operation.

## Key exchange: the `crypto_kx` construction

`src/crypto.c` wraps libsodium's `crypto_kx_*` API rather than calling
raw `crypto_scalarmult` (X25519) directly:

* `crypto_generate_keypair` → `crypto_kx_keypair`: generates an X25519
  key pair (used for both long-term identity keys, via `forgevpn-keygen`,
  and for the ephemeral keys `src/session.c` generates per handshake).
* `crypto_derive_public_key` → `crypto_scalarmult_base`: recomputes a
  peer's own public key from its configured private key at startup,
  rather than trusting a separately configured value that could drift
  out of sync with it.
* `crypto_derive_session_keys` → `crypto_kx_client_session_keys` /
  `crypto_kx_server_session_keys`: performs the ECDH exchange and, from
  the shared secret plus both public keys, derives **two independent
  session keys** -- `rx` and `tx` -- instead of one. Used twice per
  session: once for the long-term keys (protects the handshake messages
  only) and once for the ephemeral keys (protects data).

Two keys instead of one matters: if both directions of traffic used the
same key with independently chosen nonces, a nonce collision between the
two directions becomes a real risk. Separate keys per direction remove
that failure mode by construction, at essentially no extra cost, since
the exchange is already computing key material for both directions.

### Roles

Because `crypto_kx_client_session_keys` and `crypto_kx_server_session_keys`
compute their `rx`/`tx` pair in opposite order from the same shared
secret, both peers must agree on which one calls which -- otherwise
peer A's `tx` won't match peer B's `rx`. ForgeVPN calls these roles
**initiator** and **responder** (`crypto_role_t`), configured explicitly
via the `Role` key in each peer's `[Peer]` section (see
`docs/CONFIGURATION.md`). The same role also decides who sends the first
handshake message (see below) -- there is no live negotiation of roles,
they are a static part of the configuration.

## Key encoding

Keys are 32 raw bytes, displayed and stored as base64 -- the same
convention WireGuard uses for `PrivateKey`/`PublicKey` in its config
files and the output of `wg genkey`. `crypto_encode_base64` /
`crypto_decode_base64` wrap libsodium's own base64 codec
(`sodium_bin2base64` / `sodium_base642bin`); there is no hand-written
base64 here either, for the same "don't hand-roll security-adjacent code"
reasoning as above.

## `forgevpn-keygen`

A small CLI tool (`tools/keygen.c`), bundled into the runtime image
alongside `forgevpn`, generates one key pair and prints it:

```bash
docker compose run --rm peer1 forgevpn-keygen
```

```
PrivateKey = <base64>
PublicKey  = <base64>
```

This mirrors `wg genkey | tee privatekey | wg pubkey > publickey` as a
single step. `PrivateKey` goes in that peer's own `[Interface]` section;
the matching `PublicKey` goes in the *other* peer's `[Peer]` section. The
demo configs under `configs/*.conf` were generated this way -- see the
note on demo keys in `docs/CONFIGURATION.md`. This tool generates
long-term identity keys only; ephemeral keys are generated internally by
`src/session.c` and never touch disk.

## The handshake (`src/session.c`)

Rather than deriving data keys directly from the two peers' long-term
static keys (as an earlier revision of this document described), a live
2-message handshake now runs over UDP before any data flows, mixing in
fresh ephemeral keys for forward secrecy. This is a simplified
construction *inspired by* Noise-style patterns (WireGuard itself uses
Noise_IK) -- not a byte-for-byte implementation of one, and it hasn't had
the kind of formal analysis a real Noise pattern has had. Treat it as an
educational approximation of the idea, not a production-grade protocol.

1. At startup, both peers compute **static session keys** via
   `crypto_derive_session_keys` from their long-term `PrivateKey`/
   `PublicKey` (exactly Milestone 5's derivation) -- but these now
   protect the handshake messages *only*, never data.
2. Both peers also generate a fresh **ephemeral key pair**, purely
   in-memory, never written to config or disk.
3. The **initiator** sends `HANDSHAKE_INIT`: its ephemeral public key,
   sealed under the static keys.
4. The **responder** opens it (authenticating that it really came from
   the expected peer, via the static key), generates its own ephemeral
   key pair if it hasn't already, computes `crypto_derive_session_keys`
   again -- this time between the *ephemeral* key pairs -- yielding the
   forward-secret **data keys**, wipes its ephemeral private key
   (`crypto_wipe`, `sodium_memzero` under the hood), and replies with
   `HANDSHAKE_RESPONSE`: its own ephemeral public key, sealed under the
   static keys.
5. The **initiator** opens the response, performs the same ephemeral-pair
   ECDH to arrive at the identical data keys, and wipes its own ephemeral
   private key.

Both sides now hold matching `rx`/`tx` data keys that depend on both
ephemeral private keys -- neither of which was ever transmitted, and
both of which are erased from memory within the same function call that
used them. Recovering a past session's data key later requires one of
those erased ephemeral private keys; a leaked long-term `PrivateKey`
alone isn't enough. That's the forward-secrecy property this milestone
adds.

### Wire framing

Every UDP datagram now starts with a one-byte, unencrypted message type,
so the receiver knows which key applies before it can decrypt anything
(the same idea WireGuard's own message-type field serves):

```
+------+---------------------------------------------+
| type |                   payload                    |
| (1B) |                                               |
+------+---------------------------------------------+
```

| Type | Name                  | Payload (before sealing)      | Sealed under   |
|------|------------------------|--------------------------------|-----------------|
| 1    | `HANDSHAKE_INIT`       | sender's ephemeral public key (32B) | static keys |
| 2    | `HANDSHAKE_RESPONSE`   | sender's ephemeral public key (32B) | static keys |
| 3    | `DATA`                 | the IP packet from/to the TUN device | data keys |

`payload` is sealed exactly as described in "Authenticated encryption"
below (`counter || ciphertext || tag`) -- the type byte sits outside
that, in cleartext, purely as protocol framing.

### Known limitations

* **One handshake per process.** `session_t` transitions from
  `SESSION_STATE_HANDSHAKE_PENDING` to `SESSION_STATE_ESTABLISHED`
  exactly once; a `HANDSHAKE_INIT` arriving after that is rejected
  outright (`tests/session_test.c` verifies this). This is a deliberate
  guard, not an oversight: reprocessing a second handshake with the same
  already-used ephemeral key pair would silently break forward secrecy
  for whichever session did so. Real re-handshake/reconnection support
  (generating a fresh ephemeral pair each time) is future work.
* **No DoS/flood protection.** Real handshake protocols (including
  Noise_IK, via WireGuard's cookie mechanism) defend against a flood of
  bogus handshake-init messages forcing expensive crypto operations.
  Not implemented here.
* **No identity hiding.** The handshake reveals which static key pairs
  are talking to an observer who can see the traffic pattern, even
  though the ephemeral keys themselves are protected.

## Authenticated encryption: packet format

The `payload` portion of every message (handshake or data) is sealed
with ChaCha20-Poly1305 (the IETF variant: 96-bit nonce, 128-bit tag) via
`crypto_seal` / `crypto_open`:

```
+------------------+-----------------------------+----------------+
| counter (8 bytes)| ChaCha20-Poly1305 ciphertext | tag (16 bytes) |
+------------------+-----------------------------+----------------+
```

The 8-byte counter is a monotonically increasing value the sender
maintains per key (`session_t.tx_counter` for the data channel; a fixed
`0` for each handshake message, safe because each handshake key is used
for exactly one message in this milestone's one-handshake-per-process
design -- see "Known limitations"). It doubles as the low 8 bytes of the
12-byte AEAD nonce (the high 4 bytes are always zero) -- the same scheme
WireGuard uses. A counter must never repeat under the same key.

### Why decrypt-then-check-freshness, not the other way around

The counter travels in the clear and is *not* itself covered by a
separate authentication step -- but tampering with it isn't free: it
feeds directly into the nonce, so changing it while replaying old
ciphertext bytes changes what nonce `crypto_open` derives, which makes
Poly1305 tag verification fail. That only protects against *tampering*,
though -- an attacker who captures a full, untouched
(counter, ciphertext, tag) tuple and resends it verbatim later will pass
authentication, because it's byte-for-byte identical to a packet that
was genuinely sent. Catching that requires a second check: after
`crypto_open` succeeds, `session_open_data` compares the packet's counter
against the highest counter seen so far for that session and drops the
packet if it isn't strictly greater. Authenticate first, then check
freshness -- checking freshness first would mean trusting an
attacker-controlled field before it's been verified.

This is a simple strict-monotonic check, not WireGuard's sliding-window
replay filter -- it rejects any out-of-order packet, not just replays,
which is a correctness/robustness gap under real-world UDP reordering.
Documented as a known simplification; a proper sliding window is future
work.

## Testing

`tests/crypto_test.c` checks the primitive-level properties: initiator
and responder derive matching session keys without exchanging private
keys; different peer pairs get different keys; base64 round-trips and
rejects malformed input; `crypto_derive_public_key` is consistent with
`crypto_generate_keypair`; seal/open round-trips, recovers the original
counter, and rejects tampering or the wrong key.

`tests/session_test.c` checks the protocol-level properties, running a
full in-process handshake between an initiator and a responder:

* **Forward-secret keys match and differ from the static keys**: after a
  full handshake, initiator `tx` equals responder `rx` and vice versa
  (as with the raw primitive), *and* those data keys are different from
  the static keys used to protect the handshake itself -- proving the
  ephemeral step actually changed the key rather than being a no-op.
* **Data round-trips in both directions** once established.
* **Replayed data is rejected.**
* **A tampered handshake init is rejected**, and doesn't establish the
  responder's session.
* **A second handshake init after the session is already established is
  rejected** -- the one-handshake-per-process guard described above.

`tests/config_test.c` covers the corresponding config-parsing
requirements: a `[Peer]` section demands `PrivateKey` (on `[Interface]`),
`PublicKey`, and `Role`, each independently, and malformed key text is
rejected.
