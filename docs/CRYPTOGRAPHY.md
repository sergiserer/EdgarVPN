# Cryptography

This document covers ForgeVPN's cryptographic design: the X25519 key
exchange, the authenticated encryption wrapping every tunnel packet, and
what's deliberately still missing.

## Current state

Tunnel traffic is encrypted and authenticated: every packet forwarded
between two peers is sealed with ChaCha20-Poly1305 before it leaves the
sender's UDP socket, and rejected unless it authenticates on arrival. The
"any datagram on the UDP port is trusted" gap described in earlier
revisions of `docs/NETWORKING.md` is closed.

What's still missing, deliberately deferred to later milestones (see
`docs/ROADMAP.md`):

* **No live handshake.** Both peers derive their session keys locally at
  startup from their own `PrivateKey` and the other's `PublicKey`,
  already known via their config files (see `docs/CONFIGURATION.md`) --
  there is no over-the-network exchange of ephemeral keys yet. That's
  the "session lifecycle" milestone.
* **No forward secrecy.** Because session keys come directly from each
  peer's long-term static key pair rather than fresh ephemeral keys, a
  compromised `PrivateKey` would let an attacker decrypt any traffic
  captured under that key pair, past or future. Real forward secrecy
  needs the live handshake above (WireGuard gets this from combining
  static and ephemeral keys in a Noise handshake).
* **No key rotation.** The session keys derived at startup are used for
  the life of the process.

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
  key pair (used by `forgevpn-keygen`).
* `crypto_derive_public_key` → `crypto_scalarmult_base`: recomputes a
  peer's own public key from its configured private key at startup,
  rather than trusting a separately configured value that could drift
  out of sync with it.
* `crypto_derive_session_keys` → `crypto_kx_client_session_keys` /
  `crypto_kx_server_session_keys`: performs the ECDH exchange and, from
  the shared secret plus both public keys, derives **two independent
  session keys** -- `rx` and `tx` -- instead of one.

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
`docs/CONFIGURATION.md`) -- there is no live negotiation of roles, they
are a static part of the configuration today.

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
note on demo keys in `docs/CONFIGURATION.md`.

## Authenticated encryption: packet format

Every packet `forgevpn` forwards over UDP is sealed with
ChaCha20-Poly1305 (the IETF variant: 96-bit nonce, 128-bit tag) via
`crypto_seal` / `crypto_open`. The wire format is:

```
+------------------+-----------------------------+----------------+
| counter (8 bytes)| ChaCha20-Poly1305 ciphertext | tag (16 bytes) |
+------------------+-----------------------------+----------------+
```

The 8-byte counter is a per-session, monotonically increasing value the
sender maintains (`tx_counter` in `src/main.c`, starting at 0). It
doubles as the low 8 bytes of the 12-byte AEAD nonce (the high 4 bytes
are always zero) -- the same scheme WireGuard uses. A counter must never
repeat under the same key; a plain incrementing counter guarantees that
for the lifetime of a single process (key rotation, needed to make this
hold indefinitely, is future work).

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
`crypto_open` succeeds, `src/main.c` compares the packet's counter
against the highest counter seen so far for that peer and drops the
packet if it isn't strictly greater. Authenticate first, then check
freshness -- checking freshness first would mean trusting an
attacker-controlled field before it's been verified.

This is a simple strict-monotonic check, not WireGuard's sliding-window
replay filter -- it rejects any out-of-order packet, not just replays,
which is a correctness/robustness gap under real-world UDP reordering.
Documented as a known simplification; a proper sliding window is future
work alongside key rotation.

## Testing

`tests/crypto_test.c` checks the properties that actually matter, not
implementation details:

* **Both sides agree**: an initiator and a responder, given each other's
  public keys, derive session keys where initiator `tx` equals responder
  `rx` and vice versa -- without either side ever seeing the other's
  private key.
* **Different peers, different keys**: the same local key pair exchanged
  with two different remote public keys produces two unrelated session
  keys.
* **Base64 round-trips**, and malformed base64 is rejected.
* **`crypto_derive_public_key` matches `crypto_generate_keypair`'s own
  output** -- i.e. recomputing a public key from a private key is
  consistent with how the pair was generated.
* **Seal/open round-trips** and recovers the original counter.
* **Tampered ciphertext is rejected**, and **decrypting with the wrong
  key is rejected**.

`tests/config_test.c` covers the corresponding config-parsing
requirements: a `[Peer]` section demands `PrivateKey` (on `[Interface]`),
`PublicKey`, and `Role`, each independently, and malformed key text is
rejected.
