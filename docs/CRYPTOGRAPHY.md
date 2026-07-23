# Cryptography

This document covers ForgeVPN's cryptographic design: the X25519 key
exchange, the live handshake that provides forward secrecy, session
lifecycle (keepalive and reconnection), the authenticated encryption
wrapping every tunnel packet, and what's deliberately still missing.

## Current state

Every data packet forwarded between two peers is encrypted and
authenticated with ChaCha20-Poly1305, using keys derived from a live
handshake run over UDP at startup -- not directly from each peer's
long-term key pair. That handshake mixes fresh, ephemeral X25519 keys
(generated per attempt, wiped from memory the moment they're no longer
needed) with each peer's static identity, so the data channel has
**forward secrecy**: even if a `PrivateKey` leaks later, past traffic
can't be decrypted from it, because the ephemeral private keys that
actually protected that traffic are gone.

An idle established session sends periodic keepalives, and an initiator
that stops hearing from its peer re-runs the handshake with a fresh
ephemeral key pair -- so the tunnel recovers automatically if a peer
restarts or the network drops packets for a while. Replay protection uses
a sliding window, tolerating ordinary UDP reordering rather than
rejecting anything that arrives out of sequence.

What's still missing, deliberately deferred to later milestones (see
`docs/ROADMAP.md`):

* **No key rotation.** A given handshake's forward-secret data keys are
  used for as long as that session stays established -- there's no
  periodic rekey independent of a full reconnection.
* **Fixed, non-configurable timers.** The keepalive interval and session
  timeout (see below) are compile-time constants, tuned short for demo
  visibility rather than production use. Making them configurable (like
  WireGuard's `PersistentKeepalive`) is future polish.
* **No DoS/flood protection or identity hiding** -- see "Known
  limitations" further down.

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
  and for the ephemeral keys `src/session.c` generates per handshake
  attempt).
* `crypto_derive_public_key` → `crypto_scalarmult_base`: recomputes a
  peer's own public key from its configured private key at startup,
  rather than trusting a separately configured value that could drift
  out of sync with it.
* `crypto_derive_session_keys` → `crypto_kx_client_session_keys` /
  `crypto_kx_server_session_keys`: performs the ECDH exchange and, from
  the shared secret plus both public keys, derives **two independent
  session keys** -- `rx` and `tx` -- instead of one. Used twice per
  handshake attempt: once for the long-term keys (protects the handshake
  messages only) and once for the ephemeral keys (protects data).

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
handshake message, and who is responsible for noticing a dead session and
re-handshaking (see "Session lifecycle" below) -- there is no live
negotiation of roles, they are a static part of the configuration.

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
static keys, a live 2-message handshake runs over UDP before any data
flows, mixing in fresh ephemeral keys for forward secrecy. This is a
simplified construction *inspired by* Noise-style patterns (WireGuard
itself uses Noise_IK) -- not a byte-for-byte implementation of one, and
it hasn't had the kind of formal analysis a real Noise pattern has had.
Treat it as an educational approximation of the idea, not a
production-grade protocol.

1. At session start, both peers compute **static session keys** via
   `crypto_derive_session_keys` from their long-term `PrivateKey`/
   `PublicKey` -- these protect the handshake messages *only*, never
   data.
2. Both peers also generate a fresh **ephemeral key pair** for this
   attempt, purely in-memory, never written to config or disk.
3. The **initiator** sends `HANDSHAKE_INIT`: its ephemeral public key,
   sealed under the static keys with this attempt's handshake counter
   (see "Handshake counters" below).
4. The **responder** opens it (authenticating that it really came from
   the expected peer, via the static key, and that the counter is fresh
   -- see below), generates its own ephemeral key pair, computes
   `crypto_derive_session_keys` again -- this time between the
   *ephemeral* key pairs -- yielding the forward-secret **data keys**,
   wipes its ephemeral private key (`crypto_wipe`, `sodium_memzero`
   under the hood), and replies with `HANDSHAKE_RESPONSE`: its own
   ephemeral public key, sealed under the static keys, **echoing the
   same counter** the init used.
5. The **initiator** opens the response, checks the echoed counter
   matches its outstanding attempt, performs the same ephemeral-pair
   ECDH to arrive at the identical data keys, and wipes its own ephemeral
   private key.

Both sides now hold matching `rx`/`tx` data keys that depend on both
ephemeral private keys -- neither of which was ever transmitted, and
both of which are erased from memory within the same function call that
used them. Recovering a past session's data key later requires one of
those erased ephemeral private keys; a leaked long-term `PrivateKey`
alone isn't enough.

### Handshake counters

Handshake messages use their own counter namespace, entirely separate
from the data channel's (`session_t.handshake_counter` /
`highest_handshake_counter_seen`, vs. `tx_counter` / the data replay
window). This exists specifically to stop an attacker from replaying an
old, once-valid `HANDSHAKE_INIT` to force a spurious reconnection (see
"Session lifecycle" -- a responder accepts a fresh init even when already
established, which is necessary for real reconnection to work, but means
handshake replay needs its own defense):

* The **responder** tracks the highest init counter it has accepted and
  rejects anything not strictly greater -- an exact rule-for-rule replay
  of "authenticate first, then check freshness" applied to the handshake
  channel (see "Why decrypt-then-check-freshness" below; the same
  reasoning applies here).
* The **initiator** remembers the counter it used for its outstanding
  init and requires the response's echoed counter to match exactly,
  rejecting a stale response left over from an earlier, abandoned attempt
  (`tests/session_test.c`'s `test_stale_handshake_response_rejected`
  covers this).
* A session's handshake counter starts from **the wall clock**
  (`time(NULL)`, whole seconds since the epoch) rather than 0 or a random
  value. This matters for reconnection after a full process restart: the
  responder remembers the last counter it saw, but the initiator's
  in-memory counter state is gone after a restart. Starting from 0 (or
  even a random 64-bit value, which has roughly even odds of landing
  *below* the old counter) would very likely be rejected as stale. Real
  time only moves forward, so starting from it is -- barring two restarts
  within the same wall-clock second, or severe clock skew -- effectively
  guaranteed to be fresher than whatever the responder last saw.

## Session lifecycle: keepalive and reconnection

An idle tunnel still needs to prove it's alive, and a dead or restarted
peer needs to be noticed and recovered from without manual intervention.
`src/main.c` drives both with a `poll()` timeout (checked once a second)
against two timers:

* **Keepalive** -- if nothing has been sent to the peer in
  `KEEPALIVE_INTERVAL_MS`, send a `DATA` message with a **zero-length
  payload**. There's no separate keepalive message type: an empty,
  successfully-authenticated `DATA` message already proves the sender is
  alive and holds the current data keys, which is all a keepalive needs
  to demonstrate. `session_open_data` returns `0` for one (a valid,
  meaningful result, not an error); `main.c` treats that as proof of life
  and does not call `tun_write` with an empty buffer.
* **Reconnection** -- the **initiator** (only) tracks how long it's been
  since it last received *anything* valid from the peer (a handshake
  reply, data, or a keepalive). If that exceeds `SESSION_TIMEOUT_MS`, it
  assumes the session is dead, calls `session_start_handshake` (fresh
  ephemeral key pair, cleared data-channel state) and sends a new
  `HANDSHAKE_INIT`.

The **responder** has no equivalent timeout logic, and needs none: it is
purely reactive. Whenever a `HANDSHAKE_INIT` arrives with a fresh-enough
counter, `session_handle_init` accepts it -- generating a new ephemeral
key pair first if the session was already `SESSION_STATE_ESTABLISHED`
(see `tests/session_test.c`'s
`test_reconnection_succeeds_with_fresh_ephemeral_keys`). This replaces an
earlier, more conservative version of this module that rejected any
second handshake outright to avoid reusing an already-consumed ephemeral
key pair; generating a *new* one before reprocessing is the actual fix,
not just a workaround, and forward secrecy holds across reconnections the
same way it does for the first handshake.

`KEEPALIVE_INTERVAL_MS` (5s) and `SESSION_TIMEOUT_MS` (15s) are
deliberately shorter than WireGuard's real-world defaults (25s / no fixed
session timeout, since WireGuard's design differs here) so the behavior
is easy to observe in a short demo run; see "Current state" above.

## Wire framing

Every UDP datagram starts with a one-byte, unencrypted message type, so
the receiver knows which key applies before it can decrypt anything (the
same idea WireGuard's own message-type field serves):

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
| 3    | `DATA`                 | the IP packet from/to the TUN device, or empty for a keepalive | data keys |

`payload` is sealed exactly as described in "Authenticated encryption"
below (`counter || ciphertext || tag`) -- the type byte sits outside
that, in cleartext, purely as protocol framing.

## Known limitations

* **No DoS/flood protection.** Real handshake protocols (including
  Noise_IK, via WireGuard's cookie mechanism) defend against a flood of
  bogus handshake-init messages forcing expensive crypto operations. Not
  implemented here.
* **No identity hiding.** The handshake reveals which static key pairs
  are talking to an observer who can see the traffic pattern, even
  though the ephemeral keys themselves are protected.
* **No key rotation independent of reconnection.** A long-lived, never-
  interrupted session keeps using the same data keys indefinitely.

## Authenticated encryption: packet format

The `payload` portion of every message (handshake or data) is sealed
with ChaCha20-Poly1305 (the IETF variant: 96-bit nonce, 128-bit tag) via
`crypto_seal` / `crypto_open`:

```
+------------------+-----------------------------+----------------+
| counter (8 bytes)| ChaCha20-Poly1305 ciphertext | tag (16 bytes) |
+------------------+-----------------------------+----------------+
```

The 8-byte counter doubles as the low 8 bytes of the 12-byte AEAD nonce
(the high 4 bytes are always zero) -- the same scheme WireGuard uses. A
counter must never repeat under the same key. The data channel and the
handshake channel each maintain their own counter, under their own keys
(`tx_counter` / `handshake_counter` respectively -- see "Handshake
counters" above for why the latter starts from the wall clock rather than
0).

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
`crypto_open` succeeds, the freshness check compares the packet's counter
against what's already been accepted and drops the packet if it isn't
fresh. Authenticate first, then check freshness -- checking freshness
first would mean trusting an attacker-controlled field before it's been
verified. Both `session_open_data` (data, sliding window) and
`session_handle_init` (handshake, strict-monotonic) follow this order.

### Sliding-window replay protection (data channel)

`session_open_data` accepts a counter within the last
`SESSION_REPLAY_WINDOW_BITS` (1024) of the highest one seen, tracked with
a bitmap (`session_t.replay_window`) indexed by `counter %
SESSION_REPLAY_WINDOW_BITS` -- the standard sliding-window anti-replay
algorithm (the same idea IPsec and WireGuard use, though ForgeVPN's
window size is its own choice, not matched to either):

* A counter **ahead of** the current highest slides the window forward,
  clearing the bits for any slots that just entered it (so they don't
  hold stale "seen" markers from counters last used a full window's
  width ago) before marking the new counter seen.
* A counter **within** the window that hasn't been marked yet is
  accepted and marked (this is what allows ordinary UDP reordering
  through: packets 0, 2, 1 all arrive fine, in that order).
* A counter that's **already marked**, or **older than the window**, is
  rejected.

This replaced an earlier, simpler strict-monotonic check (reject anything
not greater than the last counter accepted) that technically prevented
replays but also rejected any legitimately reordered packet -- a real
robustness gap under ordinary UDP delivery. The handshake channel still
uses the simpler strict-monotonic rule (see "Handshake counters" above);
a sliding window isn't needed there since handshake messages are rare,
low-frequency events where receiving one out of order isn't a realistic
concern the way it is for a steady stream of data packets.

## Testing

`tests/crypto_test.c` checks the primitive-level properties: initiator
and responder derive matching session keys without exchanging private
keys; different peer pairs get different keys; base64 round-trips and
rejects malformed input; `crypto_derive_public_key` is consistent with
`crypto_generate_keypair`; seal/open round-trips, recovers the original
counter, and rejects tampering or the wrong key.

`tests/session_test.c` checks the protocol-level properties:

* **Forward-secret keys match and differ from the static keys**: after a
  full handshake, initiator `tx` equals responder `rx` and vice versa
  (as with the raw primitive), *and* those data keys are different from
  the static keys used to protect the handshake itself.
* **Data round-trips in both directions** once established.
* **Out-of-order data is accepted once each**, and **a repeat within the
  window is still rejected** -- the sliding window's core property.
* **A packet that falls outside the window is rejected**, even though it
  was never literally seen twice -- it just aged out.
* **A tampered handshake init is rejected**, and doesn't establish the
  responder's session.
* **A replayed (exact byte-for-byte repeat) handshake init is rejected.**
* **Reconnection succeeds with fresh keys**: after an established
  session, the initiator restarts its handshake
  (`session_start_handshake`) against a responder that never reset, and
  the resulting data keys differ from the first handshake's -- proving a
  genuinely fresh ephemeral exchange happened, not a silent reuse.
* **A stale handshake response (from an abandoned earlier attempt) is
  rejected**, while the current attempt's response still succeeds.

`tests/config_test.c` covers the corresponding config-parsing
requirements: a `[Peer]` section demands `PrivateKey` (on `[Interface]`),
`PublicKey`, and `Role`, each independently, and malformed key text is
rejected.
