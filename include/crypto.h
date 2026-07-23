#ifndef FORGEVPN_CRYPTO_H
#define FORGEVPN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CRYPTO_PUBLIC_KEY_BYTES 32
#define CRYPTO_SECRET_KEY_BYTES 32
#define CRYPTO_SESSION_KEY_BYTES 32

/* On-the-wire packet layout produced by crypto_seal / consumed by
 * crypto_open: an 8-byte little-endian counter (doubles as the low 8
 * bytes of the AEAD nonce, high 4 bytes zero -- the same scheme
 * WireGuard uses), followed by ChaCha20-Poly1305-IETF ciphertext with a
 * 16-byte authentication tag appended. */
#define CRYPTO_COUNTER_BYTES 8
#define CRYPTO_TAG_BYTES 16
#define CRYPTO_PACKET_OVERHEAD (CRYPTO_COUNTER_BYTES + CRYPTO_TAG_BYTES)

/* Buffer size (including the NUL terminator) needed to base64-encode a
 * 32-byte key: ceil(32/3)*4 = 44 chars, padded, + 1. */
#define CRYPTO_KEY_TEXT_LEN 45

typedef struct {
    unsigned char bytes[CRYPTO_PUBLIC_KEY_BYTES];
} crypto_public_key_t;

typedef struct {
    unsigned char bytes[CRYPTO_SECRET_KEY_BYTES];
} crypto_secret_key_t;

/* Two independent keys derived from one X25519 exchange: `rx` decrypts
 * traffic received from the peer, `tx` encrypts traffic sent to it. */
typedef struct {
    unsigned char rx[CRYPTO_SESSION_KEY_BYTES];
    unsigned char tx[CRYPTO_SESSION_KEY_BYTES];
} crypto_session_keys_t;

/*
 * Which side of the key exchange a peer is playing. Both peers must
 * agree out of band (today: a config key -- see docs/CRYPTOGRAPHY.md)
 * on exactly one initiator and one responder, or their rx/tx keys will
 * not line up with each other.
 */
typedef enum {
    CRYPTO_ROLE_INITIATOR,
    CRYPTO_ROLE_RESPONDER,
} crypto_role_t;

/*
 * Initializes the underlying crypto library. Must be called once, before
 * any other crypto_* function. Returns 0 on success, -1 on failure.
 */
int crypto_init(void);

/* Generates a new X25519 key pair. */
void crypto_generate_keypair(crypto_public_key_t *pk, crypto_secret_key_t *sk);

/* Derives the public key matching a given secret key (X25519 base-point
 * multiplication). Used so a peer's own public key is always computed
 * from its configured private key rather than trusted as a separate,
 * possibly-stale configured value. */
void crypto_derive_public_key(const crypto_secret_key_t *sk, crypto_public_key_t *pk);

/*
 * Performs an X25519 key exchange between the local key pair and a
 * remote public key, and derives `out`'s rx/tx session keys from it.
 * Returns 0 on success, -1 on failure (e.g. a degenerate remote public
 * key that fails libsodium's weak-key check).
 */
int crypto_derive_session_keys(crypto_role_t role,
                                const crypto_public_key_t *local_pk,
                                const crypto_secret_key_t *local_sk,
                                const crypto_public_key_t *remote_pk,
                                crypto_session_keys_t *out);

/*
 * Encodes `len` bytes of `data` as unpadded-safe base64 into `out`
 * (buffer of at least `out_len` bytes, e.g. CRYPTO_KEY_TEXT_LEN for a
 * 32-byte key). Always NUL-terminates `out`.
 */
void crypto_encode_base64(const unsigned char *data, size_t len, char *out, size_t out_len);

/*
 * Decodes `text` into exactly `expected_len` bytes at `out`.
 * Returns 0 on success, -1 if `text` is malformed or decodes to a
 * different length than expected.
 */
int crypto_decode_base64(const char *text, unsigned char *out, size_t expected_len);

/*
 * Encrypts and authenticates `plaintext_len` bytes from `plaintext` with
 * `key`, using `counter` as the nonce (see the wire layout comment
 * above). The caller must never reuse a counter value with the same
 * key -- a monotonically increasing per-session counter, as used by
 * src/main.c, guarantees this.
 *
 * Writes counter||ciphertext||tag to `out` (must be at least
 * plaintext_len + CRYPTO_PACKET_OVERHEAD bytes).
 * Returns the number of bytes written, or -1 on failure.
 */
ssize_t crypto_seal(const unsigned char key[CRYPTO_SESSION_KEY_BYTES], uint64_t counter,
                     const unsigned char *plaintext, size_t plaintext_len,
                     unsigned char *out, size_t out_len);

/*
 * Verifies and decrypts a packet produced by crypto_seal. Reads the
 * counter from the first CRYPTO_COUNTER_BYTES of `in`, then decrypts and
 * authenticates the rest with `key`.
 *
 * On success, writes the plaintext to `out` (must be at least
 * in_len - CRYPTO_PACKET_OVERHEAD bytes), writes the packet's counter to
 * `*counter_out`, and returns the plaintext length. `*counter_out` is
 * only meaningful on success -- callers must authenticate before trusting
 * the counter for replay protection (an attacker can put anything in
 * those 8 bytes; tampering with them changes the nonce and makes
 * authentication fail, but a byte-for-byte replay of a previously valid
 * packet will authenticate successfully, which is exactly what a
 * counter-freshness check after this call is for).
 *
 * Returns -1 on failure: truncated input, or authentication failure.
 */
ssize_t crypto_open(const unsigned char key[CRYPTO_SESSION_KEY_BYTES],
                     const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t out_len,
                     uint64_t *counter_out);

/*
 * Overwrites `len` bytes at `buf` with zeroes, in a way the compiler
 * won't optimize away (unlike a plain memset, which is legal for a
 * compiler to elide if it can prove `buf` is never read again). Use to
 * erase ephemeral secret key material as soon as it's no longer needed
 * -- see src/session.c, which wipes each ephemeral secret key right
 * after the handshake step that consumes it.
 */
void crypto_wipe(void *buf, size_t len);

#endif /* FORGEVPN_CRYPTO_H */
