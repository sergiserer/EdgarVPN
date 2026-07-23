#ifndef FORGEVPN_SESSION_H
#define FORGEVPN_SESSION_H

#include "crypto.h"

#include <stdint.h>
#include <sys/types.h>

/*
 * Handshake and data-channel state machine. See docs/CRYPTOGRAPHY.md for
 * the full protocol description; summary:
 *
 * At session_init(), both peers derive "static" session keys from their
 * long-term (config-file) key pairs -- these protect the handshake
 * messages only. Each side also generates a fresh ephemeral key pair.
 * The initiator sends its ephemeral public key (session_build_init); the
 * responder replies with its own (session_handle_init); the initiator
 * consumes that reply (session_handle_response). Both sides now hold
 * matching "data" session keys derived from the ephemeral exchange --
 * forward-secret, because the ephemeral private keys are wiped
 * immediately after use and never transmitted. session_seal_data /
 * session_open_data use those keys (and enforce replay protection) once
 * the session is SESSION_STATE_ESTABLISHED.
 *
 * This module supports exactly one handshake per session_t: there is no
 * re-handshake/reconnection logic yet (planned for a future milestone),
 * and a session that reaches SESSION_STATE_ESTABLISHED rejects any
 * further handshake messages rather than reprocessing them -- reusing an
 * already-consumed ephemeral key pair for a second handshake would
 * silently defeat forward secrecy for whichever session did so.
 */

typedef enum {
    SESSION_STATE_HANDSHAKE_PENDING,
    SESSION_STATE_ESTABLISHED,
} session_state_t;

/* Message type byte prepended, in cleartext, to every UDP datagram this
 * module produces -- the receiver needs it to know which key applies
 * before it can decrypt anything. */
typedef enum {
    SESSION_MSG_HANDSHAKE_INIT = 1,
    SESSION_MSG_HANDSHAKE_RESPONSE = 2,
    SESSION_MSG_DATA = 3,
} session_msg_type_t;

/* Exact length of a handshake message: 1-byte type + a sealed 32-byte
 * ephemeral public key. */
#define SESSION_HANDSHAKE_MSG_LEN (1 + CRYPTO_PACKET_OVERHEAD + CRYPTO_PUBLIC_KEY_BYTES)

/* Bytes of framing overhead session_seal_data adds around the plaintext:
 * 1-byte type + crypto_seal's own counter/tag overhead. */
#define SESSION_DATA_OVERHEAD (1 + CRYPTO_PACKET_OVERHEAD)

typedef struct {
    crypto_role_t role;
    session_state_t state;

    crypto_session_keys_t static_keys; /* protects handshake messages only */
    crypto_public_key_t local_eph_pk;
    crypto_secret_key_t local_eph_sk;

    crypto_session_keys_t data_keys;   /* forward-secret; valid once ESTABLISHED */
    uint64_t tx_counter;
    uint64_t highest_rx_counter;
    int have_received_any;
} session_t;

/*
 * Initializes a session: derives the static (handshake-only) session
 * keys via ECDH between the local key pair and `peer_pk`, and generates
 * a fresh ephemeral key pair for this handshake attempt.
 * Returns 0 on success, -1 on failure (e.g. an invalid peer public key).
 */
int session_init(session_t *s, crypto_role_t role,
                  const crypto_public_key_t *local_pk, const crypto_secret_key_t *local_sk,
                  const crypto_public_key_t *peer_pk);

/*
 * Initiator only. Builds a HANDSHAKE_INIT message carrying this
 * session's ephemeral public key, sealed under the static keys, into
 * `out` (at least SESSION_HANDSHAKE_MSG_LEN bytes).
 * Returns the message length, or -1 on failure.
 */
ssize_t session_build_init(session_t *s, unsigned char *out, size_t out_len);

/*
 * Responder only. Processes an inbound HANDSHAKE_INIT `in`: opens it
 * with the static keys to recover the initiator's ephemeral public key,
 * derives the forward-secret data keys, wipes this session's own
 * ephemeral secret key (no longer needed), and writes a HANDSHAKE_RESPONSE
 * carrying this session's ephemeral public key to `out` (at least
 * SESSION_HANDSHAKE_MSG_LEN bytes). Transitions to SESSION_STATE_ESTABLISHED
 * on success.
 * Returns the response length, or -1 on failure (malformed/unauthenticated
 * input, wrong role, or a session that is already established).
 */
ssize_t session_handle_init(session_t *s, const unsigned char *in, size_t in_len,
                             unsigned char *out, size_t out_len);

/*
 * Initiator only. Processes an inbound HANDSHAKE_RESPONSE `in`: opens it
 * with the static keys to recover the responder's ephemeral public key,
 * derives the forward-secret data keys, and wipes this session's own
 * ephemeral secret key. Transitions to SESSION_STATE_ESTABLISHED on
 * success.
 * Returns 0 on success, -1 on failure (malformed/unauthenticated input,
 * wrong role, or a session not currently awaiting a response).
 */
int session_handle_response(session_t *s, const unsigned char *in, size_t in_len);

/*
 * Seals `plaintext_len` bytes of `plaintext` as a DATA message, using
 * the data keys and this session's next tx counter. Writes the framed,
 * encrypted message to `out` (at least
 * plaintext_len + SESSION_DATA_OVERHEAD bytes).
 * Returns the message length, or -1 on failure (including if the
 * session isn't SESSION_STATE_ESTABLISHED yet).
 */
ssize_t session_seal_data(session_t *s, const unsigned char *plaintext, size_t plaintext_len,
                           unsigned char *out, size_t out_len);

/*
 * Opens an inbound DATA message `in`: authenticates and decrypts with
 * the data keys, then enforces a strict-monotonic replay check (the
 * packet's counter must exceed every counter accepted so far). Writes
 * plaintext to `out` and updates the session's replay state only if
 * both checks pass.
 * Returns the plaintext length, or -1 if the session isn't established,
 * authentication fails, or the packet is a replay/out-of-order.
 */
ssize_t session_open_data(session_t *s, const unsigned char *in, size_t in_len,
                           unsigned char *out, size_t out_len);

#endif /* FORGEVPN_SESSION_H */
