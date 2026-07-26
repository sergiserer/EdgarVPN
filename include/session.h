#ifndef EDGARVPN_SESSION_H
#define EDGARVPN_SESSION_H

#include "crypto.h"

#include <stdint.h>
#include <sys/types.h>

/*
 * Handshake and data-channel state machine. See docs/CRYPTOGRAPHY.md for
 * the full protocol description; summary:
 *
 * At session_init(), both peers derive "static" session keys from their
 * long-term (config-file) key pairs -- these protect the handshake
 * messages only, using their own monotonically increasing counter
 * namespace (handshake_counter / highest_handshake_counter_seen),
 * separate from the data channel's. Each side also generates a fresh
 * ephemeral key pair. The initiator sends its ephemeral public key
 * (session_build_init); the responder replies with its own
 * (session_handle_init); the initiator consumes that reply
 * (session_handle_response). Both sides now hold matching "data" session
 * keys derived from the ephemeral exchange -- forward-secret, because
 * the ephemeral private keys are wiped immediately after use and never
 * transmitted. session_seal_data / session_open_data use those keys
 * (and enforce a sliding-window replay check) once the session is
 * SESSION_STATE_ESTABLISHED.
 *
 * Reconnection: a HANDSHAKE_INIT with a fresher counter than any seen
 * before is accepted even if this session is already ESTABLISHED --
 * that's the signal the peer restarted and lost its old session.
 * session_handle_init generates a *fresh* ephemeral key pair before
 * reprocessing in that case, so forward secrecy holds across
 * reconnections too. session_start_handshake lets the initiator side
 * proactively restart a handshake (e.g. after a receive timeout detected
 * by the caller -- this module has no clock of its own).
 */

typedef enum {
    SESSION_STATE_HANDSHAKE_PENDING,
    SESSION_STATE_ESTABLISHED,
} session_state_t;

/* Message type byte prepended, in cleartext, to every UDP datagram this
 * module produces -- the receiver needs it to know which key applies
 * before it can decrypt anything. There is no separate keepalive type:
 * a DATA message with a zero-length payload serves as one (see
 * docs/CRYPTOGRAPHY.md). */
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

/* Width of the sliding replay window: a data-channel counter within this
 * many of the highest one accepted can arrive out of order and still be
 * accepted (once), matching ordinary UDP reordering; anything older, or
 * a repeat of one already seen, is rejected. */
#define SESSION_REPLAY_WINDOW_BITS 1024u
#define SESSION_REPLAY_WINDOW_BYTES (SESSION_REPLAY_WINDOW_BITS / 8)

typedef struct {
    crypto_role_t role;
    session_state_t state;

    crypto_session_keys_t static_keys; /* protects handshake messages only */
    crypto_public_key_t local_eph_pk;
    crypto_secret_key_t local_eph_sk;

    /* Handshake-message counters: separate namespace from the data
     * channel's, so a stale/replayed handshake message can't be
     * mistaken for a legitimate (re)connection attempt. */
    uint64_t handshake_counter;             /* counter to use for our next INIT */
    uint64_t pending_handshake_counter;      /* counter used by our outstanding INIT */
    int have_seen_handshake;                 /* responder: seen at least one INIT */
    uint64_t highest_handshake_counter_seen; /* responder: highest INIT counter accepted */

    crypto_session_keys_t data_keys;   /* forward-secret; valid once ESTABLISHED */
    uint64_t tx_counter;
    uint64_t highest_rx_counter;
    int have_received_any;
    unsigned char replay_window[SESSION_REPLAY_WINDOW_BYTES];
} session_t;

/*
 * Initializes a session: derives the static (handshake-only) session
 * keys via ECDH between the local key pair and `peer_pk`, seeds
 * handshake_counter from the wall clock (see session.c for why -- it's
 * what makes a full process restart look "fresher," not staler, to a
 * peer that's still running and remembers our old counter), and calls
 * session_start_handshake() to generate this attempt's ephemeral key
 * pair and put the session in SESSION_STATE_HANDSHAKE_PENDING.
 * Returns 0 on success, -1 on failure (e.g. an invalid peer public key).
 */
int session_init(session_t *s, crypto_role_t role,
                  const crypto_public_key_t *local_pk, const crypto_secret_key_t *local_sk,
                  const crypto_public_key_t *peer_pk);

/*
 * Generates a fresh ephemeral key pair and resets all per-attempt and
 * data-channel state (tx counter, replay window), moving the session to
 * SESSION_STATE_HANDSHAKE_PENDING. The static keys, role, and
 * handshake_counter are preserved. Called by session_init for the first
 * attempt, and by the caller (see src/main.c) to recover from a
 * timed-out or dead session -- safe to call in any state. After calling
 * this, an initiator should call session_build_init to (re)send a
 * HANDSHAKE_INIT.
 */
void session_start_handshake(session_t *s);

/*
 * Initiator only. Builds a HANDSHAKE_INIT message carrying this
 * session's ephemeral public key, sealed under the static keys with
 * this attempt's handshake counter, into `out` (at least
 * SESSION_HANDSHAKE_MSG_LEN bytes). Requires the session to be in
 * SESSION_STATE_HANDSHAKE_PENDING (i.e. freshly session_init'd or just
 * session_start_handshake'd).
 * Returns the message length, or -1 on failure.
 */
ssize_t session_build_init(session_t *s, unsigned char *out, size_t out_len);

/*
 * Responder only. Processes an inbound HANDSHAKE_INIT `in`: opens it
 * with the static keys to recover the initiator's ephemeral public key
 * and handshake counter, rejects it if that counter isn't strictly
 * greater than the last one accepted (stale or replayed init). If the
 * session was already SESSION_STATE_ESTABLISHED, this is a reconnection
 * attempt: a fresh ephemeral key pair is generated (via
 * session_start_handshake) before reprocessing, so forward secrecy holds
 * across the reconnection too. Derives the forward-secret data keys,
 * wipes this session's ephemeral secret key, and writes a
 * HANDSHAKE_RESPONSE echoing the same counter to `out` (at least
 * SESSION_HANDSHAKE_MSG_LEN bytes). Transitions to
 * SESSION_STATE_ESTABLISHED on success.
 * Returns the response length, or -1 on failure (malformed/
 * unauthenticated/stale input, or wrong role).
 */
ssize_t session_handle_init(session_t *s, const unsigned char *in, size_t in_len,
                             unsigned char *out, size_t out_len);

/*
 * Initiator only. Processes an inbound HANDSHAKE_RESPONSE `in`: opens it
 * with the static keys and checks its counter matches the outstanding
 * INIT's (session_build_init's pending_handshake_counter) -- rejecting a
 * stale response left over from an earlier attempt. Derives the
 * forward-secret data keys and wipes this session's ephemeral secret
 * key. Transitions to SESSION_STATE_ESTABLISHED on success.
 * Returns 0 on success, -1 on failure (malformed/unauthenticated/stale
 * input, wrong role, or a session not currently awaiting a response).
 */
int session_handle_response(session_t *s, const unsigned char *in, size_t in_len);

/*
 * Seals `plaintext_len` bytes of `plaintext` as a DATA message, using
 * the data keys and this session's next tx counter. `plaintext_len` may
 * be 0 -- an empty DATA message serves as a keepalive. Writes the
 * framed, encrypted message to `out` (at least
 * plaintext_len + SESSION_DATA_OVERHEAD bytes).
 * Returns the message length, or -1 on failure (including if the
 * session isn't SESSION_STATE_ESTABLISHED yet).
 */
ssize_t session_seal_data(session_t *s, const unsigned char *plaintext, size_t plaintext_len,
                           unsigned char *out, size_t out_len);

/*
 * Opens an inbound DATA message `in`: authenticates and decrypts with
 * the data keys, then enforces a sliding-window replay check over the
 * last SESSION_REPLAY_WINDOW_BITS counters (accepts reordered delivery
 * within the window, once per counter; rejects anything older than the
 * window or already seen). Writes plaintext to `out` and updates the
 * session's replay state only if both checks pass. A successfully
 * opened zero-length result (a keepalive) is a valid, meaningful
 * outcome -- callers should treat opened_len == 0 as proof of life, not
 * an error.
 * Returns the plaintext length (which may be 0), or -1 if the session
 * isn't established, authentication fails, or the packet is a replay.
 */
ssize_t session_open_data(session_t *s, const unsigned char *in, size_t in_len,
                           unsigned char *out, size_t out_len);

#endif /* EDGARVPN_SESSION_H */
