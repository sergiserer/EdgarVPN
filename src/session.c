#include "session.h"

#include <string.h>
#include <time.h>

int session_init(session_t *s, crypto_role_t role,
                  const crypto_public_key_t *local_pk, const crypto_secret_key_t *local_sk,
                  const crypto_public_key_t *peer_pk)
{
    memset(s, 0, sizeof(*s));
    s->role = role;

    if (crypto_derive_session_keys(role, local_pk, local_sk, peer_pk, &s->static_keys) != 0) {
        return -1;
    }
    /* Start from the wall clock, not 0 or a random value: if this
     * process restarts, a peer that's still running remembers our old
     * (now-lost) counter and would reject anything <= it as stale. A
     * random restart value would only be *unlikely* to collide with the
     * old one -- and has roughly even odds of landing *below* it, which
     * is exactly the failure case. Real time only moves forward, so
     * starting from it is (barring two restarts within the same second,
     * or severe clock skew) actually guaranteed to be fresher, not just
     * probably so. */
    s->handshake_counter = (uint64_t)time(NULL);
    session_start_handshake(s);
    return 0;
}

void session_start_handshake(session_t *s)
{
    crypto_generate_keypair(&s->local_eph_pk, &s->local_eph_sk);
    s->state = SESSION_STATE_HANDSHAKE_PENDING;
    s->tx_counter = 0;
    s->have_received_any = 0;
    memset(s->replay_window, 0, sizeof(s->replay_window));
}

ssize_t session_build_init(session_t *s, unsigned char *out, size_t out_len)
{
    if (s->role != CRYPTO_ROLE_INITIATOR || s->state != SESSION_STATE_HANDSHAKE_PENDING) {
        return -1;
    }
    if (out_len < SESSION_HANDSHAKE_MSG_LEN) {
        return -1;
    }

    out[0] = SESSION_MSG_HANDSHAKE_INIT;
    ssize_t sealed = crypto_seal(s->static_keys.tx, s->handshake_counter, s->local_eph_pk.bytes,
                                  sizeof(s->local_eph_pk.bytes), out + 1, out_len - 1);
    if (sealed < 0) {
        return -1;
    }

    s->pending_handshake_counter = s->handshake_counter;
    s->handshake_counter++;
    return 1 + sealed;
}

ssize_t session_handle_init(session_t *s, const unsigned char *in, size_t in_len,
                             unsigned char *out, size_t out_len)
{
    if (s->role != CRYPTO_ROLE_RESPONDER) {
        return -1;
    }
    if (in_len < 1 || in[0] != SESSION_MSG_HANDSHAKE_INIT || out_len < SESSION_HANDSHAKE_MSG_LEN) {
        return -1;
    }

    crypto_public_key_t peer_eph_pk;
    uint64_t counter = 0;
    ssize_t opened = crypto_open(s->static_keys.rx, in + 1, in_len - 1,
                                  peer_eph_pk.bytes, sizeof(peer_eph_pk.bytes), &counter);
    if (opened != (ssize_t)sizeof(peer_eph_pk.bytes)) {
        return -1;
    }

    if (s->have_seen_handshake && counter <= s->highest_handshake_counter_seen) {
        return -1; /* stale or replayed init */
    }

    if (s->state == SESSION_STATE_ESTABLISHED) {
        /* The peer is (re)connecting -- e.g. it restarted and lost its
         * previous session. Generate a fresh ephemeral key pair before
         * reprocessing: reusing the old one would silently break forward
         * secrecy for the new session. */
        session_start_handshake(s);
    }

    if (crypto_derive_session_keys(s->role, &s->local_eph_pk, &s->local_eph_sk,
                                    &peer_eph_pk, &s->data_keys) != 0) {
        return -1;
    }
    crypto_wipe(s->local_eph_sk.bytes, sizeof(s->local_eph_sk.bytes));

    out[0] = SESSION_MSG_HANDSHAKE_RESPONSE;
    ssize_t sealed = crypto_seal(s->static_keys.tx, counter, s->local_eph_pk.bytes,
                                  sizeof(s->local_eph_pk.bytes), out + 1, out_len - 1);
    if (sealed < 0) {
        return -1;
    }

    s->have_seen_handshake = 1;
    s->highest_handshake_counter_seen = counter;
    s->state = SESSION_STATE_ESTABLISHED;
    return 1 + sealed;
}

int session_handle_response(session_t *s, const unsigned char *in, size_t in_len)
{
    if (s->role != CRYPTO_ROLE_INITIATOR || s->state != SESSION_STATE_HANDSHAKE_PENDING) {
        return -1;
    }
    if (in_len < 1 || in[0] != SESSION_MSG_HANDSHAKE_RESPONSE) {
        return -1;
    }

    crypto_public_key_t peer_eph_pk;
    uint64_t counter = 0;
    ssize_t opened = crypto_open(s->static_keys.rx, in + 1, in_len - 1,
                                  peer_eph_pk.bytes, sizeof(peer_eph_pk.bytes), &counter);
    if (opened != (ssize_t)sizeof(peer_eph_pk.bytes)) {
        return -1;
    }
    if (counter != s->pending_handshake_counter) {
        return -1; /* stale response from an earlier attempt */
    }

    if (crypto_derive_session_keys(s->role, &s->local_eph_pk, &s->local_eph_sk,
                                    &peer_eph_pk, &s->data_keys) != 0) {
        return -1;
    }
    crypto_wipe(s->local_eph_sk.bytes, sizeof(s->local_eph_sk.bytes));

    s->state = SESSION_STATE_ESTABLISHED;
    return 0;
}

ssize_t session_seal_data(session_t *s, const unsigned char *plaintext, size_t plaintext_len,
                           unsigned char *out, size_t out_len)
{
    if (s->state != SESSION_STATE_ESTABLISHED) {
        return -1;
    }
    if (out_len < plaintext_len + SESSION_DATA_OVERHEAD) {
        return -1;
    }

    out[0] = SESSION_MSG_DATA;
    ssize_t sealed = crypto_seal(s->data_keys.tx, s->tx_counter, plaintext, plaintext_len,
                                  out + 1, out_len - 1);
    if (sealed < 0) {
        return -1;
    }
    s->tx_counter++;
    return 1 + sealed;
}

static int replay_bit_get(const unsigned char *window, uint64_t counter)
{
    uint64_t slot = counter % SESSION_REPLAY_WINDOW_BITS;
    return (window[slot / 8] >> (slot % 8)) & 1;
}

static void replay_bit_set(unsigned char *window, uint64_t counter)
{
    uint64_t slot = counter % SESSION_REPLAY_WINDOW_BITS;
    window[slot / 8] = (unsigned char)(window[slot / 8] | (1u << (slot % 8)));
}

static void replay_bit_clear(unsigned char *window, uint64_t counter)
{
    uint64_t slot = counter % SESSION_REPLAY_WINDOW_BITS;
    window[slot / 8] = (unsigned char)(window[slot / 8] & ~(1u << (slot % 8)));
}

/* Sliding-window freshness check: returns 1 and marks `counter` seen if
 * it's acceptable (the first packet ever, ahead of the window, or an
 * unseen slot within it); returns 0 (and leaves state unchanged) if it
 * must be rejected as too old or already seen. */
static int replay_check_and_mark(session_t *s, uint64_t counter)
{
    if (!s->have_received_any) {
        replay_bit_set(s->replay_window, counter);
        s->highest_rx_counter = counter;
        s->have_received_any = 1;
        return 1;
    }

    if (counter > s->highest_rx_counter) {
        uint64_t advance = counter - s->highest_rx_counter;
        if (advance >= SESSION_REPLAY_WINDOW_BITS) {
            memset(s->replay_window, 0, sizeof(s->replay_window));
        } else {
            for (uint64_t c = s->highest_rx_counter + 1; c < counter; c++) {
                replay_bit_clear(s->replay_window, c);
            }
        }
        replay_bit_set(s->replay_window, counter);
        s->highest_rx_counter = counter;
        return 1;
    }

    uint64_t age = s->highest_rx_counter - counter;
    if (age >= SESSION_REPLAY_WINDOW_BITS) {
        return 0;
    }
    if (replay_bit_get(s->replay_window, counter)) {
        return 0;
    }
    replay_bit_set(s->replay_window, counter);
    return 1;
}

ssize_t session_open_data(session_t *s, const unsigned char *in, size_t in_len,
                           unsigned char *out, size_t out_len)
{
    if (s->state != SESSION_STATE_ESTABLISHED) {
        return -1;
    }
    if (in_len < 1 || in[0] != SESSION_MSG_DATA) {
        return -1;
    }

    uint64_t counter = 0;
    ssize_t opened = crypto_open(s->data_keys.rx, in + 1, in_len - 1, out, out_len, &counter);
    if (opened < 0) {
        return -1;
    }

    if (!replay_check_and_mark(s, counter)) {
        return -1;
    }
    return opened;
}
