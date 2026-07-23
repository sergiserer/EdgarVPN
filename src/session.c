#include "session.h"

#include <string.h>

int session_init(session_t *s, crypto_role_t role,
                  const crypto_public_key_t *local_pk, const crypto_secret_key_t *local_sk,
                  const crypto_public_key_t *peer_pk)
{
    memset(s, 0, sizeof(*s));
    s->role = role;
    s->state = SESSION_STATE_HANDSHAKE_PENDING;

    if (crypto_derive_session_keys(role, local_pk, local_sk, peer_pk, &s->static_keys) != 0) {
        return -1;
    }
    crypto_generate_keypair(&s->local_eph_pk, &s->local_eph_sk);
    return 0;
}

ssize_t session_build_init(session_t *s, unsigned char *out, size_t out_len)
{
    if (s->role != CRYPTO_ROLE_INITIATOR || out_len < SESSION_HANDSHAKE_MSG_LEN) {
        return -1;
    }

    out[0] = SESSION_MSG_HANDSHAKE_INIT;
    ssize_t sealed = crypto_seal(s->static_keys.tx, 0, s->local_eph_pk.bytes,
                                  sizeof(s->local_eph_pk.bytes), out + 1, out_len - 1);
    if (sealed < 0) {
        return -1;
    }
    return 1 + sealed;
}

ssize_t session_handle_init(session_t *s, const unsigned char *in, size_t in_len,
                             unsigned char *out, size_t out_len)
{
    if (s->role != CRYPTO_ROLE_RESPONDER || s->state == SESSION_STATE_ESTABLISHED) {
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

    if (crypto_derive_session_keys(s->role, &s->local_eph_pk, &s->local_eph_sk,
                                    &peer_eph_pk, &s->data_keys) != 0) {
        return -1;
    }
    crypto_wipe(s->local_eph_sk.bytes, sizeof(s->local_eph_sk.bytes));

    out[0] = SESSION_MSG_HANDSHAKE_RESPONSE;
    ssize_t sealed = crypto_seal(s->static_keys.tx, 0, s->local_eph_pk.bytes,
                                  sizeof(s->local_eph_pk.bytes), out + 1, out_len - 1);
    if (sealed < 0) {
        return -1;
    }

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

    if (s->have_received_any && counter <= s->highest_rx_counter) {
        return -1;
    }
    s->have_received_any = 1;
    s->highest_rx_counter = counter;
    return opened;
}
