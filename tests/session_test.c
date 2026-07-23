/*
 * Unit tests for the handshake/session module. Runs a full handshake
 * between two in-process session_t instances (an initiator and a
 * responder with cross-configured static key pairs) and checks the
 * properties that matter: both sides end up with matching, forward-secret
 * data keys distinct from their static keys; data round-trips in both
 * directions; replays are rejected; tampering and re-handshaking are
 * rejected.
 */

#include "session.h"

#include <stdio.h>
#include <string.h>

/* Runs a full, successful handshake between `initiator` and `responder`.
 * Aborts the test (returns 1) on any unexpected failure. */
static int run_handshake(session_t *initiator, session_t *responder)
{
    unsigned char init_msg[SESSION_HANDSHAKE_MSG_LEN];
    ssize_t init_len = session_build_init(initiator, init_msg, sizeof(init_msg));
    if (init_len != SESSION_HANDSHAKE_MSG_LEN) {
        fprintf(stderr, "run_handshake: session_build_init failed\n");
        return 1;
    }

    unsigned char response_msg[SESSION_HANDSHAKE_MSG_LEN];
    ssize_t response_len = session_handle_init(responder, init_msg, (size_t)init_len,
                                                response_msg, sizeof(response_msg));
    if (response_len != SESSION_HANDSHAKE_MSG_LEN) {
        fprintf(stderr, "run_handshake: session_handle_init failed\n");
        return 1;
    }

    if (session_handle_response(initiator, response_msg, (size_t)response_len) != 0) {
        fprintf(stderr, "run_handshake: session_handle_response failed\n");
        return 1;
    }

    if (initiator->state != SESSION_STATE_ESTABLISHED ||
        responder->state != SESSION_STATE_ESTABLISHED) {
        fprintf(stderr, "run_handshake: sessions did not reach ESTABLISHED\n");
        return 1;
    }

    return 0;
}

static void make_pair(crypto_public_key_t *initiator_pk, crypto_secret_key_t *initiator_sk,
                       crypto_public_key_t *responder_pk, crypto_secret_key_t *responder_sk,
                       session_t *initiator, session_t *responder)
{
    crypto_generate_keypair(initiator_pk, initiator_sk);
    crypto_generate_keypair(responder_pk, responder_sk);
    session_init(initiator, CRYPTO_ROLE_INITIATOR, initiator_pk, initiator_sk, responder_pk);
    session_init(responder, CRYPTO_ROLE_RESPONDER, responder_pk, responder_sk, initiator_pk);
}

static int test_handshake_derives_matching_forward_secret_keys(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);

    if (run_handshake(&initiator, &responder) != 0) {
        return 1;
    }

    if (memcmp(initiator.data_keys.tx, responder.data_keys.rx, CRYPTO_SESSION_KEY_BYTES) != 0 ||
        memcmp(initiator.data_keys.rx, responder.data_keys.tx, CRYPTO_SESSION_KEY_BYTES) != 0) {
        fprintf(stderr,
                "test_handshake_derives_matching_forward_secret_keys: data keys don't line up\n");
        return 1;
    }

    if (memcmp(initiator.data_keys.tx, initiator.static_keys.tx, CRYPTO_SESSION_KEY_BYTES) == 0) {
        fprintf(stderr, "test_handshake_derives_matching_forward_secret_keys: "
                         "data key equals static key -- ephemeral step had no effect\n");
        return 1;
    }

    printf("test_handshake_derives_matching_forward_secret_keys: passed\n");
    return 0;
}

static int test_data_round_trips_both_directions(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);
    if (run_handshake(&initiator, &responder) != 0) {
        return 1;
    }

    const unsigned char msg1[] = "hello from the initiator";
    unsigned char sealed1[sizeof(msg1) + SESSION_DATA_OVERHEAD];
    ssize_t sealed1_len = session_seal_data(&initiator, msg1, sizeof(msg1),
                                             sealed1, sizeof(sealed1));
    unsigned char opened1[sizeof(msg1)];
    ssize_t opened1_len = session_open_data(&responder, sealed1, (size_t)sealed1_len,
                                             opened1, sizeof(opened1));
    if (opened1_len != (ssize_t)sizeof(msg1) || memcmp(msg1, opened1, sizeof(msg1)) != 0) {
        fprintf(stderr, "test_data_round_trips_both_directions: initiator->responder failed\n");
        return 1;
    }

    const unsigned char msg2[] = "hello back from the responder";
    unsigned char sealed2[sizeof(msg2) + SESSION_DATA_OVERHEAD];
    ssize_t sealed2_len = session_seal_data(&responder, msg2, sizeof(msg2),
                                             sealed2, sizeof(sealed2));
    unsigned char opened2[sizeof(msg2)];
    ssize_t opened2_len = session_open_data(&initiator, sealed2, (size_t)sealed2_len,
                                             opened2, sizeof(opened2));
    if (opened2_len != (ssize_t)sizeof(msg2) || memcmp(msg2, opened2, sizeof(msg2)) != 0) {
        fprintf(stderr, "test_data_round_trips_both_directions: responder->initiator failed\n");
        return 1;
    }

    printf("test_data_round_trips_both_directions: passed\n");
    return 0;
}

static int test_replayed_data_rejected(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);
    if (run_handshake(&initiator, &responder) != 0) {
        return 1;
    }

    const unsigned char msg[] = "only once";
    unsigned char sealed[sizeof(msg) + SESSION_DATA_OVERHEAD];
    ssize_t sealed_len = session_seal_data(&initiator, msg, sizeof(msg), sealed, sizeof(sealed));

    unsigned char opened[sizeof(msg)];
    if (session_open_data(&responder, sealed, (size_t)sealed_len, opened, sizeof(opened)) < 0) {
        fprintf(stderr, "test_replayed_data_rejected: first delivery unexpectedly failed\n");
        return 1;
    }
    if (session_open_data(&responder, sealed, (size_t)sealed_len, opened, sizeof(opened)) >= 0) {
        fprintf(stderr, "test_replayed_data_rejected: replay was accepted\n");
        return 1;
    }

    printf("test_replayed_data_rejected: passed\n");
    return 0;
}

static int test_tampered_handshake_init_rejected(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);

    unsigned char init_msg[SESSION_HANDSHAKE_MSG_LEN];
    session_build_init(&initiator, init_msg, sizeof(init_msg));
    init_msg[1 + CRYPTO_COUNTER_BYTES] ^= 0x01; /* flip a ciphertext bit */

    unsigned char response_msg[SESSION_HANDSHAKE_MSG_LEN];
    if (session_handle_init(&responder, init_msg, sizeof(init_msg),
                             response_msg, sizeof(response_msg)) >= 0) {
        fprintf(stderr, "test_tampered_handshake_init_rejected: tampered init was accepted\n");
        return 1;
    }
    if (responder.state == SESSION_STATE_ESTABLISHED) {
        fprintf(stderr,
                "test_tampered_handshake_init_rejected: responder session was established anyway\n");
        return 1;
    }

    printf("test_tampered_handshake_init_rejected: passed\n");
    return 0;
}

static int test_duplicate_init_after_established_rejected(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);
    if (run_handshake(&initiator, &responder) != 0) {
        return 1;
    }

    /* A second, otherwise-valid INIT arrives after the responder is
     * already established (e.g. a duplicate/late UDP datagram). It must
     * be rejected, not reprocessed -- reprocessing would reuse an
     * already-consumed ephemeral key pair and silently break forward
     * secrecy for this session. */
    session_t fresh_initiator;
    session_init(&fresh_initiator, CRYPTO_ROLE_INITIATOR, &initiator_pk, &initiator_sk,
                 &responder_pk);
    unsigned char init_msg[SESSION_HANDSHAKE_MSG_LEN];
    session_build_init(&fresh_initiator, init_msg, sizeof(init_msg));

    unsigned char response_msg[SESSION_HANDSHAKE_MSG_LEN];
    if (session_handle_init(&responder, init_msg, sizeof(init_msg),
                             response_msg, sizeof(response_msg)) >= 0) {
        fprintf(stderr,
                "test_duplicate_init_after_established_rejected: duplicate init was accepted\n");
        return 1;
    }

    printf("test_duplicate_init_after_established_rejected: passed\n");
    return 0;
}

int main(void)
{
    if (crypto_init() != 0) {
        fprintf(stderr, "crypto_init failed\n");
        return 1;
    }

    int failures = 0;
    failures += test_handshake_derives_matching_forward_secret_keys();
    failures += test_data_round_trips_both_directions();
    failures += test_replayed_data_rejected();
    failures += test_tampered_handshake_init_rejected();
    failures += test_duplicate_init_after_established_rejected();
    return failures == 0 ? 0 : 1;
}
