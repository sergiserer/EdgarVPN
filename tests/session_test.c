/*
 * Unit tests for the handshake/session module. Runs full handshakes
 * between in-process session_t instances (an initiator and a responder
 * with cross-configured static key pairs) and checks the properties
 * that matter: both sides end up with matching, forward-secret data
 * keys distinct from their static keys; data round-trips in both
 * directions, tolerating reordering within the replay window but not
 * repeats or old-enough replays; tampering and stale handshake messages
 * are rejected; and a genuine reconnection (the initiator restarting its
 * handshake) succeeds with a fresh set of forward-secret keys.
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

/* Builds and seals data packet number `i` (0-indexed) from `from`. */
static ssize_t seal_numbered(session_t *from, int i, unsigned char *out, size_t out_len)
{
    unsigned char msg = (unsigned char)i;
    return session_seal_data(from, &msg, 1, out, out_len);
}

static int test_out_of_order_data_accepted_once_each(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);
    if (run_handshake(&initiator, &responder) != 0) {
        return 1;
    }

    unsigned char pkt0[1 + SESSION_DATA_OVERHEAD];
    unsigned char pkt1[1 + SESSION_DATA_OVERHEAD];
    unsigned char pkt2[1 + SESSION_DATA_OVERHEAD];
    ssize_t len0 = seal_numbered(&initiator, 0, pkt0, sizeof(pkt0));
    ssize_t len1 = seal_numbered(&initiator, 1, pkt1, sizeof(pkt1));
    ssize_t len2 = seal_numbered(&initiator, 2, pkt2, sizeof(pkt2));

    unsigned char opened[1];
    /* Deliver out of order: 0, then 2 (skips ahead), then 1 (catches up). */
    if (session_open_data(&responder, pkt0, (size_t)len0, opened, sizeof(opened)) < 0 ||
        session_open_data(&responder, pkt2, (size_t)len2, opened, sizeof(opened)) < 0 ||
        session_open_data(&responder, pkt1, (size_t)len1, opened, sizeof(opened)) < 0) {
        fprintf(stderr,
                "test_out_of_order_data_accepted_once_each: reordered delivery was rejected\n");
        return 1;
    }

    /* Re-delivering an already-seen one (even though it's not the most
     * recent) must still be rejected. */
    if (session_open_data(&responder, pkt1, (size_t)len1, opened, sizeof(opened)) >= 0) {
        fprintf(stderr,
                "test_out_of_order_data_accepted_once_each: repeat of an in-window packet "
                "was accepted\n");
        return 1;
    }

    printf("test_out_of_order_data_accepted_once_each: passed\n");
    return 0;
}

static int test_replay_outside_window_rejected(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);
    if (run_handshake(&initiator, &responder) != 0) {
        return 1;
    }

    unsigned char pkt_first[1 + SESSION_DATA_OVERHEAD];
    ssize_t len_first = seal_numbered(&initiator, 0, pkt_first, sizeof(pkt_first));
    unsigned char opened[1];
    if (session_open_data(&responder, pkt_first, (size_t)len_first, opened, sizeof(opened)) < 0) {
        fprintf(stderr, "test_replay_outside_window_rejected: first delivery failed\n");
        return 1;
    }

    /* Jump the counter far enough ahead (>= the window width) that the
     * first packet's slot falls out of the window entirely. */
    unsigned char filler[1 + SESSION_DATA_OVERHEAD];
    for (unsigned i = 0; i < SESSION_REPLAY_WINDOW_BITS; i++) {
        ssize_t len = seal_numbered(&initiator, 1, filler, sizeof(filler));
        if (session_open_data(&responder, filler, (size_t)len, opened, sizeof(opened)) < 0) {
            fprintf(stderr, "test_replay_outside_window_rejected: filler packet %u rejected\n", i);
            return 1;
        }
    }

    /* The first packet is now too old, even though it was never
     * literally "seen twice" -- it just fell out of the window. */
    if (session_open_data(&responder, pkt_first, (size_t)len_first, opened, sizeof(opened)) >= 0) {
        fprintf(stderr,
                "test_replay_outside_window_rejected: packet outside the window was accepted\n");
        return 1;
    }

    printf("test_replay_outside_window_rejected: passed\n");
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

static int test_stale_handshake_init_replay_rejected(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);

    unsigned char init_msg[SESSION_HANDSHAKE_MSG_LEN];
    ssize_t init_len = session_build_init(&initiator, init_msg, sizeof(init_msg));

    unsigned char response_msg[SESSION_HANDSHAKE_MSG_LEN];
    if (session_handle_init(&responder, init_msg, (size_t)init_len,
                             response_msg, sizeof(response_msg)) < 0) {
        fprintf(stderr, "test_stale_handshake_init_replay_rejected: first init unexpectedly "
                         "failed\n");
        return 1;
    }

    /* Replaying the exact same (already-consumed) init bytes -- same
     * counter -- must be rejected, whether or not the responder is
     * already established. */
    unsigned char second_response[SESSION_HANDSHAKE_MSG_LEN];
    if (session_handle_init(&responder, init_msg, (size_t)init_len,
                             second_response, sizeof(second_response)) >= 0) {
        fprintf(stderr,
                "test_stale_handshake_init_replay_rejected: replayed init was accepted\n");
        return 1;
    }

    printf("test_stale_handshake_init_replay_rejected: passed\n");
    return 0;
}

static int test_reconnection_succeeds_with_fresh_ephemeral_keys(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);
    if (run_handshake(&initiator, &responder) != 0) {
        return 1;
    }

    crypto_session_keys_t first_data_keys = initiator.data_keys;

    /* Simulate the initiator deciding to reconnect (e.g. after a receive
     * timeout) while the responder is still happily ESTABLISHED from the
     * first handshake -- this is exactly what src/main.c does. */
    session_start_handshake(&initiator);
    if (run_handshake(&initiator, &responder) != 0) {
        fprintf(stderr,
                "test_reconnection_succeeds_with_fresh_ephemeral_keys: reconnection failed\n");
        return 1;
    }

    if (memcmp(initiator.data_keys.tx, responder.data_keys.rx, CRYPTO_SESSION_KEY_BYTES) != 0 ||
        memcmp(initiator.data_keys.rx, responder.data_keys.tx, CRYPTO_SESSION_KEY_BYTES) != 0) {
        fprintf(stderr, "test_reconnection_succeeds_with_fresh_ephemeral_keys: "
                         "post-reconnection keys don't line up\n");
        return 1;
    }
    if (memcmp(initiator.data_keys.tx, first_data_keys.tx, CRYPTO_SESSION_KEY_BYTES) == 0) {
        fprintf(stderr, "test_reconnection_succeeds_with_fresh_ephemeral_keys: "
                         "reconnection reused the previous data keys\n");
        return 1;
    }

    const unsigned char msg[] = "post-reconnection traffic";
    unsigned char sealed[sizeof(msg) + SESSION_DATA_OVERHEAD];
    ssize_t sealed_len = session_seal_data(&initiator, msg, sizeof(msg), sealed, sizeof(sealed));
    unsigned char opened[sizeof(msg)];
    ssize_t opened_len = session_open_data(&responder, sealed, (size_t)sealed_len,
                                            opened, sizeof(opened));
    if (opened_len != (ssize_t)sizeof(msg) || memcmp(msg, opened, sizeof(msg)) != 0) {
        fprintf(stderr, "test_reconnection_succeeds_with_fresh_ephemeral_keys: "
                         "post-reconnection data failed to round-trip\n");
        return 1;
    }

    printf("test_reconnection_succeeds_with_fresh_ephemeral_keys: passed\n");
    return 0;
}

static int test_stale_handshake_response_rejected(void)
{
    crypto_public_key_t initiator_pk, responder_pk;
    crypto_secret_key_t initiator_sk, responder_sk;
    session_t initiator, responder;
    make_pair(&initiator_pk, &initiator_sk, &responder_pk, &responder_sk, &initiator, &responder);

    /* Attempt 1: goes all the way through, so the responder is
     * ESTABLISHED and `stale_response` is a genuine, once-valid message. */
    unsigned char init1[SESSION_HANDSHAKE_MSG_LEN];
    ssize_t init1_len = session_build_init(&initiator, init1, sizeof(init1));
    unsigned char stale_response[SESSION_HANDSHAKE_MSG_LEN];
    ssize_t stale_response_len = session_handle_init(&responder, init1, (size_t)init1_len,
                                                       stale_response, sizeof(stale_response));
    if (stale_response_len != SESSION_HANDSHAKE_MSG_LEN) {
        fprintf(stderr, "test_stale_handshake_response_rejected: attempt 1 init failed\n");
        return 1;
    }

    /* The initiator moves on to attempt 2 without ever consuming
     * `stale_response` (as if it had been lost in transit). */
    session_start_handshake(&initiator);
    unsigned char init2[SESSION_HANDSHAKE_MSG_LEN];
    ssize_t init2_len = session_build_init(&initiator, init2, sizeof(init2));
    unsigned char current_response[SESSION_HANDSHAKE_MSG_LEN];
    ssize_t current_response_len = session_handle_init(&responder, init2, (size_t)init2_len,
                                                         current_response,
                                                         sizeof(current_response));
    if (current_response_len != SESSION_HANDSHAKE_MSG_LEN) {
        fprintf(stderr, "test_stale_handshake_response_rejected: attempt 2 init failed\n");
        return 1;
    }

    /* The stale attempt-1 response must not complete attempt 2. */
    if (session_handle_response(&initiator, stale_response, (size_t)stale_response_len) >= 0) {
        fprintf(stderr,
                "test_stale_handshake_response_rejected: stale response was accepted\n");
        return 1;
    }

    /* The genuine attempt-2 response must still work. */
    if (session_handle_response(&initiator, current_response, (size_t)current_response_len) !=
        0) {
        fprintf(stderr,
                "test_stale_handshake_response_rejected: current response was rejected\n");
        return 1;
    }

    printf("test_stale_handshake_response_rejected: passed\n");
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
    failures += test_out_of_order_data_accepted_once_each();
    failures += test_replay_outside_window_rejected();
    failures += test_tampered_handshake_init_rejected();
    failures += test_stale_handshake_init_replay_rejected();
    failures += test_reconnection_succeeds_with_fresh_ephemeral_keys();
    failures += test_stale_handshake_response_rejected();
    return failures == 0 ? 0 : 1;
}
