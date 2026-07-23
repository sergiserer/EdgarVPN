/*
 * Unit tests for the crypto module. The properties that actually matter
 * for a key exchange primitive: both sides derive matching session keys
 * without ever transmitting a private key, different peer pairs get
 * different keys, and key encoding round-trips.
 */

#include "crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_session_keys_agree(void)
{
    crypto_public_key_t alice_pk;
    crypto_secret_key_t alice_sk;
    crypto_public_key_t bob_pk;
    crypto_secret_key_t bob_sk;
    crypto_generate_keypair(&alice_pk, &alice_sk);
    crypto_generate_keypair(&bob_pk, &bob_sk);

    crypto_session_keys_t alice_keys;
    crypto_session_keys_t bob_keys;

    if (crypto_derive_session_keys(CRYPTO_ROLE_INITIATOR, &alice_pk, &alice_sk,
                                    &bob_pk, &alice_keys) != 0) {
        fprintf(stderr, "test_session_keys_agree: alice derivation failed\n");
        return 1;
    }
    if (crypto_derive_session_keys(CRYPTO_ROLE_RESPONDER, &bob_pk, &bob_sk,
                                    &alice_pk, &bob_keys) != 0) {
        fprintf(stderr, "test_session_keys_agree: bob derivation failed\n");
        return 1;
    }

    /* What Alice encrypts with (tx), Bob must decrypt with (rx), and vice versa. */
    if (memcmp(alice_keys.tx, bob_keys.rx, CRYPTO_SESSION_KEY_BYTES) != 0) {
        fprintf(stderr, "test_session_keys_agree: alice.tx != bob.rx\n");
        return 1;
    }
    if (memcmp(alice_keys.rx, bob_keys.tx, CRYPTO_SESSION_KEY_BYTES) != 0) {
        fprintf(stderr, "test_session_keys_agree: alice.rx != bob.tx\n");
        return 1;
    }

    printf("test_session_keys_agree: passed\n");
    return 0;
}

static int test_different_peers_get_different_keys(void)
{
    crypto_public_key_t alice_pk;
    crypto_secret_key_t alice_sk;
    crypto_public_key_t bob_pk;
    crypto_secret_key_t bob_sk;
    crypto_public_key_t carol_pk;
    crypto_secret_key_t carol_sk;
    crypto_generate_keypair(&alice_pk, &alice_sk);
    crypto_generate_keypair(&bob_pk, &bob_sk);
    crypto_generate_keypair(&carol_pk, &carol_sk);

    crypto_session_keys_t alice_bob;
    crypto_session_keys_t alice_carol;

    if (crypto_derive_session_keys(CRYPTO_ROLE_INITIATOR, &alice_pk, &alice_sk,
                                    &bob_pk, &alice_bob) != 0 ||
        crypto_derive_session_keys(CRYPTO_ROLE_INITIATOR, &alice_pk, &alice_sk,
                                    &carol_pk, &alice_carol) != 0) {
        fprintf(stderr, "test_different_peers_get_different_keys: derivation failed\n");
        return 1;
    }

    if (memcmp(alice_bob.tx, alice_carol.tx, CRYPTO_SESSION_KEY_BYTES) == 0) {
        fprintf(stderr, "test_different_peers_get_different_keys: sessions collided\n");
        return 1;
    }

    printf("test_different_peers_get_different_keys: passed\n");
    return 0;
}

static int test_base64_round_trip(void)
{
    crypto_public_key_t pk;
    crypto_secret_key_t sk;
    crypto_generate_keypair(&pk, &sk);

    char text[CRYPTO_KEY_TEXT_LEN];
    crypto_encode_base64(pk.bytes, sizeof(pk.bytes), text, sizeof(text));

    crypto_public_key_t decoded;
    if (crypto_decode_base64(text, decoded.bytes, sizeof(decoded.bytes)) != 0) {
        fprintf(stderr, "test_base64_round_trip: decode failed\n");
        return 1;
    }
    if (memcmp(pk.bytes, decoded.bytes, sizeof(pk.bytes)) != 0) {
        fprintf(stderr, "test_base64_round_trip: round-trip mismatch\n");
        return 1;
    }

    printf("test_base64_round_trip: passed\n");
    return 0;
}

static int test_bad_base64_rejected(void)
{
    crypto_public_key_t decoded;
    if (crypto_decode_base64("not-valid-base64!!", decoded.bytes, sizeof(decoded.bytes)) == 0) {
        fprintf(stderr, "test_bad_base64_rejected: malformed input was unexpectedly accepted\n");
        return 1;
    }
    printf("test_bad_base64_rejected: passed\n");
    return 0;
}

static int test_derived_public_key_matches_keypair(void)
{
    crypto_public_key_t pk;
    crypto_secret_key_t sk;
    crypto_generate_keypair(&pk, &sk);

    crypto_public_key_t derived;
    crypto_derive_public_key(&sk, &derived);

    if (memcmp(pk.bytes, derived.bytes, sizeof(pk.bytes)) != 0) {
        fprintf(stderr,
                "test_derived_public_key_matches_keypair: derived key doesn't match keypair\n");
        return 1;
    }

    printf("test_derived_public_key_matches_keypair: passed\n");
    return 0;
}

static int test_seal_open_round_trip(void)
{
    unsigned char key[CRYPTO_SESSION_KEY_BYTES];
    memset(key, 0x42, sizeof(key));

    const unsigned char plaintext[] = "the quick brown fox jumps over the lazy dog";
    unsigned char sealed[sizeof(plaintext) + CRYPTO_PACKET_OVERHEAD];

    ssize_t sealed_len = crypto_seal(key, 7, plaintext, sizeof(plaintext), sealed, sizeof(sealed));
    if (sealed_len != (ssize_t)(sizeof(plaintext) + CRYPTO_PACKET_OVERHEAD)) {
        fprintf(stderr, "test_seal_open_round_trip: unexpected sealed length %zd\n", sealed_len);
        return 1;
    }

    unsigned char opened[sizeof(plaintext)];
    uint64_t counter = 0;
    ssize_t opened_len = crypto_open(key, sealed, (size_t)sealed_len, opened, sizeof(opened),
                                      &counter);
    if (opened_len != (ssize_t)sizeof(plaintext)) {
        fprintf(stderr, "test_seal_open_round_trip: unexpected opened length %zd\n", opened_len);
        return 1;
    }
    if (counter != 7) {
        fprintf(stderr, "test_seal_open_round_trip: counter mismatch (got %llu)\n",
                (unsigned long long)counter);
        return 1;
    }
    if (memcmp(plaintext, opened, sizeof(plaintext)) != 0) {
        fprintf(stderr, "test_seal_open_round_trip: plaintext mismatch\n");
        return 1;
    }

    printf("test_seal_open_round_trip: passed\n");
    return 0;
}

static int test_tampered_ciphertext_rejected(void)
{
    unsigned char key[CRYPTO_SESSION_KEY_BYTES];
    memset(key, 0x99, sizeof(key));

    const unsigned char plaintext[] = "authenticate me";
    unsigned char sealed[sizeof(plaintext) + CRYPTO_PACKET_OVERHEAD];
    crypto_seal(key, 1, plaintext, sizeof(plaintext), sealed, sizeof(sealed));

    /* Flip a bit in the ciphertext, well past the counter prefix. */
    sealed[CRYPTO_COUNTER_BYTES] ^= 0x01;

    unsigned char opened[sizeof(plaintext)];
    uint64_t counter = 0;
    if (crypto_open(key, sealed, sizeof(sealed), opened, sizeof(opened), &counter) >= 0) {
        fprintf(stderr, "test_tampered_ciphertext_rejected: tampered packet was accepted\n");
        return 1;
    }

    printf("test_tampered_ciphertext_rejected: passed\n");
    return 0;
}

static int test_wrong_key_rejected(void)
{
    unsigned char key_a[CRYPTO_SESSION_KEY_BYTES];
    unsigned char key_b[CRYPTO_SESSION_KEY_BYTES];
    memset(key_a, 0x11, sizeof(key_a));
    memset(key_b, 0x22, sizeof(key_b));

    const unsigned char plaintext[] = "for key_a's eyes only";
    unsigned char sealed[sizeof(plaintext) + CRYPTO_PACKET_OVERHEAD];
    crypto_seal(key_a, 1, plaintext, sizeof(plaintext), sealed, sizeof(sealed));

    unsigned char opened[sizeof(plaintext)];
    uint64_t counter = 0;
    if (crypto_open(key_b, sealed, sizeof(sealed), opened, sizeof(opened), &counter) >= 0) {
        fprintf(stderr, "test_wrong_key_rejected: packet opened with the wrong key\n");
        return 1;
    }

    printf("test_wrong_key_rejected: passed\n");
    return 0;
}

int main(void)
{
    if (crypto_init() != 0) {
        fprintf(stderr, "crypto_init failed\n");
        return 1;
    }

    int failures = 0;
    failures += test_session_keys_agree();
    failures += test_different_peers_get_different_keys();
    failures += test_base64_round_trip();
    failures += test_bad_base64_rejected();
    failures += test_derived_public_key_matches_keypair();
    failures += test_seal_open_round_trip();
    failures += test_tampered_ciphertext_rejected();
    failures += test_wrong_key_rejected();
    return failures == 0 ? 0 : 1;
}
