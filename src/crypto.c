#include "crypto.h"

#include <sodium.h>
#include <string.h>

/* Our wire-format assumptions must match libsodium's actual IETF
 * ChaCha20-Poly1305 sizes, or crypto_seal/crypto_open below would be
 * silently wrong. Caught at compile time if libsodium ever changes them. */
_Static_assert(CRYPTO_TAG_BYTES == crypto_aead_chacha20poly1305_ietf_ABYTES,
               "CRYPTO_TAG_BYTES no longer matches libsodium's AEAD tag size");
_Static_assert(CRYPTO_COUNTER_BYTES <= crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
               "CRYPTO_COUNTER_BYTES no longer fits in libsodium's AEAD nonce size");

int crypto_init(void)
{
    return sodium_init() < 0 ? -1 : 0;
}

void crypto_generate_keypair(crypto_public_key_t *pk, crypto_secret_key_t *sk)
{
    crypto_kx_keypair(pk->bytes, sk->bytes);
}

void crypto_derive_public_key(const crypto_secret_key_t *sk, crypto_public_key_t *pk)
{
    crypto_scalarmult_base(pk->bytes, sk->bytes);
}

int crypto_derive_session_keys(crypto_role_t role,
                                const crypto_public_key_t *local_pk,
                                const crypto_secret_key_t *local_sk,
                                const crypto_public_key_t *remote_pk,
                                crypto_session_keys_t *out)
{
    int rc;

    if (role == CRYPTO_ROLE_INITIATOR) {
        rc = crypto_kx_client_session_keys(out->rx, out->tx,
                                            local_pk->bytes, local_sk->bytes,
                                            remote_pk->bytes);
    } else {
        rc = crypto_kx_server_session_keys(out->rx, out->tx,
                                            local_pk->bytes, local_sk->bytes,
                                            remote_pk->bytes);
    }

    return rc == 0 ? 0 : -1;
}

void crypto_encode_base64(const unsigned char *data, size_t len, char *out, size_t out_len)
{
    sodium_bin2base64(out, out_len, data, len, sodium_base64_VARIANT_ORIGINAL);
}

int crypto_decode_base64(const char *text, unsigned char *out, size_t expected_len)
{
    size_t decoded_len = 0;

    if (sodium_base642bin(out, expected_len, text, strlen(text), NULL, &decoded_len,
                           NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        return -1;
    }
    if (decoded_len != expected_len) {
        return -1;
    }
    return 0;
}

/* Builds a 12-byte AEAD nonce from an 8-byte little-endian counter,
 * zero-padded in the high 4 bytes. */
static void build_nonce(uint64_t counter,
                         unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES])
{
    memset(nonce, 0, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    for (size_t i = 0; i < CRYPTO_COUNTER_BYTES; i++) {
        nonce[i] = (unsigned char)(counter >> (8 * i));
    }
}

ssize_t crypto_seal(const unsigned char key[CRYPTO_SESSION_KEY_BYTES], uint64_t counter,
                     const unsigned char *plaintext, size_t plaintext_len,
                     unsigned char *out, size_t out_len)
{
    if (out_len < plaintext_len + CRYPTO_PACKET_OVERHEAD) {
        return -1;
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    build_nonce(counter, nonce);

    for (size_t i = 0; i < CRYPTO_COUNTER_BYTES; i++) {
        out[i] = (unsigned char)(counter >> (8 * i));
    }

    unsigned long long ciphertext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            out + CRYPTO_COUNTER_BYTES, &ciphertext_len,
            plaintext, plaintext_len,
            NULL, 0,
            NULL,
            nonce, key) != 0) {
        return -1;
    }

    return (ssize_t)(CRYPTO_COUNTER_BYTES + ciphertext_len);
}

ssize_t crypto_open(const unsigned char key[CRYPTO_SESSION_KEY_BYTES],
                     const unsigned char *in, size_t in_len,
                     unsigned char *out, size_t out_len,
                     uint64_t *counter_out)
{
    if (in_len < CRYPTO_PACKET_OVERHEAD) {
        return -1;
    }

    uint64_t counter = 0;
    for (size_t i = 0; i < CRYPTO_COUNTER_BYTES; i++) {
        counter |= ((uint64_t)in[i]) << (8 * i);
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    build_nonce(counter, nonce);

    size_t ciphertext_len = in_len - CRYPTO_COUNTER_BYTES;
    if (out_len < ciphertext_len - CRYPTO_TAG_BYTES) {
        return -1;
    }

    unsigned long long plaintext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &plaintext_len,
            NULL,
            in + CRYPTO_COUNTER_BYTES, ciphertext_len,
            NULL, 0,
            nonce, key) != 0) {
        return -1;
    }

    *counter_out = counter;
    return (ssize_t)plaintext_len;
}
