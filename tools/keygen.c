/*
 * forgevpn-keygen: generates an X25519 key pair and prints both keys as
 * base64 -- the format ForgeVPN config files expect: PrivateKey under
 * [Interface] on this peer's own file, PublicKey under [Peer] on the
 * *other* peer's file. Mirrors WireGuard's `wg genkey` / `wg pubkey`
 * as a single tool. See docs/CRYPTOGRAPHY.md.
 */

#include "crypto.h"

#include <stdio.h>

int main(void)
{
    if (crypto_init() != 0) {
        fprintf(stderr, "forgevpn-keygen: failed to initialize crypto library\n");
        return 1;
    }

    crypto_public_key_t pk;
    crypto_secret_key_t sk;
    crypto_generate_keypair(&pk, &sk);

    char pk_text[CRYPTO_KEY_TEXT_LEN];
    char sk_text[CRYPTO_KEY_TEXT_LEN];
    crypto_encode_base64(pk.bytes, sizeof(pk.bytes), pk_text, sizeof(pk_text));
    crypto_encode_base64(sk.bytes, sizeof(sk.bytes), sk_text, sizeof(sk_text));

    printf("PrivateKey = %s\n", sk_text);
    printf("PublicKey  = %s\n", pk_text);
    return 0;
}
