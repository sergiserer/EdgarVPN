/*
 * Unit tests for the configuration parser: a fully populated file with
 * multiple [Peer] sections, a capture-only file (no [Peer] section,
 * relying on defaults), and the various required-field rejections.
 */

#include "config.h"
#include "crypto.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static int write_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        return -1;
    }
    size_t len = strlen(contents);
    size_t written = fwrite(contents, 1, len, f);
    fclose(f);
    return written == len ? 0 : -1;
}

static void generate_key_text(char out[CRYPTO_KEY_TEXT_LEN])
{
    crypto_public_key_t pk;
    crypto_secret_key_t sk;
    crypto_generate_keypair(&pk, &sk);
    crypto_encode_base64(sk.bytes, sizeof(sk.bytes), out, CRYPTO_KEY_TEXT_LEN);
}

static int test_valid_config(void)
{
    const char *path = "/tmp/forgevpn_config_test_valid.conf";

    char private_key[CRYPTO_KEY_TEXT_LEN];
    char public_key[CRYPTO_KEY_TEXT_LEN];
    generate_key_text(private_key);
    generate_key_text(public_key);

    char contents[1024];
    snprintf(contents, sizeof(contents),
              "# comment\n"
              "[Interface]\n"
              "Name = peer1\n"
              "DeviceName = forge9\n"
              "Address = 10.8.0.11/24\n"
              "ListenPort = 51821\n"
              "PrivateKey = %s\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer2:51820\n"
              "PublicKey = %s\n"
              "Role = initiator\n"
              "AllowedIPs = 10.8.0.12/32\n",
              private_key, public_key);

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_valid_config: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) != 0) {
        fprintf(stderr, "test_valid_config: config_load failed unexpectedly\n");
        return 1;
    }

    char decoded_private_key[CRYPTO_KEY_TEXT_LEN];
    char decoded_public_key[CRYPTO_KEY_TEXT_LEN];
    crypto_encode_base64(cfg.private_key.bytes, sizeof(cfg.private_key.bytes),
                          decoded_private_key, sizeof(decoded_private_key));
    crypto_encode_base64(cfg.peers[0].public_key.bytes, sizeof(cfg.peers[0].public_key.bytes),
                          decoded_public_key, sizeof(decoded_public_key));

    struct in_addr expected_allowed;
    inet_pton(AF_INET, "10.8.0.12", &expected_allowed);

    if (strcmp(cfg.name, "peer1") != 0 ||
        strcmp(cfg.tun_name, "forge9") != 0 ||
        strcmp(cfg.tun_address, "10.8.0.11") != 0 ||
        strcmp(cfg.tun_netmask, "255.255.255.0") != 0 ||
        cfg.listen_port != 51821 ||
        !cfg.has_private_key ||
        strcmp(decoded_private_key, private_key) != 0 ||
        cfg.peer_count != 1 ||
        strcmp(cfg.peers[0].host, "peer2") != 0 ||
        cfg.peers[0].port != 51820 ||
        strcmp(decoded_public_key, public_key) != 0 ||
        cfg.peers[0].role != CRYPTO_ROLE_INITIATOR ||
        cfg.peers[0].allowed_address.s_addr != expected_allowed.s_addr ||
        cfg.peers[0].allowed_prefix != 32) {
        fprintf(stderr, "test_valid_config: parsed fields do not match expected values\n");
        return 1;
    }

    printf("test_valid_config: passed\n");
    return 0;
}

static int test_multiple_peers_parsed(void)
{
    const char *path = "/tmp/forgevpn_config_test_multi.conf";

    char private_key[CRYPTO_KEY_TEXT_LEN];
    char pub_a[CRYPTO_KEY_TEXT_LEN];
    char pub_b[CRYPTO_KEY_TEXT_LEN];
    char pub_c[CRYPTO_KEY_TEXT_LEN];
    generate_key_text(private_key);
    generate_key_text(pub_a);
    generate_key_text(pub_b);
    generate_key_text(pub_c);

    char contents[2048];
    snprintf(contents, sizeof(contents),
              "[Interface]\n"
              "Address = 10.8.0.11/24\n"
              "PrivateKey = %s\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer2:51820\n"
              "PublicKey = %s\n"
              "Role = initiator\n"
              "AllowedIPs = 10.8.0.12/32\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer3:51820\n"
              "PublicKey = %s\n"
              "Role = responder\n"
              "AllowedIPs = 10.8.0.13/32\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer4:51820\n"
              "PublicKey = %s\n"
              "Role = initiator\n"
              "AllowedIPs = 10.8.0.14/32\n",
              private_key, pub_a, pub_b, pub_c);

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_multiple_peers_parsed: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) != 0) {
        fprintf(stderr, "test_multiple_peers_parsed: config_load failed unexpectedly\n");
        return 1;
    }

    if (cfg.peer_count != 3) {
        fprintf(stderr, "test_multiple_peers_parsed: expected 3 peers, got %d\n", cfg.peer_count);
        return 1;
    }
    if (strcmp(cfg.peers[0].host, "peer2") != 0 || cfg.peers[0].role != CRYPTO_ROLE_INITIATOR) {
        fprintf(stderr, "test_multiple_peers_parsed: peer 0 fields wrong\n");
        return 1;
    }
    if (strcmp(cfg.peers[1].host, "peer3") != 0 || cfg.peers[1].role != CRYPTO_ROLE_RESPONDER) {
        fprintf(stderr, "test_multiple_peers_parsed: peer 1 fields wrong\n");
        return 1;
    }
    if (strcmp(cfg.peers[2].host, "peer4") != 0 || cfg.peers[2].role != CRYPTO_ROLE_INITIATOR) {
        fprintf(stderr, "test_multiple_peers_parsed: peer 2 fields wrong\n");
        return 1;
    }

    printf("test_multiple_peers_parsed: passed\n");
    return 0;
}

static int test_too_many_peers_rejected(void)
{
    const char *path = "/tmp/forgevpn_config_test_too_many.conf";

    char private_key[CRYPTO_KEY_TEXT_LEN];
    generate_key_text(private_key);

    char contents[4096];
    int offset = snprintf(contents, sizeof(contents),
                           "[Interface]\n"
                           "Address = 10.8.0.11/24\n"
                           "PrivateKey = %s\n\n",
                           private_key);

    for (int i = 0; i < CONFIG_MAX_PEERS + 1; i++) {
        char pub[CRYPTO_KEY_TEXT_LEN];
        generate_key_text(pub);
        offset += snprintf(contents + offset, sizeof(contents) - (size_t)offset,
                            "[Peer]\n"
                            "Endpoint = peer%d:51820\n"
                            "PublicKey = %s\n"
                            "Role = initiator\n"
                            "AllowedIPs = 10.8.0.%d/32\n\n",
                            i + 2, pub, i + 2);
    }

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_too_many_peers_rejected: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) == 0) {
        fprintf(stderr, "test_too_many_peers_rejected: config_load unexpectedly succeeded\n");
        return 1;
    }

    printf("test_too_many_peers_rejected: passed\n");
    return 0;
}

static int test_capture_only_config(void)
{
    const char *path = "/tmp/forgevpn_config_test_captureonly.conf";
    const char *contents =
        "[Interface]\n"
        "Address = 10.8.0.15/24\n";

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_capture_only_config: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) != 0) {
        fprintf(stderr, "test_capture_only_config: config_load failed unexpectedly\n");
        return 1;
    }

    if (cfg.peer_count != 0) {
        fprintf(stderr, "test_capture_only_config: expected peer_count 0\n");
        return 1;
    }
    if (cfg.has_private_key) {
        fprintf(stderr, "test_capture_only_config: expected has_private_key to be false\n");
        return 1;
    }
    if (strcmp(cfg.tun_name, "forge0") != 0) {
        fprintf(stderr, "test_capture_only_config: expected default DeviceName 'forge0'\n");
        return 1;
    }
    if (cfg.listen_port != 51820) {
        fprintf(stderr, "test_capture_only_config: expected default ListenPort 51820\n");
        return 1;
    }

    printf("test_capture_only_config: passed\n");
    return 0;
}

static int test_missing_address_rejected(void)
{
    const char *path = "/tmp/forgevpn_config_test_invalid.conf";
    const char *contents =
        "[Interface]\n"
        "Name = peer1\n";

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_missing_address_rejected: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) == 0) {
        fprintf(stderr, "test_missing_address_rejected: config_load unexpectedly succeeded\n");
        return 1;
    }

    printf("test_missing_address_rejected: passed\n");
    return 0;
}

static int test_peer_without_private_key_rejected(void)
{
    const char *path = "/tmp/forgevpn_config_test_no_private_key.conf";

    char public_key[CRYPTO_KEY_TEXT_LEN];
    generate_key_text(public_key);

    char contents[512];
    snprintf(contents, sizeof(contents),
              "[Interface]\n"
              "Address = 10.8.0.11/24\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer2:51820\n"
              "PublicKey = %s\n"
              "Role = initiator\n"
              "AllowedIPs = 10.8.0.12/32\n",
              public_key);

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_peer_without_private_key_rejected: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) == 0) {
        fprintf(stderr,
                "test_peer_without_private_key_rejected: config_load unexpectedly succeeded\n");
        return 1;
    }

    printf("test_peer_without_private_key_rejected: passed\n");
    return 0;
}

static int test_peer_without_public_key_rejected(void)
{
    const char *path = "/tmp/forgevpn_config_test_no_public_key.conf";

    char private_key[CRYPTO_KEY_TEXT_LEN];
    generate_key_text(private_key);

    char contents[512];
    snprintf(contents, sizeof(contents),
              "[Interface]\n"
              "Address = 10.8.0.11/24\n"
              "PrivateKey = %s\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer2:51820\n"
              "Role = initiator\n"
              "AllowedIPs = 10.8.0.12/32\n",
              private_key);

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_peer_without_public_key_rejected: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) == 0) {
        fprintf(stderr,
                "test_peer_without_public_key_rejected: config_load unexpectedly succeeded\n");
        return 1;
    }

    printf("test_peer_without_public_key_rejected: passed\n");
    return 0;
}

static int test_peer_without_role_rejected(void)
{
    const char *path = "/tmp/forgevpn_config_test_no_role.conf";

    char private_key[CRYPTO_KEY_TEXT_LEN];
    char public_key[CRYPTO_KEY_TEXT_LEN];
    generate_key_text(private_key);
    generate_key_text(public_key);

    char contents[512];
    snprintf(contents, sizeof(contents),
              "[Interface]\n"
              "Address = 10.8.0.11/24\n"
              "PrivateKey = %s\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer2:51820\n"
              "PublicKey = %s\n"
              "AllowedIPs = 10.8.0.12/32\n",
              private_key, public_key);

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_peer_without_role_rejected: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) == 0) {
        fprintf(stderr, "test_peer_without_role_rejected: config_load unexpectedly succeeded\n");
        return 1;
    }

    printf("test_peer_without_role_rejected: passed\n");
    return 0;
}

static int test_peer_without_allowed_ips_rejected(void)
{
    const char *path = "/tmp/forgevpn_config_test_no_allowed_ips.conf";

    char private_key[CRYPTO_KEY_TEXT_LEN];
    char public_key[CRYPTO_KEY_TEXT_LEN];
    generate_key_text(private_key);
    generate_key_text(public_key);

    char contents[512];
    snprintf(contents, sizeof(contents),
              "[Interface]\n"
              "Address = 10.8.0.11/24\n"
              "PrivateKey = %s\n"
              "\n"
              "[Peer]\n"
              "Endpoint = peer2:51820\n"
              "PublicKey = %s\n"
              "Role = initiator\n",
              private_key, public_key);

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_peer_without_allowed_ips_rejected: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) == 0) {
        fprintf(stderr,
                "test_peer_without_allowed_ips_rejected: config_load unexpectedly succeeded\n");
        return 1;
    }

    printf("test_peer_without_allowed_ips_rejected: passed\n");
    return 0;
}

static int test_malformed_key_rejected(void)
{
    const char *path = "/tmp/forgevpn_config_test_bad_key.conf";
    const char *contents =
        "[Interface]\n"
        "Address = 10.8.0.11/24\n"
        "PrivateKey = not-valid-base64!!\n";

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_malformed_key_rejected: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) == 0) {
        fprintf(stderr, "test_malformed_key_rejected: config_load unexpectedly succeeded\n");
        return 1;
    }

    printf("test_malformed_key_rejected: passed\n");
    return 0;
}

int main(void)
{
    if (crypto_init() != 0) {
        fprintf(stderr, "crypto_init failed\n");
        return 1;
    }

    int failures = 0;
    failures += test_valid_config();
    failures += test_multiple_peers_parsed();
    failures += test_too_many_peers_rejected();
    failures += test_capture_only_config();
    failures += test_missing_address_rejected();
    failures += test_peer_without_private_key_rejected();
    failures += test_peer_without_public_key_rejected();
    failures += test_peer_without_role_rejected();
    failures += test_peer_without_allowed_ips_rejected();
    failures += test_malformed_key_rejected();
    return failures == 0 ? 0 : 1;
}
