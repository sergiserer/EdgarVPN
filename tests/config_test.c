/*
 * Unit tests for the configuration parser: a fully populated file, a
 * capture-only file (no [Peer] section, relying on defaults), and a file
 * missing the required Address key.
 */

#include "config.h"

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

static int test_valid_config(void)
{
    const char *path = "/tmp/forgevpn_config_test_valid.conf";
    const char *contents =
        "# comment\n"
        "[Interface]\n"
        "Name = peer1\n"
        "DeviceName = forge9\n"
        "Address = 10.8.0.11/24\n"
        "ListenPort = 51821\n"
        "\n"
        "[Peer]\n"
        "Endpoint = peer2:51820\n";

    if (write_file(path, contents) != 0) {
        fprintf(stderr, "test_valid_config: failed to write fixture\n");
        return 1;
    }

    forgevpn_config_t cfg;
    if (config_load(path, &cfg) != 0) {
        fprintf(stderr, "test_valid_config: config_load failed unexpectedly\n");
        return 1;
    }

    if (strcmp(cfg.name, "peer1") != 0 ||
        strcmp(cfg.tun_name, "forge9") != 0 ||
        strcmp(cfg.tun_address, "10.8.0.11") != 0 ||
        strcmp(cfg.tun_netmask, "255.255.255.0") != 0 ||
        cfg.listen_port != 51821 ||
        !cfg.has_peer ||
        strcmp(cfg.peer_host, "peer2") != 0 ||
        cfg.peer_port != 51820) {
        fprintf(stderr, "test_valid_config: parsed fields do not match expected values\n");
        return 1;
    }

    printf("test_valid_config: passed\n");
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

    if (cfg.has_peer) {
        fprintf(stderr, "test_capture_only_config: expected has_peer to be false\n");
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

int main(void)
{
    int failures = 0;
    failures += test_valid_config();
    failures += test_capture_only_config();
    failures += test_missing_address_rejected();
    return failures == 0 ? 0 : 1;
}
