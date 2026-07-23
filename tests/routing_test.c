/*
 * Unit tests for the routing module: parsing a destination address out
 * of a raw IPv4 header, CIDR matching, and looking up which configured
 * peer covers a given destination.
 */

#include "routing.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

/* Builds a minimal (20-byte, no options) IPv4 header with the given
 * version nibble and destination address, for parser tests. */
static void build_ipv4_header(unsigned char *out, int version, const char *dest_ip)
{
    memset(out, 0, 20);
    out[0] = (unsigned char)((version << 4) | 5); /* version | IHL=5 (20 bytes) */
    struct in_addr dest;
    inet_pton(AF_INET, dest_ip, &dest);
    memcpy(out + 16, &dest.s_addr, 4);
}

static int test_parse_ipv4_dest_valid(void)
{
    unsigned char packet[20];
    build_ipv4_header(packet, 4, "10.8.0.12");

    struct in_addr dest;
    if (routing_parse_ipv4_dest(packet, sizeof(packet), &dest) != 0) {
        fprintf(stderr, "test_parse_ipv4_dest_valid: unexpected failure\n");
        return 1;
    }

    struct in_addr expected;
    inet_pton(AF_INET, "10.8.0.12", &expected);
    if (dest.s_addr != expected.s_addr) {
        fprintf(stderr, "test_parse_ipv4_dest_valid: wrong destination parsed\n");
        return 1;
    }

    printf("test_parse_ipv4_dest_valid: passed\n");
    return 0;
}

static int test_parse_ipv4_dest_rejects_short_packet(void)
{
    unsigned char packet[10];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45;

    struct in_addr dest;
    if (routing_parse_ipv4_dest(packet, sizeof(packet), &dest) == 0) {
        fprintf(stderr, "test_parse_ipv4_dest_rejects_short_packet: short packet accepted\n");
        return 1;
    }

    printf("test_parse_ipv4_dest_rejects_short_packet: passed\n");
    return 0;
}

static int test_parse_ipv4_dest_rejects_non_ipv4(void)
{
    unsigned char packet[20];
    build_ipv4_header(packet, 6, "10.8.0.12"); /* version nibble 6, not 4 */

    struct in_addr dest;
    if (routing_parse_ipv4_dest(packet, sizeof(packet), &dest) == 0) {
        fprintf(stderr, "test_parse_ipv4_dest_rejects_non_ipv4: non-IPv4 packet accepted\n");
        return 1;
    }

    printf("test_parse_ipv4_dest_rejects_non_ipv4: passed\n");
    return 0;
}

static struct in_addr addr(const char *text)
{
    struct in_addr a;
    inet_pton(AF_INET, text, &a);
    return a;
}

static int test_matches_exact_host(void)
{
    if (!routing_matches(addr("10.8.0.12"), addr("10.8.0.12"), 32)) {
        fprintf(stderr, "test_matches_exact_host: identical /32 addresses did not match\n");
        return 1;
    }
    if (routing_matches(addr("10.8.0.13"), addr("10.8.0.12"), 32)) {
        fprintf(stderr, "test_matches_exact_host: different /32 addresses matched\n");
        return 1;
    }

    printf("test_matches_exact_host: passed\n");
    return 0;
}

static int test_matches_subnet(void)
{
    if (!routing_matches(addr("10.8.0.200"), addr("10.8.0.0"), 24)) {
        fprintf(stderr, "test_matches_subnet: address inside /24 subnet did not match\n");
        return 1;
    }
    if (routing_matches(addr("10.8.1.5"), addr("10.8.0.0"), 24)) {
        fprintf(stderr, "test_matches_subnet: address outside /24 subnet matched\n");
        return 1;
    }
    if (!routing_matches(addr("192.0.2.1"), addr("0.0.0.0"), 0)) {
        fprintf(stderr, "test_matches_subnet: /0 (match everything) failed\n");
        return 1;
    }

    printf("test_matches_subnet: passed\n");
    return 0;
}

static int test_find_peer_for_dest(void)
{
    forgevpn_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.peer_count = 3;
    cfg.peers[0].allowed_address = addr("10.8.0.12");
    cfg.peers[0].allowed_prefix = 32;
    cfg.peers[1].allowed_address = addr("10.8.0.13");
    cfg.peers[1].allowed_prefix = 32;
    cfg.peers[2].allowed_address = addr("10.8.0.14");
    cfg.peers[2].allowed_prefix = 32;

    if (routing_find_peer_for_dest(&cfg, addr("10.8.0.13")) != 1) {
        fprintf(stderr, "test_find_peer_for_dest: expected peer index 1\n");
        return 1;
    }
    if (routing_find_peer_for_dest(&cfg, addr("10.8.0.99")) != -1) {
        fprintf(stderr, "test_find_peer_for_dest: expected no route (-1) for unlisted address\n");
        return 1;
    }

    printf("test_find_peer_for_dest: passed\n");
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_parse_ipv4_dest_valid();
    failures += test_parse_ipv4_dest_rejects_short_packet();
    failures += test_parse_ipv4_dest_rejects_non_ipv4();
    failures += test_matches_exact_host();
    failures += test_matches_subnet();
    failures += test_find_peer_for_dest();
    return failures == 0 ? 0 : 1;
}
