#include "routing.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

int routing_parse_ipv4_dest(const unsigned char *packet, size_t len, struct in_addr *dest_out)
{
    if (len < 20) {
        return -1;
    }
    if ((packet[0] >> 4) != 4) {
        return -1;
    }
    memcpy(&dest_out->s_addr, packet + 16, sizeof(dest_out->s_addr));
    return 0;
}

int routing_matches(struct in_addr addr, struct in_addr network, unsigned int prefix)
{
    /* A shift by 32 is undefined behavior in C; prefix 0 (match
     * everything) is the only case that would trigger one here. */
    uint32_t mask = (prefix == 0) ? 0 : htonl(~0U << (32 - prefix));
    return (addr.s_addr & mask) == (network.s_addr & mask);
}

int routing_find_peer_for_dest(const edgarvpn_config_t *cfg, struct in_addr dest)
{
    for (int i = 0; i < cfg->peer_count; i++) {
        if (routing_matches(dest, cfg->peers[i].allowed_address, cfg->peers[i].allowed_prefix)) {
            return i;
        }
    }
    return -1;
}
