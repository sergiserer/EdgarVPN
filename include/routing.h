#ifndef EDGARVPN_ROUTING_H
#define EDGARVPN_ROUTING_H

#include "config.h"

#include <netinet/in.h>
#include <stddef.h>

/*
 * Parses the destination address out of a raw IPv4 packet (as read from
 * a TUN device): 4 bytes starting at offset 16 of the header, per
 * RFC 791. Returns 0 and fills `dest_out` on success, -1 if `packet` is
 * shorter than a minimal IPv4 header (20 bytes) or its version nibble
 * isn't 4 (e.g. IPv6 traffic, which this project doesn't route).
 */
int routing_parse_ipv4_dest(const unsigned char *packet, size_t len, struct in_addr *dest_out);

/*
 * Returns 1 if `addr` falls within the `network`/`prefix` CIDR range
 * (both sides masked to `prefix` bits before comparing), 0 otherwise.
 */
int routing_matches(struct in_addr addr, struct in_addr network, unsigned int prefix);

/*
 * Finds which configured peer's AllowedIPs covers `dest`, by checking
 * cfg->peers[0..peer_count) in order and returning the first match.
 * Returns the peer's index, or -1 if no configured peer covers `dest`
 * (the routing-table equivalent of "no route to host").
 */
int routing_find_peer_for_dest(const edgarvpn_config_t *cfg, struct in_addr dest);

#endif /* EDGARVPN_ROUTING_H */
