#ifndef EDGARVPN_CONFIG_H
#define EDGARVPN_CONFIG_H

#include "crypto.h"

#include <linux/if.h>
#include <netinet/in.h>

#define CONFIG_MAX_NAME 64
#define CONFIG_MAX_HOST 256

/* Fixed cap on [Peer] sections per file -- no dynamic allocation
 * anywhere in this codebase, and 8 is comfortably more than the 4 any
 * single node needs for the full 5-peer mesh demo (see configs/*.conf). */
#define CONFIG_MAX_PEERS 8

/*
 * One [Peer] section: a single remote node this peer can exchange
 * traffic with, and the overlay address range routed to it.
 */
typedef struct {
    char host[CONFIG_MAX_HOST];
    unsigned short port;
    crypto_public_key_t public_key;
    crypto_role_t role;

    /* AllowedIPs, CIDR: traffic to an address within allowed_address/
     * allowed_prefix is routed to this peer. Only one range per peer is
     * supported (unlike real WireGuard's comma-separated list) -- this
     * project's peers each advertise exactly one overlay address. */
    struct in_addr allowed_address;
    unsigned int allowed_prefix;
} config_peer_t;

/*
 * Parsed contents of a EdgarVPN peer configuration file. See
 * docs/CONFIGURATION.md for the file format ([Interface]/[Peer]
 * sections, WireGuard-style key names).
 *
 * config_load() calls crypto_decode_base64() internally to parse key
 * material, so crypto_init() must be called before config_load().
 */
typedef struct {
    char name[CONFIG_MAX_NAME];         /* human-readable identity, for logging only */
    char tun_name[IFNAMSIZ];
    char tun_address[INET_ADDRSTRLEN];
    char tun_netmask[INET_ADDRSTRLEN];
    unsigned short listen_port;

    int has_private_key;                /* 0 if [Interface] has no PrivateKey */
    crypto_secret_key_t private_key;

    int peer_count;                     /* 0 if the file has no [Peer] sections */
    config_peer_t peers[CONFIG_MAX_PEERS];
} edgarvpn_config_t;

/*
 * Loads and parses the configuration file at `path`, filling `cfg`.
 * Optional keys are set to their documented defaults when absent.
 * Returns 0 on success. Returns -1 on failure -- including a missing
 * file, a malformed line, a missing required key, or more than
 * CONFIG_MAX_PEERS [Peer] sections -- and prints a message to stderr
 * describing what was wrong.
 *
 * Each [Peer] section requires Endpoint, PublicKey, Role, and
 * AllowedIPs; PrivateKey is required in [Interface] whenever at least
 * one [Peer] section is present -- there is no way to derive session
 * keys without them.
 */
int config_load(const char *path, edgarvpn_config_t *cfg);

#endif /* EDGARVPN_CONFIG_H */
