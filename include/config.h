#ifndef FORGEVPN_CONFIG_H
#define FORGEVPN_CONFIG_H

#include <linux/if.h>
#include <netinet/in.h>

#define CONFIG_MAX_NAME 64
#define CONFIG_MAX_HOST 256

/*
 * Parsed contents of a ForgeVPN peer configuration file. See
 * docs/CONFIGURATION.md for the file format ([Interface]/[Peer]
 * sections, WireGuard-style key names).
 */
typedef struct {
    char name[CONFIG_MAX_NAME];         /* human-readable identity, for logging only */
    char tun_name[IFNAMSIZ];
    char tun_address[INET_ADDRSTRLEN];
    char tun_netmask[INET_ADDRSTRLEN];
    unsigned short listen_port;

    int has_peer;                       /* 0 if the file has no [Peer] section */
    char peer_host[CONFIG_MAX_HOST];
    unsigned short peer_port;
} forgevpn_config_t;

/*
 * Loads and parses the configuration file at `path`, filling `cfg`.
 * Optional keys are set to their documented defaults when absent.
 * Returns 0 on success. Returns -1 on failure -- including a missing
 * file, a malformed line, or a missing required key -- and prints a
 * message to stderr describing what was wrong.
 */
int config_load(const char *path, forgevpn_config_t *cfg);

#endif /* FORGEVPN_CONFIG_H */
