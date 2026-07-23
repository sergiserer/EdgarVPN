/*
 * Entry point for the ForgeVPN peer daemon.
 *
 * At this milestone the daemon creates and configures its TUN interface
 * and captures the raw IP packets the kernel routes into it, logging
 * their size. It does not yet forward anything over the network -- that
 * is the responsibility of the upcoming UDP transport module. Peer
 * identity and interface addressing come from environment variables set
 * per-container in docker-compose.yml; a real configuration file format
 * replaces this once the configuration milestone lands.
 */

#include "tun.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_running = 1;

static void handle_shutdown(int signum)
{
    (void)signum;
    g_running = 0;
}

static const char *env_or(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return (value != NULL && value[0] != '\0') ? value : fallback;
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    const char *peer_name = env_or("PEER_NAME", "unnamed-peer");
    const char *tun_name = env_or("TUN_NAME", "forge0");
    const char *tun_netmask = env_or("TUN_NETMASK", "255.255.255.0");
    const char *tun_address = getenv("TUN_ADDRESS");

    if (tun_address == NULL || tun_address[0] == '\0') {
        fprintf(stderr, "[forgevpn] peer '%s': TUN_ADDRESS is required\n", peer_name);
        return 1;
    }

    tun_device_t tun;
    if (tun_open(&tun, tun_name) != 0) {
        fprintf(stderr, "[forgevpn] peer '%s': failed to open TUN device '%s': %s\n",
                peer_name, tun_name, strerror(errno));
        return 1;
    }

    if (tun_configure(&tun, tun_address, tun_netmask) != 0) {
        fprintf(stderr, "[forgevpn] peer '%s': failed to configure TUN device '%s': %s\n",
                peer_name, tun.name, strerror(errno));
        tun_close(&tun);
        return 1;
    }

    printf("[forgevpn] peer '%s' up: interface '%s', address %s/%s\n",
           peer_name, tun.name, tun_address, tun_netmask);
    fflush(stdout);

    unsigned char buf[2048];
    while (g_running) {
        ssize_t n = tun_read(&tun, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "[forgevpn] peer '%s': tun_read error: %s\n",
                    peer_name, strerror(errno));
            break;
        }
        printf("[forgevpn] peer '%s' captured packet: %zd bytes\n", peer_name, n);
        fflush(stdout);
    }

    printf("[forgevpn] peer '%s' shutting down\n", peer_name);
    tun_close(&tun);
    return 0;
}
