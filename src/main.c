/*
 * Entry point for the ForgeVPN peer daemon.
 *
 * This milestone bridges the TUN interface to a UDP socket: packets the
 * kernel routes into the TUN device are forwarded, unmodified and
 * unauthenticated, to a single configured remote peer, and datagrams
 * arriving over UDP are written back into the TUN device. This is enough
 * for two peers to exchange real IP traffic (e.g. ICMP) across their
 * overlay addresses. There is no encryption or peer authentication yet --
 * that is the job of the upcoming cryptography milestones.
 *
 * A peer with no PEER_ENDPOINT configured still binds its UDP socket
 * (so it can be dialed by others) but only captures TUN traffic, matching
 * the previous milestone's behavior -- this keeps the `multi-peer` demo
 * runnable before N-way routing exists.
 *
 * Peer identity, interface addressing, and the remote peer's endpoint
 * come from environment variables set per-container in
 * docker-compose.yml; a real configuration file format replaces this
 * once the configuration milestone lands.
 */

#include "tun.h"
#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FORGEVPN_PORT 51820
#define MAX_PACKET_SIZE 2048
#define ENDPOINT_RESOLVE_RETRIES 20
#define ENDPOINT_RESOLVE_DELAY_US 500000

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

/* Splits "host:port" in place: NUL-terminates the host portion and writes
 * the parsed port to *port_out. Returns 0 on success, -1 if malformed. */
static int parse_endpoint(char *endpoint, unsigned short *port_out)
{
    char *sep = strrchr(endpoint, ':');
    if (sep == NULL || sep == endpoint) {
        return -1;
    }
    *sep = '\0';

    char *end = NULL;
    long port = strtol(sep + 1, &end, 10);
    if (end == sep + 1 || *end != '\0' || port <= 0 || port > 65535) {
        return -1;
    }

    *port_out = (unsigned short)port;
    return 0;
}

/* Resolves host:port with retries, since Docker's embedded DNS may not
 * yet have an entry for a peer container that is still starting. */
static int resolve_peer_with_retry(const char *peer_name, const char *host,
                                    unsigned short port, struct sockaddr_in *addr_out)
{
    for (int attempt = 1; attempt <= ENDPOINT_RESOLVE_RETRIES && g_running; attempt++) {
        if (udp_resolve(addr_out, host, port) == 0) {
            return 0;
        }
        fprintf(stderr, "[forgevpn] peer '%s': waiting for '%s' to resolve (attempt %d/%d)\n",
                peer_name, host, attempt, ENDPOINT_RESOLVE_RETRIES);
        usleep(ENDPOINT_RESOLVE_DELAY_US);
    }
    return -1;
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
    const char *peer_endpoint_env = getenv("PEER_ENDPOINT");

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

    udp_socket_t udp;
    if (udp_bind(&udp, FORGEVPN_PORT) != 0) {
        fprintf(stderr, "[forgevpn] peer '%s': failed to bind UDP port %d: %s\n",
                peer_name, FORGEVPN_PORT, strerror(errno));
        tun_close(&tun);
        return 1;
    }

    int has_peer = 0;
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));

    if (peer_endpoint_env != NULL && peer_endpoint_env[0] != '\0') {
        char endpoint_buf[256];
        if (strlen(peer_endpoint_env) >= sizeof(endpoint_buf)) {
            fprintf(stderr, "[forgevpn] peer '%s': PEER_ENDPOINT is too long\n", peer_name);
            udp_close(&udp);
            tun_close(&tun);
            return 1;
        }
        strcpy(endpoint_buf, peer_endpoint_env);

        unsigned short peer_port;
        if (parse_endpoint(endpoint_buf, &peer_port) != 0) {
            fprintf(stderr, "[forgevpn] peer '%s': PEER_ENDPOINT must be host:port, got '%s'\n",
                    peer_name, peer_endpoint_env);
            udp_close(&udp);
            tun_close(&tun);
            return 1;
        }

        if (resolve_peer_with_retry(peer_name, endpoint_buf, peer_port, &peer_addr) != 0) {
            fprintf(stderr, "[forgevpn] peer '%s': could not resolve peer endpoint '%s'\n",
                    peer_name, peer_endpoint_env);
            udp_close(&udp);
            tun_close(&tun);
            return 1;
        }
        has_peer = 1;
    }

    if (has_peer) {
        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
        printf("[forgevpn] peer '%s' up: interface '%s' (%s/%s), UDP :%d <-> peer %s:%d\n",
               peer_name, tun.name, tun_address, tun_netmask, FORGEVPN_PORT,
               peer_ip, ntohs(peer_addr.sin_port));
    } else {
        printf("[forgevpn] peer '%s' up: interface '%s' (%s/%s), UDP :%d, no peer configured (capture-only)\n",
               peer_name, tun.name, tun_address, tun_netmask, FORGEVPN_PORT);
    }
    fflush(stdout);

    struct pollfd fds[2];
    fds[0].fd = tun.fd;
    fds[0].events = POLLIN;
    fds[1].fd = udp.fd;
    fds[1].events = POLLIN;

    unsigned char buf[MAX_PACKET_SIZE];

    while (g_running) {
        int ready = poll(fds, 2, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "[forgevpn] peer '%s': poll error: %s\n", peer_name, strerror(errno));
            break;
        }

        if (fds[0].revents & POLLIN) {
            ssize_t n = tun_read(&tun, buf, sizeof(buf));
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': tun_read error: %s\n",
                            peer_name, strerror(errno));
                }
            } else if (has_peer) {
                if (udp_send(&udp, buf, (size_t)n, &peer_addr) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_send error: %s\n",
                            peer_name, strerror(errno));
                } else {
                    printf("[forgevpn] peer '%s' tun -> udp: %zd bytes\n", peer_name, n);
                    fflush(stdout);
                }
            } else {
                printf("[forgevpn] peer '%s' captured packet: %zd bytes\n", peer_name, n);
                fflush(stdout);
            }
        }

        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t n = udp_recv(&udp, buf, sizeof(buf), &from);
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_recv error: %s\n",
                            peer_name, strerror(errno));
                }
            } else if (tun_write(&tun, buf, (size_t)n) < 0) {
                fprintf(stderr, "[forgevpn] peer '%s': tun_write error: %s\n",
                        peer_name, strerror(errno));
            } else {
                printf("[forgevpn] peer '%s' udp -> tun: %zd bytes\n", peer_name, n);
                fflush(stdout);
            }
        }
    }

    printf("[forgevpn] peer '%s' shutting down\n", peer_name);
    udp_close(&udp);
    tun_close(&tun);
    return 0;
}
