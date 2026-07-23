/*
 * Entry point for the ForgeVPN peer daemon.
 *
 * Peer identity, interface addressing, and the remote peer's endpoint
 * come from a configuration file (see docs/CONFIGURATION.md) instead of
 * the ad hoc environment variables used before this milestone. The
 * daemon still bridges its TUN device to a UDP socket exactly as before
 * -- this change is about how that setup is described, not how packets
 * move.
 */

#include "config.h"
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

#define DEFAULT_CONFIG_PATH "/etc/forgevpn/forgevpn.conf"
#define MAX_PACKET_SIZE 2048
#define ENDPOINT_RESOLVE_RETRIES 20
#define ENDPOINT_RESOLVE_DELAY_US 500000

static volatile sig_atomic_t g_running = 1;

static void handle_shutdown(int signum)
{
    (void)signum;
    g_running = 0;
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

    const char *config_path = getenv("CONFIG_FILE");
    if (config_path == NULL || config_path[0] == '\0') {
        config_path = DEFAULT_CONFIG_PATH;
    }

    forgevpn_config_t cfg;
    if (config_load(config_path, &cfg) != 0) {
        return 1;
    }

    tun_device_t tun;
    if (tun_open(&tun, cfg.tun_name) != 0) {
        fprintf(stderr, "[forgevpn] peer '%s': failed to open TUN device '%s': %s\n",
                cfg.name, cfg.tun_name, strerror(errno));
        return 1;
    }
    if (tun_configure(&tun, cfg.tun_address, cfg.tun_netmask) != 0) {
        fprintf(stderr, "[forgevpn] peer '%s': failed to configure TUN device '%s': %s\n",
                cfg.name, tun.name, strerror(errno));
        tun_close(&tun);
        return 1;
    }

    udp_socket_t udp;
    if (udp_bind(&udp, cfg.listen_port) != 0) {
        fprintf(stderr, "[forgevpn] peer '%s': failed to bind UDP port %u: %s\n",
                cfg.name, cfg.listen_port, strerror(errno));
        tun_close(&tun);
        return 1;
    }

    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));

    if (cfg.has_peer) {
        if (resolve_peer_with_retry(cfg.name, cfg.peer_host, cfg.peer_port, &peer_addr) != 0) {
            fprintf(stderr, "[forgevpn] peer '%s': could not resolve peer endpoint '%s:%u'\n",
                    cfg.name, cfg.peer_host, cfg.peer_port);
            udp_close(&udp);
            tun_close(&tun);
            return 1;
        }

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
        printf("[forgevpn] peer '%s' up: interface '%s' (%s/%s), UDP :%u <-> peer %s:%u\n",
               cfg.name, tun.name, cfg.tun_address, cfg.tun_netmask, cfg.listen_port,
               peer_ip, ntohs(peer_addr.sin_port));
    } else {
        printf("[forgevpn] peer '%s' up: interface '%s' (%s/%s), UDP :%u, "
               "no peer configured (capture-only)\n",
               cfg.name, tun.name, cfg.tun_address, cfg.tun_netmask, cfg.listen_port);
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
            fprintf(stderr, "[forgevpn] peer '%s': poll error: %s\n", cfg.name, strerror(errno));
            break;
        }

        if (fds[0].revents & POLLIN) {
            ssize_t n = tun_read(&tun, buf, sizeof(buf));
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': tun_read error: %s\n",
                            cfg.name, strerror(errno));
                }
            } else if (cfg.has_peer) {
                if (udp_send(&udp, buf, (size_t)n, &peer_addr) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_send error: %s\n",
                            cfg.name, strerror(errno));
                } else {
                    printf("[forgevpn] peer '%s' tun -> udp: %zd bytes\n", cfg.name, n);
                    fflush(stdout);
                }
            } else {
                printf("[forgevpn] peer '%s' captured packet: %zd bytes\n", cfg.name, n);
                fflush(stdout);
            }
        }

        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t n = udp_recv(&udp, buf, sizeof(buf), &from);
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_recv error: %s\n",
                            cfg.name, strerror(errno));
                }
            } else if (tun_write(&tun, buf, (size_t)n) < 0) {
                fprintf(stderr, "[forgevpn] peer '%s': tun_write error: %s\n",
                        cfg.name, strerror(errno));
            } else {
                printf("[forgevpn] peer '%s' udp -> tun: %zd bytes\n", cfg.name, n);
                fflush(stdout);
            }
        }
    }

    printf("[forgevpn] peer '%s' shutting down\n", cfg.name);
    udp_close(&udp);
    tun_close(&tun);
    return 0;
}
