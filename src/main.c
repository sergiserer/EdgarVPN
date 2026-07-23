/*
 * Entry point for the ForgeVPN peer daemon.
 *
 * When a peer has a configured [Peer] (see docs/CONFIGURATION.md), it
 * derives session keys from its own PrivateKey and the peer's PublicKey
 * at startup (see docs/CRYPTOGRAPHY.md for why this happens locally
 * rather than over a live handshake, and its forward-secrecy
 * limitation), then bridges its TUN device to a UDP socket exactly as
 * in the previous milestone -- except every packet is now sealed with
 * ChaCha20-Poly1305 before being sent, and every inbound datagram must
 * authenticate and pass a monotonic replay check before being written to
 * the TUN device. A peer with no [Peer] section still runs capture-only,
 * as before -- there is no session to encrypt with.
 */

#include "config.h"
#include "crypto.h"
#include "tun.h"
#include "udp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
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

    if (crypto_init() != 0) {
        fprintf(stderr, "[forgevpn] failed to initialize crypto library\n");
        return 1;
    }

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
    crypto_session_keys_t session_keys;
    memset(&session_keys, 0, sizeof(session_keys));

    if (cfg.has_peer) {
        if (resolve_peer_with_retry(cfg.name, cfg.peer_host, cfg.peer_port, &peer_addr) != 0) {
            fprintf(stderr, "[forgevpn] peer '%s': could not resolve peer endpoint '%s:%u'\n",
                    cfg.name, cfg.peer_host, cfg.peer_port);
            udp_close(&udp);
            tun_close(&tun);
            return 1;
        }

        crypto_public_key_t local_pk;
        crypto_derive_public_key(&cfg.private_key, &local_pk);
        if (crypto_derive_session_keys(cfg.role, &local_pk, &cfg.private_key,
                                        &cfg.peer_public_key, &session_keys) != 0) {
            fprintf(stderr, "[forgevpn] peer '%s': failed to derive session keys "
                             "(peer's PublicKey may be invalid)\n", cfg.name);
            udp_close(&udp);
            tun_close(&tun);
            return 1;
        }

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
        printf("[forgevpn] peer '%s' up: interface '%s' (%s/%s), UDP :%u <-> peer %s:%u "
               "(encrypted session established)\n",
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

    unsigned char plain_buf[MAX_PACKET_SIZE];
    unsigned char cipher_buf[MAX_PACKET_SIZE + CRYPTO_PACKET_OVERHEAD];
    uint64_t tx_counter = 0;
    uint64_t highest_rx_counter = 0;
    int have_received_any = 0;

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
            ssize_t n = tun_read(&tun, plain_buf, sizeof(plain_buf));
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': tun_read error: %s\n",
                            cfg.name, strerror(errno));
                }
            } else if (cfg.has_peer) {
                ssize_t sealed_len = crypto_seal(session_keys.tx, tx_counter, plain_buf,
                                                  (size_t)n, cipher_buf, sizeof(cipher_buf));
                if (sealed_len < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': failed to encrypt a %zd-byte packet\n",
                            cfg.name, n);
                } else if (udp_send(&udp, cipher_buf, (size_t)sealed_len, &peer_addr) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_send error: %s\n",
                            cfg.name, strerror(errno));
                } else {
                    tx_counter++;
                    printf("[forgevpn] peer '%s' tun -> udp: %zd bytes (sealed to %zd)\n",
                           cfg.name, n, sealed_len);
                    fflush(stdout);
                }
            } else {
                printf("[forgevpn] peer '%s' captured packet: %zd bytes\n", cfg.name, n);
                fflush(stdout);
            }
        }

        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            ssize_t n = udp_recv(&udp, cipher_buf, sizeof(cipher_buf), &from);
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_recv error: %s\n",
                            cfg.name, strerror(errno));
                }
            } else if (!cfg.has_peer) {
                printf("[forgevpn] peer '%s' received %zd bytes on UDP but no peer is "
                       "configured, dropping\n", cfg.name, n);
                fflush(stdout);
            } else {
                uint64_t counter = 0;
                ssize_t opened_len = crypto_open(session_keys.rx, cipher_buf, (size_t)n,
                                                  plain_buf, sizeof(plain_buf), &counter);
                if (opened_len < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': dropping a packet that failed "
                                     "authentication\n", cfg.name);
                } else if (have_received_any && counter <= highest_rx_counter) {
                    fprintf(stderr, "[forgevpn] peer '%s': dropping replayed/out-of-order "
                                     "packet (counter=%llu)\n",
                            cfg.name, (unsigned long long)counter);
                } else if (tun_write(&tun, plain_buf, (size_t)opened_len) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': tun_write error: %s\n",
                            cfg.name, strerror(errno));
                } else {
                    have_received_any = 1;
                    highest_rx_counter = counter;
                    printf("[forgevpn] peer '%s' udp -> tun: %zd bytes (opened from %zd)\n",
                           cfg.name, opened_len, n);
                    fflush(stdout);
                }
            }
        }
    }

    printf("[forgevpn] peer '%s' shutting down\n", cfg.name);
    udp_close(&udp);
    tun_close(&tun);
    return 0;
}
