/*
 * Entry point for the ForgeVPN peer daemon.
 *
 * When a peer has a configured [Peer] (see docs/CONFIGURATION.md), it
 * runs a live handshake (src/session.c) with that peer before any data
 * flows: an initiator sends a HANDSHAKE_INIT and a responder replies
 * with a HANDSHAKE_RESPONSE, each carrying a fresh ephemeral public key.
 * Once both sides have derived matching forward-secret data keys from
 * that exchange, the session is established and the TUN device is
 * bridged to the UDP socket -- every outbound packet sealed, every
 * inbound datagram authenticated and replay-checked before being written
 * to the TUN device.
 *
 * This milestone adds session lifecycle management on top of that: an
 * idle established session sends periodic keepalives (empty DATA
 * messages) so the peer can tell it's still alive, and an initiator that
 * hasn't heard from its peer in too long assumes the session is dead
 * (the peer crashed, restarted, or network connectivity dropped) and
 * re-runs the handshake with a fresh ephemeral key pair. A responder
 * needs no equivalent timeout logic: it simply accepts a fresh
 * HANDSHAKE_INIT whenever one arrives, established or not (see
 * docs/CRYPTOGRAPHY.md for why that's safe). A peer with no [Peer]
 * section still runs capture-only, as before -- there is no session to
 * encrypt with, so none of this applies to it.
 */

#include "config.h"
#include "crypto.h"
#include "session.h"
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
#include <time.h>
#include <unistd.h>

#define DEFAULT_CONFIG_PATH "/etc/forgevpn/forgevpn.conf"
#define MAX_PACKET_SIZE 2048
#define SEALED_BUF_SIZE (SESSION_DATA_OVERHEAD + MAX_PACKET_SIZE)
#define ENDPOINT_RESOLVE_RETRIES 20
#define ENDPOINT_RESOLVE_DELAY_US 500000

/* How often the poll() loop wakes up even with no I/O, to check the
 * timers below. */
#define POLL_TIMEOUT_MS 1000
/* Send a keepalive (empty DATA message) if we haven't sent anything to
 * the peer in this long. Real WireGuard defaults to 25s; this is tuned
 * shorter so the behavior is easy to observe in a short demo run. */
#define KEEPALIVE_INTERVAL_MS 5000
/* Initiator only: assume the session is dead and re-handshake if we
 * haven't received anything valid from the peer in this long. */
#define SESSION_TIMEOUT_MS 15000

static volatile sig_atomic_t g_running = 1;
static const unsigned char EMPTY_PAYLOAD[1] = {0};

static void handle_shutdown(int signum)
{
    (void)signum;
    g_running = 0;
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
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

/* Builds and sends a HANDSHAKE_INIT for a fresh (or freshly-restarted)
 * session. Used both at startup and to re-handshake after a timeout. */
static int send_handshake_init(const char *peer_name, session_t *session, udp_socket_t *udp,
                                const struct sockaddr_in *peer_addr,
                                unsigned char *buf, size_t buf_len)
{
    ssize_t init_len = session_build_init(session, buf, buf_len);
    if (init_len < 0 || udp_send(udp, buf, (size_t)init_len, peer_addr) < 0) {
        fprintf(stderr, "[forgevpn] peer '%s': failed to send handshake init\n", peer_name);
        return -1;
    }
    printf("[forgevpn] peer '%s' sent handshake init, awaiting response\n", peer_name);
    fflush(stdout);
    return 0;
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
    session_t session;
    memset(&session, 0, sizeof(session));
    unsigned char cipher_buf[SEALED_BUF_SIZE];
    uint64_t last_rx_activity_ms = monotonic_ms();
    uint64_t last_tx_activity_ms = monotonic_ms();

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
        if (session_init(&session, cfg.role, &local_pk, &cfg.private_key,
                          &cfg.peer_public_key) != 0) {
            fprintf(stderr, "[forgevpn] peer '%s': failed to initialize session "
                             "(peer's PublicKey may be invalid)\n", cfg.name);
            udp_close(&udp);
            tun_close(&tun);
            return 1;
        }

        char peer_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
        printf("[forgevpn] peer '%s' up: interface '%s' (%s/%s), UDP :%u <-> peer %s:%u\n",
               cfg.name, tun.name, cfg.tun_address, cfg.tun_netmask, cfg.listen_port,
               peer_ip, ntohs(peer_addr.sin_port));

        if (cfg.role == CRYPTO_ROLE_INITIATOR) {
            if (send_handshake_init(cfg.name, &session, &udp, &peer_addr,
                                     cipher_buf, sizeof(cipher_buf)) != 0) {
                udp_close(&udp);
                tun_close(&tun);
                return 1;
            }
            last_tx_activity_ms = monotonic_ms();
        } else {
            printf("[forgevpn] peer '%s' awaiting handshake init from peer\n", cfg.name);
        }
        last_rx_activity_ms = monotonic_ms();
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

    while (g_running) {
        int ready = poll(fds, 2, POLL_TIMEOUT_MS);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "[forgevpn] peer '%s': poll error: %s\n", cfg.name, strerror(errno));
            break;
        }

        if (ready > 0 && (fds[0].revents & POLLIN)) {
            ssize_t n = tun_read(&tun, plain_buf, sizeof(plain_buf));
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': tun_read error: %s\n",
                            cfg.name, strerror(errno));
                }
            } else if (!cfg.has_peer) {
                printf("[forgevpn] peer '%s' captured packet: %zd bytes\n", cfg.name, n);
                fflush(stdout);
            } else if (session.state != SESSION_STATE_ESTABLISHED) {
                printf("[forgevpn] peer '%s' session not established yet, dropping "
                       "%zd-byte outbound packet\n", cfg.name, n);
                fflush(stdout);
            } else {
                ssize_t sealed_len = session_seal_data(&session, plain_buf, (size_t)n,
                                                         cipher_buf, sizeof(cipher_buf));
                if (sealed_len < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': failed to encrypt a %zd-byte packet\n",
                            cfg.name, n);
                } else if (udp_send(&udp, cipher_buf, (size_t)sealed_len, &peer_addr) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_send error: %s\n",
                            cfg.name, strerror(errno));
                } else {
                    last_tx_activity_ms = monotonic_ms();
                    printf("[forgevpn] peer '%s' tun -> udp: %zd bytes (sealed to %zd)\n",
                           cfg.name, n, sealed_len);
                    fflush(stdout);
                }
            }
        }

        if (ready > 0 && (fds[1].revents & POLLIN)) {
            struct sockaddr_in from;
            ssize_t n = udp_recv(&udp, cipher_buf, sizeof(cipher_buf), &from);
            if (n < 0) {
                if (errno != EINTR) {
                    fprintf(stderr, "[forgevpn] peer '%s': udp_recv error: %s\n",
                            cfg.name, strerror(errno));
                }
            } else if (!cfg.has_peer || n < 1) {
                printf("[forgevpn] peer '%s' received %zd bytes on UDP with no session, "
                       "dropping\n", cfg.name, n);
                fflush(stdout);
            } else if (cipher_buf[0] == SESSION_MSG_HANDSHAKE_INIT &&
                       cfg.role == CRYPTO_ROLE_RESPONDER) {
                unsigned char response[SESSION_HANDSHAKE_MSG_LEN];
                ssize_t response_len = session_handle_init(&session, cipher_buf, (size_t)n,
                                                             response, sizeof(response));
                if (response_len < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': rejected a malformed, "
                                     "unauthenticated, or stale handshake init\n", cfg.name);
                } else if (udp_send(&udp, response, (size_t)response_len, &peer_addr) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': failed to send handshake response: "
                                     "%s\n", cfg.name, strerror(errno));
                } else {
                    last_rx_activity_ms = monotonic_ms();
                    last_tx_activity_ms = last_rx_activity_ms;
                    printf("[forgevpn] peer '%s' handshake complete, session established\n",
                           cfg.name);
                    fflush(stdout);
                }
            } else if (cipher_buf[0] == SESSION_MSG_HANDSHAKE_RESPONSE &&
                       cfg.role == CRYPTO_ROLE_INITIATOR) {
                if (session_handle_response(&session, cipher_buf, (size_t)n) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': rejected a malformed, "
                                     "unauthenticated, or stale handshake response\n", cfg.name);
                } else {
                    last_rx_activity_ms = monotonic_ms();
                    printf("[forgevpn] peer '%s' handshake complete, session established\n",
                           cfg.name);
                    fflush(stdout);
                }
            } else if (cipher_buf[0] == SESSION_MSG_DATA) {
                ssize_t opened_len = session_open_data(&session, cipher_buf, (size_t)n,
                                                         plain_buf, sizeof(plain_buf));
                if (opened_len < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': dropping a data packet (not "
                                     "established, failed authentication, or replayed)\n",
                            cfg.name);
                } else if (opened_len == 0) {
                    last_rx_activity_ms = monotonic_ms();
                    printf("[forgevpn] peer '%s' received keepalive\n", cfg.name);
                    fflush(stdout);
                } else if (tun_write(&tun, plain_buf, (size_t)opened_len) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': tun_write error: %s\n",
                            cfg.name, strerror(errno));
                } else {
                    last_rx_activity_ms = monotonic_ms();
                    printf("[forgevpn] peer '%s' udp -> tun: %zd bytes (opened from %zd)\n",
                           cfg.name, opened_len, n);
                    fflush(stdout);
                }
            } else {
                fprintf(stderr, "[forgevpn] peer '%s': dropping unexpected message "
                                 "(type %u) for this peer's role/state\n",
                        cfg.name, (unsigned)cipher_buf[0]);
            }
        }

        if (cfg.has_peer) {
            uint64_t now = monotonic_ms();

            if (session.state == SESSION_STATE_ESTABLISHED &&
                now - last_tx_activity_ms >= KEEPALIVE_INTERVAL_MS) {
                ssize_t sealed_len = session_seal_data(&session, EMPTY_PAYLOAD, 0,
                                                         cipher_buf, sizeof(cipher_buf));
                if (sealed_len < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': failed to build keepalive\n",
                            cfg.name);
                } else if (udp_send(&udp, cipher_buf, (size_t)sealed_len, &peer_addr) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': failed to send keepalive: %s\n",
                            cfg.name, strerror(errno));
                } else {
                    printf("[forgevpn] peer '%s' sent keepalive\n", cfg.name);
                    fflush(stdout);
                }
                last_tx_activity_ms = now;
            }

            if (cfg.role == CRYPTO_ROLE_INITIATOR && now - last_rx_activity_ms >= SESSION_TIMEOUT_MS) {
                printf("[forgevpn] peer '%s' heard nothing from peer in %ums, re-handshaking\n",
                       cfg.name, (unsigned)(now - last_rx_activity_ms));
                fflush(stdout);
                session_start_handshake(&session);
                send_handshake_init(cfg.name, &session, &udp, &peer_addr,
                                     cipher_buf, sizeof(cipher_buf));
                last_rx_activity_ms = now;
                last_tx_activity_ms = now;
            }
        }
    }

    printf("[forgevpn] peer '%s' shutting down\n", cfg.name);
    udp_close(&udp);
    tun_close(&tun);
    return 0;
}
