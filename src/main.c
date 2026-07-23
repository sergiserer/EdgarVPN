/*
 * Entry point for the ForgeVPN peer daemon.
 *
 * When a peer has a configured [Peer] (see docs/CONFIGURATION.md), it
 * runs a live handshake (src/session.c) with that peer before any data
 * flows: an initiator sends a HANDSHAKE_INIT and a responder replies
 * with a HANDSHAKE_RESPONSE, each carrying a fresh ephemeral public key.
 * Once both sides have derived matching forward-secret data keys from
 * that exchange, the session is established and the TUN device is
 * bridged to the UDP socket exactly as in the previous milestone --
 * every outbound packet sealed, every inbound datagram authenticated and
 * replay-checked before being written to the TUN device. See
 * docs/CRYPTOGRAPHY.md for the full protocol and its current
 * limitations (no re-handshake/reconnection yet). A peer with no [Peer]
 * section still runs capture-only, as before -- there is no session to
 * encrypt with.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_CONFIG_PATH "/etc/forgevpn/forgevpn.conf"
#define MAX_PACKET_SIZE 2048
#define SEALED_BUF_SIZE (SESSION_DATA_OVERHEAD + MAX_PACKET_SIZE)
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
    session_t session;
    memset(&session, 0, sizeof(session));
    unsigned char cipher_buf[SEALED_BUF_SIZE];

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
            ssize_t init_len = session_build_init(&session, cipher_buf, sizeof(cipher_buf));
            if (init_len < 0 || udp_send(&udp, cipher_buf, (size_t)init_len, &peer_addr) < 0) {
                fprintf(stderr, "[forgevpn] peer '%s': failed to send handshake init\n",
                        cfg.name);
                udp_close(&udp);
                tun_close(&tun);
                return 1;
            }
            printf("[forgevpn] peer '%s' sent handshake init, awaiting response\n", cfg.name);
        } else {
            printf("[forgevpn] peer '%s' awaiting handshake init from peer\n", cfg.name);
        }
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
                    printf("[forgevpn] peer '%s' tun -> udp: %zd bytes (sealed to %zd)\n",
                           cfg.name, n, sealed_len);
                    fflush(stdout);
                }
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
                    fprintf(stderr, "[forgevpn] peer '%s': rejected a malformed or "
                                     "unauthenticated handshake init\n", cfg.name);
                } else if (udp_send(&udp, response, (size_t)response_len, &peer_addr) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': failed to send handshake response: "
                                     "%s\n", cfg.name, strerror(errno));
                } else {
                    printf("[forgevpn] peer '%s' handshake complete, session established\n",
                           cfg.name);
                    fflush(stdout);
                }
            } else if (cipher_buf[0] == SESSION_MSG_HANDSHAKE_RESPONSE &&
                       cfg.role == CRYPTO_ROLE_INITIATOR) {
                if (session_handle_response(&session, cipher_buf, (size_t)n) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': rejected a malformed or "
                                     "unauthenticated handshake response\n", cfg.name);
                } else {
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
                } else if (tun_write(&tun, plain_buf, (size_t)opened_len) < 0) {
                    fprintf(stderr, "[forgevpn] peer '%s': tun_write error: %s\n",
                            cfg.name, strerror(errno));
                } else {
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
    }

    printf("[forgevpn] peer '%s' shutting down\n", cfg.name);
    udp_close(&udp);
    tun_close(&tun);
    return 0;
}
