/*
 * Entry point for the EdgarVPN peer daemon.
 *
 * A peer can now have any number of [Peer] sections (see
 * docs/CONFIGURATION.md), each with its own live handshake (src/session.c),
 * forward-secret session, and AllowedIPs range. Outbound TUN traffic is
 * routed to whichever configured peer's AllowedIPs covers its
 * destination address (src/routing.c); inbound UDP datagrams are matched
 * back to a peer by source address, since every peer shares the same UDP
 * socket. A peer with no [Peer] sections still runs capture-only, as
 * before.
 *
 * Only an *initiator* relationship needs to resolve its peer's endpoint
 * up front, since it has to know where to send the first HANDSHAKE_INIT.
 * A *responder* relationship needs no DNS resolution at all: its session
 * is initialized from the configured static keys alone, and its peer's
 * address is *learned* from the source of the first HANDSHAKE_INIT that
 * successfully authenticates against those keys (the same idea
 * WireGuard calls endpoint roaming). This matters once a peer's config
 * lists other peers that may not be running yet -- see the multi-peer
 * Compose profile, where not every peer in the mesh is necessarily up at
 * the same time, and see docs/NETWORKING.md for the DNS-race bug this
 * design replaced.
 *
 * Logging goes through src/log.c (see docs/LOGGING.md) rather than raw
 * printf/fprintf: leveled (DEBUG/INFO/WARN/ERROR, filtered by LOG_LEVEL,
 * default INFO) so the default output stays readable while `LOG_LEVEL=
 * debug` still shows every packet. Each peer relationship also tracks
 * basic counters (bytes/packets, handshakes, auth failures, drops),
 * logged periodically as a diagnostic summary.
 */

#include "config.h"
#include "crypto.h"
#include "log.h"
#include "routing.h"
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

#define DEFAULT_CONFIG_PATH "/etc/edgarvpn/edgarvpn.conf"
#define MAX_PACKET_SIZE 2048
#define SEALED_BUF_SIZE (SESSION_DATA_OVERHEAD + MAX_PACKET_SIZE)

/* How often the poll() loop wakes up even with no I/O, to check the
 * timers below. */
#define POLL_TIMEOUT_MS 1000
/* Send a keepalive (empty DATA message) to an established peer if we
 * haven't sent it anything in this long. Real WireGuard defaults to
 * 25s; this is tuned shorter so the behavior is easy to observe in a
 * short demo run. */
#define KEEPALIVE_INTERVAL_MS 5000
/* For a peer we're the initiator toward: assume the session is dead and
 * re-handshake (which includes retrying DNS resolution) if we haven't
 * received anything valid from it in this long. */
#define SESSION_TIMEOUT_MS 15000
/* For a peer we're the initiator toward: proactively re-handshake an
 * already-established session after this long, bounding how long any one
 * set of data keys stays in use, independent of whether the peer is
 * actually still responsive. Deliberately much larger than
 * SESSION_TIMEOUT_MS so a healthy session always rotates on its own
 * schedule rather than racing the dead-peer timeout; real WireGuard's
 * REKEY_AFTER_TIME is 120s, this is tuned shorter for demo visibility. */
#define KEY_ROTATION_INTERVAL_MS 45000
/* How often to log each peer's traffic/handshake/error counters. */
#define STATS_INTERVAL_MS 30000

static volatile sig_atomic_t g_running = 1;
static const unsigned char EMPTY_PAYLOAD[1] = {0};

/* Runtime state for one configured peer: its resolved/learned address
 * (if any), its handshake/data session, the liveness timestamps that
 * drive keepalive and reconnection, and basic diagnostic counters. */
typedef struct {
    const config_peer_t *config;
    int addr_resolved;
    struct sockaddr_in addr;
    session_t session;
    uint64_t last_rx_activity_ms;
    uint64_t last_tx_activity_ms;
    uint64_t last_handshake_completed_ms;

    uint64_t stat_packets_tx;
    uint64_t stat_bytes_tx;
    uint64_t stat_packets_rx;
    uint64_t stat_bytes_rx;
    uint64_t stat_handshakes;
    uint64_t stat_auth_failures;
    uint64_t stat_drops;
} peer_session_t;

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

/*
 * Initiator only. Resolves the peer's endpoint if not already resolved
 * (a no-op, throttled retry if that fails -- not fatal), starts a fresh
 * handshake attempt, and sends a HANDSHAKE_INIT. Used both at startup
 * and to re-handshake after a timeout.
 */
static void initiate_handshake(peer_session_t *ps, const char *local_name, udp_socket_t *udp,
                                unsigned char *buf, size_t buf_len, uint64_t now)
{
    if (!ps->addr_resolved) {
        /* Set regardless of outcome, so a failed attempt is retried no
         * sooner than SESSION_TIMEOUT_MS from now, not every tick. */
        ps->last_rx_activity_ms = now;

        if (udp_resolve(&ps->addr, ps->config->host, ps->config->port) != 0) {
            log_warn(local_name, "'%s' not resolvable yet, will keep retrying",
                      ps->config->host);
            return;
        }
        ps->addr_resolved = 1;
    }

    session_start_handshake(&ps->session);
    ps->last_rx_activity_ms = now;
    ps->last_tx_activity_ms = now;

    ssize_t init_len = session_build_init(&ps->session, buf, buf_len);
    if (init_len < 0 || udp_send(udp, buf, (size_t)init_len, &ps->addr) < 0) {
        log_error(local_name, "failed to send handshake init to '%s'", ps->config->host);
        return;
    }
    log_info(local_name, "sent handshake init to '%s', awaiting response", ps->config->host);
}

/* Finds which peer a UDP datagram came from, by matching its source
 * address against every peer whose address we already know -- every
 * peer shares one UDP socket, so this is how inbound traffic normally
 * gets attributed. Returns NULL for a responder relationship whose
 * address hasn't been learned yet (see find_responder_for_init). */
static peer_session_t *find_peer_by_addr(peer_session_t *peers, int count,
                                          const struct sockaddr_in *from)
{
    for (int i = 0; i < count; i++) {
        if (peers[i].addr_resolved &&
            peers[i].addr.sin_addr.s_addr == from->sin_addr.s_addr &&
            peers[i].addr.sin_port == from->sin_port) {
            return &peers[i];
        }
    }
    return NULL;
}

/*
 * For a HANDSHAKE_INIT from a source address that find_peer_by_addr
 * didn't recognize: tries every configured responder relationship's
 * static keys until one successfully authenticates the message (a
 * relationship we're the initiator toward would never receive an INIT,
 * so those are skipped). session_handle_init's own auth check makes a
 * wrong guess a harmless no-op -- see docs/CRYPTOGRAPHY.md.
 *
 * On success, writes the HANDSHAKE_RESPONSE to `out` and returns the
 * matching peer; the caller is responsible for actually learning the
 * address (ps->addr = *from) once it decides the response was sent
 * successfully. Returns NULL if no configured responder relationship's
 * key authenticates this message.
 */
static peer_session_t *find_responder_for_init(peer_session_t *peers, int count,
                                                const unsigned char *in, size_t in_len,
                                                unsigned char *out, size_t out_len,
                                                ssize_t *response_len_out)
{
    for (int i = 0; i < count; i++) {
        if (peers[i].config->role != CRYPTO_ROLE_RESPONDER) {
            continue;
        }
        ssize_t response_len = session_handle_init(&peers[i].session, in, in_len, out, out_len);
        if (response_len >= 0) {
            *response_len_out = response_len;
            return &peers[i];
        }
    }
    return NULL;
}

/* Logs one INFO line per peer summarizing its traffic/handshake/error
 * counters -- the "Statistics" leg of docs/LOGGING.md's diagnostics. */
static void log_stats(const char *local_name, peer_session_t *peers, int count)
{
    for (int i = 0; i < count; i++) {
        peer_session_t *ps = &peers[i];
        log_info(local_name,
                  "stats peer=%s established=%s tx_packets=%llu tx_bytes=%llu "
                  "rx_packets=%llu rx_bytes=%llu handshakes=%llu auth_failures=%llu drops=%llu",
                  ps->config->host,
                  ps->session.state == SESSION_STATE_ESTABLISHED ? "yes" : "no",
                  (unsigned long long)ps->stat_packets_tx, (unsigned long long)ps->stat_bytes_tx,
                  (unsigned long long)ps->stat_packets_rx, (unsigned long long)ps->stat_bytes_rx,
                  (unsigned long long)ps->stat_handshakes,
                  (unsigned long long)ps->stat_auth_failures, (unsigned long long)ps->stat_drops);
    }
}

int main(void)
{
    log_init();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (crypto_init() != 0) {
        log_error("edgarvpn", "failed to initialize crypto library");
        return 1;
    }

    const char *config_path = getenv("CONFIG_FILE");
    if (config_path == NULL || config_path[0] == '\0') {
        config_path = DEFAULT_CONFIG_PATH;
    }

    edgarvpn_config_t cfg;
    if (config_load(config_path, &cfg) != 0) {
        return 1;
    }

    tun_device_t tun;
    if (tun_open(&tun, cfg.tun_name) != 0) {
        log_error(cfg.name, "failed to open TUN device '%s': %s", cfg.tun_name,
                   strerror(errno));
        return 1;
    }
    if (tun_configure(&tun, cfg.tun_address, cfg.tun_netmask) != 0) {
        log_error(cfg.name, "failed to configure TUN device '%s': %s", tun.name,
                   strerror(errno));
        tun_close(&tun);
        return 1;
    }

    udp_socket_t udp;
    if (udp_bind(&udp, cfg.listen_port) != 0) {
        log_error(cfg.name, "failed to bind UDP port %u: %s", cfg.listen_port,
                   strerror(errno));
        tun_close(&tun);
        return 1;
    }

    peer_session_t peers[CONFIG_MAX_PEERS];
    memset(peers, 0, sizeof(peers));
    unsigned char cipher_buf[SEALED_BUF_SIZE];
    crypto_public_key_t local_pk;

    if (cfg.peer_count > 0) {
        crypto_derive_public_key(&cfg.private_key, &local_pk);

        for (int i = 0; i < cfg.peer_count; i++) {
            peers[i].config = &cfg.peers[i];

            /* Static-key derivation needs no network access, so every
             * relationship -- initiator or responder -- gets its session
             * ready immediately. */
            if (session_init(&peers[i].session, cfg.peers[i].role, &local_pk, &cfg.private_key,
                              &cfg.peers[i].public_key) != 0) {
                log_error(cfg.name, "failed to initialize session with '%s' (its PublicKey "
                                     "may be invalid)", cfg.peers[i].host);
                udp_close(&udp);
                tun_close(&tun);
                return 1;
            }
            peers[i].last_rx_activity_ms = monotonic_ms();

            if (cfg.peers[i].role == CRYPTO_ROLE_INITIATOR) {
                initiate_handshake(&peers[i], cfg.name, &udp, cipher_buf, sizeof(cipher_buf),
                                    monotonic_ms());
            } else {
                log_info(cfg.name, "awaiting handshake init from '%s'", cfg.peers[i].host);
            }
        }

        log_info(cfg.name, "up: interface '%s' (%s/%s), UDP :%u, %d peer(s) configured",
                  tun.name, cfg.tun_address, cfg.tun_netmask, cfg.listen_port, cfg.peer_count);
    } else {
        log_info(cfg.name, "up: interface '%s' (%s/%s), UDP :%u, no peers configured "
                            "(capture-only)",
                  tun.name, cfg.tun_address, cfg.tun_netmask, cfg.listen_port);
    }

    struct pollfd fds[2];
    fds[0].fd = tun.fd;
    fds[0].events = POLLIN;
    fds[1].fd = udp.fd;
    fds[1].events = POLLIN;

    unsigned char plain_buf[MAX_PACKET_SIZE];
    uint64_t last_stats_ms = monotonic_ms();

    while (g_running) {
        int ready = poll(fds, 2, POLL_TIMEOUT_MS);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error(cfg.name, "poll error: %s", strerror(errno));
            break;
        }

        if (ready > 0 && (fds[0].revents & POLLIN)) {
            ssize_t n = tun_read(&tun, plain_buf, sizeof(plain_buf));
            if (n < 0) {
                if (errno != EINTR) {
                    log_warn(cfg.name, "tun_read error: %s", strerror(errno));
                }
            } else if (cfg.peer_count == 0) {
                log_info(cfg.name, "captured packet: %zd bytes", n);
            } else {
                struct in_addr dest;
                int idx = (routing_parse_ipv4_dest(plain_buf, (size_t)n, &dest) == 0)
                              ? routing_find_peer_for_dest(&cfg, dest)
                              : -1;
                if (idx < 0) {
                    log_debug(cfg.name, "no route for a %zd-byte outbound packet, dropping", n);
                } else if (peers[idx].session.state != SESSION_STATE_ESTABLISHED) {
                    log_debug(cfg.name, "session with '%s' not established yet, dropping "
                                         "%zd-byte packet", peers[idx].config->host, n);
                    peers[idx].stat_drops++;
                } else {
                    ssize_t sealed_len = session_seal_data(&peers[idx].session, plain_buf,
                                                             (size_t)n, cipher_buf,
                                                             sizeof(cipher_buf));
                    if (sealed_len < 0) {
                        log_error(cfg.name, "failed to encrypt a %zd-byte packet for '%s'",
                                   n, peers[idx].config->host);
                    } else if (udp_send(&udp, cipher_buf, (size_t)sealed_len,
                                         &peers[idx].addr) < 0) {
                        log_warn(cfg.name, "udp_send to '%s' error: %s",
                                   peers[idx].config->host, strerror(errno));
                    } else {
                        peers[idx].last_tx_activity_ms = monotonic_ms();
                        peers[idx].stat_packets_tx++;
                        peers[idx].stat_bytes_tx += (uint64_t)sealed_len;
                        log_debug(cfg.name, "tun -> udp (%s): %zd bytes (sealed to %zd)",
                                   peers[idx].config->host, n, sealed_len);
                    }
                }
            }
        }

        if (ready > 0 && (fds[1].revents & POLLIN)) {
            struct sockaddr_in from;
            ssize_t n = udp_recv(&udp, cipher_buf, sizeof(cipher_buf), &from);
            if (n < 0) {
                if (errno != EINTR) {
                    log_warn(cfg.name, "udp_recv error: %s", strerror(errno));
                }
            } else if (cfg.peer_count == 0 || n < 1) {
                log_debug(cfg.name, "received %zd bytes on UDP with no session, dropping", n);
            } else {
                peer_session_t *ps = find_peer_by_addr(peers, cfg.peer_count, &from);

                if (ps == NULL && cipher_buf[0] == SESSION_MSG_HANDSHAKE_INIT) {
                    unsigned char response[SESSION_HANDSHAKE_MSG_LEN];
                    ssize_t response_len = 0;
                    peer_session_t *matched = find_responder_for_init(
                        peers, cfg.peer_count, cipher_buf, (size_t)n,
                        response, sizeof(response), &response_len);

                    if (matched == NULL) {
                        char from_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
                        log_warn(cfg.name, "handshake init from %s:%u did not authenticate "
                                            "against any configured peer, dropping",
                                   from_ip, ntohs(from.sin_port));
                    } else if (udp_send(&udp, response, (size_t)response_len, &from) < 0) {
                        log_error(cfg.name, "failed to send handshake response to '%s': %s",
                                   matched->config->host, strerror(errno));
                    } else {
                        matched->addr = from;
                        matched->addr_resolved = 1;
                        matched->last_rx_activity_ms = monotonic_ms();
                        matched->last_tx_activity_ms = matched->last_rx_activity_ms;
                        matched->last_handshake_completed_ms = matched->last_rx_activity_ms;
                        matched->stat_handshakes++;
                        char from_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
                        log_info(cfg.name, "handshake complete with '%s' (learned endpoint "
                                            "%s:%u), session established",
                                   matched->config->host, from_ip, ntohs(from.sin_port));
                    }
                } else if (ps == NULL) {
                    char from_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
                    log_warn(cfg.name, "received a datagram from unrecognized %s:%u, dropping",
                               from_ip, ntohs(from.sin_port));
                } else if (cipher_buf[0] == SESSION_MSG_HANDSHAKE_INIT &&
                           ps->config->role == CRYPTO_ROLE_RESPONDER) {
                    /* Address already known (a prior handshake or DNS
                     * resolution); this is a straightforward (re)handshake. */
                    unsigned char response[SESSION_HANDSHAKE_MSG_LEN];
                    ssize_t response_len = session_handle_init(&ps->session, cipher_buf,
                                                                 (size_t)n, response,
                                                                 sizeof(response));
                    if (response_len < 0) {
                        log_warn(cfg.name, "rejected a malformed, unauthenticated, or stale "
                                            "handshake init from '%s'", ps->config->host);
                        ps->stat_auth_failures++;
                    } else if (udp_send(&udp, response, (size_t)response_len, &ps->addr) < 0) {
                        log_error(cfg.name, "failed to send handshake response to '%s': %s",
                                   ps->config->host, strerror(errno));
                    } else {
                        ps->last_rx_activity_ms = monotonic_ms();
                        ps->last_tx_activity_ms = ps->last_rx_activity_ms;
                        ps->last_handshake_completed_ms = ps->last_rx_activity_ms;
                        ps->stat_handshakes++;
                        log_info(cfg.name, "handshake complete with '%s', session established",
                                   ps->config->host);
                    }
                } else if (cipher_buf[0] == SESSION_MSG_HANDSHAKE_RESPONSE &&
                           ps->config->role == CRYPTO_ROLE_INITIATOR) {
                    if (session_handle_response(&ps->session, cipher_buf, (size_t)n) < 0) {
                        log_warn(cfg.name, "rejected a malformed, unauthenticated, or stale "
                                            "handshake response from '%s'", ps->config->host);
                        ps->stat_auth_failures++;
                    } else {
                        ps->last_rx_activity_ms = monotonic_ms();
                        ps->last_handshake_completed_ms = ps->last_rx_activity_ms;
                        ps->stat_handshakes++;
                        log_info(cfg.name, "handshake complete with '%s', session established",
                                   ps->config->host);
                    }
                } else if (cipher_buf[0] == SESSION_MSG_DATA) {
                    ssize_t opened_len = session_open_data(&ps->session, cipher_buf, (size_t)n,
                                                             plain_buf, sizeof(plain_buf));
                    if (opened_len < 0) {
                        log_warn(cfg.name, "dropping a data packet from '%s' (not "
                                            "established, failed authentication, or replayed)",
                                   ps->config->host);
                        ps->stat_auth_failures++;
                        ps->stat_drops++;
                    } else if (opened_len == 0) {
                        ps->last_rx_activity_ms = monotonic_ms();
                        log_debug(cfg.name, "received keepalive from '%s'", ps->config->host);
                    } else if (tun_write(&tun, plain_buf, (size_t)opened_len) < 0) {
                        log_error(cfg.name, "tun_write error: %s", strerror(errno));
                    } else {
                        ps->last_rx_activity_ms = monotonic_ms();
                        ps->stat_packets_rx++;
                        ps->stat_bytes_rx += (uint64_t)n;
                        log_debug(cfg.name, "udp -> tun (%s): %zd bytes (opened from %zd)",
                                   ps->config->host, opened_len, n);
                    }
                } else {
                    log_warn(cfg.name, "dropping unexpected message (type %u) from '%s' for "
                                        "its role/state", (unsigned)cipher_buf[0],
                               ps->config->host);
                    ps->stat_drops++;
                }
            }
        }

        if (cfg.peer_count > 0) {
            uint64_t now = monotonic_ms();

            for (int i = 0; i < cfg.peer_count; i++) {
                peer_session_t *ps = &peers[i];

                if (ps->addr_resolved && ps->session.state == SESSION_STATE_ESTABLISHED &&
                    now - ps->last_tx_activity_ms >= KEEPALIVE_INTERVAL_MS) {
                    ssize_t sealed_len = session_seal_data(&ps->session, EMPTY_PAYLOAD, 0,
                                                             cipher_buf, sizeof(cipher_buf));
                    if (sealed_len < 0) {
                        log_error(cfg.name, "failed to build keepalive for '%s'",
                                   ps->config->host);
                    } else if (udp_send(&udp, cipher_buf, (size_t)sealed_len, &ps->addr) < 0) {
                        log_warn(cfg.name, "failed to send keepalive to '%s': %s",
                                   ps->config->host, strerror(errno));
                    } else {
                        ps->stat_packets_tx++;
                        ps->stat_bytes_tx += (uint64_t)sealed_len;
                        log_debug(cfg.name, "sent keepalive to '%s'", ps->config->host);
                    }
                    ps->last_tx_activity_ms = now;
                }

                if (ps->config->role == CRYPTO_ROLE_INITIATOR &&
                    now - ps->last_rx_activity_ms >= SESSION_TIMEOUT_MS) {
                    if (ps->addr_resolved) {
                        log_warn(cfg.name, "heard nothing from '%s' in %ums, re-handshaking",
                                   ps->config->host, (unsigned)(now - ps->last_rx_activity_ms));
                    }
                    initiate_handshake(ps, cfg.name, &udp, cipher_buf, sizeof(cipher_buf), now);
                } else if (ps->config->role == CRYPTO_ROLE_INITIATOR &&
                           ps->session.state == SESSION_STATE_ESTABLISHED &&
                           now - ps->last_handshake_completed_ms >= KEY_ROTATION_INTERVAL_MS) {
                    /* Proactive rekey of a healthy session -- not a
                     * dead-peer recovery. Reuses the same handshake as
                     * reconnection, but triggered by key age rather than
                     * peer silence, against a peer we already know is
                     * responsive, so it normally completes in one
                     * round-trip instead of racing SESSION_TIMEOUT_MS. */
                    log_info(cfg.name, "rotating session keys with '%s' after %ums",
                               ps->config->host, (unsigned)(now - ps->last_handshake_completed_ms));
                    initiate_handshake(ps, cfg.name, &udp, cipher_buf, sizeof(cipher_buf), now);
                }
            }

            if (now - last_stats_ms >= STATS_INTERVAL_MS) {
                log_stats(cfg.name, peers, cfg.peer_count);
                last_stats_ms = now;
            }
        }
    }

    log_info(cfg.name, "shutting down");
    udp_close(&udp);
    tun_close(&tun);
    return 0;
}
