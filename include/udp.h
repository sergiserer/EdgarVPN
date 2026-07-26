#ifndef EDGARVPN_UDP_H
#define EDGARVPN_UDP_H

#include <netinet/in.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * A UDP socket used as EdgarVPN's transport: peers exchange datagrams
 * carrying raw IP packets (today) and, once the cryptography milestones
 * land, encrypted/authenticated packets instead.
 */
typedef struct {
    int fd;
} udp_socket_t;

/*
 * Opens a UDP socket and binds it to 0.0.0.0:`port`.
 * Returns 0 on success, -1 on failure (errno set).
 */
int udp_bind(udp_socket_t *sock, unsigned short port);

/*
 * Resolves `host` (a hostname -- including Docker Compose service names
 * via the embedded DNS server -- or an IPv4 literal) and `port` into
 * `addr_out`. Returns 0 on success, -1 if resolution failed.
 */
int udp_resolve(struct sockaddr_in *addr_out, const char *host, unsigned short port);

/*
 * Sends one datagram to `dest`.
 * Returns the number of bytes sent, or -1 on error (errno set).
 */
ssize_t udp_send(const udp_socket_t *sock, const void *buf, size_t len,
                  const struct sockaddr_in *dest);

/*
 * Receives one datagram, filling `from_out` with the sender's address.
 * Returns the number of bytes received, or -1 on error (errno set --
 * including EINTR if interrupted by a signal).
 */
ssize_t udp_recv(const udp_socket_t *sock, void *buf, size_t buf_len,
                  struct sockaddr_in *from_out);

/* Closes the underlying file descriptor. Safe to call on a socket that
 * failed to open (leaves sock->fd untouched at its closed sentinel, -1). */
void udp_close(udp_socket_t *sock);

#endif /* EDGARVPN_UDP_H */
