#include "udp.h"

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int udp_bind(udp_socket_t *sock, unsigned short port)
{
    sock->fd = -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    sock->fd = fd;
    return 0;
}

int udp_resolve(struct sockaddr_in *addr_out, const char *host, unsigned short port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *result = NULL;
    int rc = getaddrinfo(host, NULL, &hints, &result);
    if (rc != 0 || result == NULL) {
        return -1;
    }

    memcpy(addr_out, result->ai_addr, sizeof(*addr_out));
    addr_out->sin_port = htons(port);
    freeaddrinfo(result);
    return 0;
}

ssize_t udp_send(const udp_socket_t *sock, const void *buf, size_t len,
                  const struct sockaddr_in *dest)
{
    return sendto(sock->fd, buf, len, 0, (const struct sockaddr *)dest, sizeof(*dest));
}

ssize_t udp_recv(const udp_socket_t *sock, void *buf, size_t buf_len,
                  struct sockaddr_in *from_out)
{
    socklen_t from_len = sizeof(*from_out);
    return recvfrom(sock->fd, buf, buf_len, 0, (struct sockaddr *)from_out, &from_len);
}

void udp_close(udp_socket_t *sock)
{
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
}
