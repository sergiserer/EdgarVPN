#include "tun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int tun_open(tun_device_t *dev, const char *name_hint)
{
    memset(dev, 0, sizeof(*dev));
    dev->fd = -1;

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (name_hint != NULL && name_hint[0] != '\0') {
        strncpy(ifr.ifr_name, name_hint, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    dev->fd = fd;
    strncpy(dev->name, ifr.ifr_name, IFNAMSIZ - 1);
    return 0;
}

/* Fills ifr_addr (or ifr_netmask, same union member layout) with an IPv4
 * address parsed from `text`. Returns 0 on success, -1 on a parse error. */
static int set_ifreq_ipv4(struct sockaddr *dst, const char *text)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, text, &addr.sin_addr) != 1) {
        errno = EINVAL;
        return -1;
    }

    memcpy(dst, &addr, sizeof(addr));
    return 0;
}

int tun_configure(const tun_device_t *dev, const char *ipv4_address, const char *netmask)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ - 1);

    if (set_ifreq_ipv4(&ifr.ifr_addr, ipv4_address) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    if (set_ifreq_ipv4(&ifr.ifr_netmask, netmask) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    close(sock);
    return 0;
}

ssize_t tun_read(const tun_device_t *dev, void *buf, size_t buf_len)
{
    return read(dev->fd, buf, buf_len);
}

ssize_t tun_write(const tun_device_t *dev, const void *buf, size_t buf_len)
{
    return write(dev->fd, buf, buf_len);
}

void tun_close(tun_device_t *dev)
{
    if (dev->fd >= 0) {
        close(dev->fd);
        dev->fd = -1;
    }
}
