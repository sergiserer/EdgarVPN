#ifndef FORGEVPN_TUN_H
#define FORGEVPN_TUN_H

#include <linux/if.h>
#include <sys/types.h>

/*
 * A Linux TUN device: a virtual, point-to-point network interface that
 * delivers raw IP packets to and from user space. This is the boundary
 * between the host's IP stack and ForgeVPN's own packet handling --
 * traffic routed to a peer's virtual address arrives here before it is
 * encrypted and sent over UDP (see the transport module, once it exists).
 */
typedef struct {
    int fd;
    char name[IFNAMSIZ];
} tun_device_t;

/*
 * Opens /dev/net/tun and creates a TUN (layer 3, no packet info) device.
 * `name_hint` requests a specific interface name (e.g. "forge0"); pass
 * NULL or an empty string to let the kernel assign the next free tunN.
 * On success, dev->name holds the name the kernel actually assigned.
 * Requires CAP_NET_ADMIN. Returns 0 on success, -1 on failure (errno set).
 */
int tun_open(tun_device_t *dev, const char *name_hint);

/*
 * Assigns an IPv4 address and netmask to the interface and brings it up
 * (IFF_UP | IFF_RUNNING). Requires CAP_NET_ADMIN.
 * Returns 0 on success, -1 on failure (errno set).
 */
int tun_configure(const tun_device_t *dev, const char *ipv4_address, const char *netmask);

/*
 * Reads one IP packet from the device into `buf`.
 * Returns the packet length in bytes, or -1 on error (errno set --
 * including EINTR if interrupted by a signal).
 */
ssize_t tun_read(const tun_device_t *dev, void *buf, size_t buf_len);

/*
 * Writes one IP packet to the device.
 * Returns the number of bytes written, or -1 on error (errno set).
 */
ssize_t tun_write(const tun_device_t *dev, const void *buf, size_t buf_len);

/*
 * Closes the underlying file descriptor. Safe to call on a device that
 * failed to open (leaves dev->fd untouched at its closed sentinel, -1).
 */
void tun_close(tun_device_t *dev);

#endif /* FORGEVPN_TUN_H */
