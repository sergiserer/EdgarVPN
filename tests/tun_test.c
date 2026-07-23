/*
 * Integration test for the TUN module. Creates a real TUN interface,
 * assigns it an address, and confirms both steps succeed. This must run
 * with CAP_NET_ADMIN and access to /dev/net/tun (granted to the `test`
 * Compose service) -- it is not a hermetic unit test, it exercises the
 * actual kernel interface, which is the point.
 */

#include "tun.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    tun_device_t dev;

    if (tun_open(&dev, "fgtest0") != 0) {
        perror("tun_open");
        return 1;
    }

    if (dev.name[0] == '\0') {
        fprintf(stderr, "tun_open: kernel returned an empty interface name\n");
        tun_close(&dev);
        return 1;
    }

    if (tun_configure(&dev, "10.8.0.250", "255.255.255.0") != 0) {
        perror("tun_configure");
        tun_close(&dev);
        return 1;
    }

    printf("tun_test: created and configured interface '%s'\n", dev.name);
    tun_close(&dev);
    printf("tun_test: passed\n");
    return 0;
}
