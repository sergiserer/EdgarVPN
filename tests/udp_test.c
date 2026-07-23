/*
 * Integration test for the UDP module: binds two local sockets, sends a
 * datagram from one to the other over the loopback interface, and
 * verifies the payload and reported source address are correct.
 */

#include "udp.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define TEST_PORT_A 51900
#define TEST_PORT_B 51901

int main(void)
{
    udp_socket_t a;
    udp_socket_t b;

    if (udp_bind(&a, TEST_PORT_A) != 0) {
        perror("udp_bind a");
        return 1;
    }
    if (udp_bind(&b, TEST_PORT_B) != 0) {
        perror("udp_bind b");
        udp_close(&a);
        return 1;
    }

    struct sockaddr_in b_addr;
    if (udp_resolve(&b_addr, "127.0.0.1", TEST_PORT_B) != 0) {
        fprintf(stderr, "udp_resolve failed\n");
        udp_close(&a);
        udp_close(&b);
        return 1;
    }

    const char *msg = "forgevpn-udp-test";
    if (udp_send(&a, msg, strlen(msg), &b_addr) < 0) {
        perror("udp_send");
        udp_close(&a);
        udp_close(&b);
        return 1;
    }

    char buf[64];
    struct sockaddr_in from;
    ssize_t n = udp_recv(&b, buf, sizeof(buf), &from);
    if (n < 0) {
        perror("udp_recv");
        udp_close(&a);
        udp_close(&b);
        return 1;
    }

    if ((size_t)n != strlen(msg) || memcmp(buf, msg, (size_t)n) != 0) {
        fprintf(stderr, "udp_test: payload mismatch\n");
        udp_close(&a);
        udp_close(&b);
        return 1;
    }

    char from_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
    printf("udp_test: received %zd bytes from %s:%d\n", n, from_ip, ntohs(from.sin_port));

    udp_close(&a);
    udp_close(&b);
    printf("udp_test: passed\n");
    return 0;
}
