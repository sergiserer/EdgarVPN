# Networking

This document covers ForgeVPN's addressing scheme and the TUN interface
module. It will grow to cover UDP transport, routing, and packet framing
as those milestones land.

## Two address spaces

ForgeVPN's Docker environment has two distinct networks, deliberately kept
separate:

* **Underlay (`10.10.0.0/24`, the `forgevpn-net` Docker bridge)** — the
  "physical" network each peer's container is attached to. In a real
  deployment this stands in for the public internet: peers exchange
  encrypted UDP packets across it, and it has no knowledge of VPN traffic.
* **Overlay (`10.8.0.0/24`, assigned to each peer's TUN interface)** — the
  virtual VPN network. This is the address space applications inside a
  peer would actually use to reach another peer once routing is
  implemented.

Keeping these separate — rather than reusing the Docker network's
addresses for the tunnel — mirrors how real VPNs (WireGuard, Tailscale)
work: the underlay is whatever network happens to connect two hosts, and
is irrelevant to the overlay addressing the VPN presents to applications.

Each peer's static assignment (set via the `TUN_ADDRESS` environment
variable in `docker-compose.yml`, one octet matching its underlay IP for
readability):

| Peer  | Underlay (Docker) | Overlay (TUN)  |
|-------|--------------------|-----------------|
| peer1 | 10.10.0.11         | 10.8.0.11       |
| peer2 | 10.10.0.12         | 10.8.0.12       |
| peer3 | 10.10.0.13         | 10.8.0.13       |
| peer4 | 10.10.0.14         | 10.8.0.14       |
| peer5 | 10.10.0.15         | 10.8.0.15       |

## TUN module (`include/tun.h`, `src/tun.c`)

A TUN device is a virtual, point-to-point network interface the kernel
exposes to user space as a file descriptor: writes to the fd become
inbound IP packets on the interface, and outbound packets the kernel
routes to the interface become reads from the fd. It operates at layer 3
(raw IP packets), as opposed to a TAP device (layer 2, Ethernet frames) —
layer 3 is the right level for a routed VPN that doesn't need to emulate
a LAN.

The module exposes five functions, deliberately kept small so the rest of
the codebase depends on an interface, not on `ioctl` details:

* `tun_open` — opens `/dev/net/tun`, issues `TUNSETIFF` with
  `IFF_TUN | IFF_NO_PI` to create the interface.
* `tun_configure` — assigns an IPv4 address and netmask (`SIOCSIFADDR`,
  `SIOCSIFNETMASK`) and brings the interface up (`SIOCSIFFLAGS` with
  `IFF_UP | IFF_RUNNING`).
* `tun_read` / `tun_write` — thin wrappers over `read`/`write` on the
  device fd, one IP packet per call.
* `tun_close` — releases the file descriptor.

Both `tun_open` and `tun_configure` require `CAP_NET_ADMIN`, which is why
every peer (and the `test` Compose service, which runs a real integration
test against this module) is granted that capability and access to
`/dev/net/tun` in `docker-compose.yml` — see `docs/DOCKER.md`.

The kernel UAPI headers (`<linux/if.h>`, `<linux/if_tun.h>`) are used
directly instead of glibc's `<net/if.h>`, which is the standard idiom for
this kind of code and avoids `struct ifreq` / `IFNAMSIZ` definitions
clashing between the two header sets.

### Current behavior

`forgevpn` currently opens and configures its TUN interface on startup and
loops reading packets from it, logging each packet's size. It does not yet
do anything with the packets — no encryption, no forwarding. That is
intentional: this milestone's scope is proving the interface works
end-to-end before the transport and crypto layers exist. The next
milestone (UDP transport) is what will actually move these bytes to
another peer.
