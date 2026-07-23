# Networking

This document covers ForgeVPN's addressing scheme, the TUN interface
module, and the UDP transport module. It will grow to cover routing and
packet framing as those milestones land.

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

## UDP transport module (`include/udp.h`, `src/udp.c`)

A thin wrapper over BSD sockets: bind a UDP socket, resolve a `host:port`
(including Docker Compose service names via the embedded DNS server) into
a `sockaddr_in`, and send/receive datagrams. Kept just as small as the TUN
module and deliberately protocol-agnostic — it doesn't know it's carrying
VPN traffic, which is what will let the cryptography milestones wrap
payloads before they reach `udp_send` without touching this module.

## Bridging TUN and UDP (`src/main.c`)

`forgevpn` now runs a `poll()` loop over two file descriptors at once: the
TUN device and the UDP socket.

* **TUN readable** → a packet arrived from the kernel (e.g. an application
  sent traffic to another peer's overlay address). If a peer endpoint is
  configured, the packet is forwarded via `udp_send` unmodified; otherwise
  it is only logged (see "Capture-only peers" below).
* **UDP readable** → a datagram arrived from the network. Its payload is
  written straight into the TUN device with `tun_write`; the kernel then
  routes it locally, exactly as if it had arrived on a physical interface.

`poll()` was chosen over `select()` because it has no fixed descriptor-set
size limit and a cleaner API — relevant once a later milestone needs to
watch several peer sockets at once for real multi-peer routing.

There is intentionally **no authentication or encryption** at this stage:
any datagram that reaches a peer's UDP port is written to its TUN device
as-is. This is safe only because the transport runs on an isolated Docker
network with no external exposure. Making this safe for a real network is
exactly what the X25519 key exchange and ChaCha20-Poly1305 milestones
exist to do.

### Capture-only peers

A peer with no `PEER_ENDPOINT` environment variable still binds its UDP
socket (so another peer could reach it) but does not forward TUN traffic
anywhere — it just logs captured packet sizes, as in the previous
milestone. This lets the `multi-peer` Compose profile keep working with an
odd number of peers before real N-way routing exists: `peer1`↔`peer2` and
`peer3`↔`peer4` are paired and forward traffic to each other; `peer5` runs
capture-only.

### Demonstrated behavior

With the `demo` profile (`peer1` ↔ `peer2`, `PEER_ENDPOINT` set on both),
a full round trip works: `ping 10.8.0.12` from inside `peer1` sends an
ICMP echo through `peer1`'s TUN, across UDP to `peer2`, into `peer2`'s TUN
— at which point the kernel on `peer2` treats it as normal inbound traffic
to its own address and generates an ICMP echo reply, which routes back out
through `peer2`'s TUN, back across UDP, and into `peer1`'s TUN, where the
original `ping` process receives it. No part of that path is VPN-specific
code recognizing ICMP; it works because both kernels see ordinary IP
traffic on a point-to-point interface.

### Known limitations

* No packet authentication: a container on the same Docker network could
  spoof traffic to a peer's UDP port. Addressed by the cryptography
  milestones.
* No handling of MTU/fragmentation overhead once packets carry
  encryption/framing overhead — revisit when the crypto milestones add
  bytes to each datagram.
* `PEER_ENDPOINT` is a single fixed remote peer, not a routing table —
  real multi-peer forwarding is future work (see the roadmap).
