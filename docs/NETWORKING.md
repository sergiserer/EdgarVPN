# Networking

This document covers ForgeVPN's addressing scheme, the TUN interface
module, the UDP transport module, and multi-peer routing.

## Two address spaces

ForgeVPN's Docker environment has two distinct networks, deliberately kept
separate:

* **Underlay (`10.10.0.0/24`, the `forgevpn-net` Docker bridge)** — the
  "physical" network each peer's container is attached to. In a real
  deployment this stands in for the public internet: peers exchange
  encrypted UDP packets across it, and it has no knowledge of VPN traffic.
* **Overlay (`10.8.0.0/24`, assigned to each peer's TUN interface)** — the
  virtual VPN network. This is the address space applications inside a
  peer actually use to reach another peer.

Keeping these separate — rather than reusing the Docker network's
addresses for the tunnel — mirrors how real VPNs (WireGuard, Tailscale)
work: the underlay is whatever network happens to connect two hosts, and
is irrelevant to the overlay addressing the VPN presents to applications.

Each peer's static assignment (set via the `Address` key in its config
file, see `docs/CONFIGURATION.md`, one octet matching its underlay IP for
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
VPN traffic. Every peer shares **one** UDP socket for all of its
relationships; see "Multi-peer routing" below for how inbound datagrams
get attributed to the right one.

## Multi-peer routing (`include/routing.h`, `src/routing.c`)

A node can have any number of `[Peer]` relationships (see
`docs/CONFIGURATION.md`), each with its own handshake session
(`docs/CRYPTOGRAPHY.md`). Two problems follow from that: given an
outbound packet from the TUN device, which peer should it go to? And
given an inbound UDP datagram, which peer did it come from?

**Outbound (routing table lookup):** each `[Peer]` section has an
`AllowedIPs` CIDR range. `routing_parse_ipv4_dest` reads the destination
address straight out of the raw IPv4 header the kernel handed to the TUN
device (bytes 16-19, per RFC 791 -- no framework, just the same
by-hand-parsing spirit as the rest of this project), and
`routing_find_peer_for_dest` returns whichever configured peer's
`AllowedIPs` covers it -- the first match, in the order `[Peer]` sections
appear in the config file. No match means "no route to host": the packet
is dropped and logged, the same way a real router would refuse to
forward traffic it has no route for. A non-IPv4 packet (e.g. IPv6
neighbor discovery traffic the kernel sometimes puts on the TUN device)
is rejected the same way, since there's nothing meaningful to route it
by.

**Inbound (peer attribution):** every peer shares one UDP socket, so
`main.c` has to figure out who sent each datagram. The straightforward
case, `find_peer_by_addr`, matches the datagram's source address against
every peer whose address is already known. But a peer we're a
*responder* toward doesn't necessarily have a known address yet -- see
"Connecting without DNS" below.

## Connecting without DNS: initiators resolve, responders learn

Only an **initiator** relationship needs to resolve `Endpoint` up front:
it has to know where to send the first `HANDSHAKE_INIT`. A **responder**
relationship needs no DNS resolution at all. Its session is initialized
from the configured static keys alone (no network access required), and
it waits; when a `HANDSHAKE_INIT` arrives from an address it doesn't
recognize, `find_responder_for_init` tries that message against every
configured responder relationship's static keys until one successfully
authenticates it. On success, the sender's address is *learned* from the
packet itself and remembered from then on -- the same mechanism
WireGuard calls endpoint roaming.

This isn't just a nicety -- it fixes a real bug found while validating
the full 5-peer mesh (`docs/ROADMAP.md`, Milestone 8): in the `demo`
profile, `peer1` and `peer2` start at nearly the same moment, and it's a
coin flip which one Docker's embedded DNS finishes registering first. In
the earlier design, if `peer2` hadn't yet resolved `peer1`'s hostname for
its *own* bookkeeping, it would drop `peer1`'s incoming handshake init as
"from an unrecognized address" even though the init was perfectly valid
-- both sides would eventually recover once their independent 15-second
retry timers happened to align, but only after an avoidable delay.
Letting a responder learn its peer's address from the first authenticated
packet, instead of requiring it to resolve that peer's hostname itself
first, removes the race entirely: `peer2` doesn't need to know anything
about where `peer1` is until `peer1` proves who it is.

## Bridging TUN and UDP (`src/main.c`)

`forgevpn` runs a `poll()` loop over two file descriptors at once: the
TUN device and the UDP socket.

* **TUN readable** → a packet arrived from the kernel (e.g. an
  application sent traffic to another peer's overlay address). Routed by
  destination address (above) to a configured peer; forwarded via
  `udp_send`, sealed with ChaCha20-Poly1305, if that peer's session is
  established, dropped and logged otherwise. If no peers are configured
  at all, it is only logged (see "Capture-only peers" below).
* **UDP readable** → a datagram arrived from the network. Attributed to
  a peer as described above, then dispatched by its first (unencrypted)
  message-type byte (`docs/CRYPTOGRAPHY.md`): handshake messages advance
  that peer's session state machine; data messages are decrypted,
  authenticated, checked for replay, and only then written into the TUN
  device with `tun_write` -- anything that fails any of those checks is
  dropped, not written.

`poll()` was chosen over `select()` because it has no fixed
descriptor-set size limit and a cleaner API. It's given a 1-second
timeout (rather than blocking forever) so `main.c` can periodically check
every peer's keepalive/reconnection timers even when neither fd has
anything ready.

Tunnel traffic between established peers is encrypted, authenticated,
forward-secret, self-healing after a peer restarts, and tolerant of UDP
reordering — see `docs/CRYPTOGRAPHY.md` for the packet format, the
handshake protocol, and what security properties are (and are not)
provided yet.

### Session lifecycle

An idle established relationship sends a keepalive (an empty `DATA`
message) if it hasn't sent anything in `KEEPALIVE_INTERVAL_MS`. For each
relationship where this node is the initiator, it additionally tracks
how long it's been since it last heard *anything* valid from that peer;
past `SESSION_TIMEOUT_MS`, it assumes the session is dead (also retrying
DNS resolution if needed) and re-runs the handshake with a fresh
ephemeral key pair. A responder relationship needs no equivalent timer --
it simply accepts a fresh `HANDSHAKE_INIT` whenever one arrives,
established or not. Full reasoning and the counter-replay protection
that makes this safe are in `docs/CRYPTOGRAPHY.md`.

### Capture-only peers

A peer whose config file has no `[Peer]` sections still binds its UDP
socket (so a peer could theoretically reach it, though nothing will
authenticate without a matching key configured) but does not forward TUN
traffic anywhere — it just logs captured packet sizes. Not currently
used by any peer in the demo topology (see "Full mesh" in
`docs/CONFIGURATION.md`), but still exercised: `smoke_test.sh` runs
`forgevpn` with no `[Peer]` section at all.

### Demonstrated behavior

With the `multi-peer` profile, all five peers connect to all four others
(`docs/CONFIGURATION.md`'s full mesh) -- confirmed by each peer's log
showing exactly four `handshake complete` lines, one per relationship.
`ping` between *any* two peers' overlay addresses works directly, not
just adjacent ones: `peer1` → `peer5`, `peer2` → `peer4`, and
non-adjacent pairs all round-trip normally, each packet routed by
`routing_find_peer_for_dest` to the right session independently. With
the `demo` profile (`peer1`/`peer2` only, three of their four mesh
relationships pointing at peers that aren't running), those three
relationships log a calm, throttled "not resolvable yet" every 15
seconds rather than blocking startup or spamming — see "Connecting
without DNS" above.

### Known limitations

* No key rotation independent of a full reconnection, no DoS/flood
  protection on the handshake, and fixed (not configurable) keepalive/
  timeout intervals — see `docs/CRYPTOGRAPHY.md` for the full list.
* No handling of MTU/fragmentation: encryption adds a few bytes of
  overhead to every packet (1-byte type + `CRYPTO_PACKET_OVERHEAD`, 24
  bytes), which isn't accounted for against the TUN interface's MTU. Not
  yet a practical problem at the packet sizes this demo generates
  (ICMP), but worth revisiting before larger payloads.
* `AllowedIPs` holds exactly one `/32`-or-wider CIDR range per peer, not
  a comma-separated list like real WireGuard -- sufficient for this
  project's peers, each of which only ever advertises its own single
  overlay address.
* Routing is first-match over a flat list of up to 8 peers, not a
  longest-prefix-match trie -- fine at this scale, would need revisiting
  for a much larger mesh.
