# ForgeVPN

> A WireGuard-inspired VPN built from scratch in C — peer-to-peer tunneling over Linux TUN interfaces, developed and demonstrated entirely through Docker.

ForgeVPN is a long-term systems programming project: implementing a modern VPN's core pieces (virtual networking, UDP transport, authenticated encryption, peer-to-peer session management) from first principles in C, rather than using an existing VPN library. It's built to be read — modular, documented, and reproducible with a single command.

---

## Tech stack

| Area              | Choice                                              |
|-------------------|------------------------------------------------------|
| Language           | C17                                                  |
| Build system       | CMake                                                |
| Containers         | Docker, Docker Compose (multi-profile environments)  |
| Networking         | Linux TUN interfaces, raw `ioctl` configuration, UDP sockets |
| Cryptography       | X25519 forward-secret handshake + ChaCha20-Poly1305 AEAD via libsodium (`crypto_kx`, `crypto_aead_chacha20poly1305_ietf`) |
| Testing            | ctest — unit and real-kernel integration tests        |
| Platform           | Linux                                                |

---

## Architecture

ForgeVPN is **peer-to-peer**: every node runs identical code, and there is no dedicated server. Any peer may initiate a connection; once the handshake completes, both sides have equal responsibilities. A node can talk to any number of peers at once — the demo runs a genuine 5-node **full mesh** (every peer connects directly to every other peer, no hub), because the architecture is meant to actually be decentralized, not just claim to be.

Each peer:

1. Owns a Linux **TUN interface** with its own virtual (overlay) IP address, through which the kernel delivers raw IP packets destined for the VPN.
2. Runs an independent live **handshake** with each configured peer over a single shared UDP socket, mixing ephemeral X25519 keys (via libsodium) into each exchange so the resulting session keys are **forward-secret** — generated fresh per relationship, wiped from memory right after use, never derived solely from long-term keys.
3. **Routes** outbound traffic to the right peer by destination address (`AllowedIPs`, the same mechanism WireGuard uses) and attributes inbound traffic back to the right peer by source address — every packet sealed and authenticated with **ChaCha20-Poly1305** before it goes out, and rejected unless it authenticates and passes a replay check (a sliding window, tolerant of UDP reordering) on the way in.
4. Sends periodic **keepalives** per relationship when idle, and automatically **reconnects** — a fresh handshake with a new ephemeral key pair — if that peer goes quiet for too long, e.g. after a restart.

Key rotation independent of a full reconnection isn't implemented yet — see [Current state](#current-state).

The entire development and demo environment runs in Docker — every peer is its own container, and Docker networks simulate independent machines on the internet. No host networking configuration is ever required.

---

## Getting started

Requirements: Docker and Docker Compose. No local C toolchain needed — the build happens inside the Docker image.

```bash
git clone <this-repository>
cd ForgeVPN
docker compose --profile demo up --build
```

Available profiles:

```bash
docker compose --profile demo up --build
# 2 peers on an isolated Docker network

docker compose --profile multi-peer up --build
# 5 peers in a full mesh -- every peer connects directly to every other one

docker compose --profile test up --build --abort-on-container-exit
# builds the project and runs the test suite (unit + real-kernel integration tests)
```

---

## Current state

What actually runs today, peer by peer:

* Each peer reads its identity, interface, keys, and any number of remote peers from a config file — a small hand-written INI-style parser (`[Interface]` + repeatable `[Peer]` sections, WireGuard-style key names), no external dependency. Keys come from `forgevpn-keygen`, a bundled CLI tool (`docker compose run --rm <peer> forgevpn-keygen`). The demo's 5 peer configs form a full mesh: 10 independent relationships, no hub.
* It then opens `/dev/net/tun`, creates a TUN interface, assigns it the configured virtual IP, and brings it up — all via direct `ioctl` calls (`TUNSETIFF`, `SIOCSIFADDR`, `SIOCSIFNETMASK`, `SIOCSIFFLAGS`), not shell commands.
* At startup, each configured relationship runs its own 2-message handshake over UDP: fresh ephemeral keys are exchanged (authenticated by, but never derived only from, each peer's long-term key), yielding forward-secret ChaCha20-Poly1305 session keys. A relationship where this node is the initiator resolves its peer's hostname up front; a responder relationship needs no DNS at all — it learns its peer's address from the first handshake message that authenticates, the same "endpoint roaming" idea WireGuard uses. Full protocol in [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md), including what it doesn't provide (no DoS protection, no identity hiding), not glossed over.
* A `poll()`-based event loop (1-second timeout, so it can check every relationship's timers even when idle) bridges the TUN device to one shared UDP socket for all peers: outbound packets are **routed** to the right peer by destination address (`AllowedIPs`) and dropped if no configured peer covers it or that relationship's handshake isn't established yet; every inbound datagram is attributed to a peer by source address, then must authenticate and pass a sliding-window replay check before being written to the TUN device. In the `multi-peer` profile, this is enough for a real `ping` between *any* two of the five peers' overlay addresses, not just adjacent ones — each routed independently to the right session.
* Each relationship sends its own keepalives when idle; if a peer restarts (verified by actually restarting a container mid-demo) the other side notices within `SESSION_TIMEOUT_MS` and reconnects automatically with a fresh ephemeral key pair, no manual intervention.
* All of this logs through a small leveled, structured logging module (`DEBUG`/`INFO`/`WARN`/`ERROR`, filtered by `LOG_LEVEL`, text or `LOG_FORMAT=json`) instead of ad hoc `printf`s, with each peer relationship tracking basic traffic/handshake/error counters logged periodically — `docker compose run --rm -e LOG_LEVEL=debug peer1` gets the full per-packet trace; the default is clean.
* Not yet implemented: key rotation independent of a full reconnection, and configurable keepalive/timeout intervals — see the roadmap below.

## Documentation

* [`docs/DOCKER.md`](docs/DOCKER.md) — Docker image and Compose network design: multi-stage builds, capabilities required for TUN, the profile system.
* [`docs/NETWORKING.md`](docs/NETWORKING.md) — the underlay/overlay addressing scheme, the TUN module, the UDP transport bridge, and multi-peer routing.
* [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) — the peer configuration file format, including the full-mesh demo topology.
* [`docs/CRYPTOGRAPHY.md`](docs/CRYPTOGRAPHY.md) — the X25519 handshake protocol, session lifecycle (keepalive/reconnection), the AEAD packet format, why libsodium, and what's not implemented yet.
* [`docs/LOGGING.md`](docs/LOGGING.md) — log levels, format, and the per-peer statistics.

---

## Roadmap

* [x] Docker infrastructure & build pipeline (multi-stage image, Compose profiles, CI-ready test target)
* [x] TUN interface module (create, configure, capture)
* [x] UDP transport between peers (`poll()`-based bridge, real ping round-trip in the demo profile)
* [x] Configuration file format (`[Interface]`/`[Peer]` INI-style, mounted per peer via Compose volumes)
* [x] X25519 key exchange (libsodium `crypto_kx`, keys from per-peer config)
* [x] ChaCha20-Poly1305 authenticated encryption + strict-monotonic replay check
* [x] Live handshake with ephemeral keys for forward secrecy (2-message, over UDP)
* [x] Session lifecycle: keepalive, automatic reconnection, sliding-window replay protection
* [x] Multi-peer routing (`AllowedIPs`-based, per-peer sessions, 5-node full mesh demo)
* [x] Structured logging and diagnostics (leveled + JSON-capable, per-peer statistics)
* [ ] Key rotation independent of a full reconnection
* [ ] Continuous integration

---

## Engineering philosophy

Readability is preferred over cleverness, correctness over premature optimization, and maintainability over unnecessary complexity. Every subsystem is designed to be replaceable — small modules with clear interfaces, high cohesion, low coupling — so the codebase stays approachable as it grows toward feature parity with the ideas behind WireGuard and Tailscale.
