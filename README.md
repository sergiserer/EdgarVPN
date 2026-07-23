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
| Cryptography (planned) | X25519 (ECDH), ChaCha20-Poly1305 AEAD           |
| Testing            | ctest — unit and real-kernel integration tests        |
| Platform           | Linux                                                |

---

## Architecture

ForgeVPN is **peer-to-peer**: every node runs identical code, and there is no dedicated server. Any peer may initiate a connection; once the handshake completes, both sides have equal responsibilities. The design intentionally avoids centralized components so it scales to many simultaneous peers without architectural changes.

Each peer:

1. Owns a Linux **TUN interface** with its own virtual (overlay) IP address, through which the kernel delivers raw IP packets destined for the VPN.
2. Will exchange those packets with other peers over a **UDP socket** (in progress).
3. Will authenticate and encrypt that traffic using an **X25519 key exchange** and **ChaCha20-Poly1305** (planned).

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
# 5 peers, demonstrating the architecture scales without changes

docker compose --profile test up --build --abort-on-container-exit
# builds the project and runs the test suite (unit + real-kernel integration tests)
```

---

## Current state

What actually runs today, peer by peer:

* Each peer opens `/dev/net/tun`, creates a TUN interface, assigns it a virtual IP, and brings it up — all via direct `ioctl` calls (`TUNSETIFF`, `SIOCSIFADDR`, `SIOCSIFNETMASK`, `SIOCSIFFLAGS`), not shell commands.
* The peer then captures real IP packets the kernel routes to that interface and logs them.
* Not yet implemented: sending those packets to another peer (UDP transport), encryption, routing, and a configuration file format — see the roadmap below.

## Documentation

* [`docs/DOCKER.md`](docs/DOCKER.md) — Docker image and Compose network design: multi-stage builds, capabilities required for TUN, the profile system.
* [`docs/NETWORKING.md`](docs/NETWORKING.md) — the TUN module design and the underlay/overlay addressing scheme.

---

## Roadmap

* [x] Docker infrastructure & build pipeline (multi-stage image, Compose profiles, CI-ready test target)
* [x] TUN interface module (create, configure, capture)
* [ ] UDP transport between peers
* [ ] Configuration file format (peer identity, endpoints, keys)
* [ ] X25519 key exchange
* [ ] ChaCha20-Poly1305 authenticated encryption, replay protection
* [ ] Session lifecycle (handshake state machine, keepalive, reconnection)
* [ ] Multi-peer routing and packet forwarding
* [ ] Structured logging and diagnostics
* [ ] Continuous integration

---

## Engineering philosophy

Readability is preferred over cleverness, correctness over premature optimization, and maintainability over unnecessary complexity. Every subsystem is designed to be replaceable — small modules with clear interfaces, high cohesion, low coupling — so the codebase stays approachable as it grows toward feature parity with the ideas behind WireGuard and Tailscale.
