# Docker Infrastructure

This document explains the design of ForgeVPN's Docker environment: why it
looks the way it does, and how it is expected to evolve alongside the VPN
implementation.

## Goals

* The host machine's networking must never require modification. All
  networking experiments happen inside Docker.
* Every peer runs in its own container, simulating an independent machine.
* A fresh clone must be runnable with a single command
  (`docker compose --profile demo up --build`), no manual setup.
* The environment must scale from a two-peer demo to many peers without
  architectural changes.

## Image design: multi-stage build

`docker/Dockerfile` has three stages:

1. **`builder`** — `debian:bookworm-slim` with `build-essential` and `cmake`.
   Compiles `forgevpn` via CMake. Nothing from this stage ships in the
   final image.
2. **`test`** — extends `builder` and simply runs `ctest`. Selected with
   `docker compose --profile test up`. Because it reuses the builder's
   toolchain, no image duplication is needed to keep test dependencies
   available.
3. **`runtime`** — a fresh `debian:bookworm-slim` layer containing only the
   compiled binary, `iproute2` (for inspecting TUN interfaces and routing
   tables from inside the container during development) and `iputils-ping`
   (for connectivity checks between peers). This is the image every peer
   service actually runs.

`debian:bookworm-slim` (glibc) was chosen over Alpine (musl) because
upcoming milestones introduce cryptography (X25519, ChaCha20-Poly1305),
where glibc-based distros have the least friction with common C crypto
libraries. The size cost relative to Alpine is small and acceptable for a
development/demo environment.

## Networking model

All peers attach to a single user-defined bridge network,
`forgevpn-net` (`10.10.0.0/24`), with static IP addresses assigned per
peer. This mirrors the target architecture: peers are independent hosts
that happen to share a network path (in real life, the public internet;
here, a Docker bridge), and they establish sessions directly with each
other rather than through a central server.

Each peer container is launched with:

* `cap_add: NET_ADMIN` — required to create and configure TUN interfaces
  and manage routes from inside the container.
* `devices: /dev/net/tun:/dev/net/tun` — exposes the kernel's TUN/TAP
  device so a peer can create its own virtual network interface without
  `--privileged`.

Static IPs make peer configuration files deterministic and reproducible
(peer2 is always reachable at `10.10.0.12` within the `forgevpn-net`
network), which matters once peers need to reference each other's
endpoints in their config.

## Compose profiles

`docker-compose.yml` defines one peer service per container plus a `test`
service, grouped with [Compose
profiles](https://docs.docker.com/compose/profiles/) so a single file
serves three different demonstrations:

| Profile       | Command                                            | What it starts                     |
|---------------|-----------------------------------------------------|-------------------------------------|
| `demo`        | `docker compose --profile demo up --build`          | `peer1`, `peer2` — minimal tunnel demo |
| `multi-peer`  | `docker compose --profile multi-peer up --build`    | `peer1`..`peer5` — scalability demo |
| `test`        | `docker compose --profile test up --build --abort-on-container-exit` | `test` — builds the `test` image stage and runs `ctest` |

Peer services share their configuration through the `x-peer-base` YAML
anchor to avoid duplicating the build context, capabilities, device
mounts, and network attachment across five near-identical service
definitions. Adding a `peer6` is a small, mechanical addition (copy one
block, bump the IP), not a structural change — this is what "naturally
supports multiple peers" means in Docker Compose terms.

## Peer configuration files

Each peer service mounts a read-only config file from `configs/<peer>.conf`
on the host to `/etc/forgevpn/forgevpn.conf` in the container:

```yaml
volumes:
  - ./configs/peer1.conf:/etc/forgevpn/forgevpn.conf:ro
```

This replaced an earlier version of this setup that passed peer identity
and addressing through `environment:` variables. See
[docs/CONFIGURATION.md](CONFIGURATION.md) for the file format itself.

## Current state vs. future work

`forgevpn` creates and configures its TUN interface, binds a UDP socket,
and bridges the two with a `poll()` loop, all driven by its mounted config
file — see [docs/NETWORKING.md](NETWORKING.md) for how packets actually
move. There is no key material yet; that arrives with the cryptography
milestones, at which point `configs/*.conf` and this Docker setup will
need to account for mounting (or generating) private keys as well.

As remaining milestones land, this document and `docker-compose.yml`
should be updated to reflect:

* Key material mounted per peer, once the cryptography milestones exist
  (likely alongside the existing `configs/` volume mounts).
* Any additional `sysctls` or capabilities required once real N-way
  routing (not just a fixed `[Peer]` endpoint) is implemented.
* CI usage of the `test` build stage (e.g. `docker build --target test`)
  once continuous integration is introduced.
