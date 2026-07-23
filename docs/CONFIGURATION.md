# Configuration

Each ForgeVPN peer reads its identity, interface, and remote peers from a
configuration file instead of environment variables. This document
describes the file format and how it is wired into the Docker environment.

## File format

An INI-style format with an `[Interface]` section and any number of
`[Peer]` sections, deliberately styled after WireGuard's own config file
syntax (`Address`, `ListenPort`, `Endpoint`, `AllowedIPs`) — anyone who
has configured WireGuard will recognize it immediately. The parser is a
small hand-written one (`src/config.c`); there is no external dependency.

* Lines starting with `#` or `;` are comments. Blank lines are ignored.
* Keys are case-insensitive (`Address`, `address`, and `ADDRESS` are
  equivalent).
* Unknown keys or sections, and lines outside of any section, are parse
  errors — the file is expected to be correct, not silently tolerant of
  typos.

### `[Interface]`

| Key          | Required | Default   | Meaning                                                   |
|--------------|----------|-----------|-------------------------------------------------------------|
| `Name`       | no       | `unnamed-peer` | Human-readable identity, used only in log output. It is not derived from the key pair, so it is a plain label rather than a WireGuard concept. |
| `DeviceName` | no       | `forge0`  | Name of the TUN interface to create.                       |
| `Address`    | **yes**  | —         | Overlay IP in CIDR form, e.g. `10.8.0.11/24`. The parser converts the prefix length to a dotted netmask internally. |
| `ListenPort` | no       | `51820`   | UDP port this peer binds to.                                |
| `PrivateKey` | required if any `[Peer]` is present | — | This peer's X25519 private key, base64-encoded (see `docs/CRYPTOGRAPHY.md`; generate with `forgevpn-keygen`). Not needed for a capture-only peer with no `[Peer]` sections. |

### `[Peer]`

Zero or more, up to `CONFIG_MAX_PEERS` (8). A peer with no `[Peer]`
sections still binds its UDP socket but runs capture-only (see
`docs/NETWORKING.md`) — it forwards nothing until it has somewhere to
forward to.

| Key          | Required (per section) | Meaning                          |
|--------------|-------------------------|-----------------------------------|
| `Endpoint`   | **yes**                 | Remote peer's `host:port`. `host` can be a hostname (e.g. a Docker Compose service name, resolved via Docker's embedded DNS) or an IPv4 literal. Only actually needed if `Role = initiator` -- see below. |
| `PublicKey`  | **yes**                 | The remote peer's X25519 public key, base64-encoded. Must match the private key on the *other* peer's `[Interface]`. |
| `Role`       | **yes**                 | Either `initiator` or `responder`. Both peers must agree on exactly one of each for this specific relationship -- see `docs/CRYPTOGRAPHY.md` for why. With more than two peers, a node can be `initiator` toward some and `responder` toward others at the same time; role is per-relationship, not global. |
| `AllowedIPs` | **yes**                 | A single overlay address in CIDR form, e.g. `10.8.0.12/32`, naming what's reachable through this peer. Outbound packets are routed to whichever `[Peer]` section's `AllowedIPs` covers their destination (`src/routing.c`) -- the same mechanism real WireGuard uses, simplified to one range per peer instead of a comma-separated list. |

Multiple `[Peer]` sections are supported (this is what lets a node talk
to more than two other peers at once -- see "Full mesh" below). Each
must independently have all four keys; an incomplete section (missing
any of them before the next `[Peer]`/`[Interface]` header or end of
file) is a parse error.

`Endpoint` is only actually used for a `Role = initiator` relationship,
where this peer must know where to send the first handshake message. A
`Role = responder` relationship doesn't need to resolve `Endpoint` at
all -- it learns the peer's real address from the first handshake
message that authenticates against `PublicKey`, the same idea WireGuard
calls endpoint roaming. `Endpoint` is still required in the file either
way, for symmetry and because a future milestone may use it for
responders too, but there is no need for it to currently be resolvable
if this section's `Role` is `responder`.

### Example

```ini
# ForgeVPN peer configuration
[Interface]
Name = peer1
DeviceName = forge0
Address = 10.8.0.11/24
ListenPort = 51820
PrivateKey = /gtFMtBv9uKoGzLmj7Mf5/1I3tQ9lLIaTKIeOtzkyJc=

[Peer]
Endpoint = peer2:51820
PublicKey = WH2RvdCDP2OfJ0K2WiFchwwi7XndB4uky9cYmQCAxEc=
Role = initiator
AllowedIPs = 10.8.0.12/32

[Peer]
Endpoint = peer3:51820
PublicKey = 0FVZjAkYgypGgyY0WCwES0D3uyhah916CLstGRmizWo=
Role = initiator
AllowedIPs = 10.8.0.13/32
```

Generate a key pair with:

```bash
docker compose run --rm peer1 forgevpn-keygen
```

`PrivateKey` goes in that peer's own `[Interface]`; the matching
`PublicKey` goes in the *other* peer's `[Peer]` section.

## How it's loaded

`forgevpn` reads its config from the path in the `CONFIG_FILE` environment
variable, defaulting to `/etc/forgevpn/forgevpn.conf` (the usual FHS
location for a daemon's config under `/etc`). In `docker-compose.yml`,
each peer service mounts its file from `configs/<peer>.conf` on the host
into that path, read-only:

```yaml
volumes:
  - ./configs/peer1.conf:/etc/forgevpn/forgevpn.conf:ro
```

### Full mesh

The five files under `configs/` connect every peer to every other peer
-- a full mesh, `C(5,2) = 10` relationships, no dedicated hub, matching
the peer-to-peer architecture described in `README.md`. Each peer has
four `[Peer]` sections, one per other peer, with a matching `AllowedIPs`
(each peer only advertises its own single overlay address). `Role` is
assigned by a simple deterministic rule so every pair agrees: **the
lower-numbered peer is the initiator toward the higher-numbered one.**
So `peer1` is `initiator` toward `peer2`/`peer3`/`peer4`/`peer5`;
`peer3` is `responder` toward `peer1`/`peer2` but `initiator` toward
`peer4`/`peer5`; `peer5` is `responder` toward all four others.

The demo key pairs committed under `configs/*.conf` were generated with
`forgevpn-keygen` solely for this repository's demo. They are public
(committed to source control) and carry no security value — never reuse
them, or any key generated the same way, outside this local Docker demo.
