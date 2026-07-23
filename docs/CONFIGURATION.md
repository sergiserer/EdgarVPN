# Configuration

Each ForgeVPN peer reads its identity, interface, and remote peer from a
configuration file instead of environment variables. This document
describes the file format and how it is wired into the Docker environment.

## File format

An INI-style format with two sections, `[Interface]` and `[Peer]`,
deliberately styled after WireGuard's own config file syntax (`Address`,
`ListenPort`, `Endpoint`) — anyone who has configured WireGuard will
recognize it immediately. The parser is a small hand-written one
(`src/config.c`); there is no external dependency.

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
| `PrivateKey` | required if `[Peer]` is present | — | This peer's X25519 private key, base64-encoded (see `docs/CRYPTOGRAPHY.md`; generate with `forgevpn-keygen`). Not needed for a capture-only peer with no `[Peer]` section. |

### `[Peer]`

Optional. A peer with no `[Peer]` section still binds its UDP socket but
runs capture-only (see `docs/NETWORKING.md`) — it forwards nothing until
it has somewhere to forward to.

| Key         | Required (if section present) | Meaning                          |
|-------------|-------------------------------|-----------------------------------|
| `Endpoint`  | **yes**                       | Remote peer's `host:port`. `host` can be a hostname (e.g. a Docker Compose service name, resolved via Docker's embedded DNS) or an IPv4 literal. |
| `PublicKey` | **yes**                       | The remote peer's X25519 public key, base64-encoded. Must match the private key on the *other* peer's `[Interface]`. |
| `Role`      | **yes**                       | Either `initiator` or `responder`. Both peers must agree on exactly one of each -- see `docs/CRYPTOGRAPHY.md` for why. |

Only **one** `[Peer]` section is supported today, matching what the
transport module can actually do (a single fixed remote peer, not a
routing table). A second `[Peer]` section is a parse error rather than
being silently ignored. Real multi-peer support replaces this section
with something richer when the routing milestone lands.

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

The five files under `configs/` mirror the pairing already established in
`docs/NETWORKING.md`: `peer1`↔`peer2` and `peer3`↔`peer4` have a `[Peer]`
section pointing at each other with matching key pairs; `peer5` has
neither, and runs capture-only.

The demo key pairs committed under `configs/*.conf` were generated with
`forgevpn-keygen` solely for this repository's demo. They are public
(committed to source control) and carry no security value — never reuse
them, or any key generated the same way, outside this local Docker demo.
