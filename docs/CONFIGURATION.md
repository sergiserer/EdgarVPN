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
| `Name`       | no       | `unnamed-peer` | Human-readable identity, used only in log output. ForgeVPN doesn't yet derive identity from a key pair (see the cryptography milestones), so this is a plain label rather than a WireGuard concept. |
| `DeviceName` | no       | `forge0`  | Name of the TUN interface to create.                       |
| `Address`    | **yes**  | —         | Overlay IP in CIDR form, e.g. `10.8.0.11/24`. The parser converts the prefix length to a dotted netmask internally. |
| `ListenPort` | no       | `51820`   | UDP port this peer binds to.                                |

### `[Peer]`

Optional. A peer with no `[Peer]` section still binds its UDP socket but
runs capture-only (see `docs/NETWORKING.md`) — it forwards nothing until
it has somewhere to forward to.

| Key        | Required (if section present) | Meaning                          |
|------------|-------------------------------|-----------------------------------|
| `Endpoint` | **yes**                       | Remote peer's `host:port`. `host` can be a hostname (e.g. a Docker Compose service name, resolved via Docker's embedded DNS) or an IPv4 literal. |

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

[Peer]
Endpoint = peer2:51820
```

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
section pointing at each other; `peer5` doesn't, and runs capture-only.
