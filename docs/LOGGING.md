# Logging & Diagnostics

This document covers EdgarVPN's logging module (`include/log.h`,
`src/log.c`) and the basic per-peer statistics built on top of it.

## Why a logging module, not `printf`

Every earlier milestone logged with plain `printf`/`fprintf(stderr, ...)`
directly in `src/main.c`. That worked, but had no way to tell a routine
per-packet trace line from a security-relevant event without reading the
source, and no way to turn the noisy stuff off. `src/log.c` replaces
those calls with four leveled functions -- `log_debug`, `log_info`,
`log_warn`, `log_error` -- filtered by a single runtime setting, so the
default output stays readable while a full trace is still one
environment variable away.

## Levels

| Level | Used for |
|-------|----------|
| `DEBUG` | Per-packet traffic (`tun -> udp`, `udp -> tun`, keepalives sent/received), and routine drops that are expected background noise (e.g. non-IPv4 packets the kernel puts on the TUN device, packets arriving before a handshake finishes). |
| `INFO`  | Peer startup, handshake completion, shutdown, periodic stats summaries -- the events that tell you the daemon is doing what it should. |
| `WARN`  | Security-relevant or recoverable problems: authentication failures, replayed/out-of-window packets, an unresolvable peer endpoint, a session timing out and being re-handshaked. |
| `ERROR` | Failures that indicate something is actually broken: failing to open the TUN device, bind the UDP socket, or encrypt a packet that should always encrypt successfully. |

Set with the `LOG_LEVEL` environment variable (`debug`/`info`/`warn`/
`error`, case-insensitive). Defaults to `info` if unset or set to
something unrecognized -- a typo shouldn't silence or crash the daemon,
so it just falls back rather than erroring out.

```bash
docker compose run --rm -e LOG_LEVEL=debug peer1
```

`DEBUG` and `INFO` go to stdout; `WARN` and `ERROR` go to stderr --
matching the split earlier milestones already used, just made consistent
and level-driven instead of a mix of ad hoc choices at each call site.

## Format

| `LOG_FORMAT` | Output |
|--------------|--------|
| `text` (default) | `<ISO-8601 UTC timestamp> <LEVEL> [<component>] <message>` -- readable directly in `docker logs`. |
| `json` | One `{"time":...,"level":...,"component":...,"message":...}` object per line, message and component JSON-escaped -- meant for feeding into a real log aggregator (Loki, ELK, etc.), not for reading by eye. |

```bash
docker compose run --rm -e LOG_FORMAT=json peer1
```

`component` is always the peer's own `Name` (from its config file) --
every log line is attributable to which peer process emitted it, useful
once you're reading `docker compose logs` for several peers interleaved.

## Statistics

Each configured peer relationship (`peer_session_t` in `src/main.c`)
tracks plain counters as it runs:

* `tx_packets` / `tx_bytes` -- sealed packets (data and keepalives) sent
  to this peer.
* `rx_packets` / `rx_bytes` -- data packets successfully decrypted and
  written to the TUN device (keepalives aren't counted here, since they
  never reach the TUN device).
* `handshakes` -- completed handshakes (initial connections and
  reconnections both count).
* `auth_failures` -- packets that failed to authenticate (a bad
  handshake message, or a data packet that failed `crypto_open` or the
  replay check).
* `drops` -- packets discarded for any reason (auth failure, no route,
  session not established yet, unexpected message type).

Every `STATS_INTERVAL_MS` (30 seconds), one `INFO`-level line per peer is
logged with all of the above -- a lightweight, `docker logs`-native
alternative to a `wg show`-style status command, without needing to add
one.

## What this doesn't do

* No metrics export (Prometheus, StatsD, etc.) -- the periodic stats
  line is meant to be read, not scraped. Adding an export format would
  be straightforward on top of the same counters if a future milestone
  needs it.
* No packet-level tracing beyond `DEBUG` level -- there's no separate
  "dump full packet contents" mode.
* `LOG_LEVEL`/`LOG_FORMAT` are read once at startup (`log_init()`);
  changing them requires restarting the process, not a live reload.
