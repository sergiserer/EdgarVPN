#!/bin/sh
# Smoke test invoked by ctest (see CMakeLists.txt).
#
# Verifies that the forgevpn binary starts (including opening and
# configuring its TUN device -- requires CAP_NET_ADMIN and /dev/net/tun,
# granted to the `test` Compose service) and terminates cleanly on
# SIGTERM.

set -eu

BIN="${1:?usage: smoke_test.sh <path-to-forgevpn-binary>}"

TUN_ADDRESS="10.8.0.254" TUN_NAME="fgsmoke0" "$BIN" &
PID=$!

sleep 1

if ! kill -0 "$PID" 2>/dev/null; then
    echo "smoke test failed: process exited prematurely"
    exit 1
fi

kill -TERM "$PID"
wait "$PID"
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
    echo "smoke test failed: exit status $STATUS"
    exit 1
fi

echo "smoke test passed"
