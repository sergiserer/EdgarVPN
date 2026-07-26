#!/bin/sh
# Smoke test invoked by ctest (see CMakeLists.txt).
#
# Verifies that the edgarvpn binary starts (including opening and
# configuring its TUN device -- requires CAP_NET_ADMIN and /dev/net/tun,
# granted to the `test` Compose service) and terminates cleanly on
# SIGTERM.

set -eu

BIN="${1:?usage: smoke_test.sh <path-to-edgarvpn-binary>}"

CONFIG_PATH="/tmp/edgarvpn_smoke_test.conf"
cat > "$CONFIG_PATH" <<'EOF'
[Interface]
Name = smoke-test-peer
DeviceName = fgsmoke0
Address = 10.8.0.254/24
EOF

CONFIG_FILE="$CONFIG_PATH" "$BIN" &
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
