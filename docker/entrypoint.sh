#!/bin/sh
# Entrypoint for the ForgeVPN peer runtime image.
#
# Kept as a separate script (rather than a bare ENTRYPOINT ["forgevpn"])
# so future milestones can add pre-flight steps here -- e.g. creating the
# TUN device, validating mounted config/key files -- without changing the
# Dockerfile.

set -eu

exec forgevpn "$@"
