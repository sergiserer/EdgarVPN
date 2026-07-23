#!/bin/sh
# Entrypoint for the ForgeVPN runtime image.
#
# Execs whatever command the container was given, defaulting to the peer
# daemon (see CMD in docker/Dockerfile). This is the standard Docker
# entrypoint idiom: it lets `docker compose run --rm <service>
# forgevpn-keygen` run a different bundled binary instead of always
# forcing `forgevpn`. Kept as a separate script (rather than a bare
# ENTRYPOINT ["forgevpn"]) so future milestones can add pre-flight steps
# here -- e.g. validating mounted config/key files -- without changing
# the Dockerfile.

set -eu

exec "$@"
