#!/bin/sh
# Entrypoint for the EdgarVPN runtime image.
#
# Execs whatever command the container was given, defaulting to the peer
# daemon (see CMD in docker/Dockerfile). This is the standard Docker
# entrypoint idiom: it lets `docker compose run --rm <service>
# edgarvpn-keygen` run a different bundled binary instead of always
# forcing `edgarvpn`. Kept as a separate script (rather than a bare
# ENTRYPOINT ["edgarvpn"]) so future milestones can add pre-flight steps
# here -- e.g. validating mounted config/key files -- without changing
# the Dockerfile.

set -eu

exec "$@"
