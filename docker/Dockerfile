# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage: builder
# Compiles the project with CMake. Kept separate from the runtime image so
# the final image ships neither compilers nor build artifacts.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src
COPY include ./include
COPY tests ./tests

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --parallel

# ---------------------------------------------------------------------------
# Stage: test
# Reuses the builder's toolchain to run the test suite via ctest. Selected
# with `docker compose --profile test up`; never shipped as the runtime image.
# ---------------------------------------------------------------------------
FROM builder AS test

WORKDIR /src
CMD ["ctest", "--test-dir", "build", "--output-on-failure"]

# ---------------------------------------------------------------------------
# Stage: runtime
# Minimal image that actually runs as a VPN peer. Includes iproute2 for
# inspecting/managing the TUN interface and routing table inside the
# container, which is needed from the networking milestones onward.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/build/forgevpn /usr/local/bin/forgevpn
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
