# syntax=docker/dockerfile:1
# ---- build stage ----
FROM rust:1-slim-trixie AS builder

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libdbus-1-dev \
    libsqlite3-dev

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Cache mounts persist the cargo registry and compiled artifacts across builds.
# Binaries are copied out of the target cache mount so the runtime stage can
# COPY them — cache-mounted paths are not part of the image layer.
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/build/target \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    CARGO_PROFILE_RELEASE_LTO=false \
    cargo build --release --features ui -j1 \
    && strip target/release/pantalaimon target/release/panctl \
    && cp target/release/pantalaimon /pantalaimon \
    && cp target/release/panctl /panctl

# ---- runtime stage ----
FROM debian:trixie-slim

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libdbus-1-3 \
    libsqlite3-0 \
    dbus \
    ca-certificates

COPY --from=builder /pantalaimon /usr/local/bin/pantalaimon
COPY --from=builder /panctl      /usr/local/bin/panctl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Fixed socket path exported to both the daemon and any exec'd panctl.
ENV DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/pantalaimon-dbus.sock

VOLUME /data
ENTRYPOINT ["/entrypoint.sh"]
# Default: read config and data from the /data volume.
# Set UseKeyring = False in pantalaimon.conf — no OS keyring is available in
# containers; tokens are stored in /data/pan.db instead.
CMD ["-c", "/data/pantalaimon.conf", "--data-path", "/data"]
