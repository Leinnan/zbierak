# syntax=docker/dockerfile:1.7
FROM rust:1-bookworm AS builder

WORKDIR /app

# Copy the complete workspace so Cargo can resolve every local path dependency.
# BuildKit cache mounts keep repeated builds reasonably fast without assuming a
# particular crates/* layout or requiring manifests to be copied individually.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --locked --release --package zbierak && \
    install -Dm0755 target/release/zbierak /out/zbierak

FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --gid 10001 zbierak && \
    useradd --uid 10001 --gid 10001 --no-create-home --home-dir /app \
      --shell /usr/sbin/nologin zbierak && \
    mkdir -p /app /data && \
    chown -R 10001:10001 /app /data

WORKDIR /app
# Templates and static assets are embedded in the binary, so the runtime
# image needs nothing but the executable itself.
COPY --from=builder --chown=10001:10001 /out/zbierak /usr/local/bin/zbierak

ENV ZBIERAK_LISTEN_ADDR=0.0.0.0:3000 \
    ZBIERAK_DATABASE_URL=sqlite:///data/zbierak.db?mode=rwc \
    ZBIERAK_COOKIE_SECURE=false \
    ZBIERAK_SESSION_DAYS=30 \
    RUST_LOG=zbierak=info

USER 10001:10001
EXPOSE 3000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:3000/ready >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/zbierak"]
