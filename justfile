set dotenv-load := true

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

check:
    cargo check --locked --workspace --all-targets --all-features

test:
    cargo test --locked --workspace --all-features

clippy:
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# Real rustdoc check: fails on broken links and (via workspace lints)
# incomplete public documentation.
docs-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps

run:
    ZBIERAK_LISTEN_ADDR="${ZBIERAK_DEV_LISTEN_ADDR:-127.0.0.1:3000}" ZBIERAK_DATABASE_URL="${ZBIERAK_DEV_DATABASE_URL:-sqlite://data/zbierak.db}" ZBIERAK_STATIC_DIR=src/static ZBIERAK_TEMPLATE_DIR=src/templates cargo run --locked --package zbierak

verify: fmt-check check test clippy docs-check

docker-build:
    docker compose build

docker-up:
    docker compose up --build -d

docker-down:
    docker compose down

logs:
    docker compose logs --follow app

# Cold backup: stop writes and archive the complete persistent volume.
backup:
    #!/usr/bin/env sh
    set -eu
    mkdir -p backups
    archive="backups/zbierak-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    docker compose stop app
    trap 'docker compose start app >/dev/null' EXIT HUP INT TERM
    docker compose run --rm --no-deps --entrypoint sh app -c \
      'tar -C /data -czf - .' > "$archive"
    docker compose start app >/dev/null
    trap - EXIT HUP INT TERM
    printf '%s\n' "$archive"

# Destructive restore of the complete persistent volume from a cold backup.
restore archive:
    #!/usr/bin/env sh
    set -eu
    test -f "{{archive}}"
    docker compose down
    docker compose run --rm --no-deps --entrypoint sh app -c \
      'rm -rf /data/* /data/.[!.]* /data/..?*; tar -C /data -xzf -' < "{{archive}}"
    docker compose up -d
