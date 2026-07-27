run:
    cargo run

ex-comms:
    RUST_LOG=info cargo run --example comms_example

ex-signup:
    cargo run --example signup_example 

reset-db:
    cargo sqlx database reset --force -y

test:
    cargo test --all-features

generate-keys:
    #!/bin/bash
    openssl genrsa -out /tmp/private.pem 2048 2>/dev/null
    openssl rsa -in /tmp/private.pem -pubout -out /tmp/public.pem 2>/dev/null
    echo "APP__AUTH__PRIVATE_KEY_BASE64=$(cat /tmp/private.pem | base64 | tr -d '\n')"
    echo ""
    echo "APP__AUTH__PUBLIC_KEY_BASE64=$(cat /tmp/public.pem | base64 | tr -d '\n')"
    rm /tmp/private.pem /tmp/public.pem

local-ci:
    #!/bin/bash
    set -e
    echo "=== Checking format ==="
    cargo fmt --all -- --check
    echo "=== Running clippy ==="
    cargo clippy --all-targets --all-features -- -D warnings
    echo "=== Running check ==="
    cargo check --all-targets --all-features
    echo "=== Running tests ==="
    cargo test --all-features
    echo "=== Running audit ==="
    cargo audit --ignore RUSTSEC-2023-0071
    echo "=== All checks passed! ==="

prepare-sqlx:
    cargo sqlx prepare -- --all-targets