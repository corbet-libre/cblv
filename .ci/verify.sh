#!/usr/bin/env bash
# .ci/verify.sh for cblv: format, lint, tests (native, all features) and the
# wasm32 client build. No coverage gate is claimed here.
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
cargo fmt --check
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --all-features
# Browser build of the device side: pure-Rust HPKE, getrandom's browser backend.
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo check --locked --no-default-features --features client,browser --target wasm32-unknown-unknown --lib
