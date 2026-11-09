#!/usr/bin/env bash
# Execute the manifest's selected checks with content-keyed result reuse.
set -euo pipefail
: "${CCID_BIN:?Missing verified ccid job runtime}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
: "${CI_REPOSITORY_URL:?Missing canonical repository identity}"
: "${CHECKS:?Missing declared check selection}"
if [ "$CHECKS" != "verify,advisories" ] && [ "$CHECKS" != "resolve-dependencies" ]; then
  echo "CHECKS must be verify,advisories or resolve-dependencies, got: $CHECKS" >&2
  exit 2
fi
cache_root=${CI_CACHE_ROOT:-${CARGO_HOME:-}}
[[ $cache_root = /* ]] || { echo 'An absolute persistent CI_CACHE_ROOT or CARGO_HOME is required' >&2; exit 2; }
export CI_CACHE_ROOT="$cache_root"
namespace=$(printf '%s' "$CI_REPOSITORY_URL" | sha256sum | cut -c1-24)
state="$cache_root/ccid-cached/$namespace"
toolchains=${CI_TOOLCHAIN_ROOT:-$cache_root/ccid-cached/toolchains}
[[ $toolchains = /* ]] || { echo 'CI_TOOLCHAIN_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$state" "$toolchains"
exec 9>"$state/lock"
flock -w "${CI_TIMEOUT:-2700}" 9
mkdir -p "$state/moon-cache/hashes" "$state/moon-cache/outputs" "$state/moon-home"
mkdir -p .moon/cache
ln -s "$state/moon-cache/hashes" .moon/cache/hashes
ln -s "$state/moon-cache/outputs" .moon/cache/outputs
# Tool installation is an explicit part of this job, in persistent CI storage.
# cblv has no git dependencies, so no insteadOf rewrite is set.
tool_source=github:NixOS/nixpkgs/b7c2ada94fe99c15b0dbcf4d11fd7850b957a436?narHash=sha256-IItrdb7Puk05RqOBWZYFC5X6Wl1sJmCfh5MWVHw5iMM=
tool_paths=$(nix build --no-link --print-out-paths "$tool_source#moon" "$tool_source#proto" "$tool_source#nodejs" "$tool_source#python3" "$tool_source#cargo-deny" "$tool_source#cargo-llvm-cov" "$tool_source#wasm-pack" "$tool_source#clang" "$tool_source#chromedriver" "$tool_source#chromium" "$tool_source#pkg-config" "$tool_source#openssl.dev" "$tool_source#openssl.out")
for path in $tool_paths; do PATH="$path/bin:$PATH"; done
for path in $tool_paths; do [ -d "$path/lib/pkgconfig" ] && PKG_CONFIG_PATH="$path/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"; done; export PKG_CONFIG_PATH
for path in $tool_paths; do [ -e "$path/lib/libcrypto.so.3" ] && LD_LIBRARY_PATH="$path/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"; done; export LD_LIBRARY_PATH
export PROTO_HOME="$toolchains/proto"
export MOON_HOME="$state/moon-home"
export PROTO_AUTO_CLEAN=false PROTO_TELEMETRY=false PROTO_YES=true
export RUSTUP_INIT_SKIP_PATH_CHECK=yes RUSTUP_TOOLCHAIN=stable
export PATH="$(dirname "$CCID_BIN"):$PROTO_HOME/shims:$PROTO_HOME/bin:$PATH"
export CI_JOBS="${CI_JOBS:-2}" CARGO_BUILD_JOBS="${CI_JOBS:-2}"
export RUST_TEST_THREADS="${CI_TEST_THREADS:-2}"
# Shared-first toolchain lock: jobs share a provisioned toolchain and take
# exclusive only to provision missing pieces. Same lock file, so old
# whole-job-exclusive runners interoperate (they just serialize).
# The stable wasm32 target is covered by TOOLCHAIN_WASM_TARGETS (provisioned
# under exclusive when missing); the unconditional `rustup target add` in
# verify.sh is removed, so no toolchain mutation executes downstream under
# the shared lock.
TOOLCHAIN_LOCK_FILE="$toolchains/install.lock"
TOOLCHAIN_LOCK_TIMEOUT="${CI_TIMEOUT:-2700}"
TOOLCHAIN_WANT_NIGHTLY=1
TOOLCHAIN_WASM_TARGETS="stable:wasm32-unknown-unknown"
# shellcheck source=toolchain-lock.sh
source "$(dirname "${BASH_SOURCE[0]}")/toolchain-lock.sh"
toolchain_ensure
cargo_bin=$(rustup which --toolchain stable cargo)
test -x "$cargo_bin"
export PATH="$(dirname "$cargo_bin"):$PATH"
export ARTIFACT_ROOT="${ARTIFACT_ROOT:-$state/release-artifacts}"
[[ "$ARTIFACT_ROOT" = /* ]] || { echo 'ARTIFACT_ROOT must be absolute' >&2; exit 2; }
mkdir -p "$ARTIFACT_ROOT"
export CCID_SOURCE_REVISION="$CI_COMMIT_SHA"
"$CCID_BIN" render --repo "$PWD" --check
if [ "$CHECKS" = "resolve-dependencies" ]; then
  exec "$CCID_BIN" check --repo "$PWD" --check "$CHECKS"
fi
proto --version
moon --version
rustc -vV
cargo --version
node --version
python3 --version
wasm-pack --version
clang --version
command -v cc
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "nix chromedriver not executable at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "nix chromium not executable at $CHROME_BIN" >&2; exit 2; }
chromedriver --version
chromium --version
cargo-deny --version
rustup run nightly rustc -vV
rustup run nightly cargo llvm-cov --version
"$CCID_BIN" cached --repo "$PWD" --check verify
test -s ".ccid/results/verify.jsonl"
"$CCID_BIN" check --repo "$PWD" --check advisories
