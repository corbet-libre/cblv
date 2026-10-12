#!/usr/bin/env bash
# Resolve and retain the actual integration graph, not a validation verdict.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
cargo update
cargo metadata --locked --all-features --format-version 1 > dependency-metadata.json
cp Cargo.lock "$ARTIFACT_ROOT/resolve-dependencies-Cargo.lock"
cp dependency-metadata.json "$ARTIFACT_ROOT/resolve-dependencies-metadata.json"
sha256sum Cargo.lock dependency-metadata.json
echo 'Resolved dependency graph only; retain the lock in a commit and run verify.'
