# cblv — agent instructions

Work in a lane, never in ~/agents/scratch/ws. From the repo dir (full: .ci/verify.sh):
`cargo fmt --check`,
`cargo clippy --locked --all-features --all-targets -- -D warnings`,
`cargo test --locked --all-features`,
`RUSTFLAGS='--cfg getrandom_backend="wasm_js"' cargo check --locked
--no-default-features --features client,browser --target wasm32-unknown-unknown --lib`.
`client` builds for wasm32; `gateway` is native-only; `test-store` is tests-only:
the replay store is a contract, never process memory. No registry publication.

Invariants (tests/tests/roundtrip.rs):
- Relay sees only ciphertext; gateway sees the call, never the sender
  (round_trip_reaches_the_handler_unchanged:174; asserts ViaOhttp, no ConnectInfo).
- Replayed outer bytes refuse (400) without re-dispatch (:185).
- Tampered ciphertext never reaches the handler (:219).
- Broken replay store fails closed on mutates (503); reads bypass (:206).
- Unknown key id is KeyMismatch: refresh the signed feed, never fetch keys
  from the gateway (:233).
- Retired keys refuse after not_after + RETIRE_SKEW_SECONDS; overlap rotation
  keeps the live key (:243).
- Empty/unverified snapshot gives NoKey before any network use (:267).
- Relay auth required (404 without); non-/ohttp paths pass through (:301, :313).
- Padding classes with nonce/timestamp binding (src/codec.rs:195,204,227,240);
  feed keys replace, never merge, newest valid wins (src/keys.rs:218,233,258).

Pointers: README.md, src/codec.rs, src/keys.rs, src/client.rs, src/gateway.rs,
src/replay.rs, src/browser.rs, tests/roundtrip.rs, .ci/verify.sh.
