# cblv

Oblivious HTTP (RFC 9458) for member-to-server calls: the device encapsulates
every request/response call to the gateway's key; a Cloudflare proxy in front
of the gateway sees the sender but only ciphertext; the gateway layer sees the
call but never the sender.

* `keys`: gateway key configurations as published in the signed trust feed.
* `codec`: inner Binary HTTP messages with nonce/timestamp binding and padding.
* `replay`: store-backed replay cache contract (never process memory).
* feature `client`: device-side `Wire` (builds for wasm32).
* feature `gateway`: tower layer for axum.
