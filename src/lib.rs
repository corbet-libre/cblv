//! cblv: Oblivious HTTP (RFC 9458) for every request/response call from a member's
//! device to our servers. The relay sees who sends but only ciphertext; the
//! gateway sees the request but never the sender's address.
//!
//! * [`keys`]: the gateway key configuration as published in the signed trust feed.
//! * [`codec`]: inner Binary HTTP (RFC 9292) messages with replay binding and padding.
//! * [`replay`]: the store-backed replay cache contract (never process memory).
//! * `client` (feature): the device-side [`client::Wire`].
//! * `gateway` (feature): the tower layer in front of an axum router.
#![forbid(unsafe_code)]

pub mod codec;
pub mod keys;
pub mod replay;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "gateway")]
pub mod gateway;

pub const REQUEST_MEDIA: &str = "message/ohttp-req";
pub const RESPONSE_MEDIA: &str = "message/ohttp-res";
/// Accepted clock skew between device and gateway, both directions.
pub const WINDOW_SECONDS: u64 = 120;
/// How long a retired gateway key still decrypts after its published end.
pub const RETIRE_SKEW_SECONDS: u64 = 3600;

/// The single gateway path. Cloudflare's free plan allows one rate-limit rule,
/// so there are no separate lanes: one per-IP rule covers this path.
pub const PATH: &str = "/ohttp";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No published key is valid now for the service.
    NoKey,
    /// The published key configuration is malformed or unsupported.
    KeyConfig,
    /// Inner message could not be encoded or decoded.
    Codec,
    Random,
    Encapsulate,
    Decapsulate,
    /// The gateway does not know the key id: refresh the signed feed, never fetch a key from the gateway.
    KeyMismatch,
    /// Non-success outer status from the relay or gateway.
    Status(u16),
    Transport,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ohttp: {self:?}")
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
