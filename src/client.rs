//! Device side. Every member request to a server passes through one [`Wire`];
//! streams keep their direct connection and never use this module.
use crate::{Error, PATH, REQUEST_MEDIA, Result, codec, keys::KeySource};
use std::future::Future;

pub struct RawReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The outer POST to the relay. Native reqwest and browser fetch implement it.
/// Implementations must send no cookies, credentials or identifying headers.
pub trait Post {
    fn post(
        &self,
        url: &str,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<RawReply>>;
}

/// The single request/response seam.
pub trait Wire {
    fn exchange(&self, request: codec::Request) -> impl Future<Output = Result<codec::Response>>;
}

pub struct OhttpWire<P, K> {
    post: P,
    service: String,
    keys: K,
    clock: fn() -> u64,
}

impl<P: Post, K: KeySource> OhttpWire<P, K> {
    /// `service` is the gateway authority whose published key must be used;
    /// `keys` yields the verified relay and key from the signed trust feed.
    pub fn new(post: P, service: &str, keys: K, clock: fn() -> u64) -> Self {
        Self {
            post,
            service: service.to_owned(),
            keys,
            clock,
        }
    }

    /// Replace the key source (tests, rotation of a fixed source).
    pub fn set_keys(&mut self, keys: K) {
        self.keys = keys;
    }
}

impl<P: Post, K: KeySource> Wire for OhttpWire<P, K> {
    async fn exchange(&self, request: codec::Request) -> Result<codec::Response> {
        let now = (self.clock)();
        let (relay, key) = self.keys.current(&self.service, now).ok_or(Error::NoKey)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
        let inner = codec::encode_request(&request, &nonce, now)?;
        let client =
            ohttp::ClientRequest::from_encoded_config(&key.config).map_err(|_| Error::KeyConfig)?;
        let (outer, response) = client.encapsulate(&inner).map_err(|_| Error::Encapsulate)?;
        let reply = self
            .post
            .post(
                &format!("{}{PATH}", relay.trim_end_matches('/')),
                REQUEST_MEDIA,
                outer,
            )
            .await?;
        match reply.status {
            200 => {}
            401 => return Err(Error::KeyMismatch),
            status => return Err(Error::Status(status)),
        }
        let plain = response
            .decapsulate(&reply.body)
            .map_err(|_| Error::Decapsulate)?;
        codec::decode_response(&plain)
    }
}
