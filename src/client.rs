//! Device side. Every member request to a server passes through one [`Wire`];
//! streams keep their direct connection and never use this module.
use crate::{Error, PATH, REQUEST_MEDIA, Result, codec, keys::VerifiedKeys};
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

pub struct OhttpWire<P> {
    post: P,
    url: String,
    service: String,
    keys: VerifiedKeys,
    clock: fn() -> u64,
}

impl<P: Post> OhttpWire<P> {
    /// `relay` is the base URL of the proxied gateway host; `service` the gateway authority whose
    /// published key must be used.
    pub fn new(
        post: P,
        relay: &str,
        service: &str,
        keys: VerifiedKeys,
        clock: fn() -> u64,
    ) -> Self {
        let base = relay.trim_end_matches('/');
        Self {
            post,
            url: format!("{base}{PATH}"),
            service: service.to_owned(),
            keys,
            clock,
        }
    }

    /// Replace the keys after a verified feed refresh (rotation).
    pub fn set_keys(&mut self, keys: VerifiedKeys) {
        self.keys = keys;
    }
}

impl<P: Post> Wire for OhttpWire<P> {
    async fn exchange(&self, request: codec::Request) -> Result<codec::Response> {
        let now = (self.clock)();
        let key = self.keys.current(&self.service, now).ok_or(Error::NoKey)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
        let inner = codec::encode_request(&request, &nonce, now)?;
        let client =
            ohttp::ClientRequest::from_encoded_config(&key.config).map_err(|_| Error::KeyConfig)?;
        let (outer, response) = client.encapsulate(&inner).map_err(|_| Error::Encapsulate)?;
        let reply = self.post.post(&self.url, REQUEST_MEDIA, outer).await?;
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
