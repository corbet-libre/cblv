//! Gateway layer in front of an axum router. It decapsulates, dispatches the
//! inner request to the existing handlers unchanged, and encapsulates the
//! response. Handlers never see the sender's address: the inner request has no
//! connection info and carries the [`ViaOhttp`] marker, which per-source
//! limiters must treat as "limited at the proxy".
use crate::{
    PATH, REQUEST_MEDIA, RESPONSE_MEDIA, RETIRE_SKEW_SECONDS, WINDOW_SECONDS, codec,
    keys::PublishedKey,
    replay::{self, Insert, ReplayStore},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, header},
};
use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service, ServiceExt};
use zeroize::Zeroizing;

const MAX_OUTER: usize = 128 * 1024;
const RELAY_AUTH: &str = "x-relay-auth";

/// Request extension: this call arrived through OHTTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViaOhttp;

/// One gateway key. The secret input keying material lives in the secret store
/// (not in code or the feed); the public half is published in the trust feed.
pub struct GatewayKey {
    key_id: u8,
    not_after: u64,
    server: ohttp::Server,
    config: Vec<u8>,
}
impl GatewayKey {
    pub fn derive(
        key_id: u8,
        ikm: &Zeroizing<Vec<u8>>,
        not_after: u64,
    ) -> Result<Self, crate::Error> {
        if ikm.len() < 32 {
            return Err(crate::Error::KeyConfig);
        }
        let config = ohttp::KeyConfig::derive(
            key_id,
            ohttp::hpke::Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::ChaCha20Poly1305,
            )],
            ikm,
        )
        .map_err(|_| crate::Error::KeyConfig)?;
        let encoded = config.encode().map_err(|_| crate::Error::KeyConfig)?;
        let server = ohttp::Server::new(config).map_err(|_| crate::Error::KeyConfig)?;
        Ok(Self {
            key_id,
            not_after,
            server,
            config: encoded,
        })
    }

    /// The entry the operator puts into the signed trust feed manifest.
    pub fn published(&self, service: &str, not_before: u64) -> PublishedKey {
        PublishedKey {
            service: service.to_owned(),
            key_id: self.key_id,
            config: self.config.clone(),
            not_before,
            not_after: self.not_after,
        }
    }
}

pub struct Gateway {
    pub authority: String,
    pub keys: Vec<GatewayKey>,
    pub replay: Arc<dyn ReplayStore>,
    /// State-changing inner paths: only these touch the replay store.
    pub mutating: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// Optional shared secret a front proxy adds (header `x-relay-auth`).
    pub relay_secret: Option<Zeroizing<Vec<u8>>>,
    pub max_inner_response: usize,
    pub clock: fn() -> u64,
}

pub fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Mount the gateway outermost, so the OHTTP routes exist whatever the router holds.
pub fn mount(router: Router, gateway: Arc<Gateway>) -> Router {
    Router::new().fallback_service(OhttpLayer(gateway).layer(router))
}

#[derive(Clone)]
pub struct OhttpLayer(pub Arc<Gateway>);
impl<S> Layer<S> for OhttpLayer {
    type Service = OhttpService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        OhttpService {
            gateway: self.0.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
pub struct OhttpService<S> {
    gateway: Arc<Gateway>,
    inner: S,
}

type Reply = Result<Response<Body>, Infallible>;

impl<S> Service<Request<Body>> for OhttpService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Reply> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);
        let gateway = self.gateway.clone();
        Box::pin(async move {
            if request.uri().path() == PATH {
                Ok(handle(&gateway, request, inner).await)
            } else {
                inner.oneshot(request).await
            }
        })
    }
}

fn outer(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn key_mismatch() -> Response<Body> {
    let mut response = outer(StatusCode::UNAUTHORIZED);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    *response.body_mut() = Body::from(r#"{"type":"urn:ietf:params:ohttp:error:key-mismatch"}"#);
    response
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn handle<S>(gateway: &Gateway, request: Request<Body>, inner: S) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let bad = || outer(StatusCode::BAD_REQUEST);
    if request.method() != Method::POST
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .map(HeaderValue::as_bytes)
            != Some(REQUEST_MEDIA.as_bytes())
    {
        return bad();
    }
    if let Some(secret) = &gateway.relay_secret {
        let sent = request.headers().get(RELAY_AUTH).map(HeaderValue::as_bytes);
        if !sent.is_some_and(|sent| equal(sent, secret)) {
            return outer(StatusCode::NOT_FOUND);
        }
    }
    let Ok(body) = to_bytes(request.into_body(), MAX_OUTER).await else {
        return bad();
    };
    let now = (gateway.clock)();
    let Some(key) = body.first().and_then(|id| {
        gateway.keys.iter().find(|key| {
            key.key_id == *id && now < key.not_after.saturating_add(RETIRE_SKEW_SECONDS)
        })
    }) else {
        return key_mismatch();
    };
    let Ok((plain, sealer)) = key.server.decapsulate(&body) else {
        return bad();
    };
    let Ok(decoded) = codec::decode_request(&plain) else {
        return bad();
    };
    let inner_request = &decoded.request;
    let Ok(path) = std::str::from_utf8(&inner_request.path) else {
        return bad();
    };
    if inner_request.authority != gateway.authority.as_bytes()
        || !path.starts_with('/')
        || now.abs_diff(decoded.timestamp) > WINDOW_SECONDS
        || decoded.timestamp < gateway.replay.started_at()
    {
        return bad();
    }
    if (gateway.mutating)(path) {
        let id = replay::id(key.key_id, &decoded.nonce);
        let expires = decoded.timestamp.saturating_add(2 * WINDOW_SECONDS);
        match gateway.replay.insert_if_absent(id, expires).await {
            Ok(Insert::Fresh) => {}
            Ok(Insert::Replayed) => return bad(),
            Err(_) => return outer(StatusCode::SERVICE_UNAVAILABLE),
        }
    }
    let Some(dispatch) = build(inner_request, path) else {
        return bad();
    };
    let response = match inner.oneshot(dispatch).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let (parts, body) = response.into_parts();
    let reply = match to_bytes(body, gateway.max_inner_response).await {
        Ok(bytes) => codec::Response {
            status: parts.status.as_u16(),
            headers: parts
                .headers
                .iter()
                .filter(|(name, _)| !skipped(name.as_str()))
                .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
                .collect(),
            body: bytes.to_vec(),
        },
        Err(_) => codec::Response {
            status: 502,
            headers: Vec::new(),
            body: Vec::new(),
        },
    };
    let Ok(encoded) = codec::encode_response(&reply) else {
        return outer(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(sealed) = sealer.encapsulate(&encoded) else {
        return outer(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = outer(StatusCode::OK);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(RESPONSE_MEDIA),
    );
    *response.body_mut() = Body::from(sealed);
    response
}

fn skipped(name: &str) -> bool {
    matches!(
        name,
        "connection" | "transfer-encoding" | "content-length" | "keep-alive"
    )
}

fn build(request: &codec::Request, path: &str) -> Option<Request<Body>> {
    let method = Method::from_bytes(&request.method).ok()?;
    let mut built = Request::builder().method(method).uri(path);
    for (name, value) in &request.headers {
        if name == b"host" || name == RELAY_AUTH.as_bytes() {
            continue;
        }
        built = built.header(
            HeaderName::from_bytes(name).ok()?,
            HeaderValue::from_bytes(value).ok()?,
        );
    }
    // The signed authority becomes the Host the handlers validate.
    built = built.header(
        header::HOST,
        HeaderValue::from_bytes(&request.authority).ok()?,
    );
    let mut built = built.body(Body::from(request.body.clone())).ok()?;
    built.extensions_mut().insert(ViaOhttp);
    Some(built)
}
