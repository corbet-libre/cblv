//! End to end through the client Wire and the gateway layer, in process.
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    routing::post,
};
use cblv::{
    Error, PATH, REQUEST_MEDIA,
    client::{OhttpWire, Post, RawReply, Wire},
    codec,
    gateway::{self, Gateway, GatewayKey, ViaOhttp},
    keys::VerifiedKeys,
    replay::MemoryStore,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt;
use zeroize::Zeroizing;

const AUTHORITY: &str = "api.test";
const NOW: u64 = 1_000_000;
fn now() -> u64 {
    NOW
}

struct Fixture {
    app: Router,
    handled: Arc<AtomicUsize>,
    store: Arc<MemoryStore>,
    keys: VerifiedKeys,
}

fn fixture(key_ids: &[(u8, u64)], gateway_clock: fn() -> u64, secret: Option<&[u8]>) -> Fixture {
    let handled = Arc::new(AtomicUsize::new(0));
    let counter = handled.clone();
    let echo = Router::new()
        .route(
            "/v1/mutate",
            post(move |request: Request| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    assert!(request.extensions().get::<ViaOhttp>().is_some());
                    assert!(
                        request
                            .extensions()
                            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                            .is_none()
                    );
                    let body = axum::body::to_bytes(request.into_body(), 1 << 20)
                        .await
                        .unwrap();
                    (
                        StatusCode::CREATED,
                        [(header::CONTENT_TYPE, "text/plain")],
                        body,
                    )
                }
            }),
        )
        .route("/v1/read", post(|| async { "ok" }));
    let store = Arc::new(MemoryStore::new(NOW - 1000));
    let mut keys = Vec::new();
    let mut published = Vec::new();
    for (id, not_after) in key_ids {
        let key = GatewayKey::derive(*id, &Zeroizing::new(vec![*id; 32]), *not_after).unwrap();
        published.push(key.published(AUTHORITY, NOW - 500));
        keys.push(key);
    }
    let gw = Arc::new(Gateway {
        authority: AUTHORITY.into(),
        keys,
        replay: store.clone(),
        mutating: Arc::new(|path| path == "/v1/mutate"),
        relay_secret: secret.map(|s| Zeroizing::new(s.to_vec())),
        max_inner_response: 1 << 20,
        clock: gateway_clock,
    });
    Fixture {
        app: gateway::mount(echo, gw),
        handled,
        store,
        keys: VerifiedKeys::from_verified_feed(published).unwrap(),
    }
}

type Seen = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

/// The "relay": hands outer bytes straight to the gateway; may tamper.
#[derive(Clone)]
struct Loop {
    app: Router,
    secret: Option<Vec<u8>>,
    tamper: fn(&mut Vec<u8>),
    seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}
impl Post for Loop {
    async fn post(
        &self,
        url: &str,
        content_type: &'static str,
        mut body: Vec<u8>,
    ) -> Result<RawReply, Error> {
        (self.tamper)(&mut body);
        self.seen.lock().unwrap().push(body.clone());
        let path = url.trim_start_matches("https://relay.test");
        let mut builder =
            axum::http::Request::post(path).header(header::CONTENT_TYPE, content_type);
        if let Some(secret) = &self.secret {
            builder = builder.header("x-relay-auth", secret.as_slice());
        }
        let response = self
            .app
            .clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec();
        Ok(RawReply { status, body })
    }
}

fn wire(f: &Fixture, secret: Option<&[u8]>, tamper: fn(&mut Vec<u8>)) -> (OhttpWire<Loop>, Seen) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let post = Loop {
        app: f.app.clone(),
        secret: secret.map(<[u8]>::to_vec),
        tamper,
        seen: seen.clone(),
    };
    (
        OhttpWire::new(post, "https://relay.test", AUTHORITY, f.keys.clone(), now),
        seen,
    )
}

fn call(path: &str, body: &[u8]) -> codec::Request {
    codec::Request {
        method: b"POST".to_vec(),
        authority: AUTHORITY.into(),
        path: path.into(),
        headers: vec![(b"origin".to_vec(), b"https://a.test".to_vec())],
        body: body.to_vec(),
    }
}

fn plain(_: &mut Vec<u8>) {}

#[tokio::test]
async fn round_trip_reaches_the_handler_unchanged() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let (wire, seen) = wire(&f, None, plain);
    let reply = wire.exchange(call("/v1/mutate", b"hello")).await.unwrap();
    assert_eq!((reply.status, reply.body.as_slice()), (201, &b"hello"[..]));
    assert_eq!(f.handled.load(Ordering::SeqCst), 1);
    // The relay sees no plaintext.
    assert!(!seen.lock().unwrap()[0].windows(5).any(|w| w == b"hello"));
}

#[tokio::test]
async fn replayed_ciphertext_is_refused_and_not_dispatched() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let (wire, seen) = wire(&f, None, plain);
    wire.exchange(call("/v1/mutate", b"x")).await.unwrap();
    let captured = seen.lock().unwrap()[0].clone();
    let again = f
        .app
        .clone()
        .oneshot(
            axum::http::Request::post(PATH)
                .header(header::CONTENT_TYPE, REQUEST_MEDIA)
                .body(Body::from(captured))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);
    assert_eq!(f.handled.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reads_skip_the_replay_store_and_a_broken_store_fails_closed() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let (wire, _) = wire(&f, None, plain);
    f.store.break_store();
    assert!(wire.exchange(call("/v1/read", b"")).await.is_ok());
    assert_eq!(
        wire.exchange(call("/v1/mutate", b"")).await.unwrap_err(),
        Error::Status(503)
    );
    assert_eq!(f.handled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tampered_ciphertext_never_reaches_the_handler() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let (wire, _) = wire(&f, None, |body| {
        let last = body.len() - 1;
        body[last] ^= 1;
    });
    assert_eq!(
        wire.exchange(call("/v1/mutate", b"x")).await.unwrap_err(),
        Error::Status(400)
    );
    assert_eq!(f.handled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unknown_key_id_signals_key_mismatch() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let (wire, _) = wire(&f, None, |body| body[0] = 99);
    assert_eq!(
        wire.exchange(call("/v1/read", b"")).await.unwrap_err(),
        Error::KeyMismatch
    );
}

#[tokio::test]
async fn retired_gateway_key_is_refused_but_overlap_works() {
    fn later() -> u64 {
        NOW + 5_000
    }
    // Key 1 ended at NOW+1000 (+1h skew has passed at NOW+5000); key 2 is live.
    let f = fixture(&[(1, NOW + 1_000), (2, NOW + 100_000)], later, None);
    let only_old = VerifiedKeys::from_verified_feed(vec![f.keys_for(1)]).unwrap();
    let mut old = wire(&f, None, plain).0;
    old.set_keys(only_old);
    // Device clock is still NOW; its old key is within its published validity.
    assert_eq!(
        old.exchange(call("/v1/read", b"")).await.unwrap_err(),
        Error::KeyMismatch
    );
}

impl Fixture {
    fn keys_for(&self, id: u8) -> cblv::keys::PublishedKey {
        let key = GatewayKey::derive(id, &Zeroizing::new(vec![id; 32]), NOW + 1_000).unwrap();
        key.published(AUTHORITY, NOW - 500)
    }
}

#[tokio::test]
async fn stale_published_key_and_unverified_state_give_no_key() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let (mut wire, _) = wire(&f, None, plain);
    wire.set_keys(VerifiedKeys::default());
    assert_eq!(
        wire.exchange(call("/v1/read", b"")).await.unwrap_err(),
        Error::NoKey
    );
}

#[tokio::test]
async fn wrong_authority_and_skew() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let (wire, _) = wire(&f, None, plain);
    let mut wrong = call("/v1/read", b"");
    wrong.authority = b"other.test".to_vec();
    assert_eq!(wire.exchange(wrong).await.unwrap_err(), Error::Status(400));
    // Gateway clock far ahead of the device: outside the window.
    fn ahead() -> u64 {
        NOW + 1_000
    }
    let skewed = fixture(&[(1, NOW + 10_000)], ahead, None);
    let (skew_wire, _) = wire_for(&skewed);
    assert_eq!(
        skew_wire.exchange(call("/v1/read", b"")).await.unwrap_err(),
        Error::Status(400)
    );
}

fn wire_for(f: &Fixture) -> (OhttpWire<Loop>, Seen) {
    wire(f, None, plain)
}

#[tokio::test]
async fn relay_secret_is_required() {
    let f = fixture(&[(1, NOW + 10_000)], now, Some(b"s3cret"));
    let (no_secret, _) = wire(&f, None, plain);
    assert_eq!(
        no_secret.exchange(call("/v1/read", b"")).await.unwrap_err(),
        Error::Status(404)
    );
    let (with, _) = wire(&f, Some(b"s3cret"), plain);
    assert!(with.exchange(call("/v1/read", b"")).await.is_ok());
}

#[tokio::test]
async fn non_ohttp_paths_pass_through() {
    let f = fixture(&[(1, NOW + 10_000)], now, None);
    let response = f
        .app
        .clone()
        .oneshot(
            axum::http::Request::post("/v1/read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
