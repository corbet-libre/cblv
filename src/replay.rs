//! Replay cache contract. OHTTP has no replay protection, so the gateway
//! records a digest of (key id, nonce) for every state-changing call inside
//! the clock window. The implementation must live in a shared store (Valkey,
//! the door database), never in process memory, because instances come and go.
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin};

pub type Id = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insert {
    Fresh,
    Replayed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait ReplayStore: Send + Sync {
    /// Atomically record `id` until `expires_at` (unix seconds). Failure means
    /// the gateway refuses the request (fail closed).
    fn insert_if_absent(
        &self,
        id: Id,
        expires_at: u64,
    ) -> BoxFuture<'_, Result<Insert, StoreError>>;
    /// When the cache's current life began. A flushed or fresh cache cannot
    /// remember earlier nonces, so requests stamped before this are refused.
    fn started_at(&self) -> u64;
}

pub fn id(key_id: u8, nonce: &[u8; 16]) -> Id {
    let digest = Sha256::new()
        .chain_update([key_id])
        .chain_update(nonce)
        .finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Test-only store.
#[cfg(any(test, feature = "test-store"))]
pub struct MemoryStore {
    seen: std::sync::Mutex<std::collections::HashMap<Id, u64>>,
    started: u64,
    fail: std::sync::atomic::AtomicBool,
}
#[cfg(any(test, feature = "test-store"))]
impl MemoryStore {
    pub fn new(started: u64) -> Self {
        Self {
            seen: Default::default(),
            started,
            fail: Default::default(),
        }
    }
    pub fn break_store(&self) {
        self.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
#[cfg(any(test, feature = "test-store"))]
impl ReplayStore for MemoryStore {
    fn insert_if_absent(
        &self,
        id: Id,
        expires_at: u64,
    ) -> BoxFuture<'_, Result<Insert, StoreError>> {
        Box::pin(async move {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(StoreError);
            }
            let mut seen = self.seen.lock().map_err(|_| StoreError)?;
            Ok(match seen.insert(id, expires_at) {
                Some(_) => Insert::Replayed,
                None => Insert::Fresh,
            })
        })
    }
    fn started_at(&self) -> u64 {
        self.started
    }
}
