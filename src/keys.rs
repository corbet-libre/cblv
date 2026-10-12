//! Gateway key configurations as they travel in the community's signed trust
//! feed (inside the manifest the policy key signs). This module never
//! verifies signatures: [`VerifiedKeys::from_verified_feed`] must only be
//! given entries taken from a feed that already passed the Beacon (cbcn)
//! verification. The client API accepts nothing but [`VerifiedKeys`], so a key
//! fetched from the gateway or anywhere unauthenticated has no way in.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const MAX_ENTRIES: usize = 16;
const MAX_CONFIG: usize = 256;
/// DHKEM(X25519, HKDF-SHA256): the only KEM we publish.
const KEM_X25519: [u8; 2] = [0x00, 0x20];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedKey {
    /// Which gateway: the exact service authority, e.g. `api.alpha.example`.
    pub service: String,
    pub key_id: u8,
    /// RFC 9458 key configuration bytes (`application/ohttp-keys` item).
    pub config: Vec<u8>,
    /// Unix seconds, `not_before <= now < not_after`.
    pub not_before: u64,
    pub not_after: u64,
}

/// What the signed trust manifest carries: the relay in front of the gateways
/// and the current key entries (several during a rotation overlap).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    /// Base URL of the proxied gateway host that forwards ciphertext.
    pub relay: String,
    pub keys: Vec<PublishedKey>,
}

impl Directory {
    /// Check a directory taken from a signature-verified manifest.
    pub fn verify(self) -> Result<Snapshot> {
        let relay = self.relay.as_str();
        if !relay.starts_with("https://")
            || relay.len() > 253
            || relay.len() <= "https://".len()
            || relay.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'?' | b'#' | b'@')
            })
        {
            return Err(Error::KeyConfig);
        }
        Ok(Snapshot {
            relay: self.relay,
            keys: VerifiedKeys::from_verified_feed(self.keys)?,
        })
    }
}

/// A verified directory: where to send and which keys may be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    relay: String,
    keys: VerifiedKeys,
}

/// Source of the current verified keys. Production sources follow the signed
/// trust feed; a fixed [`Snapshot`] serves tests.
pub trait KeySource {
    /// Relay base URL and the newest key valid now for exactly this service.
    fn current(&self, service: &str, now: u64) -> Option<(String, PublishedKey)>;
}

impl KeySource for Snapshot {
    fn current(&self, service: &str, now: u64) -> Option<(String, PublishedKey)> {
        self.keys
            .current(service, now)
            .map(|key| (self.relay.clone(), key.clone()))
    }
}

impl<T: KeySource + ?Sized> KeySource for std::sync::Arc<T> {
    fn current(&self, service: &str, now: u64) -> Option<(String, PublishedKey)> {
        (**self).current(service, now)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedKeys(Vec<PublishedKey>);

impl VerifiedKeys {
    /// Entries must come from a signature-verified trust feed.
    pub fn from_verified_feed(entries: Vec<PublishedKey>) -> Result<Self> {
        if entries.len() > MAX_ENTRIES {
            return Err(Error::KeyConfig);
        }
        for (index, entry) in entries.iter().enumerate() {
            let config = &entry.config;
            if entry.not_before >= entry.not_after
                || config.is_empty()
                || config.len() > MAX_CONFIG
                || config[0] != entry.key_id
                || config.get(1..3) != Some(&KEM_X25519[..])
                || ohttp::KeyConfig::decode(config).is_err()
                || entries[..index]
                    .iter()
                    .any(|other| other.service == entry.service && other.key_id == entry.key_id)
            {
                return Err(Error::KeyConfig);
            }
        }
        Ok(Self(entries))
    }

    /// The newest key valid now for exactly this service.
    pub fn current(&self, service: &str, now: u64) -> Option<&PublishedKey> {
        self.0
            .iter()
            .filter(|key| key.service == service && key.not_before <= now && now < key.not_after)
            .max_by_key(|key| key.not_before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(id: u8) -> Vec<u8> {
        ohttp::KeyConfig::derive(
            id,
            ohttp::hpke::Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::ChaCha20Poly1305,
            )],
            &[id; 32],
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    fn entry(id: u8, from: u64, to: u64) -> PublishedKey {
        PublishedKey {
            service: "a".into(),
            key_id: id,
            config: config(id),
            not_before: from,
            not_after: to,
        }
    }

    #[test]
    fn picks_newest_valid_and_refuses_bad_entries() {
        let keys =
            VerifiedKeys::from_verified_feed(vec![entry(1, 0, 100), entry(2, 50, 200)]).unwrap();
        assert_eq!(keys.current("a", 10).unwrap().key_id, 1);
        assert_eq!(keys.current("a", 60).unwrap().key_id, 2);
        assert!(keys.current("a", 200).is_none());
        assert!(keys.current("b", 60).is_none());
        let mut wrong_id = entry(3, 0, 10);
        wrong_id.key_id = 4;
        assert!(VerifiedKeys::from_verified_feed(vec![wrong_id]).is_err());
        assert!(VerifiedKeys::from_verified_feed(vec![entry(1, 5, 5)]).is_err());
        assert!(VerifiedKeys::from_verified_feed(vec![entry(1, 0, 9), entry(1, 5, 20)]).is_err());
    }

    #[test]
    fn directory_refuses_unsafe_relays_and_accepts_overlap() {
        for relay in [
            "http://r.example",
            "https://",
            "https://u@r.example",
            "https://r.example/?x",
            "https://r.example/#f",
            "https://r .example",
        ] {
            let directory = Directory {
                relay: relay.into(),
                keys: vec![entry(1, 0, 10)],
            };
            assert!(directory.verify().is_err(), "{relay}");
        }
        let overlap = Directory {
            relay: "https://r.example".into(),
            keys: vec![entry(1, 0, 100), entry(2, 50, 200)],
        };
        let snapshot = overlap.verify().unwrap();
        assert_eq!(snapshot.current("a", 60).unwrap().1.key_id, 2);
        assert_eq!(snapshot.current("a", 10).unwrap().0, "https://r.example");
    }
}
