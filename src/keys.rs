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
}
