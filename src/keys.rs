//! Key hierarchy for the simplified Orchard protocol
//!
//! Following Orchard's key structure:
//! ```text
//! SpendingKey (sk)
//!     |
//!     +---> FullViewingKey (fvk)
//!     |         |
//!     |         +---> NullifierKey (nk) - used to derive nullifiers
//!     |         |
//!     |         +---> IncomingViewingKey (ivk) - decrypt incoming notes
//!     |         |
//!     |         +---> OutgoingViewingKey (ovk) - decrypt outgoing notes
//!     |
//!     +---> Address - where notes are sent to
//! ```

use blake2::{Blake2b512, Digest};
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::pasta::Fp;
use rand::{CryptoRng, RngCore};
use std::fmt;

use crate::constants::domains;

/// The root spending key - must be kept secret
/// In real Orchard this is derived from a seed phrase via ZIP-32
#[derive(Clone)]
pub struct SpendingKey {
    inner: [u8; 32],
}

impl SpendingKey {
    /// Generate a new random spending key
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut inner = [0u8; 32];
        rng.fill_bytes(&mut inner);
        Self { inner }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Get the raw bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner
    }

    /// Derive the full viewing key
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey::derive_from_spending_key(self)
    }

    /// Derive an address for receiving notes
    pub fn to_address(&self) -> Address {
        self.to_full_viewing_key().to_address()
    }
}

impl fmt::Debug for SpendingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpendingKey")
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

/// Full viewing key - can view all transactions but not spend
/// Contains subkeys for different viewing capabilities
#[derive(Clone, Debug)]
pub struct FullViewingKey {
    /// Nullifier derivation key
    nk: NullifierKey,
    /// Incoming viewing key (decrypt notes sent to us)
    ivk: IncomingViewingKey,
    /// Outgoing viewing key (decrypt notes we sent)
    ovk: OutgoingViewingKey,
}

impl FullViewingKey {
    fn derive_from_spending_key(sk: &SpendingKey) -> Self {
        // Derive nullifier key
        let nk = {
            let mut hasher = Blake2b512::new();
            hasher.update(domains::KEY_DERIVE);
            hasher.update(b"_nk");
            hasher.update(&sk.inner);
            let hash = hasher.finalize();
            let mut nk_bytes = [0u8; 32];
            nk_bytes.copy_from_slice(&hash[..32]);
            NullifierKey { inner: nk_bytes }
        };

        // Derive incoming viewing key
        let ivk = {
            let mut hasher = Blake2b512::new();
            hasher.update(domains::KEY_DERIVE);
            hasher.update(b"_ivk");
            hasher.update(&sk.inner);
            let hash = hasher.finalize();
            let mut ivk_bytes = [0u8; 32];
            ivk_bytes.copy_from_slice(&hash[..32]);
            IncomingViewingKey { inner: ivk_bytes }
        };

        // Derive outgoing viewing key
        let ovk = {
            let mut hasher = Blake2b512::new();
            hasher.update(domains::KEY_DERIVE);
            hasher.update(b"_ovk");
            hasher.update(&sk.inner);
            let hash = hasher.finalize();
            let mut ovk_bytes = [0u8; 32];
            ovk_bytes.copy_from_slice(&hash[..32]);
            OutgoingViewingKey { inner: ovk_bytes }
        };

        Self { nk, ivk, ovk }
    }

    pub fn nk(&self) -> &NullifierKey {
        &self.nk
    }

    pub fn ivk(&self) -> &IncomingViewingKey {
        &self.ivk
    }

    pub fn ovk(&self) -> &OutgoingViewingKey {
        &self.ovk
    }

    /// Derive an address from the full viewing key
    pub fn to_address(&self) -> Address {
        let mut hasher = Blake2b512::new();
        hasher.update(domains::KEY_DERIVE);
        hasher.update(b"_addr");
        hasher.update(&self.ivk.inner);
        let hash = hasher.finalize();
        let mut addr_bytes = [0u8; 32];
        addr_bytes.copy_from_slice(&hash[..32]);
        Address { inner: addr_bytes }
    }
}

/// Nullifier derivation key - used to compute nullifiers for notes we own
#[derive(Clone)]
pub struct NullifierKey {
    inner: [u8; 32],
}

impl NullifierKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner
    }

    /// Convert to field element for circuit operations
    pub fn to_field(&self) -> Fp {
        // Interpret bytes as a field element (reduce mod p if needed)
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&self.inner);
        Fp::from_uniform_bytes(&wide)
    }
}

impl fmt::Debug for NullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NullifierKey")
            .field("inner", &hex::encode(&self.inner[..8]))
            .finish()
    }
}

/// Incoming viewing key - decrypt notes sent to us
#[derive(Clone)]
pub struct IncomingViewingKey {
    inner: [u8; 32],
}

impl IncomingViewingKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner
    }

    /// Derive the encryption key for a note using the ephemeral public key
    pub fn derive_note_key(&self, epk: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake2b512::new();
        hasher.update(domains::NOTE_ENCRYPTION);
        hasher.update(&self.inner);
        hasher.update(epk);
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash[..32]);
        key
    }
}

impl fmt::Debug for IncomingViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingViewingKey")
            .field("inner", &hex::encode(&self.inner[..8]))
            .finish()
    }
}

/// Outgoing viewing key - decrypt notes we sent to others
#[derive(Clone)]
pub struct OutgoingViewingKey {
    inner: [u8; 32],
}

impl OutgoingViewingKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner
    }

    /// Derive the outgoing encryption key
    pub fn derive_ock(&self, cmx: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Blake2b512::new();
        hasher.update(domains::NOTE_ENCRYPTION);
        hasher.update(b"_ock");
        hasher.update(&self.inner);
        hasher.update(cmx);
        hasher.update(epk);
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash[..32]);
        key
    }
}

impl fmt::Debug for OutgoingViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingViewingKey")
            .field("inner", &hex::encode(&self.inner[..8]))
            .finish()
    }
}

/// Address where notes can be sent
/// In real Orchard this includes diversifier for multiple addresses per key
#[derive(Clone, PartialEq, Eq)]
pub struct Address {
    inner: [u8; 32],
}

impl Address {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Convert to field element for circuit operations
    pub fn to_field(&self) -> Fp {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&self.inner);
        Fp::from_uniform_bytes(&wide)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Address")
            .field("inner", &hex::encode(&self.inner[..8]))
            .finish()
    }
}

// Helper module for hex encoding in debug output
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_key_derivation() {
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = fvk.to_address();

        // Verify deterministic derivation
        let fvk2 = sk.to_full_viewing_key();
        let addr2 = fvk2.to_address();
        assert_eq!(addr.to_bytes(), addr2.to_bytes());
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let sk1 = SpendingKey::random(&mut OsRng);
        let sk2 = SpendingKey::random(&mut OsRng);

        let addr1 = sk1.to_address();
        let addr2 = sk2.to_address();

        assert_ne!(addr1.to_bytes(), addr2.to_bytes());
    }
}
