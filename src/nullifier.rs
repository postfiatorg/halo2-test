//! Nullifier derivation
//!
//! The nullifier is a unique identifier for a note that is revealed when spending.
//! It prevents double-spending: once a nullifier is published, that note cannot be spent again.
//!
//! In Orchard: nf = [Hash(nk, rho) + psi] * G + cm
//! We simplify to: nf = PoseidonHash(nk, rho)
//!
//! Properties:
//! - Only the note owner (who has nk) can compute the nullifier
//! - The nullifier doesn't reveal which note is being spent
//! - Each note has exactly one nullifier

use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::pasta::Fp;
use std::fmt;

use crate::keys::NullifierKey;
use crate::commitment::poseidon_hash;
use crate::constants::domains;

/// A nullifier - revealed when spending a note to prevent double-spending
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nullifier {
    inner: Fp,
}

// Custom Hash implementation since Fp doesn't implement Hash
impl std::hash::Hash for Nullifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl Nullifier {
    /// Derive a nullifier from the nullifier key and note's rho
    ///
    /// nf = PoseidonHash(domain_separator, nk, rho)
    pub fn derive(nk: &NullifierKey, rho: Fp) -> Self {
        // Domain separator as a field element
        let domain = domain_separator_field(domains::NULLIFIER);

        // Hash: domain || nk || rho
        let nk_field = nk.to_field();
        let inner = poseidon_hash(&[domain, nk_field, rho]);

        Self { inner }
    }

    /// Create from a raw field element
    pub fn from_field(f: Fp) -> Self {
        Self { inner: f }
    }

    /// Get the inner field element
    pub fn to_field(&self) -> Fp {
        self.inner
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_repr()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let inner = Fp::from_repr(*bytes);
        if inner.is_some().into() {
            Some(Self { inner: inner.unwrap() })
        } else {
            None
        }
    }
}

impl fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Nullifier({:02x}{:02x}...)", bytes[0], bytes[1])
    }
}

/// Convert a domain separator to a field element
fn domain_separator_field(domain: &[u8]) -> Fp {
    use blake2::{Blake2b512, Digest};

    let mut hasher = Blake2b512::new();
    hasher.update(domain);
    let hash = hasher.finalize();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Fp::from_uniform_bytes(&wide)
}

/// A set of nullifiers (used to track spent notes)
#[derive(Default, Clone)]
pub struct NullifierSet {
    nullifiers: std::collections::HashSet<Nullifier>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a nullifier has been seen (note already spent)
    pub fn contains(&self, nf: &Nullifier) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Add a nullifier (mark note as spent)
    /// Returns false if already present (double-spend attempt)
    pub fn insert(&mut self, nf: Nullifier) -> bool {
        self.nullifiers.insert(nf)
    }

    /// Number of spent notes
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use crate::note::Note;
    use rand::rngs::OsRng;

    #[test]
    fn test_nullifier_derivation() {
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        let note = Note::new(1000, addr, &mut OsRng);

        // Derive nullifier
        let nf = note.nullifier(&fvk);

        // Should be deterministic
        let nf2 = note.nullifier(&fvk);
        assert_eq!(nf, nf2);
    }

    #[test]
    fn test_different_notes_different_nullifiers() {
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        let note1 = Note::new(1000, addr.clone(), &mut OsRng);
        let note2 = Note::new(1000, addr, &mut OsRng);

        let nf1 = note1.nullifier(&fvk);
        let nf2 = note2.nullifier(&fvk);

        // Different rho means different nullifier
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_wrong_key_wrong_nullifier() {
        let sk1 = SpendingKey::random(&mut OsRng);
        let sk2 = SpendingKey::random(&mut OsRng);
        let fvk1 = sk1.to_full_viewing_key();
        let fvk2 = sk2.to_full_viewing_key();
        let addr = sk1.to_address();

        let note = Note::new(1000, addr, &mut OsRng);

        let nf1 = note.nullifier(&fvk1);
        let nf2 = note.nullifier(&fvk2);

        // Different key produces different nullifier
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_set() {
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        let note = Note::new(1000, addr, &mut OsRng);
        let nf = note.nullifier(&fvk);

        let mut nf_set = NullifierSet::new();

        // First insertion succeeds
        assert!(nf_set.insert(nf));

        // Second insertion fails (double-spend)
        assert!(!nf_set.insert(nf));

        // Contains check works
        assert!(nf_set.contains(&nf));
    }
}
