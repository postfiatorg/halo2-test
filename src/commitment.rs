//! Note commitment implementation
//!
//! The note commitment is a hiding commitment to the note contents.
//! In real Orchard, this uses the Sinsemilla hash function.
//! We use Poseidon for simplicity while maintaining similar security properties.
//!
//! Commitment structure:
//! cm = PoseidonHash(value || recipient || rho || rcm)
//!
//! Where rcm is derived from rseed.

use ff::PrimeField;
use halo2_proofs::pasta::Fp;
use std::fmt;

use crate::note::Note;

/// A note commitment - the public representation of a note
/// This is what gets stored in the Merkle tree
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteCommitment {
    inner: Fp,
}

impl NoteCommitment {
    /// Derive a commitment from a note
    pub fn derive(note: &Note) -> Self {
        // Get all the components
        let value = Fp::from(note.value());
        let recipient = note.recipient().to_field();
        let rho = note.rho();
        let rcm = note.rcm();

        // Hash them together using our Poseidon implementation
        let inner = poseidon_hash(&[value, recipient, rho, rcm]);

        Self { inner }
    }

    /// Create from a raw field element (for deserialization)
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

impl fmt::Debug for NoteCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "NoteCommitment({:02x}{:02x}...)", bytes[0], bytes[1])
    }
}

/// Poseidon hash function for the Pasta field
///
/// This is a simplified implementation for demonstration.
/// Real Orchard uses a highly optimized Poseidon with specific parameters.
///
/// Poseidon parameters for Pasta:
/// - Width: 3 (2 inputs + 1 capacity)
/// - Full rounds: 8
/// - Partial rounds: 56
/// - S-box: x^5
pub fn poseidon_hash(inputs: &[Fp]) -> Fp {
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};

    // For 2 inputs, we can use the built-in Poseidon
    // For more inputs, we chain multiple hashes
    match inputs.len() {
        0 => {
            // Hash of empty input
            let message = [Fp::zero(), Fp::zero()];
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message)
        }
        1 => {
            let message = [inputs[0], Fp::zero()];
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message)
        }
        2 => {
            let message = [inputs[0], inputs[1]];
            poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message)
        }
        _ => {
            // For more than 2 inputs, we use a Merkle-Damgard style construction
            // Hash pairs and accumulate
            let mut acc = {
                let message = [inputs[0], inputs[1]];
                poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message)
            };

            for chunk in inputs[2..].iter() {
                let message = [acc, *chunk];
                acc = poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message);
            }

            acc
        }
    }
}

/// Hash two field elements (used for Merkle tree)
pub fn poseidon_hash_2(left: Fp, right: Fp) -> Fp {
    poseidon_hash(&[left, right])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_commitment_deterministic() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        let note = crate::note::Note::new(1000, addr, &mut OsRng);

        let cm1 = NoteCommitment::derive(&note);
        let cm2 = NoteCommitment::derive(&note);

        assert_eq!(cm1, cm2);
    }

    #[test]
    fn test_different_notes_different_commitments() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        let note1 = crate::note::Note::new(1000, addr.clone(), &mut OsRng);
        let note2 = crate::note::Note::new(1000, addr, &mut OsRng);

        let cm1 = NoteCommitment::derive(&note1);
        let cm2 = NoteCommitment::derive(&note2);

        // Different rseed means different commitment
        assert_ne!(cm1, cm2);
    }

    #[test]
    fn test_commitment_serialization() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();
        let note = crate::note::Note::new(1000, addr, &mut OsRng);

        let cm = NoteCommitment::derive(&note);
        let bytes = cm.to_bytes();
        let recovered = NoteCommitment::from_bytes(&bytes).unwrap();

        assert_eq!(cm, recovered);
    }

    #[test]
    fn test_poseidon_hash() {
        // Verify Poseidon produces consistent results
        let a = Fp::from(123u64);
        let b = Fp::from(456u64);

        let h1 = poseidon_hash(&[a, b]);
        let h2 = poseidon_hash(&[a, b]);

        assert_eq!(h1, h2);

        // Different inputs produce different hashes
        let h3 = poseidon_hash(&[b, a]);
        assert_ne!(h1, h3);
    }
}
