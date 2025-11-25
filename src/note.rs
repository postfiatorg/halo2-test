//! Note structure - the fundamental unit of value in the protocol
//!
//! A note represents a "coin" that can be spent. It contains:
//! - value: the amount
//! - recipient: the address that can spend this note
//! - rho: randomness used in nullifier derivation
//! - rseed: random seed for commitment randomness
//!
//! This matches Orchard's Note structure from the `orchard` crate.

use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::pasta::Fp;
use rand::{CryptoRng, RngCore};

use crate::keys::{Address, FullViewingKey};
use crate::commitment::NoteCommitment;
use crate::nullifier::Nullifier;
use crate::constants::MEMO_SIZE;

/// A note representing a unit of value that can be spent
#[derive(Clone, Debug)]
pub struct Note {
    /// The value of this note in base units
    value: u64,
    /// The recipient address that can spend this note
    recipient: Address,
    /// Randomness for nullifier derivation (rho in Orchard)
    /// In real Orchard, rho is derived from the nullifier of the spent note
    rho: Fp,
    /// Random seed used to derive commitment randomness (rseed in Orchard)
    rseed: [u8; 32],
}

impl Note {
    /// Create a new note with random rho and rseed
    pub fn new<R: RngCore + CryptoRng>(
        value: u64,
        recipient: Address,
        rng: &mut R,
    ) -> Self {
        // Generate random rho as a field element
        let rho = {
            let mut rho_bytes = [0u8; 64];
            rng.fill_bytes(&mut rho_bytes);
            Fp::from_uniform_bytes(&rho_bytes)
        };

        // Generate random rseed
        let mut rseed = [0u8; 32];
        rng.fill_bytes(&mut rseed);

        Self {
            value,
            recipient,
            rho,
            rseed,
        }
    }

    /// Create a note with specific randomness (for testing/determinism)
    pub fn from_parts(
        value: u64,
        recipient: Address,
        rho: Fp,
        rseed: [u8; 32],
    ) -> Self {
        Self {
            value,
            recipient,
            rho,
            rseed,
        }
    }

    /// Get the value of this note
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Get the recipient address
    pub fn recipient(&self) -> &Address {
        &self.recipient
    }

    /// Get rho (used in nullifier derivation)
    pub fn rho(&self) -> Fp {
        self.rho
    }

    /// Get rseed
    pub fn rseed(&self) -> &[u8; 32] {
        &self.rseed
    }

    /// Compute the note commitment
    /// This is what gets added to the Merkle tree
    pub fn commitment(&self) -> NoteCommitment {
        NoteCommitment::derive(self)
    }

    /// Compute the nullifier for this note given the full viewing key
    /// The nullifier is revealed when spending to prevent double-spends
    pub fn nullifier(&self, fvk: &FullViewingKey) -> Nullifier {
        Nullifier::derive(fvk.nk(), self.rho)
    }

    /// Derive the commitment randomness from rseed
    /// In Orchard this uses a PRF; we simplify to a hash
    pub fn rcm(&self) -> Fp {
        use blake2::{Blake2b512, Digest};

        let mut hasher = Blake2b512::new();
        hasher.update(b"SimplifiedOrchard_rcm");
        hasher.update(&self.rseed);
        let hash = hasher.finalize();

        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        Fp::from_uniform_bytes(&wide)
    }

    /// Serialize the note to bytes for encryption
    pub fn to_plaintext(&self, memo: &[u8; MEMO_SIZE]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(crate::constants::NOTE_PLAINTEXT_SIZE);

        // Note type flag (0x02 for Orchard-style notes)
        plaintext.push(0x02);

        // Value (8 bytes, little-endian)
        plaintext.extend_from_slice(&self.value.to_le_bytes());

        // Recipient address (32 bytes)
        plaintext.extend_from_slice(&self.recipient.to_bytes());

        // rseed (32 bytes)
        plaintext.extend_from_slice(&self.rseed);

        // Memo (512 bytes)
        plaintext.extend_from_slice(memo);

        plaintext
    }

    /// Deserialize a note from plaintext bytes
    pub fn from_plaintext(plaintext: &[u8], rho: Fp) -> Option<(Self, [u8; MEMO_SIZE])> {
        if plaintext.len() != crate::constants::NOTE_PLAINTEXT_SIZE {
            return None;
        }

        // Check note type flag
        if plaintext[0] != 0x02 {
            return None;
        }

        // Parse value
        let value = u64::from_le_bytes(plaintext[1..9].try_into().ok()?);

        // Parse recipient
        let recipient = Address::from_bytes(plaintext[9..41].try_into().ok()?);

        // Parse rseed
        let rseed: [u8; 32] = plaintext[41..73].try_into().ok()?;

        // Parse memo
        let mut memo = [0u8; MEMO_SIZE];
        memo.copy_from_slice(&plaintext[73..]);

        let note = Self {
            value,
            recipient,
            rho,
            rseed,
        };

        Some((note, memo))
    }
}

/// A spent note's output - used to derive rho for the new note
/// In real Orchard, rho of output note = nullifier of input note
/// This creates a chain that prevents certain attacks
#[derive(Clone, Debug)]
pub struct NoteDerivation {
    /// The nullifier of the note being spent
    pub input_nullifier: Nullifier,
}

impl NoteDerivation {
    /// Derive rho for a new note from the input nullifier
    pub fn derive_rho(&self) -> Fp {
        self.input_nullifier.to_field()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_note_creation() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        let note = Note::new(1000, addr, &mut OsRng);

        assert_eq!(note.value(), 1000);
    }

    #[test]
    fn test_note_commitment_deterministic() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        let note = Note::new(1000, addr.clone(), &mut OsRng);

        let cm1 = note.commitment();
        let cm2 = note.commitment();

        assert_eq!(cm1.to_bytes(), cm2.to_bytes());
    }

    #[test]
    fn test_note_serialization_roundtrip() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        let note = Note::new(1000, addr.clone(), &mut OsRng);
        let memo = [0u8; MEMO_SIZE];

        let plaintext = note.to_plaintext(&memo);
        let (recovered, recovered_memo) = Note::from_plaintext(&plaintext, note.rho()).unwrap();

        assert_eq!(recovered.value(), note.value());
        assert_eq!(recovered.recipient().to_bytes(), note.recipient().to_bytes());
        assert_eq!(recovered.rseed(), note.rseed());
        assert_eq!(recovered_memo, memo);
    }

    #[test]
    fn test_nullifier_requires_viewing_key() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();
        let fvk = sk.to_full_viewing_key();

        let note = Note::new(1000, addr, &mut OsRng);

        // Can compute nullifier with correct viewing key
        let nf = note.nullifier(&fvk);

        // Different viewing key produces different nullifier
        let sk2 = SpendingKey::random(&mut OsRng);
        let fvk2 = sk2.to_full_viewing_key();
        let nf2 = note.nullifier(&fvk2);

        assert_ne!(nf.to_bytes(), nf2.to_bytes());
    }
}
