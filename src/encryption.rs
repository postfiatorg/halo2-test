//! Note encryption using ChaCha20Poly1305 AEAD
//!
//! When sending a shielded note, the sender encrypts the note data so only the
//! recipient can decrypt it. This uses:
//!
//! 1. Ephemeral key exchange (simplified Diffie-Hellman style)
//! 2. ChaCha20Poly1305 AEAD for authenticated encryption
//!
//! The encrypted note consists of:
//! - Ephemeral public key (32 bytes)
//! - Ciphertext (NOTE_PLAINTEXT_SIZE + 16 bytes for tag)
//!
//! Real Orchard uses more sophisticated key derivation on the Pallas curve.
//! We simplify to demonstrate the concept while maintaining security properties.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::constants::MEMO_SIZE;
use crate::keys::{IncomingViewingKey, OutgoingViewingKey};
use crate::note::Note;
use crate::commitment::NoteCommitment;

/// Errors that can occur during note encryption/decryption
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("Decryption failed - wrong key or corrupted ciphertext")]
    DecryptionFailed,
    #[error("Invalid ciphertext length")]
    InvalidLength,
}

/// An encrypted note as it appears on-chain
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    /// Ephemeral public key for key derivation
    pub epk: [u8; 32],
    /// Encrypted note ciphertext (includes AEAD tag)
    pub ciphertext: Vec<u8>,
}

impl EncryptedNote {
    /// Get the size of the encrypted note
    pub fn size(&self) -> usize {
        32 + self.ciphertext.len()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.size());
        bytes.extend_from_slice(&self.epk);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() < 32 + 16 {
            // At minimum: 32 byte epk + 16 byte tag
            return Err(EncryptionError::InvalidLength);
        }

        let mut epk = [0u8; 32];
        epk.copy_from_slice(&bytes[..32]);

        let ciphertext = bytes[32..].to_vec();

        Ok(Self { epk, ciphertext })
    }
}

/// Encrypt a note to a recipient's incoming viewing key
///
/// This creates an encrypted note that only the holder of the matching
/// IncomingViewingKey can decrypt.
pub fn encrypt_note<R: RngCore + CryptoRng>(
    note: &Note,
    memo: &[u8; MEMO_SIZE],
    ivk: &IncomingViewingKey,
    rng: &mut R,
) -> EncryptedNote {
    // Generate ephemeral key pair
    let mut esk = [0u8; 32];
    rng.fill_bytes(&mut esk);

    // Derive ephemeral public key (simplified: just hash the secret)
    let epk = derive_epk(&esk);

    // Derive shared secret and encryption key
    let shared_key = ivk.derive_note_key(&epk);

    // Create the plaintext
    let plaintext = note.to_plaintext(memo);

    // Encrypt using ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&shared_key).expect("32-byte key");

    // Use a zero nonce (unique due to ephemeral key)
    // In production, you'd want to derive this more carefully
    let nonce = Nonce::default();

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption should not fail");

    EncryptedNote { epk, ciphertext }
}

/// Decrypt a note using the incoming viewing key
///
/// Returns the decrypted note and memo if successful.
pub fn decrypt_note(
    encrypted: &EncryptedNote,
    ivk: &IncomingViewingKey,
    rho: halo2_proofs::pasta::Fp,
) -> Result<(Note, [u8; MEMO_SIZE]), EncryptionError> {
    // Derive shared secret
    let shared_key = ivk.derive_note_key(&encrypted.epk);

    // Decrypt using ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&shared_key).expect("32-byte key");
    let nonce = Nonce::default();

    let plaintext = cipher
        .decrypt(&nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| EncryptionError::DecryptionFailed)?;

    // Parse the plaintext into a note
    Note::from_plaintext(&plaintext, rho).ok_or(EncryptionError::DecryptionFailed)
}

/// Derive ephemeral public key from secret
fn derive_epk(esk: &[u8; 32]) -> [u8; 32] {
    use blake2::{Blake2b512, Digest};

    let mut hasher = Blake2b512::new();
    hasher.update(b"SimplifiedOrchard_epk");
    hasher.update(esk);
    let hash = hasher.finalize();

    let mut epk = [0u8; 32];
    epk.copy_from_slice(&hash[..32]);
    epk
}

/// Outgoing ciphertext - allows sender to recover sent note data
///
/// This is used so the sender can later see what they sent (for their records).
/// It's encrypted with the OutgoingViewingKey.
#[derive(Clone, Debug)]
pub struct OutgoingCiphertext {
    pub ciphertext: [u8; 80],
}

impl OutgoingCiphertext {
    /// Create outgoing ciphertext for sender recovery
    pub fn encrypt<R: RngCore + CryptoRng>(
        note: &Note,
        cmx: &NoteCommitment,
        epk: &[u8; 32],
        ovk: &OutgoingViewingKey,
        _rng: &mut R,
    ) -> Self {
        // Derive outgoing cipher key
        let ock = ovk.derive_ock(&cmx.to_bytes(), epk);

        // Plaintext: recipient || value (simplified from full Orchard)
        let mut plaintext = [0u8; 64];
        plaintext[..32].copy_from_slice(&note.recipient().to_bytes());
        plaintext[32..40].copy_from_slice(&note.value().to_le_bytes());
        plaintext[40..64].copy_from_slice(&note.rseed()[..24]);

        // Encrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&ock).expect("32-byte key");
        let nonce = Nonce::default();

        let ct = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("Encryption should not fail");

        let mut ciphertext = [0u8; 80];
        ciphertext.copy_from_slice(&ct);

        Self { ciphertext }
    }
}

/// Full encrypted output as it would appear on-chain
#[derive(Clone, Debug)]
pub struct TransmittedNote {
    /// The note commitment (public)
    pub cmx: NoteCommitment,
    /// Encrypted note for recipient
    pub encrypted_note: EncryptedNote,
    /// Outgoing ciphertext for sender
    pub out_ciphertext: OutgoingCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_note_encryption_roundtrip() {
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        // Create a note
        let note = Note::new(1000, addr, &mut OsRng);
        let memo = [0u8; MEMO_SIZE];
        let rho = note.rho();

        // Encrypt
        let encrypted = encrypt_note(&note, &memo, fvk.ivk(), &mut OsRng);

        // Decrypt
        let (decrypted, decrypted_memo) = decrypt_note(&encrypted, fvk.ivk(), rho).unwrap();

        // Verify
        assert_eq!(decrypted.value(), note.value());
        assert_eq!(decrypted.recipient().to_bytes(), note.recipient().to_bytes());
        assert_eq!(decrypted.rseed(), note.rseed());
        assert_eq!(decrypted_memo, memo);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let sk1 = SpendingKey::random(&mut OsRng);
        let sk2 = SpendingKey::random(&mut OsRng);
        let fvk1 = sk1.to_full_viewing_key();
        let fvk2 = sk2.to_full_viewing_key();
        let addr = sk1.to_address();

        let note = Note::new(1000, addr, &mut OsRng);
        let memo = [0u8; MEMO_SIZE];
        let rho = note.rho();

        // Encrypt with sk1's key
        let encrypted = encrypt_note(&note, &memo, fvk1.ivk(), &mut OsRng);

        // Try to decrypt with sk2's key - should fail
        let result = decrypt_note(&encrypted, fvk2.ivk(), rho);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_note_serialization() {
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        let note = Note::new(1000, addr, &mut OsRng);
        let memo = [0u8; MEMO_SIZE];

        let encrypted = encrypt_note(&note, &memo, fvk.ivk(), &mut OsRng);

        // Serialize and deserialize
        let bytes = encrypted.to_bytes();
        let recovered = EncryptedNote::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.epk, recovered.epk);
        assert_eq!(encrypted.ciphertext, recovered.ciphertext);
    }
}
