//! Simplified Orchard-like Protocol Implementation
//!
//! This implements a privacy protocol similar to Zcash's Orchard, with:
//! - 32-level Merkle tree for note commitments (same as production Zcash)
//! - Poseidon hash for commitments and nullifiers
//! - Halo2 circuit for proving valid spends
//! - Note encryption using ChaCha20Poly1305 AEAD
//!
//! The protocol supports:
//! - Fully shielded transfers (private sender, private receiver, private amount)
//! - Public outputs (deshielding - private input to public output)

pub mod constants;
pub mod keys;
pub mod note;
pub mod commitment;
pub mod nullifier;
pub mod encryption;
pub mod merkle;
pub mod circuit;

// Re-exports for convenience
pub use constants::*;
pub use keys::{SpendingKey, FullViewingKey, IncomingViewingKey, OutgoingViewingKey, NullifierKey, Address};
pub use note::Note;
pub use commitment::NoteCommitment;
pub use nullifier::Nullifier;
pub use encryption::{EncryptedNote, encrypt_note, decrypt_note};
pub use merkle::{MerkleTree, MerklePath, Anchor};
