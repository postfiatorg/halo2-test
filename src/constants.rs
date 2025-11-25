//! Protocol constants matching Zcash Orchard production values

/// Merkle tree depth - 32 levels allows for 2^32 (~4.3 billion) notes
/// This matches Zcash Orchard production: sapling::NOTE_COMMITMENT_TREE_DEPTH
pub const MERKLE_TREE_DEPTH: usize = 32;

/// Note plaintext size in bytes:
/// - 1 byte: note type flag
/// - 8 bytes: value (u64)
/// - 32 bytes: recipient address
/// - 32 bytes: rseed
/// - 512 bytes: memo
pub const NOTE_PLAINTEXT_SIZE: usize = 1 + 8 + 32 + 32 + 512;

/// Encrypted note ciphertext size (plaintext + 16 byte AEAD tag)
pub const ENCRYPTED_NOTE_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;

/// Memo field size in bytes (matches Zcash)
pub const MEMO_SIZE: usize = 512;

/// Maximum value in a note (64-bit unsigned integer)
pub const MAX_NOTE_VALUE: u64 = u64::MAX;

/// Domain separators for hash functions (following Orchard conventions)
pub mod domains {
    /// Domain separator for note commitment
    pub const NOTE_COMMIT: &[u8] = b"SimplifiedOrchard_NoteCommit";

    /// Domain separator for nullifier derivation
    pub const NULLIFIER: &[u8] = b"SimplifiedOrchard_Nullifier";

    /// Domain separator for Merkle tree hashing
    pub const MERKLE_TREE: &[u8] = b"SimplifiedOrchard_MerkleTree";

    /// Domain separator for key derivation
    pub const KEY_DERIVE: &[u8] = b"SimplifiedOrchard_KeyDerive";

    /// Domain separator for note encryption key derivation
    pub const NOTE_ENCRYPTION: &[u8] = b"SimplifiedOrchard_NoteEncrypt";
}
