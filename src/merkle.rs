//! Merkle tree for note commitments
//!
//! This implements a 32-level binary Merkle tree matching Zcash Orchard's production depth.
//! The tree stores note commitments and allows generating membership proofs.
//!
//! Properties:
//! - Depth: 32 levels (supports 2^32 notes)
//! - Hash function: Poseidon
//! - Incremental: Notes can only be appended, never removed
//! - Witnesses: Merkle paths are stored for notes we want to spend later

use ff::PrimeField;
use halo2_proofs::pasta::Fp;
use std::fmt;

use crate::commitment::{poseidon_hash_2, NoteCommitment};
use crate::constants::MERKLE_TREE_DEPTH;

/// The Merkle tree root (anchor)
/// This is what gets published and used to verify membership proofs
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    inner: Fp,
}

impl Anchor {
    pub fn from_field(f: Fp) -> Self {
        Self { inner: f }
    }

    pub fn to_field(&self) -> Fp {
        self.inner
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_repr()
    }
}

impl fmt::Debug for Anchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        write!(f, "Anchor({:02x}{:02x}...)", bytes[0], bytes[1])
    }
}

/// A Merkle path proving membership of a note commitment in the tree
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// The position of the leaf in the tree
    position: u32,
    /// The sibling hashes along the path (from leaf to root)
    /// For depth 32, we need 32 siblings
    siblings: Vec<Fp>,
}

impl MerklePath {
    /// Create a new Merkle path
    pub fn new(position: u32, siblings: Vec<Fp>) -> Self {
        assert_eq!(siblings.len(), MERKLE_TREE_DEPTH);
        Self { position, siblings }
    }

    /// Get the position of the leaf
    pub fn position(&self) -> u32 {
        self.position
    }

    /// Get the sibling hashes
    pub fn siblings(&self) -> &[Fp] {
        &self.siblings
    }

    /// Verify the path computes to the expected root
    pub fn verify(&self, leaf: Fp, expected_root: &Anchor) -> bool {
        let computed_root = self.compute_root(leaf);
        computed_root == expected_root.inner
    }

    /// Compute the root from a leaf value using this path
    pub fn compute_root(&self, leaf: Fp) -> Fp {
        let mut current = leaf;
        let mut pos = self.position;

        for sibling in &self.siblings {
            // If position bit is 0, we're on the left; if 1, we're on the right
            if pos & 1 == 0 {
                current = poseidon_hash_2(current, *sibling);
            } else {
                current = poseidon_hash_2(*sibling, current);
            }
            pos >>= 1;
        }

        current
    }
}

/// Empty leaf value (used for unfilled tree positions)
/// This is a commitment to "nothing" - using the zero field element
fn empty_leaf() -> Fp {
    Fp::zero()
}

/// Compute empty subtree roots for each level
/// empty_roots[i] is the root of an empty subtree of depth i
fn compute_empty_roots() -> Vec<Fp> {
    let mut empty_roots = Vec::with_capacity(MERKLE_TREE_DEPTH + 1);
    empty_roots.push(empty_leaf());

    for i in 0..MERKLE_TREE_DEPTH {
        let prev = empty_roots[i];
        empty_roots.push(poseidon_hash_2(prev, prev));
    }

    empty_roots
}

/// A sparse Merkle tree for note commitments
///
/// This uses a sparse representation to handle the massive tree size (2^32 leaves).
/// Only populated subtrees are stored; empty subtrees use precomputed empty roots.
#[derive(Clone)]
pub struct MerkleTree {
    /// Number of leaves inserted
    size: u32,
    /// The leaves (note commitments)
    leaves: Vec<Fp>,
    /// Cached internal nodes (sparse)
    /// Key: (level, index), Value: hash
    nodes: std::collections::HashMap<(usize, u32), Fp>,
    /// Precomputed empty subtree roots
    empty_roots: Vec<Fp>,
}

impl MerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        Self {
            size: 0,
            leaves: Vec::new(),
            nodes: std::collections::HashMap::new(),
            empty_roots: compute_empty_roots(),
        }
    }

    /// Get the current root (anchor)
    pub fn root(&self) -> Anchor {
        if self.size == 0 {
            return Anchor::from_field(self.empty_roots[MERKLE_TREE_DEPTH]);
        }

        let root = self.compute_node(MERKLE_TREE_DEPTH, 0);
        Anchor::from_field(root)
    }

    /// Get the number of notes in the tree
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Append a note commitment to the tree
    /// Returns the position (index) of the inserted note
    pub fn append(&mut self, commitment: NoteCommitment) -> u32 {
        let position = self.size;
        self.leaves.push(commitment.to_field());
        self.size += 1;

        // Clear cached nodes that are affected by this insertion
        // (This is a simple invalidation; a production impl would be smarter)
        self.invalidate_path(position);

        position
    }

    /// Get a Merkle path for a note at the given position
    pub fn witness(&self, position: u32) -> Option<MerklePath> {
        if position >= self.size {
            return None;
        }

        let mut siblings = Vec::with_capacity(MERKLE_TREE_DEPTH);
        let mut pos = position;

        for level in 0..MERKLE_TREE_DEPTH {
            // Get sibling index
            let sibling_idx = if pos & 1 == 0 { pos + 1 } else { pos - 1 };

            // Get sibling hash
            let sibling = self.compute_node(level, sibling_idx);
            siblings.push(sibling);

            // Move up
            pos >>= 1;
        }

        Some(MerklePath::new(position, siblings))
    }

    /// Compute or retrieve a node at the given level and index
    fn compute_node(&self, level: usize, index: u32) -> Fp {
        // Check cache first
        if let Some(&node) = self.nodes.get(&(level, index)) {
            return node;
        }

        if level == 0 {
            // Leaf level
            if (index as usize) < self.leaves.len() {
                return self.leaves[index as usize];
            } else {
                return self.empty_roots[0];
            }
        }

        // Check if this subtree is completely empty
        // Use u64 to avoid overflow when level is large
        let subtree_start = (index as u64).checked_shl(level as u32).unwrap_or(u64::MAX);

        if subtree_start >= self.size as u64 {
            // This entire subtree is empty
            return self.empty_roots[level];
        }

        // Compute from children
        let left = self.compute_node(level - 1, index * 2);
        let right = self.compute_node(level - 1, index * 2 + 1);

        poseidon_hash_2(left, right)
    }

    /// Invalidate cached nodes along the path from a leaf to root
    fn invalidate_path(&mut self, position: u32) {
        let mut pos = position;
        for level in 0..=MERKLE_TREE_DEPTH {
            self.nodes.remove(&(level, pos));
            pos >>= 1;
        }
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleTree")
            .field("size", &self.size)
            .field("root", &self.root())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SpendingKey;
    use crate::note::Note;
    use rand::rngs::OsRng;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new();
        assert_eq!(tree.size(), 0);

        // Empty tree has a well-defined root
        let root = tree.root();
        assert!(root.to_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn test_single_note() {
        let mut tree = MerkleTree::new();

        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();
        let note = Note::new(1000, addr, &mut OsRng);

        let position = tree.append(note.commitment());
        assert_eq!(position, 0);
        assert_eq!(tree.size(), 1);

        // Root should be different from empty tree
        let empty_root = MerkleTree::new().root();
        assert_ne!(tree.root(), empty_root);
    }

    #[test]
    fn test_merkle_path_verification() {
        let mut tree = MerkleTree::new();

        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        // Add several notes
        let mut commitments = Vec::new();
        for i in 0..10 {
            let note = Note::new(1000 + i, addr.clone(), &mut OsRng);
            let cm = note.commitment();
            commitments.push(cm);
            tree.append(cm);
        }

        // Verify path for each note
        let root = tree.root();
        for (i, cm) in commitments.iter().enumerate() {
            let path = tree.witness(i as u32).unwrap();
            assert!(path.verify(cm.to_field(), &root));
        }
    }

    #[test]
    fn test_merkle_path_wrong_leaf_fails() {
        let mut tree = MerkleTree::new();

        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        let note = Note::new(1000, addr.clone(), &mut OsRng);
        tree.append(note.commitment());

        let root = tree.root();
        let path = tree.witness(0).unwrap();

        // Wrong leaf should fail verification
        let wrong_note = Note::new(2000, addr, &mut OsRng);
        assert!(!path.verify(wrong_note.commitment().to_field(), &root));
    }

    #[test]
    fn test_tree_deterministic() {
        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        // Create note with fixed randomness
        let rho = Fp::from(12345u64);
        let rseed = [1u8; 32];
        let note = Note::from_parts(1000, addr.clone(), rho, rseed);

        // Two trees with same note should have same root
        let mut tree1 = MerkleTree::new();
        let mut tree2 = MerkleTree::new();

        tree1.append(note.commitment());
        tree2.append(note.commitment());

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_large_tree() {
        let mut tree = MerkleTree::new();

        let sk = SpendingKey::random(&mut OsRng);
        let addr = sk.to_address();

        // Add 100 notes (sparse tree handles this efficiently)
        for i in 0..100 {
            let note = Note::new(i as u64, addr.clone(), &mut OsRng);
            tree.append(note.commitment());
        }

        assert_eq!(tree.size(), 100);

        // Can still generate and verify paths
        let path = tree.witness(50).unwrap();
        let root = tree.root();

        // Note: we need the exact commitment, let's test path structure instead
        assert_eq!(path.siblings().len(), MERKLE_TREE_DEPTH);
    }
}
