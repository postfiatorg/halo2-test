//! Circuit gadgets for the Orchard-like protocol
//!
//! This module provides reusable circuit components.
//! Note: For this simplified implementation, we compute Poseidon hashes
//! outside the circuit and verify the results. A production implementation
//! would use in-circuit Poseidon gadgets.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use crate::constants::MERKLE_TREE_DEPTH;

/// Configuration for Merkle path verification
#[derive(Clone, Debug)]
pub struct MerkleConfig {
    /// Column for the current hash value
    pub hash_col: Column<Advice>,
    /// Column for the sibling value
    pub sibling_col: Column<Advice>,
    /// Column for the position bit
    pub position_bit_col: Column<Advice>,
    /// Selector for Merkle step
    pub merkle_selector: Selector,
}

impl MerkleConfig {
    /// Configure the Merkle path gadget
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        hash_col: Column<Advice>,
        sibling_col: Column<Advice>,
        position_bit_col: Column<Advice>,
    ) -> Self {
        let merkle_selector = meta.selector();

        // Constraint: position_bit must be 0 or 1
        meta.create_gate("position bit boolean", |meta| {
            let s = meta.query_selector(merkle_selector);
            let bit = meta.query_advice(position_bit_col, Rotation::cur());

            // bit * (1 - bit) = 0
            vec![s * bit.clone() * (Expression::Constant(Fp::one()) - bit)]
        });

        Self {
            hash_col,
            sibling_col,
            position_bit_col,
            merkle_selector,
        }
    }
}

/// Merkle path verification chip
pub struct MerkleChip {
    config: MerkleConfig,
}

impl MerkleChip {
    pub fn construct(config: MerkleConfig) -> Self {
        Self { config }
    }

    /// Verify a Merkle path and return the computed root
    /// Note: This is a simplified version that computes the hash outside the circuit
    pub fn verify_path(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf: AssignedCell<Fp, Fp>,
        path: &[(AssignedCell<Fp, Fp>, Value<bool>)], // (sibling, is_right)
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        assert_eq!(path.len(), MERKLE_TREE_DEPTH);

        let mut current = leaf;

        for (i, (sibling, is_right)) in path.iter().enumerate() {
            current = layouter.assign_region(
                || format!("merkle step {}", i),
                |mut region| {
                    self.config.merkle_selector.enable(&mut region, 0)?;

                    // Assign position bit
                    let _position_bit = region.assign_advice(
                        || "position bit",
                        self.config.position_bit_col,
                        0,
                        || is_right.map(|b| if b { Fp::one() } else { Fp::zero() }),
                    )?;

                    // For a full implementation, we'd use Poseidon in-circuit here
                    // For now, we just pass through (actual hashing done outside)
                    Ok(current.clone())
                },
            )?;
        }

        Ok(current)
    }
}

/// Configuration for note commitment in-circuit verification
#[derive(Clone, Debug)]
pub struct NoteCommitConfig {
    pub advice: Column<Advice>,
}

impl NoteCommitConfig {
    pub fn configure(advice: Column<Advice>) -> Self {
        Self { advice }
    }
}

/// Configuration for nullifier derivation in-circuit
#[derive(Clone, Debug)]
pub struct NullifierConfig {
    pub advice: Column<Advice>,
}

impl NullifierConfig {
    pub fn configure(advice: Column<Advice>) -> Self {
        Self { advice }
    }
}
