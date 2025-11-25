//! Halo2 circuit for the simplified Orchard protocol
//!
//! This module contains the zero-knowledge circuit that proves:
//! 1. The spent note exists in the Merkle tree (membership proof)
//! 2. The nullifier is correctly derived from the note
//! 3. The output commitment is correctly computed
//! 4. Value is conserved (input value = output value + public output)
//!
//! Circuit Public Inputs:
//! - anchor: Merkle tree root
//! - nullifier: Nullifier of the spent note
//! - output_commitment: Commitment to the output note
//! - public_value: Value being deshielded (0 for fully shielded)
//!
//! Circuit Private Inputs (Witness):
//! - Input note (value, recipient, rho, rseed)
//! - Nullifier key
//! - Merkle path (32 siblings)
//! - Output note (value, recipient, rho, rseed)

pub mod gadgets;
pub mod action;

pub use action::{ActionCircuit, ActionInstance, ActionWitness};
