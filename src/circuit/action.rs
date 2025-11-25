//! Action Circuit - the main ZK circuit for the protocol
//!
//! This circuit proves a valid "action" which consists of:
//! 1. Spending an existing note (proving it exists in the tree)
//! 2. Creating a new output note
//! 3. Optionally deshielding value (public output)
//!
//! The circuit enforces IN-CIRCUIT using Poseidon hash gadgets:
//! - Input note commitment is correctly computed and exists in the Merkle tree
//! - Nullifier is correctly derived from input note and nullifier key
//! - Output note commitment is correctly computed
//! - Value balance: input_value = output_value + public_value

use ff::FromUniformBytes;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};

use crate::constants::MERKLE_TREE_DEPTH;
use crate::merkle::Anchor;
use crate::nullifier::Nullifier;
use crate::commitment::NoteCommitment;

/// Poseidon spec: P128Pow5T3 for Pasta field
/// - Width: 3 (state size)
/// - Rate: 2 (input rate)
type PoseidonSpec = P128Pow5T3;
const WIDTH: usize = 3;
const RATE: usize = 2;

/// Public inputs to the circuit (instance)
#[derive(Clone, Debug)]
pub struct ActionInstance {
    /// Merkle root when the input note was created
    pub anchor: Anchor,
    /// Nullifier of the spent note
    pub nullifier: Nullifier,
    /// Commitment to the output note
    pub output_commitment: NoteCommitment,
    /// Value being made public (0 for fully shielded)
    pub public_value: u64,
}

impl ActionInstance {
    /// Convert to field elements for circuit verification
    pub fn to_instance(&self) -> Vec<Vec<Fp>> {
        vec![vec![
            self.anchor.to_field(),
            self.nullifier.to_field(),
            self.output_commitment.to_field(),
            Fp::from(self.public_value),
        ]]
    }
}

/// Private inputs to the circuit (witness)
#[derive(Clone, Debug)]
pub struct ActionWitness {
    // Input note data
    pub input_value: u64,
    pub input_recipient: Fp,
    pub input_rho: Fp,
    pub input_rcm: Fp,

    // Nullifier key
    pub nk: Fp,

    // Domain separator for nullifier (precomputed)
    pub nullifier_domain: Fp,

    // Merkle path (32 siblings and position bits)
    pub merkle_path: Vec<Fp>,
    pub merkle_position: u32,

    // Output note data
    pub output_value: u64,
    pub output_recipient: Fp,
    pub output_rho: Fp,
    pub output_rcm: Fp,
}

impl ActionWitness {
    /// Create witness with automatic domain separator computation
    pub fn new(
        input_value: u64,
        input_recipient: Fp,
        input_rho: Fp,
        input_rcm: Fp,
        nk: Fp,
        merkle_path: Vec<Fp>,
        merkle_position: u32,
        output_value: u64,
        output_recipient: Fp,
        output_rho: Fp,
        output_rcm: Fp,
    ) -> Self {
        // Compute nullifier domain separator
        let nullifier_domain = {
            use blake2::{Blake2b512, Digest};
            use crate::constants::domains;
            let mut hasher = Blake2b512::new();
            hasher.update(domains::NULLIFIER);
            let hash = hasher.finalize();
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&hash);
            Fp::from_uniform_bytes(&wide)
        };

        Self {
            input_value,
            input_recipient,
            input_rho,
            input_rcm,
            nk,
            nullifier_domain,
            merkle_path,
            merkle_position,
            output_value,
            output_recipient,
            output_rho,
            output_rcm,
        }
    }
}

/// Circuit configuration with Poseidon
#[derive(Clone, Debug)]
pub struct ActionConfig {
    // Advice columns for witness data and Poseidon state
    advice: [Column<Advice>; WIDTH],

    // Additional advice column for Poseidon partial S-box
    partial_sbox: Column<Advice>,

    // Instance column for public inputs
    instance: Column<Instance>,

    // Poseidon chip configuration
    poseidon_config: Pow5Config<Fp, WIDTH, RATE>,

    // Selector for value balance
    s_value_balance: Selector,
}

/// The main action circuit with in-circuit Poseidon hashing
#[derive(Clone, Default)]
pub struct ActionCircuit {
    /// The witness data (private inputs)
    pub witness: Option<ActionWitness>,
}

impl ActionCircuit {
    /// Create a new circuit with witness data
    pub fn new(witness: ActionWitness) -> Self {
        Self {
            witness: Some(witness),
        }
    }

    /// Create a circuit without witness (for key generation)
    pub fn empty() -> Self {
        Self { witness: None }
    }

    /// Helper: Hash two field elements using the Poseidon chip
    fn poseidon_hash_2(
        config: &Pow5Config<Fp, WIDTH, RATE>,
        mut layouter: impl Layouter<Fp>,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let chip = Pow5Chip::construct(config.clone());
        let hasher = Hash::<_, _, PoseidonSpec, ConstantLength<2>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "poseidon_hash_2 init"),
        )?;
        hasher.hash(layouter.namespace(|| "poseidon_hash_2"), [a, b])
    }

    /// Helper: Hash four field elements (for note commitment)
    /// Uses Merkle-Damgard construction: hash(hash(hash(a,b), c), d)
    fn poseidon_hash_4(
        config: &Pow5Config<Fp, WIDTH, RATE>,
        mut layouter: impl Layouter<Fp>,
        inputs: [AssignedCell<Fp, Fp>; 4],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        // First: hash(inputs[0], inputs[1])
        let h1 = Self::poseidon_hash_2(
            config,
            layouter.namespace(|| "hash_4 step 1"),
            inputs[0].clone(),
            inputs[1].clone(),
        )?;

        // Second: hash(h1, inputs[2])
        let h2 = Self::poseidon_hash_2(
            config,
            layouter.namespace(|| "hash_4 step 2"),
            h1,
            inputs[2].clone(),
        )?;

        // Third: hash(h2, inputs[3])
        Self::poseidon_hash_2(
            config,
            layouter.namespace(|| "hash_4 step 3"),
            h2,
            inputs[3].clone(),
        )
    }

    /// Helper: Hash three field elements (for nullifier)
    /// Uses: hash(hash(a, b), c)
    fn poseidon_hash_3(
        config: &Pow5Config<Fp, WIDTH, RATE>,
        mut layouter: impl Layouter<Fp>,
        inputs: [AssignedCell<Fp, Fp>; 3],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        // First: hash(inputs[0], inputs[1])
        let h1 = Self::poseidon_hash_2(
            config,
            layouter.namespace(|| "hash_3 step 1"),
            inputs[0].clone(),
            inputs[1].clone(),
        )?;

        // Second: hash(h1, inputs[2])
        Self::poseidon_hash_2(
            config,
            layouter.namespace(|| "hash_3 step 2"),
            h1,
            inputs[2].clone(),
        )
    }
}

impl Circuit<Fp> for ActionCircuit {
    type Config = ActionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // Create advice columns for Poseidon state
        let advice: [Column<Advice>; WIDTH] = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Enable equality for all advice columns
        for col in &advice {
            meta.enable_equality(*col);
        }

        // Partial S-box column for Poseidon
        let partial_sbox = meta.advice_column();
        meta.enable_equality(partial_sbox);

        // Create instance column for public inputs
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // Fixed columns for Poseidon round constants
        let rc_a: [Column<Fixed>; WIDTH] = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let rc_b: [Column<Fixed>; WIDTH] = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        // Enable constants (needed for Poseidon)
        meta.enable_constant(rc_b[0]);

        // Configure Poseidon chip
        let poseidon_config = Pow5Chip::configure::<PoseidonSpec>(
            meta,
            advice,
            partial_sbox,
            rc_a,
            rc_b,
        );

        // Value balance selector
        let s_value_balance = meta.selector();

        // Gate: Value balance constraint
        // input_value = output_value + public_value
        meta.create_gate("value balance", |meta| {
            let s = meta.query_selector(s_value_balance);
            let input_value = meta.query_advice(advice[0], Rotation::cur());
            let output_value = meta.query_advice(advice[1], Rotation::cur());
            let public_value = meta.query_advice(advice[2], Rotation::cur());

            // input_value - output_value - public_value = 0
            vec![s * (input_value - output_value - public_value)]
        });

        ActionConfig {
            advice,
            partial_sbox,
            instance,
            poseidon_config,
            s_value_balance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let witness = self.witness.as_ref();

        // Get reference to poseidon config for helper functions
        let poseidon_config = &config.poseidon_config;

        // ===== Assign input note values =====
        let (input_value, input_recipient, input_rho, input_rcm) = layouter.assign_region(
            || "assign input note",
            |mut region| {
                let value = region.assign_advice(
                    || "input value",
                    config.advice[0],
                    0,
                    || Value::known(Fp::from(witness.map(|w| w.input_value).unwrap_or(0))),
                )?;

                let recipient = region.assign_advice(
                    || "input recipient",
                    config.advice[1],
                    0,
                    || Value::known(witness.map(|w| w.input_recipient).unwrap_or(Fp::zero())),
                )?;

                let rho = region.assign_advice(
                    || "input rho",
                    config.advice[2],
                    0,
                    || Value::known(witness.map(|w| w.input_rho).unwrap_or(Fp::zero())),
                )?;

                let rcm = region.assign_advice(
                    || "input rcm",
                    config.advice[0],
                    1,
                    || Value::known(witness.map(|w| w.input_rcm).unwrap_or(Fp::zero())),
                )?;

                Ok((value, recipient, rho, rcm))
            },
        )?;

        // ===== Assign nullifier key and domain =====
        let (nk, nullifier_domain) = layouter.assign_region(
            || "assign nk and domain",
            |mut region| {
                let nk = region.assign_advice(
                    || "nk",
                    config.advice[0],
                    0,
                    || Value::known(witness.map(|w| w.nk).unwrap_or(Fp::zero())),
                )?;

                let domain = region.assign_advice(
                    || "nullifier domain",
                    config.advice[1],
                    0,
                    || Value::known(witness.map(|w| w.nullifier_domain).unwrap_or(Fp::zero())),
                )?;

                Ok((nk, domain))
            },
        )?;

        // ===== Assign output note values =====
        let (output_value, output_recipient, output_rho, output_rcm) = layouter.assign_region(
            || "assign output note",
            |mut region| {
                let value = region.assign_advice(
                    || "output value",
                    config.advice[0],
                    0,
                    || Value::known(Fp::from(witness.map(|w| w.output_value).unwrap_or(0))),
                )?;

                let recipient = region.assign_advice(
                    || "output recipient",
                    config.advice[1],
                    0,
                    || Value::known(witness.map(|w| w.output_recipient).unwrap_or(Fp::zero())),
                )?;

                let rho = region.assign_advice(
                    || "output rho",
                    config.advice[2],
                    0,
                    || Value::known(witness.map(|w| w.output_rho).unwrap_or(Fp::zero())),
                )?;

                let rcm = region.assign_advice(
                    || "output rcm",
                    config.advice[0],
                    1,
                    || Value::known(witness.map(|w| w.output_rcm).unwrap_or(Fp::zero())),
                )?;

                Ok((value, recipient, rho, rcm))
            },
        )?;

        // ===== Assign Merkle path siblings =====
        let merkle_siblings: Vec<AssignedCell<Fp, Fp>> = layouter.assign_region(
            || "assign merkle path",
            |mut region| {
                let mut siblings = Vec::with_capacity(MERKLE_TREE_DEPTH);
                for i in 0..MERKLE_TREE_DEPTH {
                    let sibling = region.assign_advice(
                        || format!("sibling {}", i),
                        config.advice[i % WIDTH],
                        i / WIDTH,
                        || {
                            Value::known(
                                witness
                                    .and_then(|w| w.merkle_path.get(i).copied())
                                    .unwrap_or(Fp::zero()),
                            )
                        },
                    )?;
                    siblings.push(sibling);
                }
                Ok(siblings)
            },
        )?;

        // ===== IN-CIRCUIT: Compute input note commitment =====
        // cm = poseidon_hash_4(value, recipient, rho, rcm)
        let input_cm = Self::poseidon_hash_4(
            poseidon_config,
            layouter.namespace(|| "input note commitment"),
            [
                input_value.clone(),
                input_recipient.clone(),
                input_rho.clone(),
                input_rcm.clone(),
            ],
        )?;

        // ===== IN-CIRCUIT: Compute output note commitment =====
        let output_cm = Self::poseidon_hash_4(
            poseidon_config,
            layouter.namespace(|| "output note commitment"),
            [
                output_value.clone(),
                output_recipient,
                output_rho,
                output_rcm,
            ],
        )?;

        // ===== IN-CIRCUIT: Compute nullifier =====
        // nf = poseidon_hash_3(domain, nk, rho)
        let nullifier = Self::poseidon_hash_3(
            poseidon_config,
            layouter.namespace(|| "nullifier derivation"),
            [nullifier_domain, nk, input_rho],
        )?;

        // ===== IN-CIRCUIT: Verify Merkle path =====
        // Start from input_cm and hash up to the root
        let mut current = input_cm;
        let position = witness.map(|w| w.merkle_position).unwrap_or(0);

        for (i, sibling) in merkle_siblings.iter().enumerate() {
            let is_right = (position >> i) & 1 == 1;

            // Conditional swap based on position bit
            // If is_right, hash(sibling, current), else hash(current, sibling)
            let (left, right) = if is_right {
                (sibling.clone(), current)
            } else {
                (current, sibling.clone())
            };

            current = Self::poseidon_hash_2(
                poseidon_config,
                layouter.namespace(|| format!("merkle hash level {}", i)),
                left,
                right,
            )?;
        }
        let computed_anchor = current;

        // ===== Value balance check =====
        let public_value = layouter.assign_region(
            || "value balance",
            |mut region| {
                config.s_value_balance.enable(&mut region, 0)?;

                // Re-assign values in the same row for the constraint
                let iv = region.assign_advice(
                    || "input value for balance",
                    config.advice[0],
                    0,
                    || Value::known(Fp::from(witness.map(|w| w.input_value).unwrap_or(0))),
                )?;

                let ov = region.assign_advice(
                    || "output value for balance",
                    config.advice[1],
                    0,
                    || Value::known(Fp::from(witness.map(|w| w.output_value).unwrap_or(0))),
                )?;

                // Use saturating_sub to avoid overflow - the constraint will catch invalid cases
                let public_val = witness.map(|w| w.input_value.saturating_sub(w.output_value)).unwrap_or(0);
                let pv = region.assign_advice(
                    || "public value",
                    config.advice[2],
                    0,
                    || Value::known(Fp::from(public_val)),
                )?;

                // Copy constraints to ensure these match the note values
                region.constrain_equal(iv.cell(), input_value.cell())?;
                region.constrain_equal(ov.cell(), output_value.cell())?;

                Ok(pv)
            },
        )?;

        // ===== Constrain public inputs =====

        // Constrain computed anchor to public anchor
        layouter.constrain_instance(computed_anchor.cell(), config.instance, 0)?;

        // Constrain computed nullifier to public nullifier
        layouter.constrain_instance(nullifier.cell(), config.instance, 1)?;

        // Constrain computed output commitment to public output commitment
        layouter.constrain_instance(output_cm.cell(), config.instance, 2)?;

        // Constrain public value
        layouter.constrain_instance(public_value.cell(), config.instance, 3)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_action_circuit_valid() {
        use crate::merkle::MerkleTree;
        use crate::keys::SpendingKey;
        use crate::note::Note;
        use rand::rngs::OsRng;

        // Setup: Create a note and add it to the tree
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        let input_note = Note::new(1000, addr.clone(), &mut OsRng);
        let input_cm = input_note.commitment();

        // Add to Merkle tree
        let mut tree = MerkleTree::new();
        let position = tree.append(input_cm);
        let merkle_path = tree.witness(position).unwrap();
        let anchor = tree.root();

        // Compute nullifier
        let nf = input_note.nullifier(&fvk);

        // Create output note (fully shielded - same value)
        let output_note = Note::new(1000, addr.clone(), &mut OsRng);
        let output_cm = output_note.commitment();

        // Create witness using the new constructor
        let witness = ActionWitness::new(
            input_note.value(),
            input_note.recipient().to_field(),
            input_note.rho(),
            input_note.rcm(),
            fvk.nk().to_field(),
            merkle_path.siblings().to_vec(),
            merkle_path.position(),
            output_note.value(),
            output_note.recipient().to_field(),
            output_note.rho(),
            output_note.rcm(),
        );

        // Create circuit
        let circuit = ActionCircuit::new(witness);

        // Create instance
        let instance = ActionInstance {
            anchor,
            nullifier: nf,
            output_commitment: output_cm,
            public_value: 0, // Fully shielded
        };

        // Verify with MockProver
        // k=13 because Poseidon requires more rows
        let k = 13;
        let prover = MockProver::run(k, &circuit, instance.to_instance()).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_action_circuit_deshielding() {
        use crate::merkle::MerkleTree;
        use crate::keys::SpendingKey;
        use crate::note::Note;
        use rand::rngs::OsRng;

        // Setup
        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        let input_note = Note::new(1000, addr.clone(), &mut OsRng);
        let input_cm = input_note.commitment();

        let mut tree = MerkleTree::new();
        let position = tree.append(input_cm);
        let merkle_path = tree.witness(position).unwrap();
        let anchor = tree.root();

        let nf = input_note.nullifier(&fvk);

        // Create output note with less value (deshielding 300)
        let output_note = Note::new(700, addr.clone(), &mut OsRng);
        let output_cm = output_note.commitment();

        let witness = ActionWitness::new(
            1000,
            input_note.recipient().to_field(),
            input_note.rho(),
            input_note.rcm(),
            fvk.nk().to_field(),
            merkle_path.siblings().to_vec(),
            merkle_path.position(),
            700,
            output_note.recipient().to_field(),
            output_note.rho(),
            output_note.rcm(),
        );

        let circuit = ActionCircuit::new(witness);

        let instance = ActionInstance {
            anchor,
            nullifier: nf,
            output_commitment: output_cm,
            public_value: 300, // Deshielding 300
        };

        let k = 13;
        let prover = MockProver::run(k, &circuit, instance.to_instance()).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_invalid_value_balance_fails() {
        use crate::merkle::MerkleTree;
        use crate::keys::SpendingKey;
        use crate::note::Note;
        use rand::rngs::OsRng;

        let sk = SpendingKey::random(&mut OsRng);
        let fvk = sk.to_full_viewing_key();
        let addr = sk.to_address();

        let input_note = Note::new(1000, addr.clone(), &mut OsRng);
        let input_cm = input_note.commitment();

        let mut tree = MerkleTree::new();
        let position = tree.append(input_cm);
        let merkle_path = tree.witness(position).unwrap();
        let anchor = tree.root();

        let nf = input_note.nullifier(&fvk);

        // Create output note with WRONG value (trying to create value from nothing)
        let output_note = Note::new(1500, addr.clone(), &mut OsRng); // More than input!
        let output_cm = output_note.commitment();

        let witness = ActionWitness::new(
            1000,
            input_note.recipient().to_field(),
            input_note.rho(),
            input_note.rcm(),
            fvk.nk().to_field(),
            merkle_path.siblings().to_vec(),
            merkle_path.position(),
            1500, // Wrong!
            output_note.recipient().to_field(),
            output_note.rho(),
            output_note.rcm(),
        );

        let circuit = ActionCircuit::new(witness);

        let instance = ActionInstance {
            anchor,
            nullifier: nf,
            output_commitment: output_cm,
            public_value: 0, // Claiming no public output
        };

        let k = 13;
        let prover = MockProver::run(k, &circuit, instance.to_instance()).unwrap();

        // This should FAIL because value balance is violated
        assert!(prover.verify().is_err());
    }
}
