//! Simplified Orchard Protocol - Examples
//!
//! This demonstrates two key operations:
//! 1. Fully shielded transfer - private input to private output
//! 2. Public output (deshielding) - private input to public value
//!
//! The protocol mirrors Zcash's Orchard with:
//! - 32-level Merkle tree (same as production)
//! - Poseidon hash for commitments
//! - Note encryption with ChaCha20Poly1305
//! - Halo2 ZK proofs

use halo2_proofs::dev::MockProver;
use rand::rngs::OsRng;

use halo2_test::{
    circuit::{ActionCircuit, ActionInstance, ActionWitness},
    encryption::{encrypt_note, decrypt_note},
    keys::SpendingKey,
    merkle::MerkleTree,
    note::Note,
    nullifier::NullifierSet,
    constants::MEMO_SIZE,
};

fn main() {
    println!("==============================================");
    println!("  Simplified Orchard Protocol Demonstration");
    println!("==============================================\n");

    // Run both examples
    example_fully_shielded_transfer();
    println!("\n{}\n", "=".repeat(46));
    example_public_output();
}

/// Example 1: Fully Shielded Transfer
///
/// Alice sends 1000 units to Bob, completely privately.
/// - Input: Alice's note (1000 units)
/// - Output: Bob's note (1000 units)
/// - Public value: 0 (nothing revealed)
fn example_fully_shielded_transfer() {
    println!("Example 1: Fully Shielded Transfer");
    println!("-----------------------------------\n");

    // ===== Setup: Create keys for Alice and Bob =====
    println!("1. Setting up keys...");

    let alice_sk = SpendingKey::random(&mut OsRng);
    let alice_fvk = alice_sk.to_full_viewing_key();
    let alice_addr = alice_sk.to_address();
    println!("   Alice's address created");

    let bob_sk = SpendingKey::random(&mut OsRng);
    let bob_fvk = bob_sk.to_full_viewing_key();
    let bob_addr = bob_sk.to_address();
    println!("   Bob's address created");

    // ===== Create Alice's initial note =====
    println!("\n2. Creating Alice's initial note (1000 units)...");

    let alice_note = Note::new(1000, alice_addr.clone(), &mut OsRng);
    let alice_cm = alice_note.commitment();
    println!("   Note commitment: {:?}", alice_cm);

    // ===== Add to Merkle tree (simulating blockchain) =====
    println!("\n3. Adding note to Merkle tree...");

    let mut tree = MerkleTree::new();
    let position = tree.append(alice_cm);
    let anchor = tree.root();
    println!("   Position in tree: {}", position);
    println!("   Merkle root (anchor): {:?}", anchor);

    // ===== Alice spends her note to create Bob's note =====
    println!("\n4. Alice creates shielded transfer to Bob...");

    // Get Merkle path for Alice's note
    let merkle_path = tree.witness(position).expect("Note should be in tree");

    // Compute nullifier (this will be revealed to prevent double-spend)
    let nullifier = alice_note.nullifier(&alice_fvk);
    println!("   Nullifier: {:?}", nullifier);

    // Create Bob's note (same value - fully shielded)
    let bob_note = Note::new(1000, bob_addr.clone(), &mut OsRng);
    let bob_cm = bob_note.commitment();
    println!("   Bob's note commitment: {:?}", bob_cm);

    // ===== Encrypt note for Bob =====
    println!("\n5. Encrypting note for Bob...");

    let memo = [0u8; MEMO_SIZE]; // Empty memo
    let encrypted_note = encrypt_note(&bob_note, &memo, bob_fvk.ivk(), &mut OsRng);
    println!("   Encrypted note size: {} bytes", encrypted_note.size());

    // ===== Create and verify ZK proof =====
    println!("\n6. Creating zero-knowledge proof...");

    let witness = ActionWitness::new(
        alice_note.value(),
        alice_note.recipient().to_field(),
        alice_note.rho(),
        alice_note.rcm(),
        alice_fvk.nk().to_field(),
        merkle_path.siblings().to_vec(),
        merkle_path.position(),
        bob_note.value(),
        bob_note.recipient().to_field(),
        bob_note.rho(),
        bob_note.rcm(),
    );

    let circuit = ActionCircuit::new(witness);

    let instance = ActionInstance {
        anchor,
        nullifier,
        output_commitment: bob_cm,
        public_value: 0, // Fully shielded!
    };

    // Verify with MockProver (in production, this would generate a real proof)
    // k=13 because in-circuit Poseidon hashing requires more rows
    let k = 13;
    let prover = MockProver::run(k, &circuit, instance.to_instance()).unwrap();

    match prover.verify() {
        Ok(_) => println!("   Proof VERIFIED successfully!"),
        Err(e) => println!("   Proof FAILED: {:?}", e),
    }

    // ===== Simulate Bob receiving the note =====
    println!("\n7. Bob decrypts and receives the note...");

    // Bob needs to know rho (in real Orchard, this is derived from nullifier)
    // For this demo, we pass it directly
    let rho = bob_note.rho();

    match decrypt_note(&encrypted_note, bob_fvk.ivk(), rho) {
        Ok((decrypted_note, _memo)) => {
            println!("   Bob decrypted note successfully!");
            println!("   Value received: {} units", decrypted_note.value());
        }
        Err(e) => println!("   Decryption failed: {:?}", e),
    }

    // ===== Update nullifier set (prevent double-spend) =====
    println!("\n8. Recording nullifier to prevent double-spend...");

    let mut nullifier_set = NullifierSet::new();
    nullifier_set.insert(nullifier);
    println!("   Nullifier recorded. Alice's note is now spent.");

    println!("\n   Transfer complete!");
    println!("   - Alice spent 1000 units (privately)");
    println!("   - Bob received 1000 units (privately)");
    println!("   - No values or addresses were revealed publicly");
}

/// Example 2: Public Output (Deshielding)
///
/// Carol deshields 300 units from her shielded note.
/// - Input: Carol's note (1000 units)
/// - Output: Carol's change note (700 units)
/// - Public value: 300 (revealed for withdrawal)
fn example_public_output() {
    println!("Example 2: Public Output (Deshielding)");
    println!("--------------------------------------\n");

    // ===== Setup =====
    println!("1. Setting up Carol's keys...");

    let carol_sk = SpendingKey::random(&mut OsRng);
    let carol_fvk = carol_sk.to_full_viewing_key();
    let carol_addr = carol_sk.to_address();
    println!("   Carol's address created");

    // ===== Create Carol's shielded note =====
    println!("\n2. Creating Carol's shielded note (1000 units)...");

    let carol_note = Note::new(1000, carol_addr.clone(), &mut OsRng);
    let carol_cm = carol_note.commitment();

    let mut tree = MerkleTree::new();
    let position = tree.append(carol_cm);
    let anchor = tree.root();
    println!("   Note added to tree at position {}", position);

    // ===== Carol deshields 300 units =====
    println!("\n3. Carol deshields 300 units...");
    println!("   - Input: 1000 units (shielded)");
    println!("   - Output: 700 units (shielded change)");
    println!("   - Public: 300 units (deshielded)");

    let merkle_path = tree.witness(position).unwrap();
    let nullifier = carol_note.nullifier(&carol_fvk);

    // Create change note (700 units back to Carol)
    let change_note = Note::new(700, carol_addr.clone(), &mut OsRng);
    let change_cm = change_note.commitment();

    // ===== Create ZK proof for deshielding =====
    println!("\n4. Creating zero-knowledge proof...");

    let witness = ActionWitness::new(
        1000,
        carol_note.recipient().to_field(),
        carol_note.rho(),
        carol_note.rcm(),
        carol_fvk.nk().to_field(),
        merkle_path.siblings().to_vec(),
        merkle_path.position(),
        700,
        change_note.recipient().to_field(),
        change_note.rho(),
        change_note.rcm(),
    );

    let circuit = ActionCircuit::new(witness);

    let instance = ActionInstance {
        anchor,
        nullifier,
        output_commitment: change_cm,
        public_value: 300, // This is revealed!
    };

    // k=13 for in-circuit Poseidon
    let k = 13;
    let prover = MockProver::run(k, &circuit, instance.to_instance()).unwrap();

    match prover.verify() {
        Ok(_) => println!("   Proof VERIFIED successfully!"),
        Err(e) => println!("   Proof FAILED: {:?}", e),
    }

    // ===== Show what's public vs private =====
    println!("\n5. Transaction summary:");
    println!("\n   PUBLIC (visible to everyone):");
    println!("   - Merkle anchor: {:?}", anchor);
    println!("   - Nullifier: {:?}", nullifier);
    println!("   - Output commitment: {:?}", change_cm);
    println!("   - Deshielded value: 300 units");

    println!("\n   PRIVATE (hidden by ZK proof):");
    println!("   - Carol's identity");
    println!("   - Original note value (1000)");
    println!("   - Change note value (700)");
    println!("   - Which note in the tree was spent");

    println!("\n   Deshielding complete!");
    println!("   Carol can now use 300 units publicly (e.g., exchange withdrawal)");
}
