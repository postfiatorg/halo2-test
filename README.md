# Halo2 Test - Simplified Orchard Protocol

A simplified implementation of a privacy-preserving transaction protocol inspired by Zcash's Orchard, built with the Halo2 proof system.

## Overview

This project demonstrates how to build a privacy protocol that allows:
- **Fully shielded transfers** - Send value privately between users
- **Public outputs (deshielding)** - Withdraw private funds to public addresses
- **Zero-knowledge proofs** - Prove transaction validity without revealing sensitive data

The implementation follows Zcash's production design choices while simplifying certain aspects for clarity and educational purposes.

## Key Features

### Cryptographic Components

- **32-level Merkle tree** - Same depth as Zcash production for note commitment tracking
- **Poseidon hash function** - Efficient algebraic hash (P128Pow5T3 spec, width=3, rate=2)
- **In-circuit computation** - All hashing happens inside the ZK circuit with proper constraints
- **ChaCha20Poly1305 AEAD** - Industry-standard note encryption
- **Halo2 proof system** - Recursive-friendly SNARKs without trusted setup

### Privacy Features

- **Hidden sender** - Transaction nullifiers reveal nothing about the spender
- **Hidden recipient** - Note commitments hide the receiver's address
- **Hidden amounts** - Values are encrypted in shielded transfers
- **Double-spend prevention** - Nullifiers prevent spending the same note twice
- **Selective disclosure** - Can prove specific properties without revealing everything

## Architecture

### Core Components

```
src/
├── main.rs              # Example demonstrations
├── lib.rs               # Public API
├── constants.rs         # Protocol parameters
├── keys.rs              # Key hierarchy (SpendingKey → FVK → Address)
├── note.rs              # Note structure and serialization
├── commitment.rs        # Note commitment computation
├── nullifier.rs         # Nullifier derivation and tracking
├── encryption.rs        # ChaCha20Poly1305 note encryption
├── merkle.rs            # 32-level sparse Merkle tree
└── circuit/
    ├── mod.rs           # Circuit interface
    ├── action.rs        # Main action circuit with in-circuit Poseidon
    └── gadgets.rs       # Poseidon hash gadgets
```

### Key Hierarchy

```
SpendingKey (sk)
    ↓
FullViewingKey (fvk)
    ├── NullifierKey (nk)        - Derives nullifiers
    ├── IncomingViewingKey (ivk) - Decrypts received notes
    └── OutgoingViewingKey (ovk) - Decrypts sent notes
    ↓
Address (recipient)              - Public payment address
```

### Note Structure

```rust
Note {
    value: u64,           // Amount (hidden in commitment)
    recipient: Address,   // Recipient address (hidden)
    rho: Fp,             // Randomness for unlinkability
    rseed: Fp,           // Random seed for commitment
}
```

### Circuit Public Inputs

The zero-knowledge proof reveals only:
- `anchor` - Merkle tree root (proves note exists in valid state)
- `nullifier` - Unique identifier for spent note (prevents double-spend)
- `output_commitment` - New note commitment (hides value and recipient)
- `public_value` - Amount entering/leaving shielded pool (0 for fully private)

Everything else (sender identity, amounts, which note was spent) remains private.

## How It Works

### Shielded Transfer Example

Alice sends 1000 units to Bob privately:

```
1. Alice has a note: Note(1000, alice_addr, ...)
2. Alice computes nullifier: nf = poseidon_hash(nk, rho)
3. Alice creates Bob's note: Note(1000, bob_addr, ...)
4. Alice generates Merkle path for her note
5. Alice creates ZK proof proving:
   - She knows a note in the tree (Merkle path verification)
   - She knows the spending key (can derive nullifier)
   - Input value = Output value (no inflation)
6. Alice publishes: (proof, nf, bob_cm, encrypted_note)
7. Blockchain verifies proof and checks nf not spent
8. Bob scans encrypted_note, decrypts with his ivk
9. Bob receives the note privately
```

**What's public:** Nullifier, new commitment, encrypted blob
**What's private:** Alice's identity, Bob's identity, amount, which note was spent

### Deshielding Example

Carol withdraws 300 units from a 1000-unit shielded note:

```
1. Carol has: Note(1000, carol_addr, ...)
2. Carol creates change note: Note(700, carol_addr, ...)
3. Carol generates proof with public_value = 300
4. Blockchain verifies proof
5. Blockchain mints 300 public coins to Carol
6. Carol keeps 700 units shielded as change
```

**What's public:** 300 units withdrawn
**What's private:** Carol's identity, original amount (1000), change amount (700)

## Blockchain Integration

### On-Chain Data (Public)

| Data | Size | Purpose |
|------|------|---------|
| Merkle root | 32 bytes | Current state of note commitment tree |
| Nullifier | 32 bytes | Spent note identifier (prevents double-spend) |
| Output commitment | 32 bytes | New note identifier (hides value/recipient) |
| ZK Proof | ~KB | Proves transaction validity |
| Encrypted note | ~100 bytes | Ciphertext for recipient |
| Public value | 8 bytes | Amount entering/leaving pool |

### Off-Chain Data (Private)

- Note contents (value, recipient, randomness)
- Spending keys and viewing keys
- Full Merkle tree (validators maintain this)
- Transaction graph (who paid whom)

### Validator Responsibilities

Validators must:
1. Maintain full Merkle tree of all note commitments
2. Maintain full nullifier set
3. Verify ZK proofs
4. Check nullifiers not already spent
5. Insert new commitments into tree
6. Update tree root
7. Enforce value balance (no inflation)

Light clients only need:
- Merkle root (from block headers)
- Nullifier set (or proofs of non-membership)

## Technical Details

### Poseidon Hash Configuration

```rust
Type: P128Pow5T3
Width: 3 (state size)
Rate: 2 (inputs per permutation)
Capacity: 1 (security buffer)
Security: 128-bit
```

Used for:
- Note commitments: `cm = poseidon_hash_4(value, recipient, rho, rcm)`
- Nullifiers: `nf = poseidon_hash_3(domain, nk, rho)`
- Merkle tree: `parent = poseidon_hash_2(left, right)`

### Circuit Parameters

- **k = 13** - Circuit size parameter (2^13 = 8192 rows)
- Required for in-circuit Poseidon hashing across:
  - 1 note commitment computation
  - 1 nullifier computation
  - 32 Merkle path hash computations

### Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| halo2_proofs | 0.3 | ZK proof system |
| halo2_gadgets | 0.3 | Poseidon chip implementation |
| ff | 0.13 | Finite field arithmetic |
| group | 0.13 | Elliptic curve operations |
| chacha20poly1305 | 0.10 | AEAD encryption |
| blake2 | 0.10 | Key derivation |
| rand | 0.8 | Randomness generation |

## Running the Examples

```bash
# Run both demonstrations
cargo run

# Run tests
cargo test

# Run specific example
cargo run --bin halo2-test
```

### Example Output

The demo runs two scenarios:

1. **Fully Shielded Transfer** - Alice → Bob (1000 units, fully private)
2. **Public Output** - Carol deshields 300 units (private → public)

Both generate and verify zero-knowledge proofs using MockProver.

## Differences from Production Orchard

This implementation simplifies:

| Aspect | This Project | Zcash Orchard |
|--------|--------------|---------------|
| Transaction parsing | Manual witness construction | Parse from bytes |
| Proof generation | MockProver (testing) | Real proof generation |
| Key agreement | Simplified | Full DH key agreement |
| Memo handling | Basic array | Rich memo format |
| Value commitment | Simplified | Pedersen commitments |
| Binding signature | Not implemented | RedPallas signature |

Core cryptography matches production:
- ✅ 32-level Merkle tree
- ✅ Poseidon hash (same spec)
- ✅ In-circuit computation
- ✅ Note encryption
- ✅ Key hierarchy
- ✅ Nullifier derivation

## Security Considerations

This is **educational code** and should not be used in production without:

1. **Formal audit** - Cryptographic review of circuit constraints
2. **Real proof generation** - Replace MockProver with actual proving system
3. **Binding signatures** - Add signatures to prevent malleability
4. **Comprehensive tests** - Including malicious witness testing
5. **Constant-time operations** - Prevent timing side-channels
6. **Key management** - Secure storage and handling
7. **Fee mechanism** - Incentivize validators
8. **Replay protection** - Cross-chain protection

## Learning Resources

- [Zcash Orchard Book](https://zcash.github.io/orchard/) - Official Orchard documentation
- [Halo2 Book](https://zcash.github.io/halo2/) - Halo2 proof system guide
- [ZCash Protocol Spec](https://zips.z.cash/protocol/protocol.pdf) - Full protocol specification
- [Poseidon Paper](https://eprint.iacr.org/2019/458.pdf) - Hash function design

## License

This is educational demonstration code. See LICENSE for details.

## Acknowledgments

Built on the shoulders of:
- Zcash team for Orchard protocol design
- Electric Coin Company for Halo2 implementation
- Poseidon hash function designers
