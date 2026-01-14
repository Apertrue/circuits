/// Apertrue ProofA - Certificate Chain Verification
///
/// Refactored for Oracle-Based Verification (No in-circuit RSA)
///
/// ProofA proves:
/// 1. The Leaf Public Key (identity) is exposed publicly as a hash.
/// 2. The Leaf Public Key is bound to the Nullifier (preventing double-spend).
/// 3. The Proof is linked to ProofB via a Link Commitment.
///
/// The Off-chain Oracle (Verifier) assumes responsibility for verifying:
/// - The Certificate Chain (Leaf -> Intermediate -> Root).
/// - The Leaf Public Key Hash matches the actual Leaf Certificate.

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;

// Constants
global LEAF_ALG_ECDSA: Field = 0;
global LEAF_ALG_RSA: Field = 1;

/// ProofA main entry point
fn main(
    // === PUBLIC INPUTS (shared with ProofB) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,
    cert_not_before: pub Field,
    cert_not_after: pub Field,
    link_commit: pub Field,

    // === NEW PUBLIC INPUT: Leaf Key Identity ===
    // This allows the Oracle/Server to check the off-chain signature against this key
    leaf_pubkey_hash: pub Field,

    // === PRIVATE: ALGORITHM SELECTORS ===
    cert_algorithm: Field,  // Unused in this simplified circuit but kept for structure
    leaf_key_type: Field,   // 0 = ECDSA, 1 = RSA

    // === PRIVATE: LEAF KEY (for nullifier binding) ===
    // ECDSA leaf key
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],
    // RSA leaf key (first two limbs sufficient for hash)
    leaf_rsa_modulus_limb0: u128,
    leaf_rsa_modulus_limb1: u128,

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,  // pedersen_hash of intermediate key material
    link_blind: Field          // random blinding factor (same as in ProofB)
) {
    // ================================================================
    // STEP 1: Derive Leaf Key Hash
    // ================================================================
    let computed_leaf_key_hash = if leaf_key_type == LEAF_ALG_ECDSA {
        let x_field = bytes_to_field(leaf_pubkey_x);
        let y_field = bytes_to_field(leaf_pubkey_y);
        pedersen_hash([x_field, y_field])
    } else {
        pedersen_hash([leaf_rsa_modulus_limb0 as Field, leaf_rsa_modulus_limb1 as Field])
    };

    // Correctness Check: Assert the derived hash matches the public claim
    assert(leaf_pubkey_hash == computed_leaf_key_hash, "Leaf public key hash mismatch");

    // ================================================================
    // STEP 2: Verify Nullifier Derivation
    // ================================================================
    // This binds the Leaf Key to the Content Hash
    let expected_nullifier = pedersen_hash([content_hash, computed_leaf_key_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier (leaf key binding failed)");

    // ================================================================
    // STEP 3: Verify Link Commitment
    // ================================================================
    // This binds this proof to ProofB (which validates intermediate_leaf in Trust List)
    let expected_link_commit = pedersen_hash([intermediate_leaf, link_blind]);
    assert(link_commit == expected_link_commit, "Link commitment mismatch");

    // ================================================================
    // STEP 4: Certificate Validity (Time)
    // ================================================================
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid at proof time");
    assert(ts <= not_after, "Certificate expired at proof time");

    // Unused inputs to silence warnings
    let _ = trust_list_root;
    let _ = cert_algorithm;
}

/// Convert 32 bytes to Field (big-endian)
fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_intermediate_leaf_ecdsa() {
    let x: [u8; 32] = [1; 32];
    let y: [u8; 32] = [2; 32];
    
    let x_field = bytes_to_field(x);
    let y_field = bytes_to_field(y);
    let leaf = pedersen_hash([x_field, y_field]);
    
    // Verify same inputs produce same output
    let leaf2 = pedersen_hash([x_field, y_field]);
    assert(leaf == leaf2);
}

#[test]
fn test_intermediate_leaf_rsa() {
    let modulus_limb0: u128 = 12345678901234567890;
    let modulus_limb1: u128 = 98765432109876543210;
    
    let leaf = pedersen_hash([modulus_limb0 as Field, modulus_limb1 as Field]);
    
    // Different limbs -> different leaf
    let different_limb0: u128 = 11111111111111111111;
    let different_leaf = pedersen_hash([different_limb0 as Field, modulus_limb1 as Field]);
    assert(leaf != different_leaf);
}

#[test]
fn test_leaf_key_binding() {
    // Simulate the splice attack prevention:
    // ProofA derives nullifier from TBS leaf key
    // ProofB derives nullifier from COSE leaf key
    // If they match, the leaf keys must be the same
    
    let content_hash: Field = 999;
    let leaf_key_hash_a: Field = 111;
    let leaf_key_hash_b: Field = 111; // Same as A
    
    let nullifier_a = pedersen_hash([content_hash, leaf_key_hash_a]);
    let nullifier_b = pedersen_hash([content_hash, leaf_key_hash_b]);
    
    assert(nullifier_a == nullifier_b);
    
    // Different leaf key -> different nullifier (attack detected)

    let attacker_leaf_key: Field = 222;
    let attacker_nullifier = pedersen_hash([content_hash, attacker_leaf_key]);
    assert(nullifier_a != attacker_nullifier);
}
