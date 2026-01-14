/// Apertrue ProofB - COSE Signature + Merkle Membership
///
/// This is the second half of the split-proof architecture for RSA-4096 support.
///
/// ProofB proves:
/// 1. A valid COSE signature exists (ES256 or PS256) using the leaf key
/// 2. The intermediate CA is in the Oracle's promoted trust list (Merkle membership)
/// 3. The blinded link commitment matches (links to ProofA without revealing intermediate)
/// 4. The nullifier is correctly derived from the leaf key and content hash
/// 5. Certificate validity at proof time
///
/// PUBLIC INPUTS (shared with ProofA - must match):
/// - trust_list_root: Oracle's Merkle root
/// - content_hash: SHA256 of stripped image
/// - nullifier: pedersen_hash([content_hash, leaf_key_hash])
/// - proof_timestamp: When proof was generated
/// - cert_not_before: Certificate validity start
/// - cert_not_after: Certificate validity end
/// - link_commit: pedersen_hash([intermediate_leaf, link_blind])
///
/// PRIVATE INPUTS:
/// - COSE signature and leaf key (ECDSA or RSA-2048)
/// - COSE message hash (SHA256 of Sig_structure)
/// - Intermediate leaf value and link_blind
/// - Merkle path for intermediate

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;

// RSA verification from noir_rsa (zkpassport fork with PSS support)
use noir_rsa::rsa::verify_sha256_pss;
use noir_rsa::types::RBN2048;
use bignum::params::BigNumParams;

/// Maximum depth of the Merkle tree for promoted intermediates
global MERKLE_TREE_DEPTH: u32 = 8;

/// RSA-2048 uses 18 limbs of 120 bits
global RSA_NUM_LIMBS: u32 = 18;

/// Algorithm selectors
global ALG_ECDSA: Field = 0;
global ALG_RSA: Field = 1;

/// ProofB main entry point
fn main(
    // === PUBLIC INPUTS (shared with ProofA) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,
    cert_not_before: pub Field,
    cert_not_after: pub Field,
    link_commit: pub Field,

    // === PRIVATE: ALGORITHM SELECTOR ===
    cose_algorithm: Field,  // 0 = ECDSA (ES256), 1 = RSA (PS256)

    // === PRIVATE: ECDSA COSE SIGNATURE (when cose_algorithm == 0) ===
    cose_signature_ecdsa: [u8; 64],
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],

    // === PRIVATE: RSA COSE SIGNATURE (when cose_algorithm == 1) ===
    cose_signature_rsa_limbs: [u128; RSA_NUM_LIMBS],
    leaf_rsa_modulus_limbs: [u128; RSA_NUM_LIMBS],
    leaf_rsa_redc_limbs: [u128; RSA_NUM_LIMBS],

    // === PRIVATE: COSE MESSAGE HASH ===
    cose_message_hash: [u8; 32],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,  // pedersen_hash of intermediate key material
    link_blind: Field,         // random blinding factor

    // === PRIVATE: MERKLE MEMBERSHIP ===
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH]
) {
    // Validate algorithm selector
    assert((cose_algorithm == ALG_ECDSA) | (cose_algorithm == ALG_RSA), "Invalid COSE algorithm");

    // ================================================================
    // STEP 1: Verify COSE signature (leaf key signed the C2PA claim)
    // ================================================================
    if cose_algorithm == ALG_ECDSA {
        // ES256: ECDSA P-256 signature
        let cose_valid = verify_signature(
            leaf_pubkey_x,
            leaf_pubkey_y,
            cose_signature_ecdsa,
            cose_message_hash
        );
        assert(cose_valid, "Invalid ECDSA COSE signature");
    } else {
        // PS256: RSA-2048 with RSASSA-PSS (SHA-256)
        let params: BigNumParams<18, 2048> = BigNumParams::new(
            false,
            leaf_rsa_modulus_limbs,
            leaf_rsa_redc_limbs
        );
        let signature: RBN2048 = RBN2048::from_array(params, cose_signature_rsa_limbs);
        // Try with salt_len = 32 (hash output length, RFC 8152 recommendation)
        // If this fails, Adobe might use different salt length
        let rsa_valid = verify_sha256_pss(cose_message_hash, signature, 65537, 32);
        assert(rsa_valid, "Invalid RSA COSE signature (PS256)");
    }

    // ================================================================
    // STEP 2: Verify Merkle membership for intermediate
    // ================================================================
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate not in trust list");

    // ================================================================
    // STEP 3: Verify link commitment (binds to ProofA)
    // ================================================================
    let expected_link_commit = pedersen_hash([intermediate_leaf, link_blind]);
    assert(link_commit == expected_link_commit, "Link commitment mismatch");

    // ================================================================
    // STEP 4: Verify nullifier derivation (binds leaf key to content)
    // ================================================================
    let leaf_pubkey_hash = if cose_algorithm == ALG_ECDSA {
        let leaf_x_field = bytes_to_field(leaf_pubkey_x);
        let leaf_y_field = bytes_to_field(leaf_pubkey_y);
        pedersen_hash([leaf_x_field, leaf_y_field])
    } else {
        pedersen_hash([leaf_rsa_modulus_limbs[0] as Field, leaf_rsa_modulus_limbs[1] as Field])
    };

    let expected_nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");

    // ================================================================
    // STEP 5: Verify certificate validity at proof time
    // ================================================================
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid at proof time");
    assert(ts <= not_after, "Certificate expired at proof time");
}

/// Convert 32 bytes to Field (big-endian)
fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Compute Merkle root from leaf and proof
fn compute_merkle_root(
    leaf: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [Field; MERKLE_TREE_DEPTH]
) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        let path_element = path[i];
        let is_right = indices[i];
        let left = if is_right == 0 { current } else { path_element };
        let right = if is_right == 0 { path_element } else { current };
        current = pedersen_hash([left, right]);
    }

    current
}

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_link_commitment() {
    let intermediate_leaf: Field = 12345;
    let link_blind: Field = 67890;
    let commit = pedersen_hash([intermediate_leaf, link_blind]);
    
    // Verify same inputs produce same output
    let commit2 = pedersen_hash([intermediate_leaf, link_blind]);
    assert(commit == commit2);
}

#[test]
fn test_nullifier_derivation() {
    let content_hash: Field = 111;
    let leaf_key_hash: Field = 222;
    let nullifier = pedersen_hash([content_hash, leaf_key_hash]);
    
    // Different content hash -> different nullifier
    let different_content: Field = 333;
    let different_nullifier = pedersen_hash([different_content, leaf_key_hash]);
    assert(nullifier != different_nullifier);
}
