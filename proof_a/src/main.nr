use bignum::params::BigNumParams;
use noir_rsa::types::RBN4096; 
use noir_rsa::types::RBN2048;
use noir_rsa::rsa::verify_sha256_pkcs1v15;

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

    // === NEW PUBLIC INPUT: Pre-computed TBS Hash ===
    tbs_hash_bytes: pub [u8; 32],

    // === PRIVATE: ALGORITHM SELECTORS ===
    cert_algorithm: Field,  // 2 = RSA-4096, 1 = RSA-2048
    leaf_key_type: Field,   // 0 = ECDSA, 1 = RSA

    // === PRIVATE: LEAF KEY (for nullifier binding) ===
    // ECDSA leaf key
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],
    // RSA leaf key (first two limbs sufficient for hash)
    leaf_rsa_modulus_limb0: u128,
    leaf_rsa_modulus_limb1: u128,

    // === PRIVATE: CERTIFICATE SIGNATURE & KEY ===
    // RSA-4096 Signature & Key
    cert_signature_rsa_4096_limbs: [u128; 35],
    intermediate_rsa_4096_modulus_limbs: [u128; 35],
    intermediate_rsa_4096_redc_limbs: [u128; 35],

    // RSA-2048 Fallback (optional, for other chains)
    cert_signature_rsa_2048_limbs: [u128; 18],
    intermediate_rsa_2048_modulus_limbs: [u128; 18],
    intermediate_rsa_2048_redc_limbs: [u128; 18],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,  // pedersen_hash of intermediate key material
    link_blind: Field          // random blinding factor (same as in ProofB)
) {
    // ================================================================
    // STEP 1: Verify RSA Signature (Root/Intermediate validates Leaf)
    // ================================================================

    if cert_algorithm == 2 {
        // RSA-4096 (Standard Lib)
        let params: BigNumParams<35, 4096> = BigNumParams::new(false, intermediate_rsa_4096_modulus_limbs, intermediate_rsa_4096_redc_limbs);
        let signature: RBN4096 = RBN4096::from_array(params, cert_signature_rsa_4096_limbs);
        
        let valid = verify_sha256_pkcs1v15(tbs_hash_bytes, signature, 65537);
        assert(valid, "RSA-4096 verification failed");
    } else {
        // RSA-2048 (Fallback)
        let params: BigNumParams<18, 2048> = BigNumParams::new(false, intermediate_rsa_2048_modulus_limbs, intermediate_rsa_2048_redc_limbs);
        let signature: RBN2048 = RBN2048::from_array(params, cert_signature_rsa_2048_limbs);
        
        let valid = verify_sha256_pkcs1v15(tbs_hash_bytes, signature, 65537);
        assert(valid, "RSA-2048 verification failed");
    }

    // ================================================================
    // STEP 2: Derive Leaf Key Hash
    // ================================================================
    let computed_leaf_key_hash = if leaf_key_type == LEAF_ALG_ECDSA {
        let x_field = bytes_to_field(leaf_pubkey_x);
        let y_field = bytes_to_field(leaf_pubkey_y);
        pedersen_hash([x_field, y_field])
    } else {
        pedersen_hash([leaf_rsa_modulus_limb0 as Field, leaf_rsa_modulus_limb1 as Field])
    };

    // ================================================================
    // STEP 3: Verify Nullifier Derivation
    // ================================================================
    // This binds the Leaf Key to the Content Hash
    let expected_nullifier = pedersen_hash([content_hash, computed_leaf_key_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier (leaf key binding failed)");

    // ================================================================
    // STEP 4: Verify Link Commitment
    // ================================================================
    // This binds this proof to ProofB (which validates intermediate_leaf in Trust List)
    let expected_link_commit = pedersen_hash([intermediate_leaf, link_blind]);
    assert(link_commit == expected_link_commit, "Link commitment mismatch");

    // ================================================================
    // STEP 5: Certificate Validity (Time)
    // ================================================================
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid at proof time");
    assert(ts <= not_after, "Certificate expired at proof time");

    // Unused inputs to silence warnings
    let _ = trust_list_root;
}

/// Convert 32 bytes to Field (big-endian)
fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}
