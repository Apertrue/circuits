/// Apertrue ProofA RSA-2048 - Certificate Chain Verification (RSA-2048 only)
///
/// Specialized circuit for RSA-2048 certificate verification only.
/// Removes all ECDSA code paths for constraint optimization.
///
/// Use cases:
/// - Some Adobe signed content
/// - Standard RSA C2PA implementations
///
/// This circuit proves:
/// 1. A valid RSA-2048 certificate signature exists
/// 2. The intermediate CA is in the Oracle's promoted trust list (Merkle membership)
/// 3. The nullifier is correctly derived from the leaf key and content hash
/// 4. Certificate validity at proof time
/// 5. Time range proof (graduated time disclosure)
/// 6. Location range proof (privacy circles)
/// 7. Hash chain verification (claim and assertion integrity)
/// 8. Poseidon commitments for optional future reveal

use bignum::params::BigNumParams;
use noir_rsa::types::RBN2048;
use noir_rsa::rsa::verify_sha256_pkcs1v15;

use std::hash::pedersen_hash;
use dep::poseidon::poseidon2::Poseidon2;

mod hash_chain;

use hash_chain::{
    verify_claim_hash,
    verify_content_hash_in_claim,
    verify_assertion_chain,
    verify_actions_assertion_chain,
};

/// RSA-2048 uses 18 limbs
global RSA_NUM_LIMBS: u32 = 18;

/// ProofA RSA-2048 main entry point
fn main(
    // === PUBLIC INPUTS (shared with ProofB) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,
    cert_not_before: pub Field,
    cert_not_after: pub Field,

    // === PUBLIC INPUTS: TIME RANGE BOUNDS ===
    time_min: pub Field,
    time_max: pub Field,

    // === PUBLIC INPUTS: LOCATION PRIVACY CIRCLE ===
    center_lat_scaled: pub Field,
    center_lon_scaled: pub Field,
    location_flags: pub u8,           // bit 0 = lat negative (South), bit 1 = lon negative (West)
    radius_squared_scaled: pub Field,

    // === PUBLIC INPUT: TBS Hash Commitment (packed from 32 bytes to 1 Field) ===
    tbs_hash_commitment: pub Field,

    // === PUBLIC INPUT: Claim Hash Commitment (packed from 32 bytes to 1 Field) ===
    claim_hash_commitment: pub Field,

    // === PUBLIC INPUT: Content Hash Offset ===
    content_hash_offset: pub u32,

    // === PRIVATE: TBS HASH BYTES (unpacked from commitment) ===
    tbs_hash_bytes: [u8; 32],

    // === PRIVATE: CLAIM HASH BYTES (unpacked from commitment) ===
    claim_hash: [u8; 32],

    // === PRIVATE: SKIP FLAGS ===
    skip_content_hash_binding: u8,
    skip_assertion_hash_verification: u8,

    // === PRIVATE: RSA-2048 LEAF KEY (first 8 limbs for nullifier binding) ===
    leaf_rsa_modulus_limbs: [u128; 8],

    // === PRIVATE: RSA-2048 CERTIFICATE SIGNATURE & KEY ===
    cert_signature_rsa_2048_limbs: [u128; RSA_NUM_LIMBS],
    intermediate_rsa_2048_modulus_limbs: [u128; RSA_NUM_LIMBS],
    intermediate_rsa_2048_redc_limbs: [u128; RSA_NUM_LIMBS],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,
    link_blind: Field,

    // === PRIVATE: MERKLE MEMBERSHIP ===
    merkle_path: [Field; 8],
    merkle_indices: [Field; 8],

    // === PRIVATE: EXACT TIMESTAMP ===
    exact_timestamp: Field,

    // === PRIVATE: EXACT GPS LOCATION ===
    exact_lat_scaled: Field,
    exact_lon_scaled: Field,
    exact_lat_is_negative: u8,
    exact_lon_is_negative: u8,

    // === PRIVATE: HASH CHAIN DATA ===
    enable_hash_chain_verification: u8,
    claim_bytes: [u8; 2048],
    claim_length: u32,
    exif_assertion_hash_offset: u32,
    exif_assertion_bytes: [u8; 1024],
    exif_assertion_length: u32,

    // === PRIVATE: ACTIONS ASSERTION ===
    actions_assertion_hash_offset: u32,
    actions_assertion_bytes: [u8; 2048],
    actions_assertion_length: u32,

    // === PRIVATE: COMMITMENT SALTS ===
    location_salt: Field,
    time_salt: Field
) -> pub (Field, Field, Field, [u8; 32]) {
    // ================================================================
    // STEP 0: Verify commitment packing (PUBLIC INPUT OPTIMIZATION)
    // ================================================================
    let computed_tbs_commitment = Poseidon2::hash(bytes32_to_field_array(tbs_hash_bytes), 2);
    assert(computed_tbs_commitment == tbs_hash_commitment, "TBS hash commitment mismatch");

    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

    // ================================================================
    // STEP 1: Verify RSA-2048 Certificate Signature
    // ================================================================
    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        intermediate_rsa_2048_modulus_limbs,
        intermediate_rsa_2048_redc_limbs
    );
    let signature: RBN2048 = RBN2048::from_array(params, cert_signature_rsa_2048_limbs);

    let valid = verify_sha256_pkcs1v15(tbs_hash_bytes, signature, 65537);
    assert(valid, "RSA-2048 certificate verification failed");

    // ================================================================
    // STEP 2: Derive Leaf Key Hash (RSA - hash 8 limbs)
    // ================================================================
    let computed_leaf_key_hash = pedersen_hash([
        leaf_rsa_modulus_limbs[0] as Field,
        leaf_rsa_modulus_limbs[1] as Field,
        leaf_rsa_modulus_limbs[2] as Field,
        leaf_rsa_modulus_limbs[3] as Field,
        leaf_rsa_modulus_limbs[4] as Field,
        leaf_rsa_modulus_limbs[5] as Field,
        leaf_rsa_modulus_limbs[6] as Field,
        leaf_rsa_modulus_limbs[7] as Field
    ]);

    // ================================================================
    // STEP 3: Verify Nullifier Derivation
    // ================================================================
    let expected_nullifier = pedersen_hash([content_hash, computed_leaf_key_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier (leaf key binding failed)");

    // ================================================================
    // STEP 4: Compute Link Commitment
    // ================================================================
    let claim_hash_field = bytes_to_field(claim_hash);
    let link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);

    // ================================================================
    // STEP 4b: Verify Intermediate Leaf Formulation
    // ================================================================
    let computed_intermediate_hash = pedersen_hash([
        intermediate_rsa_2048_modulus_limbs[0] as Field,
        intermediate_rsa_2048_modulus_limbs[1] as Field,
        intermediate_rsa_2048_modulus_limbs[2] as Field,
        intermediate_rsa_2048_modulus_limbs[3] as Field,
        intermediate_rsa_2048_modulus_limbs[4] as Field,
        intermediate_rsa_2048_modulus_limbs[5] as Field,
        intermediate_rsa_2048_modulus_limbs[6] as Field,
        intermediate_rsa_2048_modulus_limbs[7] as Field
    ]);

    assert(
        intermediate_leaf == computed_intermediate_hash,
        "Intermediate Leaf witnessing mismatch"
    );

    // ================================================================
    // STEP 4c: Merkle Membership
    // ================================================================
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate CA not in trust list");

    // ================================================================
    // STEP 5: Certificate Validity
    // ================================================================
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid");
    assert(ts <= not_after, "Certificate expired");

    // ================================================================
    // STEP 6: Time Range Proof
    // ================================================================
    let exact_ts = exact_timestamp as u64;
    let min_ts = time_min as u64;
    let max_ts = time_max as u64;

    assert(exact_ts >= min_ts, "Exact timestamp before time_min");
    assert(exact_ts <= max_ts, "Exact timestamp after time_max");

    // ================================================================
    // STEP 7: Location Range Proof
    // ================================================================
    // Unpack location_flags: bit 0 = lat negative, bit 1 = lon negative
    let center_lat_is_negative = location_flags & 1;
    let center_lon_is_negative = (location_flags >> 1) & 1;

    {
        let lat_same_sign = (exact_lat_is_negative == center_lat_is_negative);
        let d_lat = if lat_same_sign {
            if exact_lat_scaled as u64 > center_lat_scaled as u64 {
                exact_lat_scaled - center_lat_scaled
            } else {
                center_lat_scaled - exact_lat_scaled
            }
        } else {
            exact_lat_scaled + center_lat_scaled
        };

        let lon_same_sign = (exact_lon_is_negative == center_lon_is_negative);
        let d_lon = if lon_same_sign {
            if exact_lon_scaled as u64 > center_lon_scaled as u64 {
                exact_lon_scaled - center_lon_scaled
            } else {
                center_lon_scaled - exact_lon_scaled
            }
        } else {
            exact_lon_scaled + center_lon_scaled
        };

        let distance_squared = d_lat * d_lat + d_lon * d_lon;
        assert(
            distance_squared as u64 <= radius_squared_scaled as u64,
            "Location outside privacy circle"
        );
    }

    // ================================================================
    // STEP 8: Hash Chain Verification
    // ================================================================
    assert(enable_hash_chain_verification == 1, "Hash chain verification must be enabled");

    verify_claim_hash(claim_bytes, claim_length, claim_hash);

    if skip_content_hash_binding == 0 {
        verify_content_hash_binding(claim_bytes, content_hash_offset, content_hash);
    }

    if skip_assertion_hash_verification == 0 {
        verify_assertion_chain(
            claim_bytes,
            exif_assertion_hash_offset,
            exif_assertion_bytes,
            exif_assertion_length
        );
    }

    let actions_assertion_hash: [u8; 32] = if actions_assertion_hash_offset > 0 {
        verify_actions_assertion_chain(
            claim_bytes,
            actions_assertion_hash_offset,
            actions_assertion_bytes,
            actions_assertion_length
        );
        dep::sha256::sha256_var(actions_assertion_bytes, actions_assertion_length as u64)
    } else {
        [0u8; 32]
    };

    // ================================================================
    // STEP 9: Compute Poseidon Commitments
    // ================================================================
    let lat_sign_field = exact_lat_is_negative as Field;
    let lon_sign_field = exact_lon_is_negative as Field;

    let location_commitment = Poseidon2::hash(
        [exact_lat_scaled, exact_lon_scaled, lat_sign_field, lon_sign_field, location_salt],
        5
    );

    let time_commitment = Poseidon2::hash([exact_timestamp, time_salt], 2);

    (link_commit, location_commitment, time_commitment, actions_assertion_hash)
}

fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Convert 32 bytes to 2 Field elements for Poseidon2 hashing
fn bytes32_to_field_array(bytes: [u8; 32]) -> [Field; 2] {
    let mut f0: Field = 0;
    for i in 0..16 {
        f0 = f0 * 256 + bytes[i] as Field;
    }
    let mut f1: Field = 0;
    for i in 16..32 {
        f1 = f1 * 256 + bytes[i] as Field;
    }
    [f0, f1]
}

fn verify_content_hash_binding(
    claim_bytes: [u8; 2048],
    content_hash_offset: u32,
    expected_content_hash: Field
) {
    verify_content_hash_in_claim(claim_bytes, content_hash_offset, expected_content_hash);
}

fn compute_merkle_root(leaf: Field, path: [Field; 8], indices: [Field; 8]) -> Field {
    let mut current = leaf;
    for i in 0..8 {
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
fn test_merkle_root_computation() {
    let leaf: Field = 12345;
    let path: [Field; 8] = [0; 8];
    let indices: [Field; 8] = [0; 8];
    let root = compute_merkle_root(leaf, path, indices);
    assert(root != leaf);
    let root2 = compute_merkle_root(leaf, path, indices);
    assert(root == root2);
}

#[test]
fn test_nullifier_derivation_rsa() {
    let content_hash: Field = 111;
    let modulus_limbs: [u128; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let leaf_pubkey_hash = pedersen_hash([
        modulus_limbs[0] as Field, modulus_limbs[1] as Field,
        modulus_limbs[2] as Field, modulus_limbs[3] as Field,
        modulus_limbs[4] as Field, modulus_limbs[5] as Field,
        modulus_limbs[6] as Field, modulus_limbs[7] as Field
    ]);
    let nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);
    let different_nullifier = pedersen_hash([333 as Field, leaf_pubkey_hash]);
    assert(nullifier != different_nullifier);
}

#[test]
fn test_bytes_to_field() {
    let mut bytes: [u8; 32] = [0; 32];
    bytes[31] = 1;
    assert(bytes_to_field(bytes) == 1);
}
