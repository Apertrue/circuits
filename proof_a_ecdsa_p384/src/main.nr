/// Apertrue ProofA ECDSA P-384 - Certificate Chain Verification (P-384 only)
///
/// Specialized circuit for ECDSA P-384 certificate verification only.
/// Removes all RSA and P-256 code paths.
///
/// Use cases:
/// - Google Pixel devices (P-384 certs)
/// - Truepic (P-384 certs)
/// - High-security ECDSA C2PA implementations
///
/// This circuit proves:
/// 1. A valid ECDSA P-384 certificate signature exists
/// 2. The intermediate CA is in the Oracle's promoted trust list
/// 3. The nullifier is correctly derived from the leaf key and content hash
/// 4. Certificate validity at proof time
/// 5. Time range proof (graduated time disclosure)
/// 6. Location range proof (privacy circles)
/// 7. Hash chain verification
/// 8. Poseidon commitments for optional future reveal

use std::hash::pedersen_hash;
use dep::poseidon::poseidon2::Poseidon2;

mod crypto;
mod crypto_utils;
mod hash_chain;

use crypto_utils::verify_ecdsa_p384;
use hash_chain::{
    verify_claim_hash,
    verify_content_hash_in_claim,
    verify_assertion_chain,
    verify_actions_assertion_chain,
};

/// ProofA ECDSA P-384 main entry point
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
    center_lat_is_negative: pub u8,
    center_lon_is_negative: pub u8,
    radius_squared_scaled: pub Field,

    // === PUBLIC INPUT: Pre-computed TBS Hash (SHA-384 for P-384) ===
    tbs_hash_sha384: pub [u8; 48],

    // === PUBLIC INPUT: Claim Hash ===
    claim_hash: pub [u8; 32],

    // === PUBLIC INPUT: Content Hash Offset ===
    content_hash_offset: pub u32,

    // === PRIVATE: SKIP FLAGS ===
    skip_content_hash_binding: u8,
    skip_assertion_hash_verification: u8,

    // === PRIVATE: ECDSA P-384 LEAF KEY (for nullifier binding) ===
    leaf_pubkey_x: [u8; 48],
    leaf_pubkey_y: [u8; 48],

    // === PRIVATE: ECDSA P-384 CERTIFICATE SIGNATURE & KEY ===
    cert_signature_ecdsa_p384_r: [u8; 48],
    cert_signature_ecdsa_p384_s: [u8; 48],
    intermediate_ecdsa_p384_pubkey_x: [u8; 48],
    intermediate_ecdsa_p384_pubkey_y: [u8; 48],

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
    // STEP 1: Verify ECDSA P-384 Certificate Signature
    // ================================================================
    let valid = verify_ecdsa_p384(
        tbs_hash_sha384,
        intermediate_ecdsa_p384_pubkey_x,
        intermediate_ecdsa_p384_pubkey_y,
        cert_signature_ecdsa_p384_r,
        cert_signature_ecdsa_p384_s
    );
    assert(valid, "ECDSA P-384 certificate verification failed");

    // ================================================================
    // STEP 2: Derive Leaf Key Hash (P-384 - 48-byte coordinates)
    // ================================================================
    let x_field = bytes48_to_field(leaf_pubkey_x);
    let y_field = bytes48_to_field(leaf_pubkey_y);
    let computed_leaf_key_hash = pedersen_hash([x_field, y_field]);

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
    let int_x_field = bytes48_to_field(intermediate_ecdsa_p384_pubkey_x);
    let int_y_field = bytes48_to_field(intermediate_ecdsa_p384_pubkey_y);
    let computed_intermediate_hash = pedersen_hash([int_x_field, int_y_field]);

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

/// Convert 32 bytes to Field (big-endian)
fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Convert 48 bytes to Field (big-endian)
fn bytes48_to_field(bytes: [u8; 48]) -> Field {
    let mut result: Field = 0;
    for i in 0..48 {
        result = result * 256 + bytes[i] as Field;
    }
    result
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
fn test_bytes48_to_field() {
    let mut bytes: [u8; 48] = [0; 48];
    bytes[47] = 1;
    let field = bytes48_to_field(bytes);
    assert(field == 1);
}

#[test]
fn test_bytes_to_field() {
    let mut bytes: [u8; 32] = [0; 32];
    bytes[31] = 1;
    assert(bytes_to_field(bytes) == 1);
}

#[test]
fn test_nullifier_derivation_ecdsa_p384() {
    let content_hash: Field = 111;
    let leaf_key_hash: Field = 222;
    let nullifier = pedersen_hash([content_hash, leaf_key_hash]);
    let different_nullifier = pedersen_hash([333 as Field, leaf_key_hash]);
    assert(nullifier != different_nullifier);
}
