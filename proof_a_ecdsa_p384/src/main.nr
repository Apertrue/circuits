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

    // === PUBLIC INPUTS: EDIT TIME RANGE BOUNDS (for edited images) ===
    // When a photo is edited (e.g., Leica capture -> Lightroom export), the capture
    // and edit timestamps differ. These bounds constrain the edit/signing timestamp.
    // Set to 0 when no edit occurred (direct camera capture).
    edit_time_min: pub Field,  // Minimum edit timestamp bound (0 if no edit)
    edit_time_max: pub Field,  // Maximum edit timestamp bound (0 if no edit)

    // === PUBLIC INPUTS: LOCATION PRIVACY CIRCLE ===
    center_lat_scaled: pub Field,
    center_lon_scaled: pub Field,
    location_flags: pub u8,           // bit 0 = lat negative (South), bit 1 = lon negative (West)
    radius_squared_scaled: pub Field,

    // === PUBLIC INPUT: TBS Hash Commitment (packed from 48 bytes to 1 Field) ===
    // This is Poseidon2(bytes48_to_field_array(tbs_hash_sha384)). Saves 47 public input fields.
    tbs_hash_commitment: pub Field,

    // === PUBLIC INPUT: Claim Hash Commitment (packed from 32 bytes to 1 Field) ===
    // This is Poseidon2(bytes32_to_field_array(claim_hash)). Saves 31 public input fields.
    claim_hash_commitment: pub Field,

    // === PUBLIC INPUT: Content Hash Offset ===
    content_hash_offset: pub u32,

    // === PRIVATE: TBS HASH BYTES (SHA-384 for P-384, unpacked from commitment) ===
    tbs_hash_sha384: [u8; 48],

    // === PRIVATE: CLAIM HASH BYTES (unpacked from commitment) ===
    claim_hash: [u8; 32],

    // === PRIVATE: SKIP FLAGS ===
    skip_content_hash_binding: pub u8,
    skip_assertion_hash_verification: pub u8,

    // === PRIVATE: ECDSA LEAF KEY (for nullifier binding) ===
    // NOTE: Leaf key is P-256 (32 bytes) even when intermediate is P-384.
    // The intermediate key type determines cert signature verification,
    // but COSE signatures use ES256 (P-256) for the leaf key.
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],

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
    time_salt: Field,

    // === PRIVATE: EDIT TIMESTAMP & SALT (for separate edit time commitment) ===
    exact_edit_timestamp: Field,  // Edit/signing timestamp (0 if no edit)
    edit_time_salt: Field         // Salt for edit time commitment
) -> pub (Field, Field, Field, Field, [u8; 32]) {  // Returns (link_commit, location_commitment, time_commitment, edit_time_commitment, actions_assertion_hash)
    // ================================================================
    // STEP 0: Verify commitment packing (PUBLIC INPUT OPTIMIZATION)
    // ================================================================
    // Verify TBS hash commitment (SHA-384 for P-384)
    let computed_tbs_commitment = Poseidon2::hash(bytes48_to_field_array(tbs_hash_sha384), 2);
    assert(computed_tbs_commitment == tbs_hash_commitment, "TBS hash commitment mismatch (SHA-384)");

    // Verify claim hash commitment
    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

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
    // STEP 2: Derive Leaf Key Hash (P-256 - 32-byte coordinates)
    // NOTE: Leaf key is P-256 even when intermediate is P-384.
    // COSE signatures use ES256 (P-256) for the leaf key.
    // ================================================================
    let x_field = bytes_to_field(leaf_pubkey_x);
    let y_field = bytes_to_field(leaf_pubkey_y);
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
    assert(proof_timestamp as u64 as Field == proof_timestamp, "proof_timestamp exceeds u64");
    assert(cert_not_before as u64 as Field == cert_not_before, "cert_not_before exceeds u64");
    assert(cert_not_after as u64 as Field == cert_not_after, "cert_not_after exceeds u64");
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid");
    assert(ts <= not_after, "Certificate expired");

    // ================================================================
    // STEP 6: Time Range Proof
    // ================================================================
    assert(exact_timestamp as u64 as Field == exact_timestamp, "exact_timestamp exceeds u64");
    assert(time_min as u64 as Field == time_min, "time_min exceeds u64");
    assert(time_max as u64 as Field == time_max, "time_max exceeds u64");
    let exact_ts = exact_timestamp as u64;
    let min_ts = time_min as u64;
    let max_ts = time_max as u64;

    assert(exact_ts >= min_ts, "Exact timestamp before time_min");
    assert(exact_ts <= max_ts, "Exact timestamp after time_max");

    // ================================================================
    // STEP 6b: Edit Time Range Proof (0 = no edit, skip)
    // ================================================================
    // When a photo is edited (capture -> export), exact_edit_timestamp is the
    // signing/export time. For direct camera captures, it's 0 (sentinel).
    if exact_edit_timestamp != 0 {
        assert(exact_edit_timestamp as u64 as Field == exact_edit_timestamp, "exact_edit_timestamp exceeds u64");
        assert(edit_time_min as u64 as Field == edit_time_min, "edit_time_min exceeds u64");
        assert(edit_time_max as u64 as Field == edit_time_max, "edit_time_max exceeds u64");
        let edit_ts = exact_edit_timestamp as u64;
        let edit_min = edit_time_min as u64;
        let edit_max = edit_time_max as u64;
        assert(edit_ts >= edit_min, "Edit timestamp before edit_time_min");
        assert(edit_ts <= edit_max, "Edit timestamp after edit_time_max");
    } else {
        assert(edit_time_min == 0, "edit_time_min must be 0 when no edit");
        assert(edit_time_max == 0, "edit_time_max must be 0 when no edit");
    }

    // ================================================================
    // STEP 7: Location Range Proof
    // ================================================================
    // Unpack location_flags: bit 0 = lat negative, bit 1 = lon negative
    // Reject if unused high bits (2-7) are set - prevents flag stuffing
    assert(location_flags <= 3, "location_flags has invalid high bits set (must be 0-3)");
    let center_lat_is_negative = location_flags & 1;
    let center_lon_is_negative = (location_flags >> 1) & 1;

    assert(exact_lat_is_negative <= 1, "exact_lat_is_negative must be 0 or 1");
    assert(exact_lon_is_negative <= 1, "exact_lon_is_negative must be 0 or 1");
    assert(skip_content_hash_binding <= 1, "skip_content_hash_binding must be 0 or 1");
    assert(skip_assertion_hash_verification <= 1, "skip_assertion_hash_verification must be 0 or 1");

    assert(exact_lat_scaled as u64 as Field == exact_lat_scaled, "exact_lat_scaled exceeds u64");
    assert(center_lat_scaled as u64 as Field == center_lat_scaled, "center_lat_scaled exceeds u64");
    assert(exact_lon_scaled as u64 as Field == exact_lon_scaled, "exact_lon_scaled exceeds u64");
    assert(center_lon_scaled as u64 as Field == center_lon_scaled, "center_lon_scaled exceeds u64");

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
        assert(distance_squared as u64 as Field == distance_squared, "distance_squared exceeds u64");
        assert(radius_squared_scaled as u64 as Field == radius_squared_scaled, "radius_squared_scaled exceeds u64");
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
        dep::sha256::sha256_var(actions_assertion_bytes, actions_assertion_length as u32)
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

    // Edit time commitment: Poseidon2([edit_timestamp, salt]) or 0 sentinel
    // Poseidon2 never outputs 0 for valid inputs, so 0 is safe as "no edit" sentinel
    let edit_time_commitment = if exact_edit_timestamp == 0 {
        0  // Sentinel: no edit happened
    } else {
        Poseidon2::hash([exact_edit_timestamp, edit_time_salt], 2)
    };

    (link_commit, location_commitment, time_commitment, edit_time_commitment, actions_assertion_hash)
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

/// Convert 32 bytes to 2 Field elements for Poseidon2 hashing
/// Splits into two 16-byte (128-bit) chunks that fit within the BN254 field
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

/// Convert 48 bytes to 2 Field elements for Poseidon2 hashing
/// Splits into two 24-byte (192-bit) chunks that fit within the BN254 field
fn bytes48_to_field_array(bytes: [u8; 48]) -> [Field; 2] {
    let mut f0: Field = 0;
    for i in 0..24 {
        f0 = f0 * 256 + bytes[i] as Field;
    }
    let mut f1: Field = 0;
    for i in 24..48 {
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
        assert((indices[i] == 0) | (indices[i] == 1), "Merkle index must be 0 or 1");
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
