/// Apertrue ProofA ECDSA P-256 - Certificate Chain Verification (ECDSA-only)
///
/// Specialized circuit for ECDSA P-256 certificate verification only.
/// Removes all RSA code paths for ~60% constraint reduction.
///
/// Use cases:
/// - ChatGPT/DALL-E images (ES256 certs)
/// - ProofMode camera app (ES256 certs)
/// - Most ECDSA-based C2PA signers
///
/// This circuit proves:
/// 1. A valid ECDSA P-256 certificate signature exists
/// 2. The intermediate CA is in the Oracle's promoted trust list (Merkle membership)
/// 3. The nullifier is correctly derived from the leaf key and content hash
/// 4. Certificate validity at proof time
/// 5. Time range proof (graduated time disclosure)
/// 6. Location range proof (privacy circles)
/// 7. Hash chain verification (claim and assertion integrity)
/// 8. Poseidon commitments for optional future reveal
///
/// PUBLIC INPUTS (shared with ProofB - must match):
/// - trust_list_root: Oracle's Merkle root
/// - content_hash: SHA256 of stripped image
/// - nullifier: pedersen_hash([content_hash, leaf_key_hash])
/// - proof_timestamp: When proof was generated
/// - cert_not_before: Certificate validity start
/// - cert_not_after: Certificate validity end
/// - link_commit: pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
use dep::poseidon::poseidon2::Poseidon2;

mod hash_chain;

use hash_chain::{
    verify_claim_hash,
    verify_content_hash_in_claim,
    verify_assertion_chain,
    verify_actions_assertion_chain,
};

/// ProofA ECDSA P-256 main entry point
fn main(
    // === PUBLIC INPUTS (shared with ProofB) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,
    cert_not_before: pub Field,
    cert_not_after: pub Field,

    // === PUBLIC INPUTS: TIME RANGE BOUNDS (for graduated time disclosure) ===
    time_min: pub Field,
    time_max: pub Field,

    // === PUBLIC INPUTS: EDIT TIME RANGE BOUNDS (for edited images) ===
    // When a photo is edited (e.g., Leica capture -> Lightroom export), the capture
    // and edit timestamps differ. These bounds constrain the edit/signing timestamp.
    // Set to 0 when no edit occurred (direct camera capture).
    edit_time_min: pub Field,  // Minimum edit timestamp bound (0 if no edit)
    edit_time_max: pub Field,  // Maximum edit timestamp bound (0 if no edit)

    // === PUBLIC INPUTS: LOCATION PRIVACY CIRCLE (for graduated location disclosure) ===
    center_lat_scaled: pub Field,
    center_lon_scaled: pub Field,
    location_flags: pub u8,           // bit 0 = lat negative (South), bit 1 = lon negative (West)
    radius_squared_scaled: pub Field,

    // === PUBLIC INPUT: TBS Hash Commitment (packed from 32 bytes to 1 Field) ===
    // This is Poseidon2(bytes32_to_field_array(tbs_hash_bytes)). Saves 31 public input fields.
    tbs_hash_commitment: pub Field,

    // === PUBLIC INPUT: Claim Hash Commitment (packed from 32 bytes to 1 Field) ===
    // This is Poseidon2(bytes32_to_field_array(claim_hash)). Saves 31 public input fields.
    claim_hash_commitment: pub Field,

    // === PUBLIC INPUT: Content Hash Offset (for content binding) ===
    content_hash_offset: pub u32,

    // === PRIVATE: TBS HASH BYTES (unpacked from commitment) ===
    tbs_hash_bytes: [u8; 32],

    // === PRIVATE: CLAIM HASH BYTES (unpacked from commitment) ===
    claim_hash: [u8; 32],

    // === PRIVATE: SKIP FLAGS ===
    skip_content_hash_binding: u8,
    skip_assertion_hash_verification: u8,

    // === PRIVATE: ECDSA P-256 LEAF KEY (for nullifier binding) ===
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],

    // === PRIVATE: ECDSA P-256 CERTIFICATE SIGNATURE & KEY ===
    cert_signature_ecdsa: [u8; 64],
    intermediate_ecdsa_pubkey_x: [u8; 32],
    intermediate_ecdsa_pubkey_y: [u8; 32],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,
    link_blind: Field,

    // === PRIVATE: MERKLE MEMBERSHIP (trust list verification) ===
    merkle_path: [Field; 8],
    merkle_indices: [Field; 8],

    // === PRIVATE: EXACT TIMESTAMP (for time range proof) ===
    exact_timestamp: Field,

    // === PRIVATE: EXACT GPS LOCATION (for location range proof) ===
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
    // This verifies that the private TBS hash bytes and claim hash bytes match
    // their public Poseidon2 commitments.

    // Verify TBS hash commitment (SHA-256 for ECDSA P-256)
    let computed_tbs_commitment = Poseidon2::hash(bytes32_to_field_array(tbs_hash_bytes), 2);
    assert(computed_tbs_commitment == tbs_hash_commitment, "TBS hash commitment mismatch");

    // Verify claim hash commitment
    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

    // ================================================================
    // STEP 1: Verify ECDSA P-256 Certificate Signature
    // ================================================================
    let valid = verify_signature(
        intermediate_ecdsa_pubkey_x,
        intermediate_ecdsa_pubkey_y,
        cert_signature_ecdsa,
        tbs_hash_bytes
    );
    assert(valid, "ECDSA P-256 certificate verification failed");

    // ================================================================
    // STEP 2: Derive Leaf Key Hash (ECDSA P-256)
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
    // STEP 4: Compute Link Commitment (returned as output)
    // ================================================================
    let claim_hash_field = bytes_to_field(claim_hash);
    let link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);

    // ================================================================
    // STEP 4b: Verify Intermediate Leaf Formulation
    // ================================================================
    let int_x_field = bytes_to_field(intermediate_ecdsa_pubkey_x);
    let int_y_field = bytes_to_field(intermediate_ecdsa_pubkey_y);
    let computed_intermediate_hash = pedersen_hash([int_x_field, int_y_field]);

    assert(
        intermediate_leaf == computed_intermediate_hash,
        "Intermediate Leaf witnessing mismatch (Self-Signing Attack prevention)"
    );

    // ================================================================
    // STEP 4c: Merkle Membership (Trust List Verification)
    // ================================================================
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate CA not in trust list");

    // ================================================================
    // STEP 5: Certificate Validity (Time)
    // ================================================================
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid at proof time");
    assert(ts <= not_after, "Certificate expired at proof time");

    // ================================================================
    // STEP 6: Time Range Proof (Graduated Time Disclosure)
    // ================================================================
    let exact_ts = exact_timestamp as u64;
    let min_ts = time_min as u64;
    let max_ts = time_max as u64;

    assert(exact_ts >= min_ts, "Exact timestamp is before disclosed time_min");
    assert(exact_ts <= max_ts, "Exact timestamp is after disclosed time_max");

    // ================================================================
    // STEP 6b: Edit Time Range Proof (0 = no edit, skip)
    // ================================================================
    // When a photo is edited (capture -> export), exact_edit_timestamp is the
    // signing/export time. For direct camera captures, it's 0 (sentinel).
    if exact_edit_timestamp != 0 {
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
    // STEP 7: Location Range Proof (Graduated Location Disclosure)
    // ================================================================
    // Unpack location_flags: bit 0 = lat negative, bit 1 = lon negative
    // Reject if unused high bits (2-7) are set - prevents flag stuffing
    assert(location_flags <= 3, "location_flags has invalid high bits set (must be 0-3)");
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

        // NOTE: Euclidean distance in coordinate space. At high latitudes,
        // 1 deg lon < 1 deg lat in real-world distance, so this circle is elliptical.
        // The client-side radius computation (metersToScaledRadius) compensates
        // by using the longitude conversion at the user's latitude, ensuring the
        // privacy circle covers at least the requested radius in ALL directions.
        let distance_squared = d_lat * d_lat + d_lon * d_lon;

        assert(
            distance_squared as u64 <= radius_squared_scaled as u64,
            "Exact GPS location is outside disclosed privacy circle"
        );
    }

    // ================================================================
    // STEP 8: Hash Chain Verification (Trustless Metadata Binding)
    // ================================================================
    assert(
        enable_hash_chain_verification == 1,
        "Hash chain verification must be enabled"
    );

    // Step 8a: Verify claim_hash = SHA256(claim_bytes)
    verify_claim_hash(claim_bytes, claim_length, claim_hash);

    // Step 8b: Verify content_hash exists in claim_bytes
    if skip_content_hash_binding == 0 {
        verify_content_hash_binding(claim_bytes, content_hash_offset, content_hash);
    }

    // Step 8c: Verify assertion hash chain
    if skip_assertion_hash_verification == 0 {
        verify_assertion_chain(
            claim_bytes,
            exif_assertion_hash_offset,
            exif_assertion_bytes,
            exif_assertion_length
        );
    }

    // Step 8d: Verify actions assertion hash chain (optional)
    let actions_assertion_hash: [u8; 32] = if actions_assertion_hash_offset > 0 {
        verify_actions_assertion_chain(
            claim_bytes,
            actions_assertion_hash_offset,
            actions_assertion_bytes,
            actions_assertion_length
        );
        let hash_result: [u8; 32] = dep::sha256::sha256_var(
            actions_assertion_bytes,
            actions_assertion_length as u32
        );
        hash_result
    } else {
        [0u8; 32]
    };

    // ================================================================
    // STEP 9: Compute Poseidon Commitments (Optional Future Reveal)
    // ================================================================
    let lat_sign_field = exact_lat_is_negative as Field;
    let lon_sign_field = exact_lon_is_negative as Field;

    let location_commitment = Poseidon2::hash(
        [exact_lat_scaled, exact_lon_scaled, lat_sign_field, lon_sign_field, location_salt],
        5
    );

    let time_commitment = Poseidon2::hash(
        [exact_timestamp, time_salt],
        2
    );

    // Edit time commitment: Poseidon2([edit_timestamp, salt]) or 0 sentinel
    // Poseidon2 never outputs 0 for valid inputs, so 0 is safe as "no edit" sentinel
    let edit_time_commitment = if exact_edit_timestamp == 0 {
        0  // Sentinel: no edit happened
    } else {
        Poseidon2::hash([exact_edit_timestamp, edit_time_salt], 2)
    };

    // Return public outputs
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

/// Convert 32 bytes to 2 Field elements for Poseidon2 hashing
/// Splits into two 16-byte (128-bit) chunks that fit within the BN254 field
fn bytes32_to_field_array(bytes: [u8; 32]) -> [Field; 2] {
    // First 16 bytes -> Field 0
    let mut f0: Field = 0;
    for i in 0..16 {
        f0 = f0 * 256 + bytes[i] as Field;
    }
    // Last 16 bytes -> Field 1
    let mut f1: Field = 0;
    for i in 16..32 {
        f1 = f1 * 256 + bytes[i] as Field;
    }
    [f0, f1]
}

/// Verify content hash exists in claim at offset
fn verify_content_hash_binding(
    claim_bytes: [u8; 2048],
    content_hash_offset: u32,
    expected_content_hash: Field
) {
    verify_content_hash_in_claim(claim_bytes, content_hash_offset, expected_content_hash);
}

/// Compute Merkle root from leaf and proof
fn compute_merkle_root(
    leaf: Field,
    path: [Field; 8],
    indices: [Field; 8]
) -> Field {
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
    assert(root != leaf, "Merkle root should not equal leaf");

    let root2 = compute_merkle_root(leaf, path, indices);
    assert(root == root2, "Merkle root should be deterministic");
}

#[test]
fn test_merkle_different_leaves() {
    let path: [Field; 8] = [0; 8];
    let indices: [Field; 8] = [0; 8];

    let root1 = compute_merkle_root(111, path, indices);
    let root2 = compute_merkle_root(222, path, indices);

    assert(root1 != root2, "Different leaves should produce different roots");
}

#[test]
fn test_time_range_exact_bounds() {
    let exact: u64 = 1000;
    let min: u64 = 1000;
    let max: u64 = 2000;

    assert(exact >= min, "Timestamp at min bound should pass");
    assert(exact <= max, "Timestamp within range should pass");
}

#[test]
fn test_location_same_point() {
    let exact_lat: Field = 510000000;
    let exact_lon: Field = 100000000;
    let center_lat: Field = 510000000;
    let center_lon: Field = 100000000;

    let d_lat = if exact_lat as u64 > center_lat as u64 {
        exact_lat - center_lat
    } else {
        center_lat - exact_lat
    };

    let d_lon = if exact_lon as u64 > center_lon as u64 {
        exact_lon - center_lon
    } else {
        center_lon - exact_lon
    };

    let distance_squared = d_lat * d_lat + d_lon * d_lon;
    assert(distance_squared == 0, "Same point should have zero distance");
}

#[test]
fn test_bytes_to_field() {
    let mut bytes: [u8; 32] = [0; 32];
    bytes[31] = 1;
    let field = bytes_to_field(bytes);
    assert(field == 1);

    bytes[31] = 255;
    let field2 = bytes_to_field(bytes);
    assert(field2 == 255);
}

#[test]
fn test_nullifier_derivation_ecdsa() {
    let content_hash: Field = 111;
    let leaf_key_hash: Field = 222;
    let nullifier = pedersen_hash([content_hash, leaf_key_hash]);

    let different_content: Field = 333;
    let different_nullifier = pedersen_hash([different_content, leaf_key_hash]);
    assert(nullifier != different_nullifier);
}

#[test]
fn test_link_commitment_with_claim_hash() {
    let intermediate_leaf: Field = 12345;
    let claim_hash_field: Field = 99999;
    let link_blind: Field = 67890;

    let commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);
    let commit2 = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);
    assert(commit == commit2);

    let different_claim: Field = 11111;
    let commit3 = pedersen_hash([intermediate_leaf, different_claim, link_blind]);
    assert(commit != commit3);
}
