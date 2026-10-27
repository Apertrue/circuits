/// Apertrue ProofA RSA-2048 SHA-384 v2 - Certificate Chain Verification
///
/// For a leaf certificate issued by an RSA-2048 intermediate that signs with
/// sha384WithRSAEncryption (PKCS#1 v1.5, e = 65537), such as the Truepic
/// WebClaimSigningCA behind ChatGPT images. The leaf key may be uncompressed
/// P-256 (pair with proof_b_es256_v2*) or RSA-2048/65537 (pair with
/// proof_b_ps256_v2). The key type is read from the leaf SPKI DER.
///
/// Identical to proof_a_rsa_2048_v2 except for the digest: the full leaf
/// TBSCertificate is hashed with SHA-384, its signature algorithm must be
/// sha384WithRSAEncryption (cert_binding::bind_leaf_cert_rsa_signed_sha384),
/// and the intermediate's signature is verified over that SHA-384.
/// intermediate_leaf = cert_binding::rsa_key_hash over all 18 modulus limbs.
///
/// This circuit proves:
/// 1. The intermediate CA signed (RSA-2048, SHA-384) the leaf TBSCertificate
/// 2. The intermediate CA is in the Oracle's promoted trust list (Merkle membership)
/// 3. The nullifier is derived from the leaf key found in that TBSCertificate
/// 4. proof_timestamp lies within that certificate's validity (dates private)
/// 5. Time range proof (graduated time disclosure)
/// 6. Location range proof (privacy circles)
/// 7. Hash chain verification (claim and assertion integrity)
/// 8. Poseidon commitments for optional future reveal
///
/// Supported leaf: TBS <= 1280 B. Claim/assertion size classes as
/// proof_a_rsa_2048_v2 (claim 2048, exif 1024, actions 2048).
///
/// PUBLIC LAYOUT (index: name; one Field each unless noted)
///  0 trust_list_root
///  1 content_hash
///  2 nullifier            pedersen_hash([content_hash, leaf_key_hash])
///  3 proof_timestamp
///  4 time_min
///  5 time_max
///  6 edit_time_min
///  7 edit_time_max
///  8 center_lat_scaled
///  9 center_lon_scaled
/// 10 location_flags
/// 11 radius_squared_scaled
/// 12 claim_hash_commitment
/// 13 content_hash_offset
/// 14 skip_content_hash_binding
/// 15 skip_assertion_hash_verification
/// Return values:
/// 16 link_commit          pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])
/// 17 location_commitment
/// 18 time_commitment
/// 19 edit_time_commitment
/// 20..51 actions_assertion_hash (32 x u8)
/// Total 52. Versus v1: cert_not_before (4), cert_not_after (5) and
/// tbs_hash_commitment (14) are removed; every later index shifts down.
///
/// Shared with ProofB v2 (must be equal across the pair): trust_list_root,
/// content_hash, nullifier, proof_timestamp, claim_hash_commitment,
/// content_hash_offset, link_commit.

use bignum::params::BigNumParams;
use noir_rsa::rsa::verify_sha384_pkcs1v15;
use std::hash::pedersen_hash;
use dep::poseidon::poseidon2::Poseidon2;
use dep::cert_binding::{bind_leaf_cert_rsa_signed_sha384, be_bytes_to_limbs, rsa_key_hash, LeafCertAnyKeySha384};

mod hash_chain;

use hash_chain::{
    MAX_CLAIM_SIZE,
    MAX_EXIF_ASSERTION_SIZE,
    MAX_ACTIONS_ASSERTION_SIZE,
    verify_claim_hash,
    verify_content_hash_in_claim,
    verify_assertion_chain,
    verify_actions_assertion_chain,
};

/// Maximum leaf TBSCertificate size (DER bytes)
global MAX_TBS_SIZE: u32 = 1280;

/// RSA-2048 uses 18 limbs of 120 bits
global RSA_NUM_LIMBS: u32 = 18;

/// ProofA RSA-2048 v2 main entry point
fn main(
    // === PUBLIC INPUTS (shared with ProofB) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,

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

    // === PUBLIC INPUT: Claim Hash Commitment (packed from 32 bytes to 1 Field) ===
    // This is Poseidon2(bytes32_to_field_array(claim_hash)). Saves 31 public input fields.
    claim_hash_commitment: pub Field,

    // === PUBLIC INPUT: Content Hash Offset (for content binding) ===
    content_hash_offset: pub u32,

    // === PRIVATE: LEAF TBSCertificate (DER, zero padded past tbs_len) ===
    tbs_certificate: [u8; MAX_TBS_SIZE],
    tbs_len: u32,

    // === PRIVATE: CLAIM HASH BYTES (unpacked from commitment) ===
    claim_hash: [u8; 32],

    // === PRIVATE: SKIP FLAGS ===
    skip_content_hash_binding: pub u8,
    skip_assertion_hash_verification: pub u8,

    // === PRIVATE: RSA-2048 CERTIFICATE SIGNATURE & KEY (big-endian bytes) ===
    cert_signature_rsa: [u8; 256],
    intermediate_rsa_modulus: [u8; 256],
    intermediate_rsa_redc_limbs: [u128; RSA_NUM_LIMBS], // floor(2^(2*2048+6) / n)

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
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    claim_length: u32,
    exif_assertion_hash_offset: u32,
    exif_assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE],
    exif_assertion_length: u32,

    // === PRIVATE: ACTIONS ASSERTION ===
    actions_assertion_hash_offset: u32,
    actions_assertion_bytes: [u8; MAX_ACTIONS_ASSERTION_SIZE],
    actions_assertion_length: u32,

    // === PRIVATE: COMMITMENT SALTS ===
    location_salt: Field,
    time_salt: Field,

    // === PRIVATE: EDIT TIMESTAMP & SALT (for separate edit time commitment) ===
    exact_edit_timestamp: Field,  // Edit/signing timestamp (0 if no edit)
    edit_time_salt: Field         // Salt for edit time commitment
) -> pub (Field, Field, Field, Field, [u8; 32]) {  // Returns (link_commit, location_commitment, time_commitment, edit_time_commitment, actions_assertion_hash)
    // ================================================================
    // STEP 0: Verify claim hash commitment packing
    // ================================================================
    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

    // ================================================================
    // STEP 1: Hash + DER-walk the leaf TBS; intermediate signs that hash
    // ================================================================
    let leaf = verify_leaf_certificate(
        tbs_certificate,
        tbs_len,
        cert_signature_rsa,
        intermediate_rsa_modulus,
        intermediate_rsa_redc_limbs
    );

    // ================================================================
    // STEP 2: Derive Leaf Key Hash (key taken from the signed TBS)
    // ================================================================
    // P-256: pedersen_hash([x, y]); RSA-2048: rsa_key_hash (18 limbs)
    let computed_leaf_key_hash = leaf.key_hash;

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
    let computed_intermediate_hash = rsa_key_hash::<256, 18>(intermediate_rsa_modulus);

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
    // Dates come from the signed TBS and stay private.
    assert(proof_timestamp as u64 as Field == proof_timestamp, "proof_timestamp exceeds u64");
    let ts = proof_timestamp as u64;
    let not_before = leaf.not_before;
    let not_after = leaf.not_after;
    assert(ts >= not_before, "Certificate not yet valid at proof time");
    assert(ts <= not_after, "Certificate expired at proof time");

    // ================================================================
    // STEP 6: Time Range Proof (Graduated Time Disclosure)
    // ================================================================
    assert(exact_timestamp as u64 as Field == exact_timestamp, "exact_timestamp exceeds u64");
    assert(time_min as u64 as Field == time_min, "time_min exceeds u64");
    assert(time_max as u64 as Field == time_max, "time_max exceeds u64");
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
    // STEP 7: Location Range Proof (Graduated Location Disclosure)
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

        // NOTE: Euclidean distance in coordinate space. At high latitudes,
        // 1 deg lon < 1 deg lat in real-world distance, so this circle is elliptical.
        // The client-side radius computation (metersToScaledRadius) compensates
        // by using the longitude conversion at the user's latitude, ensuring the
        // privacy circle covers at least the requested radius in ALL directions.
        let distance_squared = d_lat * d_lat + d_lon * d_lon;
        assert(distance_squared as u64 as Field == distance_squared, "distance_squared exceeds u64");
        assert(radius_squared_scaled as u64 as Field == radius_squared_scaled, "radius_squared_scaled exceeds u64");

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

/// Hash and DER-walk the leaf TBSCertificate (sha384WithRSAEncryption),
/// then check that the intermediate's RSA-2048 PKCS#1 v1.5 signature covers
/// exactly that SHA-384.
fn verify_leaf_certificate(
    tbs_certificate: [u8; MAX_TBS_SIZE],
    tbs_len: u32,
    sig: [u8; 256],
    intermediate_modulus: [u8; 256],
    intermediate_redc: [u128; RSA_NUM_LIMBS]
) -> LeafCertAnyKeySha384 {
    let leaf = bind_leaf_cert_rsa_signed_sha384(tbs_certificate, tbs_len);
    assert(intermediate_modulus[0] >= 0x80, "RSA intermediate modulus is not 2048 bits");
    let limbs: [u128; RSA_NUM_LIMBS] = be_bytes_to_limbs(intermediate_modulus);
    let params: BigNumParams<RSA_NUM_LIMBS, 2048> = BigNumParams::new(false, limbs, intermediate_redc);
    let signature = bignum::RuntimeBigNum::from_be_bytes(params, sig);
    let valid = verify_sha384_pkcs1v15(leaf.sha384, signature, 65537);
    assert(valid, "RSA-2048 certificate verification failed");
    leaf
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
    claim_bytes: [u8; MAX_CLAIM_SIZE],
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

// ====================================================================
// CERTIFICATE TESTS (real ChatGPT chain: Truepic RSA-2048 CA, sha384WithRSAEncryption)
// ====================================================================

mod chatgpt_vectors;

mod cert_tests {
    use super::{verify_leaf_certificate, MAX_TBS_SIZE};
    use super::chatgpt_vectors as cv;
    use dep::cert_binding::test_vectors as tv;
    use dep::cert_binding::rsa_vectors as rv;
    use dep::cert_binding::{bind_leaf_cert_rsa_signed_sha384, p256_key_hash, rsa_key_hash};

    fn pad<let M: u32>(a: [u8; M]) -> [u8; MAX_TBS_SIZE] {
        let mut out: [u8; MAX_TBS_SIZE] = [0; MAX_TBS_SIZE];
        for i in 0..M {
            out[i] = a[i];
        }
        out
    }

    #[test]
    fn test_chatgpt_leaf_verifies_and_binds_key() {
        let leaf = verify_leaf_certificate(
            pad(cv::CHATGPT_LEAF_TBS),
            cv::CHATGPT_LEAF_TBS_LEN,
            cv::CHATGPT_CA_SIG,
            cv::CHATGPT_CA_MODULUS,
            cv::CHATGPT_CA_REDC,
        );
        assert(leaf.key_type == 0);
        assert(leaf.key_hash == p256_key_hash(cv::CHATGPT_LEAF_PUB_X, cv::CHATGPT_LEAF_PUB_Y));
        assert(leaf.not_before < leaf.not_after);
    }

    #[test]
    fn test_chatgpt_ca_trust_list_leaf() {
        // The trust-list bundle v2 leaf for WebClaimSigningCA.
        let leaf = rsa_key_hash::<256, 18>(cv::CHATGPT_CA_MODULUS);
        assert(leaf == 0x071fa0bd01954392bc85b9fbe4ae6e750382fe394cfe76322ba9aadec8d772d9);
    }

    // noir_rsa's PKCS#1 v1.5 check fails unlabelled assertions rather than
    // returning false, so the negatives use plain should_fail. Each tampered
    // TBS has a positive twin showing it still parses, so the failure is the
    // CA signature check.

    fn key_swapped() -> [u8; MAX_TBS_SIZE] {
        let mut t = pad(cv::CHATGPT_LEAF_TBS);
        let mut off: u32 = 0;
        for i in 0..400 {
            if (off == 0) & (t[i] == 0x30) & (t[i + 1] == 0x59) & (t[i + 2] == 0x30) & (t[i + 3] == 0x13) {
                off = i;
            }
        }
        assert(off != 0);
        for i in 0..32 {
            t[off + 27 + i] = tv::LEICA_LEAF_PUB_X[i];
            t[off + 59 + i] = tv::LEICA_LEAF_PUB_Y[i];
        }
        t
    }

    #[test]
    fn test_key_swapped_tbs_parses_to_other_key() {
        let c = bind_leaf_cert_rsa_signed_sha384(key_swapped(), cv::CHATGPT_LEAF_TBS_LEN);
        assert(c.key_hash == p256_key_hash(tv::LEICA_LEAF_PUB_X, tv::LEICA_LEAF_PUB_Y));
    }

    #[test(should_fail)]
    fn test_substituted_leaf_key_rejected() {
        let _ = verify_leaf_certificate(key_swapped(), cv::CHATGPT_LEAF_TBS_LEN, cv::CHATGPT_CA_SIG, cv::CHATGPT_CA_MODULUS, cv::CHATGPT_CA_REDC);
    }

    fn date_pushed() -> [u8; MAX_TBS_SIZE] {
        // Move the second UTCTime (notAfter) a decade later: year digit +1.
        let mut t = pad(cv::CHATGPT_LEAF_TBS);
        let mut first: u32 = 0;
        let mut second: u32 = 0;
        for i in 0..300 {
            if (t[i] == 0x17) & (t[i + 1] == 0x0d) {
                if first == 0 {
                    first = i;
                } else if second == 0 {
                    second = i;
                }
            }
        }
        assert(second != 0);
        t[second + 2] = t[second + 2] + 1;
        t
    }

    #[test]
    fn test_date_pushed_tbs_parses_to_later_date() {
        let c = bind_leaf_cert_rsa_signed_sha384(date_pushed(), cv::CHATGPT_LEAF_TBS_LEN);
        let real = bind_leaf_cert_rsa_signed_sha384(pad(cv::CHATGPT_LEAF_TBS), cv::CHATGPT_LEAF_TBS_LEN);
        assert(c.not_after > real.not_after);
    }

    #[test(should_fail)]
    fn test_tampered_not_after_rejected() {
        let _ = verify_leaf_certificate(date_pushed(), cv::CHATGPT_LEAF_TBS_LEN, cv::CHATGPT_CA_SIG, cv::CHATGPT_CA_MODULUS, cv::CHATGPT_CA_REDC);
    }

    #[test(should_fail)]
    fn test_sha256_signed_leaf_rejected() {
        // A leaf signed sha256WithRSAEncryption must use proof_a_rsa_2048_v2.
        let _ = bind_leaf_cert_rsa_signed_sha384(pad(rv::SYN_P256_LEAF_BY_RSA2048_TBS), rv::SYN_P256_LEAF_BY_RSA2048_TBS_LEN);
    }

    #[test(should_fail)]
    fn test_other_ca_rejected() {
        let _ = verify_leaf_certificate(
            pad(cv::CHATGPT_LEAF_TBS),
            cv::CHATGPT_LEAF_TBS_LEN,
            cv::CHATGPT_CA_SIG,
            rv::SYN_RSA2048_CA_MODULUS,
            rv::SYN_RSA2048_CA_REDC,
        );
    }
}
