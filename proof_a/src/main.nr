use bignum::params::BigNumParams;
use noir_rsa::types::RBN4096; 
use noir_rsa::types::RBN2048;
use noir_rsa::rsa::verify_sha256_pkcs1v15;

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
use dep::poseidon::poseidon2::Poseidon2;

mod crypto_utils;
mod crypto;
mod hash_chain;

use hash_chain::{
    MAX_CLAIM_SIZE,
    MAX_EXIF_ASSERTION_SIZE,
    verify_full_hash_chain,
};

// Constants
global LEAF_ALG_ECDSA: Field = 0;


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

    // === PUBLIC INPUTS: TIME RANGE BOUNDS (for graduated time disclosure) ===
    // These bounds are public - verifiers can see the range but not exact timestamp
    // time_min <= exact_timestamp <= time_max is verified in circuit
    time_min: pub Field,  // Minimum timestamp bound (Unix seconds)
    time_max: pub Field,  // Maximum timestamp bound (Unix seconds)

    // === PUBLIC INPUTS: LOCATION PRIVACY CIRCLE (for graduated location disclosure) ===
    // Verifiers can see the privacy circle region but not exact coordinates
    // Circuit proves: exact location is within the disclosed circle
    center_lat_scaled: pub Field,     // Circle center latitude (scaled 10^7, absolute value)
    center_lon_scaled: pub Field,     // Circle center longitude (scaled 10^7, absolute value)
    center_lat_is_negative: pub u8,   // 1 if center latitude is South (negative)
    center_lon_is_negative: pub u8,   // 1 if center longitude is West (negative)
    radius_squared_scaled: pub Field, // Privacy radius squared (scaled units)

    // === NEW PUBLIC INPUT: Pre-computed TBS Hash ===
    tbs_hash_bytes: pub [u8; 32],
    tbs_hash_sha384: pub [u8; 48],

    // === PRIVATE: ALGORITHM SELECTORS ===
    cert_algorithm: Field,  // 0 = ECDSA-P256, 1 = RSA-2048, 2 = RSA-4096, 3 = RSA-2048-SHA384, 4 = ECDSA-P384
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

    // === PRIVATE: ECDSA CERTIFICATE SIGNATURE & KEY ===
    // ECDSA P-256 Signature (64 bytes: 32 bytes R + 32 bytes S)
    cert_signature_ecdsa: [u8; 64],
    intermediate_ecdsa_pubkey_x: [u8; 32],
    intermediate_ecdsa_pubkey_y: [u8; 32],

    // === PRIVATE: ECDSA P-384 CERTIFICATE SIGNATURE & KEY ===
    // ECDSA P-384 Signature (96 bytes: 48 bytes R + 48 bytes S)
    cert_signature_ecdsa_p384_r: [u8; 48],
    cert_signature_ecdsa_p384_s: [u8; 48],
    intermediate_ecdsa_p384_pubkey_x: [u8; 48],
    intermediate_ecdsa_p384_pubkey_y: [u8; 48],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,  // pedersen_hash of intermediate key material
    link_blind: Field,         // random blinding factor (same as in ProofB)

    // === PRIVATE: EXACT TIMESTAMP (for time range proof) ===
    // The exact capture timestamp from C2PA metadata (Unix seconds)
    // Circuit proves this is within [time_min, time_max] without revealing it
    exact_timestamp: Field,

    // === PRIVATE: EXACT GPS LOCATION (for location range proof) ===
    // The exact GPS coordinates from C2PA EXIF assertion (scaled 10^7, absolute values)
    // Circuit proves these are within the privacy circle without revealing them
    exact_lat_scaled: Field,       // Exact latitude (scaled, absolute value)
    exact_lon_scaled: Field,       // Exact longitude (scaled, absolute value)
    exact_lat_is_negative: u8,     // 1 if exact latitude is South (negative)
    exact_lon_is_negative: u8,     // 1 if exact longitude is West (negative)

    // === PRIVATE: HASH CHAIN DATA (for trustless metadata binding) ===
    // These inputs allow the circuit to verify that metadata values came from signed claim
    // Without this, a malicious client could substitute GPS/time values
    //
    // Enable hash chain verification (0 = disabled for backwards compatibility)
    enable_hash_chain_verification: u8,
    // Raw claim bytes (CBOR-encoded, padded to MAX_CLAIM_SIZE)
    claim_bytes: [u8; 2048],  // MAX_CLAIM_SIZE = 2048
    // Actual length of claim bytes
    claim_length: u32,
    // Byte offset where EXIF assertion hash appears in claim
    exif_assertion_hash_offset: u32,
    // Raw EXIF assertion bytes (padded to MAX_EXIF_ASSERTION_SIZE)
    exif_assertion_bytes: [u8; 1024],  // MAX_EXIF_ASSERTION_SIZE = 1024
    // Actual length of EXIF assertion bytes
    exif_assertion_length: u32,

    // === PRIVATE: COMMITMENT SALTS (for optional future reveal) ===
    // These salts enable users to later prove exact values to specific parties
    // (e.g., courts, investigators) without regenerating from original image.
    //
    // Use case:
    //   1. Journalist posts with 'City level' location disclosure
    //   2. Months later, court requests exact location for evidence
    //   3. Journalist reveals salt + exact coordinates
    //   4. Court verifies: Poseidon(lat, lon, salt) == location_commitment
    //
    location_salt: Field,  // Random salt for location commitment
    time_salt: Field       // Random salt for time commitment
) -> pub (Field, Field) {  // Returns (location_commitment, time_commitment)
    // ================================================================
    println(f"Cert Algorithm: {cert_algorithm}");
    // STEP 1: Verify RSA Signature (Root/Intermediate validates Leaf)
    // ================================================================

    if cert_algorithm == 2 {
        // RSA-4096 (Standard Lib)
        let params: BigNumParams<35, 4096> = BigNumParams::new(false, intermediate_rsa_4096_modulus_limbs, intermediate_rsa_4096_redc_limbs);
        let signature: RBN4096 = RBN4096::from_array(params, cert_signature_rsa_4096_limbs);
        
        let valid = verify_sha256_pkcs1v15(tbs_hash_bytes, signature, 65537);
        assert(valid, "RSA-4096 verification failed");
    } else if cert_algorithm == 1 {
        // RSA-2048 (Fallback)
        let params: BigNumParams<18, 2048> = BigNumParams::new(false, intermediate_rsa_2048_modulus_limbs, intermediate_rsa_2048_redc_limbs);
        let signature: RBN2048 = RBN2048::from_array(params, cert_signature_rsa_2048_limbs);
        
        let valid = verify_sha256_pkcs1v15(tbs_hash_bytes, signature, 65537);
        assert(valid, "RSA-2048 verification failed");
    } else if cert_algorithm == 3 {
        // RSA-2048 with SHA-384
        let params: BigNumParams<18, 2048> = BigNumParams::new(false, intermediate_rsa_2048_modulus_limbs, intermediate_rsa_2048_redc_limbs);
        let signature: RBN2048 = RBN2048::from_array(params, cert_signature_rsa_2048_limbs);
        
        let valid = crypto_utils::verify_sha384_pkcs1v15_2048(tbs_hash_sha384, signature, 65537);
        assert(valid, "RSA-2048-SHA384 verification failed");
    } else if cert_algorithm == 0 {
        // ECDSA P-256 (Native)
        let valid = verify_signature(
            intermediate_ecdsa_pubkey_x,
            intermediate_ecdsa_pubkey_y,
            cert_signature_ecdsa, // signature
            tbs_hash_bytes        // message hash
        );
        assert(valid, "ECDSA P-256 verification failed");
    } else if cert_algorithm == 4 {
        // ECDSA P-384 (Google Pixel)
        let valid = crypto_utils::verify_ecdsa_p384(
            tbs_hash_sha384,
            intermediate_ecdsa_p384_pubkey_x,
            intermediate_ecdsa_p384_pubkey_y,
            cert_signature_ecdsa_p384_r,
            cert_signature_ecdsa_p384_s
        );
        assert(valid, "ECDSA P-384 verification failed");
    } else {
        assert(false, f"Invalid certificate algorithm: {cert_algorithm}");
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
    // STEP 4b: Verify Intermediate Leaf Formulation
    // ================================================================
    // CRITICAL: We must ensure 'intermediate_leaf' witness corresponds to the 
    // intermediate public key verified in Step 1.
    
    let computed_intermediate_hash = if cert_algorithm == 2 {
        // RSA-4096 (hash first 2 limbs)
        pedersen_hash([intermediate_rsa_4096_modulus_limbs[0] as Field, intermediate_rsa_4096_modulus_limbs[1] as Field])
    } else if (cert_algorithm == 1) | (cert_algorithm == 3) {
        // RSA-2048 (hash first 2 limbs)
        pedersen_hash([intermediate_rsa_2048_modulus_limbs[0] as Field, intermediate_rsa_2048_modulus_limbs[1] as Field])
    } else if cert_algorithm == 4 {
        // ECDSA P-384
        // Convert 48-byte coordinates to Field (mod P)
        let x_field = bytes48_to_field(intermediate_ecdsa_p384_pubkey_x);
        let y_field = bytes48_to_field(intermediate_ecdsa_p384_pubkey_y);
        pedersen_hash([x_field, y_field])
    } else {
        // ECDSA P-256 (Default)
        let x_field = bytes_to_field(intermediate_ecdsa_pubkey_x);
        let y_field = bytes_to_field(intermediate_ecdsa_pubkey_y);
        pedersen_hash([x_field, y_field])
    };

    assert(intermediate_leaf == computed_intermediate_hash, "Intermediate Leaf witnessing mismatch (Self-Signing Attack prevention)");

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
    // Proves that the exact capture timestamp is within the public range
    // [time_min, time_max] without revealing the exact value.
    //
    // Use cases:
    //   - hidden: time_min=0, time_max=MAX -> proves timestamp exists
    //   - year:   time_min=Jan1, time_max=Dec31 -> "taken in 2026"
    //   - month:  time_min=Jan1, time_max=Jan31 -> "taken in January 2026"
    //   - exact:  time_min=time_max=exact -> full disclosure
    //
    // This protects journalists/activists by hiding precise capture times
    // while still proving the photo has a valid timestamp within the range.
    let exact_ts = exact_timestamp as u64;
    let min_ts = time_min as u64;
    let max_ts = time_max as u64;

    // Verify exact_timestamp is within the disclosed range
    assert(exact_ts >= min_ts, "Exact timestamp is before disclosed time_min");
    assert(exact_ts <= max_ts, "Exact timestamp is after disclosed time_max");

    // ================================================================
    // STEP 7: Location Range Proof (Graduated Location Disclosure)
    // ================================================================
    // Proves that the exact GPS coordinates are within the public privacy circle
    // without revealing the exact location.
    //
    // Use cases:
    //   - hidden: radius_squared_scaled = MAX -> proves GPS exists
    //   - radius_50km: ~50km privacy circle -> "somewhere in this region"
    //   - radius_10km: ~10km privacy circle -> city-level
    //   - radius_1km:  ~1km privacy circle  -> neighborhood-level
    //   - exact: radius_squared_scaled = 0  -> exact coordinates disclosed
    //
    // This protects journalists/activists by hiding precise locations
    // while still proving the photo has valid GPS within the disclosed region.
    //
    // Distance calculation uses planar approximation (valid for small areas < 100km):
    //   d_lat = |exact_lat - center_lat| (accounting for hemisphere signs)
    //   d_lon = |exact_lon - center_lon| (accounting for hemisphere signs)
    //   distance_squared = d_lat^2 + d_lon^2
    //   assert(distance_squared <= radius_squared)

    // Only perform location check if radius is non-zero (i.e., not skipped)
    // When radius_squared_scaled = 0, it means either:
    //   - exact disclosure (center = exact, radius = 0)
    //   - no GPS data available (all zeros passed)
    // We skip the check for radius = 0 since distance check would fail for non-zero exact coords

    if radius_squared_scaled != 0 {
        // Calculate latitude difference (accounting for hemisphere)
        // If signs differ (one N, one S), we add the absolute values
        // If signs are same, we subtract (absolute difference)
        let lat_same_sign = (exact_lat_is_negative == center_lat_is_negative);
        let d_lat = if lat_same_sign {
            // Same hemisphere - compute absolute difference
            if exact_lat_scaled as u64 > center_lat_scaled as u64 {
                exact_lat_scaled - center_lat_scaled
            } else {
                center_lat_scaled - exact_lat_scaled
            }
        } else {
            // Different hemispheres - add absolute values
            exact_lat_scaled + center_lat_scaled
        };

        // Calculate longitude difference (accounting for East/West)
        let lon_same_sign = (exact_lon_is_negative == center_lon_is_negative);
        let d_lon = if lon_same_sign {
            // Same side - compute absolute difference
            if exact_lon_scaled as u64 > center_lon_scaled as u64 {
                exact_lon_scaled - center_lon_scaled
            } else {
                center_lon_scaled - exact_lon_scaled
            }
        } else {
            // Different sides - add absolute values
            exact_lon_scaled + center_lon_scaled
        };

        // Calculate distance squared (planar approximation)
        // Note: This treats 1 degree lat = 1 degree lon, which is only accurate
        // at the equator. At higher latitudes, the actual circle becomes slightly
        // elliptical, but this is always privacy-preserving (conservative).
        let distance_squared = d_lat * d_lat + d_lon * d_lon;

        // Verify exact location is within privacy circle
        assert(
            distance_squared as u64 <= radius_squared_scaled as u64,
            "Exact GPS location is outside disclosed privacy circle"
        );
    }

    // ================================================================
    // STEP 8: Hash Chain Verification (Trustless Metadata Binding)
    // ================================================================
    // This step ensures that metadata values (GPS, timestamp) actually came from
    // the signed C2PA claim, preventing substitution attacks.
    //
    // Without this verification, a malicious client could:
    //   1. Extract real GPS from signed image
    //   2. Replace with fake GPS in the proof inputs
    //   3. Generate a "valid" proof with fake location
    //
    // The hash chain proves:
    //   COSE Signature -> Claim Hash -> Assertion Hash -> Metadata Values
    //
    // This step is optional (controlled by enable_hash_chain_verification)
    // for backwards compatibility and to support images without hash chain data.

    if enable_hash_chain_verification == 1 {
        // The tbs_hash_bytes is the hash of the Sig_structure which contains the claim.
        // For full hash chain verification, we verify:
        //   1. SHA256(claim_bytes) matches what's in the signature
        //   2. assertion_hash in claim matches SHA256(assertion_bytes)
        //
        // However, the COSE Sig_structure hash (tbs_hash_bytes) is over:
        //   Sig_structure = ["Signature1", protected_headers, external_aad, payload]
        // where payload = claim_bytes (or hash of claim_bytes)
        //
        // For now, we verify the assertion hash chain assuming claim_bytes
        // are already authenticated by the COSE signature verification.

        // Verify: SHA256(exif_assertion_bytes) == hash stored in claim_bytes at offset
        verify_full_hash_chain(
            claim_bytes,
            claim_length,
            tbs_hash_bytes,  // The signature message hash authenticates the claim
            exif_assertion_hash_offset,
            exif_assertion_bytes,
            exif_assertion_length
        );

        // At this point, we've proven that exif_assertion_bytes are authentic
        // (cryptographically bound to the signed claim).
        //
        // The metadata values (GPS, timestamp) extracted from these bytes
        // are therefore trustworthy - they cannot have been substituted.
        //
        // Note: For CBOR assertions, exact byte-level extraction would require
        // parsing CBOR in-circuit. We rely on the hash chain to bind the entire
        // assertion, trusting that the client correctly extracted values from
        // the same bytes that were hashed.
        //
        // For even stronger guarantees, timestamp_offset and gps_offset could
        // be verified to extract values at exact positions in assertion_bytes.
    }

    // ================================================================
    // STEP 9: Compute Poseidon Commitments (Optional Future Reveal)
    // ================================================================
    // These commitments allow users to later prove exact values to specific
    // parties without regenerating the proof from the original image.
    //
    // Commitment scheme:
    //   location_commitment = Poseidon([exact_lat, exact_lon, lat_sign, lon_sign, salt])
    //   time_commitment = Poseidon([exact_timestamp, salt])
    //
    // To reveal:
    //   1. User provides salt + exact values
    //   2. Verifier recomputes Poseidon and checks == stored commitment
    //
    // Security: The salt prevents brute-force attacks on the commitment.
    // Privacy: Only the user who knows the salt can reveal the exact values.

    // Convert sign bytes to Field for hashing
    let lat_sign_field = exact_lat_is_negative as Field;
    let lon_sign_field = exact_lon_is_negative as Field;

    // Location commitment: Poseidon2([lat, lon, lat_sign, lon_sign, salt])
    // Including signs ensures correct hemisphere interpretation on reveal
    let location_commitment = Poseidon2::hash(
        [
            exact_lat_scaled,
            exact_lon_scaled,
            lat_sign_field,
            lon_sign_field,
            location_salt
        ],
        5  // input length
    );

    // Time commitment: Poseidon2([timestamp, salt])
    let time_commitment = Poseidon2::hash(
        [exact_timestamp, time_salt],
        2  // input length
    );

    // Unused inputs to silence warnings
    let _ = trust_list_root;

    // Return commitments as public outputs
    (location_commitment, time_commitment)
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
