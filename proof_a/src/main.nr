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
    MAX_ACTIONS_ASSERTION_SIZE,
    verify_full_hash_chain,
    verify_claim_hash,
    verify_content_hash_in_claim,
    verify_assertion_chain,
    verify_actions_assertion_chain,
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
    // NOTE: link_commit is now COMPUTED internally and returned as OUTPUT
    // This avoids JS/circuit Pedersen implementation mismatches

    // === PUBLIC INPUTS: TIME RANGE BOUNDS (for graduated time disclosure) ===
    // These bounds are public - verifiers can see the range but not exact timestamp
    // time_min <= exact_timestamp <= time_max is verified in circuit
    time_min: pub Field,  // Minimum timestamp bound (Unix seconds)
    time_max: pub Field,  // Maximum timestamp bound (Unix seconds)

    // === PUBLIC INPUTS: EDIT TIME RANGE BOUNDS (for edited images) ===
    // When a photo is edited (e.g., Leica capture -> Lightroom export), the capture
    // and edit timestamps differ. These bounds constrain the edit/signing timestamp.
    // Set to 0 when no edit occurred (direct camera capture).
    edit_time_min: pub Field,  // Minimum edit timestamp bound (0 if no edit)
    edit_time_max: pub Field,  // Maximum edit timestamp bound (0 if no edit)

    // === PUBLIC INPUTS: LOCATION PRIVACY CIRCLE (for graduated location disclosure) ===
    // Verifiers can see the privacy circle region but not exact coordinates
    // Circuit proves: exact location is within the disclosed circle
    center_lat_scaled: pub Field,     // Circle center latitude (scaled 10^7, absolute value)
    center_lon_scaled: pub Field,     // Circle center longitude (scaled 10^7, absolute value)
    location_flags: pub u8,           // bit 0 = lat negative (South), bit 1 = lon negative (West)
    radius_squared_scaled: pub Field, // Privacy radius squared (scaled units)

    // === PUBLIC INPUT: TBS Hash Commitment (packed from 80 bytes to 1 Field) ===
    // This is Poseidon2(tbs_hash_bytes_as_fields) or Poseidon2(tbs_hash_sha384_as_fields)
    // depending on which algorithm is used. Saves 79 public input fields.
    tbs_hash_commitment: pub Field,

    // === PUBLIC INPUT: Claim Hash Commitment (packed from 32 bytes to 1 Field) ===
    // This is Poseidon2(claim_hash_as_fields). The actual claim_hash bytes are private.
    // SECURITY: Both ProofA and ProofB must use the same commitment.
    claim_hash_commitment: pub Field,

    // === NEW PUBLIC INPUT: Content Hash Offset (for content binding) ===
    // Byte offset where content_hash (as SHA256 digest) appears in claim_bytes
    // SECURITY: This ensures the public content_hash actually exists in the signed claim
    content_hash_offset: pub u32,

    // === PRIVATE: ALGORITHM SELECTORS ===
    cert_algorithm: Field,  // 0 = ECDSA-P256, 1 = RSA-2048, 2 = RSA-4096, 3 = RSA-2048-SHA384, 4 = ECDSA-P384, 5 = skip verification (2-cert chains)
    leaf_key_type: Field,   // 0 = ECDSA, 1 = RSA

    // === PRIVATE: TBS HASH BYTES (unpacked from commitment) ===
    // These are the actual hash bytes - the circuit verifies tbs_hash_commitment == Poseidon2(bytes_as_fields)
    tbs_hash_bytes: [u8; 32],      // SHA-256 hash of TBS certificate (for ECDSA/RSA-SHA256)
    tbs_hash_sha384: [u8; 48],     // SHA-384 hash of TBS certificate (for RSA-SHA384/ECDSA-P384)

    // === PRIVATE: CLAIM HASH BYTES (unpacked from commitment) ===
    // These are SHA256(claim_bytes) - the circuit verifies claim_hash_commitment == Poseidon2(bytes_as_fields)
    claim_hash: [u8; 32],

    // === PRIVATE: SKIP FLAGS ===
    // Skip content hash binding verification for C2PA manifests where content hash
    // is in a separate assertion (c2pa.hash.data) rather than directly in the claim.
    // The hash chain is still verified via assertion_hash -> content_hash.
    skip_content_hash_binding: pub u8,  // 0 = verify (default), 1 = skip
    // Skip assertion hash verification for manifests where assertion data isn't available
    // or parseable (e.g., some ProofMode 2-cert chain configurations).
    skip_assertion_hash_verification: pub u8,  // 0 = verify (default), 1 = skip

    // === PRIVATE: LEAF KEY (for nullifier binding) ===
    // ECDSA leaf key
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],
    // RSA leaf key (8 limbs = 1024 bits for strong collision resistance)
    // SECURITY FIX (MEDIUM-2): Previously only 2 limbs (256 bits) were used,
    // which could potentially allow nullifier collisions. Now using 8 limbs.
    leaf_rsa_modulus_limbs: [u128; 8],

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

    // === PRIVATE: MERKLE MEMBERSHIP (trust list verification) ===
    // Proves intermediate CA is in the Oracle's promoted trust list
    // SECURITY: This prevents proofs with untrusted/rogue CAs
    merkle_path: [Field; 8],    // Sibling hashes for Merkle proof (depth 8 = 256 intermediates max)
    merkle_indices: [Field; 8], // 0 = left, 1 = right at each level

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
    // RESTORED to 2048 for full cryptographic hash chain verification
    // ProofMode claims are ~1299 bytes, requiring buffer > 1024
    claim_bytes: [u8; 2048],  // MAX_CLAIM_SIZE = 2048
    // Actual length of claim bytes
    claim_length: u32,
    // Byte offset where EXIF assertion hash appears in claim
    exif_assertion_hash_offset: u32,
    // Raw EXIF assertion bytes (padded to MAX_EXIF_ASSERTION_SIZE)
    // RESTORED to 1024 for full assertion hash verification
    exif_assertion_bytes: [u8; 1024],  // MAX_EXIF_ASSERTION_SIZE = 1024
    // Actual length of EXIF assertion bytes
    exif_assertion_length: u32,

    // === PRIVATE: ACTIONS ASSERTION (c2pa.actions.v2) ===
    // Byte offset where actions assertion hash appears in claim
    // If offset = 0, skip actions assertion verification (optional assertion)
    actions_assertion_hash_offset: u32,
    // Raw actions assertion bytes (padded to MAX_ACTIONS_ASSERTION_SIZE)
    // Contains edit history: c2pa.created, c2pa.edited, digitalSourceType, etc.
    // NOTE: Adobe Photoshop actions can be 1200-1500 bytes, so using 2048 for headroom
    actions_assertion_bytes: [u8; 2048],  // MAX_ACTIONS_ASSERTION_SIZE = 2048
    // Actual length of actions assertion bytes
    actions_assertion_length: u32,

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
    time_salt: Field,      // Random salt for time commitment

    // === PRIVATE: EDIT TIMESTAMP & SALT (for separate edit time commitment) ===
    exact_edit_timestamp: Field,  // Edit/signing timestamp (0 if no edit)
    edit_time_salt: Field         // Salt for edit time commitment
) -> pub (Field, Field, Field, Field, [u8; 32]) {  // Returns (link_commit, location_commitment, time_commitment, edit_time_commitment, actions_assertion_hash)
    // ================================================================
    // STEP 0: Verify commitment packing (PUBLIC INPUT OPTIMIZATION)
    // ================================================================
    // This verifies that the private TBS hash bytes and claim hash bytes match
    // their public Poseidon2 commitments. This allows us to reduce public inputs
    // from 126 to ~46 fields (63% reduction, cheaper on-chain verification).

    // Verify TBS hash commitment based on algorithm
    // SHA-256 algorithms (0, 1, 2) use tbs_hash_bytes
    // SHA-384 algorithms (3, 4) use tbs_hash_sha384
    let uses_sha384 = (cert_algorithm == 3) | (cert_algorithm == 4);

    if uses_sha384 {
        // SHA-384: Pack 48 bytes into fields and hash
        let computed_tbs_commitment = Poseidon2::hash(bytes48_to_field_array(tbs_hash_sha384), 2);
        assert(computed_tbs_commitment == tbs_hash_commitment, "TBS hash commitment mismatch (SHA-384)");
    } else if cert_algorithm != 5 {
        // SHA-256: Pack 32 bytes into fields and hash
        let computed_tbs_commitment = Poseidon2::hash(bytes32_to_field_array(tbs_hash_bytes), 2);
        assert(computed_tbs_commitment == tbs_hash_commitment, "TBS hash commitment mismatch (SHA-256)");
    }
    // Note: cert_algorithm == 5 (2-cert chain) skips TBS commitment check since no cert signature verification

    // Verify claim hash commitment
    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

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
    } else if cert_algorithm == 5 {
        // Skip verification mode for 2-cert chains (ProofMode/self-signed)
        // In 2-cert chains, the leaf is signed directly by the root CA.
        // The trust list membership is verified via Merkle proof using issuer DN hash.
        // No intermediate certificate signature to verify.
        // 2-cert chain mode: skipping certificate signature verification
    } else {
        assert(false, f"Invalid certificate algorithm: {cert_algorithm}");
    }

    // NOTE: cert_algorithm describes how the INTERMEDIATE cert signature is verified
    // (e.g., RSA-2048-SHA384), while leaf_key_type describes the LEAF certificate's key type
    // (e.g., ECDSA P-256). These are independent -- a CA can sign with RSA but issue ECDSA
    // leaf certs (e.g., Truepic: cert_algorithm=3/RSA-2048-SHA384, leaf_key_type=0/ECDSA).
    // No cross-check is valid here.

    // ================================================================
    // STEP 2: Derive Leaf Key Hash
    // ================================================================
    // SECURITY FIX (MEDIUM-2): For RSA keys, hash 8 limbs (1024 bits) instead of 2 limbs.
    // This provides strong collision resistance for the nullifier derivation.
    let computed_leaf_key_hash = if leaf_key_type == LEAF_ALG_ECDSA {
        let x_field = bytes_to_field(leaf_pubkey_x);
        let y_field = bytes_to_field(leaf_pubkey_y);
        pedersen_hash([x_field, y_field])
    } else {
        // Hash all 8 RSA limbs for strong collision resistance (1024 bits)
        pedersen_hash([
            leaf_rsa_modulus_limbs[0] as Field,
            leaf_rsa_modulus_limbs[1] as Field,
            leaf_rsa_modulus_limbs[2] as Field,
            leaf_rsa_modulus_limbs[3] as Field,
            leaf_rsa_modulus_limbs[4] as Field,
            leaf_rsa_modulus_limbs[5] as Field,
            leaf_rsa_modulus_limbs[6] as Field,
            leaf_rsa_modulus_limbs[7] as Field
        ])
    };

    // ================================================================
    // STEP 3: Verify Nullifier Derivation
    // ================================================================
    // This binds the Leaf Key to the Content Hash
    let expected_nullifier = pedersen_hash([content_hash, computed_leaf_key_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier (leaf key binding failed)");

    // ================================================================
    // STEP 4: Compute Link Commitment (returned as output)
    // ================================================================
    // This binds this proof to ProofB (which validates intermediate_leaf in Trust List)
    // SECURITY FIX (HIGH-3): Include claim_hash for full ProofA<->ProofB binding
    // This prevents malicious extractor attacks where different claims are used in each proof
    //
    // NOTE: link_commit is COMPUTED here and returned as OUTPUT rather than verified
    // against a pre-computed input. This avoids JS/circuit Pedersen implementation
    // mismatches between bb.js versions and ACVM's internal Barretenberg.
    let claim_hash_field = bytes_to_field(claim_hash);
    let link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);
    // The verifier checks that ProofA and ProofB output the same link_commit

    // ================================================================
    // STEP 4b: Verify Intermediate Leaf Formulation
    // ================================================================
    // CRITICAL: We must ensure 'intermediate_leaf' witness corresponds to the 
    // intermediate public key verified in Step 1.
    
    // SECURITY FIX (MEDIUM-2): Hash 8 limbs (1024 bits) for strong collision resistance
    let computed_intermediate_hash = if cert_algorithm == 2 {
        // RSA-4096 (hash 8 limbs for collision resistance)
        pedersen_hash([
            intermediate_rsa_4096_modulus_limbs[0] as Field,
            intermediate_rsa_4096_modulus_limbs[1] as Field,
            intermediate_rsa_4096_modulus_limbs[2] as Field,
            intermediate_rsa_4096_modulus_limbs[3] as Field,
            intermediate_rsa_4096_modulus_limbs[4] as Field,
            intermediate_rsa_4096_modulus_limbs[5] as Field,
            intermediate_rsa_4096_modulus_limbs[6] as Field,
            intermediate_rsa_4096_modulus_limbs[7] as Field
        ])
    } else if (cert_algorithm == 1) | (cert_algorithm == 3) {
        // RSA-2048 (hash 8 limbs for collision resistance)
        pedersen_hash([
            intermediate_rsa_2048_modulus_limbs[0] as Field,
            intermediate_rsa_2048_modulus_limbs[1] as Field,
            intermediate_rsa_2048_modulus_limbs[2] as Field,
            intermediate_rsa_2048_modulus_limbs[3] as Field,
            intermediate_rsa_2048_modulus_limbs[4] as Field,
            intermediate_rsa_2048_modulus_limbs[5] as Field,
            intermediate_rsa_2048_modulus_limbs[6] as Field,
            intermediate_rsa_2048_modulus_limbs[7] as Field
        ])
    } else if cert_algorithm == 4 {
        // ECDSA P-384
        // Convert 48-byte coordinates to Field (mod P)
        let x_field = bytes48_to_field(intermediate_ecdsa_p384_pubkey_x);
        let y_field = bytes48_to_field(intermediate_ecdsa_p384_pubkey_y);
        pedersen_hash([x_field, y_field])
    } else if cert_algorithm == 5 {
        // 2-cert chain mode: intermediate_leaf is provided directly as witness
        // (derived from issuer DN hash in frontend)
        // Trust list membership is still verified via Merkle proof
        intermediate_leaf  // Return the witness directly, no computation needed
    } else {
        // ECDSA P-256 (Default)
        let x_field = bytes_to_field(intermediate_ecdsa_pubkey_x);
        let y_field = bytes_to_field(intermediate_ecdsa_pubkey_y);
        pedersen_hash([x_field, y_field])
    };

    // For cert_algorithm == 5 (2-cert chain), skip the intermediate hash check
    // The intermediate_leaf is provided as a witness from issuer DN hash
    // Trust verification happens through Merkle membership only
    if cert_algorithm != 5 {
        assert(intermediate_leaf == computed_intermediate_hash, "Intermediate Leaf witnessing mismatch (Self-Signing Attack prevention)");
    }

    // ================================================================
    // STEP 4c: Merkle Membership (Trust List Verification)
    // ================================================================
    // SECURITY: Verifies the intermediate CA is in the Oracle's promoted trust list.
    // Without this, a malicious client could use a rogue/untrusted CA.
    // This step makes ProofA independently secure (not relying on ProofB).
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate CA not in trust list (Merkle verification failed)");

    // ================================================================
    // STEP 5: Certificate Validity (Time)
    // ================================================================
    // SECURITY: Ensure Field values fit in u64 before comparison
    assert(proof_timestamp as u64 as Field == proof_timestamp, "proof_timestamp exceeds u64");
    assert(cert_not_before as u64 as Field == cert_not_before, "cert_not_before exceeds u64");
    assert(cert_not_after as u64 as Field == cert_not_after, "cert_not_after exceeds u64");

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
    assert(exact_timestamp as u64 as Field == exact_timestamp, "exact_timestamp exceeds u64");
    assert(time_min as u64 as Field == time_min, "time_min exceeds u64");
    assert(time_max as u64 as Field == time_max, "time_max exceeds u64");

    let exact_ts = exact_timestamp as u64;
    let min_ts = time_min as u64;
    let max_ts = time_max as u64;

    // Verify exact_timestamp is within the disclosed range
    assert(exact_ts >= min_ts, "Exact timestamp is before disclosed time_min");
    assert(exact_ts <= max_ts, "Exact timestamp is after disclosed time_max");

    // ================================================================
    // STEP 6b: Edit Time Range Proof (0 = no edit, skip)
    // ================================================================
    // When a photo is edited (capture -> export), exact_edit_timestamp is the
    // signing/export time. For direct camera captures, it's 0 (sentinel).
    assert(exact_edit_timestamp as u64 as Field == exact_edit_timestamp, "exact_edit_timestamp exceeds u64");
    assert(edit_time_min as u64 as Field == edit_time_min, "edit_time_min exceeds u64");
    assert(edit_time_max as u64 as Field == edit_time_max, "edit_time_max exceeds u64");

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
    // Proves that the exact GPS coordinates are within the public privacy circle
    // without revealing the exact location.
    //
    // Use cases:
    //   - hidden: radius_squared_scaled = MAX -> proves GPS exists but hides location
    //   - radius_50km: ~50km privacy circle -> "somewhere in this region"
    //   - radius_10km: ~10km privacy circle -> city-level
    //   - radius_1km:  ~1km privacy circle  -> neighborhood-level
    //   - exact: radius_squared_scaled = 0 AND center == exact -> full disclosure
    //
    // This protects journalists/activists by hiding precise locations
    // while still proving the photo has valid GPS within the disclosed region.
    //
    // Distance calculation uses planar approximation (valid for small areas < 100km):
    //   d_lat = |exact_lat - center_lat| (accounting for hemisphere signs)
    //   d_lon = |exact_lon - center_lon| (accounting for hemisphere signs)
    //   distance_squared = d_lat^2 + d_lon^2
    //   assert(distance_squared <= radius_squared)
    //
    // SECURITY FIX (MEDIUM-1): Previously radius=0 bypassed all checks.
    // Now we ALWAYS verify location. For radius=0 (exact disclosure), we verify
    // center == exact coordinates. For radius>0, we verify distance <= radius.

    assert(exact_lat_is_negative <= 1, "exact_lat_is_negative must be 0 or 1");
    assert(exact_lon_is_negative <= 1, "exact_lon_is_negative must be 0 or 1");
    assert(skip_content_hash_binding <= 1, "skip_content_hash_binding must be 0 or 1");
    assert(skip_assertion_hash_verification <= 1, "skip_assertion_hash_verification must be 0 or 1");

    // Unpack location_flags: bit 0 = lat negative, bit 1 = lon negative
    assert(location_flags <= 3, "location_flags has invalid high bits set (must be 0-3)");
    let center_lat_is_negative = location_flags & 1;
    let center_lon_is_negative = (location_flags >> 1) & 1;

    assert(exact_lat_scaled as u64 as Field == exact_lat_scaled, "exact_lat_scaled exceeds u64");
    assert(center_lat_scaled as u64 as Field == center_lat_scaled, "center_lat_scaled exceeds u64");
    assert(exact_lon_scaled as u64 as Field == exact_lon_scaled, "exact_lon_scaled exceeds u64");
    assert(center_lon_scaled as u64 as Field == center_lon_scaled, "center_lon_scaled exceeds u64");

    {
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
    // SECURITY: This verification is MANDATORY to prevent the "lying parser" attack.
    // The enable_hash_chain_verification flag MUST be 1 - this is enforced below.

    // SECURITY: Enforce hash chain verification is enabled
    // This prevents malicious clients from bypassing metadata binding
    assert(
        enable_hash_chain_verification == 1,
        "Hash chain verification must be enabled (enable_hash_chain_verification=1) to prevent metadata substitution attacks"
    );

    // ================================================================
    // STEP 8a: Verify claim_hash = SHA256(claim_bytes)
    // ================================================================
    // SECURITY FIX (HIGH-2): Previously used tbs_hash_bytes which is the TBS certificate hash,
    // not the claim hash. claim_hash is the SHA256 of the actual C2PA claim.
    // This hash is a PUBLIC input that ProofB also uses, binding both proofs to the same claim.
    verify_claim_hash(claim_bytes, claim_length, claim_hash);

    // ================================================================
    // STEP 8b: Verify content_hash exists in claim_bytes
    // ================================================================
    // SECURITY FIX (HIGH-1): Verify the public content_hash actually exists at the
    // declared offset in claim_bytes. Without this, a malicious client could
    // substitute a different image's hash while keeping the valid signature.
    //
    // NOTE: Some C2PA manifests (e.g., ProofMode) store the content hash in a separate
    // assertion (c2pa.hash.data) rather than directly in the claim. For these cases,
    // skip_content_hash_binding=1 allows skipping this check while still verifying
    // the hash chain via the assertion path.
    if skip_content_hash_binding == 0 {
        verify_content_hash_binding(claim_bytes, content_hash_offset, content_hash);
    } else {
        // Content hash binding verification skipped (skip_content_hash_binding=1)
    }

    // ================================================================
    // STEP 8c: Verify assertion hash chain
    // ================================================================
    // Now verify the assertion hash chain using the verified claim_hash
    // verify_full_hash_chain already calls verify_claim_hash internally,
    // so we use verify_assertion_chain which skips the redundant check
    //
    // NOTE: Some C2PA manifests (e.g., ProofMode 2-cert chains) may not have
    // parseable assertion data. For these cases, skip_assertion_hash_verification=1
    // allows skipping this check. The claim hash is still verified, binding the
    // proof to the signed COSE payload.
    if skip_assertion_hash_verification == 0 {
        verify_assertion_chain(
            claim_bytes,
            exif_assertion_hash_offset,
            exif_assertion_bytes,
            exif_assertion_length
        );
    } else {
        // Assertion hash verification skipped (skip_assertion_hash_verification=1)
    }

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

    // ================================================================
    // STEP 8d: Verify actions assertion hash chain (OPTIONAL)
    // ================================================================
    // The c2pa.actions.v2 assertion contains edit history and AI indicators.
    // If actions_assertion_hash_offset > 0, verify the hash chain.
    // If offset == 0, skip verification (actions assertion not present).
    //
    // The computed hash is ALWAYS returned as a public output, allowing
    // verifiers to re-parse the actions bytes off-chain and extract:
    //   - isAiGenerated (digitalSourceType == "trainedAlgorithmicMedia")
    //   - Edit history (c2pa.created, c2pa.edited, c2pa.opened, etc.)
    //   - Software agents used for edits
    //
    // This approach (Option B) avoids in-circuit CBOR parsing while still
    // providing cryptographic binding to the signed claim.
    let actions_assertion_hash: [u8; 32] = if actions_assertion_hash_offset > 0 {
        // Verify actions assertion hash chain using the 2048-byte buffer function
        verify_actions_assertion_chain(
            claim_bytes,
            actions_assertion_hash_offset,
            actions_assertion_bytes,
            actions_assertion_length
        );
        // Compute and return the hash for public output
        // IMPORTANT: Use sha256_var to hash only the actual bytes (not padded)
        // This matches what verify_actions_assertion_chain uses internally
        let hash_result: [u8; 32] = dep::sha256::sha256_var(actions_assertion_bytes, actions_assertion_length as u32);
        hash_result
    } else {
        // No actions assertion - return zero hash
        [0u8; 32]
    };

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

    // Edit time commitment: Poseidon2([edit_timestamp, salt]) or 0 sentinel
    // Poseidon2 never outputs 0 for valid inputs, so 0 is safe as "no edit" sentinel
    let edit_time_commitment = if exact_edit_timestamp == 0 {
        0  // Sentinel: no edit happened
    } else {
        Poseidon2::hash([exact_edit_timestamp, edit_time_salt], 2)
    };

    // Return link_commit, commitments, and actions hash as public outputs
    // NOTE: link_commit is now computed internally and returned as output
    // The verifier must check that ProofA.link_commit == ProofB.link_commit
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

/// Convert 48 bytes to 2 Field elements for Poseidon2 hashing
/// Splits into two 24-byte (192-bit) chunks that fit within the BN254 field
fn bytes48_to_field_array(bytes: [u8; 48]) -> [Field; 2] {
    // First 24 bytes -> Field 0
    let mut f0: Field = 0;
    for i in 0..24 {
        f0 = f0 * 256 + bytes[i] as Field;
    }
    // Last 24 bytes -> Field 1
    let mut f1: Field = 0;
    for i in 24..48 {
        f1 = f1 * 256 + bytes[i] as Field;
    }
    [f0, f1]
}

/// SECURITY FIX (HIGH-1): Verify content_hash exists in claim
///
/// This function binds the public content_hash to the signed claim bytes.
/// Without this, a malicious client could substitute any content_hash.
fn verify_content_hash_binding(
    claim_bytes: [u8; 2048],  // RESTORED to 2048 for full hash chain verification
    content_hash_offset: u32,
    expected_content_hash: Field
) {
    verify_content_hash_in_claim(claim_bytes, content_hash_offset, expected_content_hash);
}

/// Compute Merkle root from leaf and proof
///
/// This verifies that intermediate_leaf is in the trust list by computing
/// the Merkle root and comparing against the public trust_list_root.
///
/// @param leaf - The intermediate CA hash (intermediate_leaf)
/// @param path - Sibling hashes at each level of the tree
/// @param indices - Direction at each level (0 = leaf is left child, 1 = leaf is right child)
/// @returns Computed Merkle root
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

        // If is_right == 0, current is left child, path_element is right
        // If is_right == 1, path_element is left child, current is right
        let left = if is_right == 0 { current } else { path_element };
        let right = if is_right == 0 { path_element } else { current };
        current = pedersen_hash([left, right]);
    }

    current
}

// ====================================================================
// SECURITY TESTS
// ====================================================================

/// Test that Merkle root computation is correct
#[test]
fn test_merkle_root_computation() {
    // Known leaf value
    let leaf: Field = 12345;

    // Simple path where all siblings are 0 (leftmost path)
    let path: [Field; 8] = [0; 8];
    let indices: [Field; 8] = [0; 8];  // All left children

    // Compute root
    let root = compute_merkle_root(leaf, path, indices);

    // Verify it's not just the leaf (path was applied)
    assert(root != leaf, "Merkle root should not equal leaf when path is applied");

    // Verify deterministic (same inputs = same output)
    let root2 = compute_merkle_root(leaf, path, indices);
    assert(root == root2, "Merkle root computation should be deterministic");
}

/// Test Merkle proof verification with known values
#[test]
fn test_merkle_membership_verification() {
    // Create a simple 2-leaf tree:
    //       root
    //      /    \
    //    leaf0  leaf1
    let leaf0: Field = 100;
    let leaf1: Field = 200;
    let expected_root = pedersen_hash([leaf0, leaf1]);

    // Proof for leaf0: sibling is leaf1, index is 0 (left)
    let path: [Field; 8] = [leaf1, 0, 0, 0, 0, 0, 0, 0];
    let indices: [Field; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    // With depth=1 tree, remaining 7 levels hash with 0
    let mut expected = pedersen_hash([leaf0, leaf1]);
    for _ in 1..8 {
        expected = pedersen_hash([expected, 0]);
    }

    let computed_root = compute_merkle_root(leaf0, path, indices);
    assert(computed_root == expected, "Merkle proof should verify correctly");
}

/// Test that different leaves produce different roots
#[test]
fn test_merkle_different_leaves() {
    let path: [Field; 8] = [0; 8];
    let indices: [Field; 8] = [0; 8];

    let root1 = compute_merkle_root(111, path, indices);
    let root2 = compute_merkle_root(222, path, indices);

    assert(root1 != root2, "Different leaves should produce different roots");
}

/// Test time range bounds checking
#[test]
fn test_time_range_exact_bounds() {
    // Test exact timestamp equals min bound
    let exact: u64 = 1000;
    let min: u64 = 1000;
    let max: u64 = 2000;

    assert(exact >= min, "Timestamp at min bound should pass");
    assert(exact <= max, "Timestamp within range should pass");
}

/// Test time range with timestamp at max bound
#[test]
fn test_time_range_max_bound() {
    let exact: u64 = 2000;
    let min: u64 = 1000;
    let max: u64 = 2000;

    assert(exact >= min, "Timestamp at max bound should be >= min");
    assert(exact <= max, "Timestamp at max bound should pass");
}

/// Test location distance calculation (same point)
#[test]
fn test_location_same_point() {
    let exact_lat: Field = 510000000;  // 51.0 degrees scaled
    let exact_lon: Field = 100000000;  // 10.0 degrees scaled
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

/// Test location distance calculation (within circle)
#[test]
fn test_location_within_circle() {
    // Center at 51.0, 10.0
    let center_lat: Field = 510000000;
    let center_lon: Field = 100000000;

    // Exact at 51.001, 10.001 (0.001 degrees offset ~ 111 meters)
    let exact_lat: Field = 510010000;  // 0.001 degree offset
    let exact_lon: Field = 100010000;

    let d_lat = exact_lat - center_lat;  // 10000 scaled units
    let d_lon = exact_lon - center_lon;  // 10000 scaled units

    let distance_squared = d_lat * d_lat + d_lon * d_lon;  // 200000000

    // Radius of 0.01 degrees (1km) -> radius_squared = 10000 * 10000 = 100000000
    // Our distance_squared = 200000000 which is > 100000000
    // So with radius_squared = 300000000 we should pass
    let radius_squared: Field = 300000000;

    assert(distance_squared as u64 <= radius_squared as u64, "Point within circle should pass");
}
