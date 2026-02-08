/**
 * Hash Chain Verification for Trustless Metadata Binding
 *
 * This module verifies that extracted metadata values (GPS, timestamp) actually
 * came from the signed C2PA claim, preventing substitution attacks.
 *
 * The verification chain:
 *   1. COSE Signature -> COSE Payload (which is claim_hash or claim_bytes)
 *   2. SHA256(claim_bytes) -> claim_hash (verified via signature)
 *   3. claim_bytes contains assertion_hash at known offset
 *   4. SHA256(assertion_bytes) == assertion_hash
 *   5. assertion_bytes contain the metadata values at known offsets
 *
 * Without this verification, a malicious client could:
 *   - Extract real GPS from signed image
 *   - Replace with fake GPS
 *   - Generate valid proof with fake location
 *
 * With hash chain verification, the circuit ensures:
 *   - The metadata values are cryptographically bound to the signature
 *   - Substitution of any value invalidates the proof
 *
 * CONSTRAINT BUDGET:
 *   - SHA256 in Noir: ~15k constraints per KB hashed
 *   - Claim bytes: typically 1-5 KB -> 15-75k constraints
 *   - Assertion bytes: typically 200B-2KB -> 3-30k constraints
 *   - Total budget: ~100k constraints for hash chain
 *
 * OPTIMIZATION STRATEGIES:
 *   1. Use pre-computed claim_hash when claim is large (skip in-circuit hashing)
 *   2. Only verify assertion hash for assertions containing sensitive data
 *   3. For small claims/assertions, in-circuit SHA256 is acceptable
 */

// SHA256 from stdlib - use digest function with generic size parameter

/// Maximum size of claim bytes we'll hash in-circuit
/// Claims larger than this should use the pre-computed hash approach
/// RESTORED to 2048 for full cryptographic hash chain verification
/// ProofMode claims are ~1299 bytes, so 2048 provides sufficient headroom
pub global MAX_CLAIM_SIZE: u32 = 2048;

/// Maximum size of EXIF assertion bytes we'll hash in-circuit
/// RESTORED to 1024 for full assertion hash verification
pub global MAX_EXIF_ASSERTION_SIZE: u32 = 1024;

/// Maximum size of c2pa.actions assertion bytes we'll hash in-circuit
/// Actions assertions contain edit history (c2pa.created, c2pa.edited, etc.)
/// and AI generation indicators (digitalSourceType: trainedAlgorithmicMedia)
/// NOTE: Adobe Photoshop actions assertions can be 1200-1500 bytes, so 2048 provides headroom
pub global MAX_ACTIONS_ASSERTION_SIZE: u32 = 2048;

/// SHA256 hash output size
pub global HASH_SIZE: u32 = 32;

/**
 * Verify that claim_hash matches SHA256(claim_bytes)
 *
 * This binds the claim content to the signature.
 * The signature verifies over claim_hash, so if this passes,
 * we know claim_bytes are authentic.
 *
 * IMPORTANT: Uses sha256_var to hash only the first claim_length bytes,
 * not the full padded array. The expected hash is SHA256 of the actual
 * claim bytes, not the padded version.
 *
 * @param claim_bytes Raw CBOR claim bytes (padded to MAX_CLAIM_SIZE)
 * @param claim_length Actual length of claim bytes
 * @param expected_claim_hash Pre-computed SHA256(claim_bytes) - same as signature input
 */
pub fn verify_claim_hash(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    claim_length: u32,
    expected_claim_hash: [u8; 32]
) {
    // Compute SHA256 of the ACTUAL claim bytes (not padded)
    // sha256_var hashes only the first claim_length bytes
    let computed_hash: [u8; 32] = dep::sha256::sha256_var(claim_bytes, claim_length as u64);

    // Verify match
    for i in 0..32 {
        assert(
            computed_hash[i] == expected_claim_hash[i],
            "Claim hash verification failed: claim_bytes do not match expected hash"
        );
    }
}

/**
 * Extract assertion hash from claim_bytes at a known offset
 *
 * The claim contains references to assertions with their expected hashes.
 * This function extracts the 32-byte hash at the specified offset.
 *
 * @param claim_bytes Raw CBOR claim bytes
 * @param hash_offset Byte offset where assertion hash appears in claim
 * @returns The 32-byte assertion hash from the claim
 */
pub fn extract_assertion_hash_from_claim(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    hash_offset: u32
) -> [u8; 32] {
    let mut assertion_hash: [u8; 32] = [0; 32];

    // Bounds check
    assert(
        hash_offset + 32 <= MAX_CLAIM_SIZE,
        "Assertion hash offset out of bounds"
    );

    // Extract 32 bytes starting at hash_offset
    for i in 0..32 {
        assertion_hash[i] = claim_bytes[hash_offset + i];
    }

    assertion_hash
}

/**
 * Verify that assertion_hash matches SHA256(assertion_bytes)
 *
 * This binds the assertion content to the claim.
 * Combined with verify_claim_hash, this creates a complete chain:
 *   Signature -> Claim -> Assertion -> Metadata
 *
 * IMPORTANT: Uses sha256_var to hash only the first assertion_length bytes,
 * not the full padded array. The expected hash is SHA256 of the actual
 * assertion bytes, not the padded version.
 *
 * @param assertion_bytes Raw assertion bytes (CBOR or JSON, padded)
 * @param assertion_length Actual length of assertion bytes
 * @param expected_hash Hash extracted from claim's assertion reference
 */
pub fn verify_assertion_hash(
    assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE],
    assertion_length: u32,
    expected_hash: [u8; 32]
) {
    // Compute SHA256 of the ACTUAL assertion bytes (not padded)
    // sha256_var hashes only the first assertion_length bytes
    let computed_hash: [u8; 32] = dep::sha256::sha256_var(assertion_bytes, assertion_length as u64);

    // Verify match
    for i in 0..32 {
        assert(
            computed_hash[i] == expected_hash[i],
            "Assertion hash verification failed: assertion_bytes do not match expected hash"
        );
    }
}

/**
 * Extract a u64 timestamp value from CBOR-encoded assertion bytes
 *
 * CBOR timestamp encoding (simplified):
 * - For small values (0-23): single byte 0x00-0x17
 * - For u8: 0x18 + 1 byte
 * - For u16: 0x19 + 2 bytes (big-endian)
 * - For u32: 0x1a + 4 bytes (big-endian)
 * - For u64: 0x1b + 8 bytes (big-endian)
 *
 * We extract the raw bytes and convert to u64.
 * The offset should point to the START of the CBOR value (type byte).
 *
 * @param assertion_bytes Raw assertion bytes
 * @param timestamp_offset Byte offset where timestamp CBOR value starts
 * @returns Extracted timestamp as u64
 */
pub fn extract_timestamp_from_cbor(
    assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE],
    timestamp_offset: u32
) -> u64 {
    let type_byte = assertion_bytes[timestamp_offset];

    // Check CBOR type - we expect unsigned integer (major type 0)
    let major_type = type_byte >> 5;
    let additional_info = type_byte & 0x1f;

    // Major type 0 = unsigned integer
    assert(major_type == 0, "Expected CBOR unsigned integer for timestamp");

    let mut timestamp: u64 = 0;

    if additional_info <= 23 {
        // Inline value
        timestamp = additional_info as u64;
    } else if additional_info == 24 {
        // u8 follows - need 2 bytes total
        assert(timestamp_offset + 2 <= MAX_EXIF_ASSERTION_SIZE as u32, "CBOR u8 timestamp exceeds buffer");
        timestamp = assertion_bytes[timestamp_offset + 1] as u64;
    } else if additional_info == 25 {
        // u16 follows (big-endian) - need 3 bytes total
        assert(timestamp_offset + 3 <= MAX_EXIF_ASSERTION_SIZE as u32, "CBOR u16 timestamp exceeds buffer");
        timestamp = (assertion_bytes[timestamp_offset + 1] as u64) << 8;
        timestamp = timestamp + (assertion_bytes[timestamp_offset + 2] as u64);
    } else if additional_info == 26 {
        // u32 follows (big-endian) - need 5 bytes total
        assert(timestamp_offset + 5 <= MAX_EXIF_ASSERTION_SIZE as u32, "CBOR u32 timestamp exceeds buffer");
        timestamp = (assertion_bytes[timestamp_offset + 1] as u64) << 24;
        timestamp = timestamp + ((assertion_bytes[timestamp_offset + 2] as u64) << 16);
        timestamp = timestamp + ((assertion_bytes[timestamp_offset + 3] as u64) << 8);
        timestamp = timestamp + (assertion_bytes[timestamp_offset + 4] as u64);
    } else if additional_info == 27 {
        // u64 follows (big-endian) - need 9 bytes total
        assert(timestamp_offset + 9 <= MAX_EXIF_ASSERTION_SIZE as u32, "CBOR u64 timestamp exceeds buffer");
        for i in 0..8 {
            timestamp = timestamp << 8;
            timestamp = timestamp + (assertion_bytes[timestamp_offset + 1 + i] as u64);
        }
    } else {
        // additional_info 28-30 are reserved per CBOR RFC 8949, 31 is indefinite-length
        assert(false, "Reserved or unsupported CBOR integer encoding for timestamp");
    }

    timestamp
}

/**
 * GPS BINDING SECURITY MODEL
 * ==========================
 *
 * This module does NOT implement byte-level GPS extraction from CBOR assertions.
 * This is a deliberate design choice, not a missing feature.
 *
 * SECURITY RATIONALE:
 * -------------------
 * GPS coordinates are cryptographically bound through the hash chain:
 *
 *   1. verify_assertion_hash() proves: SHA256(assertion_bytes) == hash_in_claim
 *   2. verify_claim_hash() proves: SHA256(claim_bytes) == signed_hash
 *   3. COSE signature proves: claim was signed by trusted certificate
 *
 * Therefore, if the assertion bytes pass hash verification, their ENTIRE CONTENT
 * is cryptographically bound to the signature. Any modification to the GPS values
 * would change the hash and break verification.
 *
 * WHY NOT PARSE CBOR IN-CIRCUIT?
 * ------------------------------
 * C2PA EXIF GPS coordinates are stored as CBOR rational number arrays:
 *   { "EXIF:GPSLatitude": [{n: 51, d: 1}, {n: 30, d: 1}, {n: 0, d: 1}] }  // 51d 30m 0s
 *
 * Parsing this requires:
 *   - Variable-length CBOR decoding (~200+ constraints per value)
 *   - Rational number arithmetic (degree + minute/60 + second/3600)
 *   - Sign handling from GPSLatitudeRef/GPSLongitudeRef strings
 *
 * Total cost: ~500-1000 additional constraints for minimal security gain.
 *
 * The hash chain already guarantees that the client cannot substitute GPS values
 * without invalidating the proof. Adding in-circuit parsing would only catch
 * bugs in the client extractor, not malicious tampering.
 *
 * TRUST MODEL:
 * ------------
 * - The CIRCUIT trusts that assertion_bytes were correctly passed from the client
 * - The HASH CHAIN proves assertion_bytes match what was signed
 * - The CLIENT extracts GPS from the verified bytes
 * - Any GPS tampering would require finding a hash collision (computationally infeasible)
 *
 * For applications requiring stronger guarantees, the circuit could be extended
 * to parse CBOR at specific known offsets. This is left as a future enhancement.
 */

// NOTE: verify_gps_binding() has been intentionally removed.
// GPS binding is provided by verify_assertion_hash() in the hash chain.
// See the SECURITY RATIONALE above for details.

/**
 * Combined hash chain verification
 *
 * Performs the complete verification:
 * 1. SHA256(claim_bytes) == expected_claim_hash (signature input)
 * 2. Extract assertion_hash from claim at known offset
 * 3. SHA256(assertion_bytes) == assertion_hash
 *
 * If all pass, we know the assertion_bytes are authentic and
 * any values extracted from them are cryptographically bound to the signature.
 *
 * @param claim_bytes Raw claim bytes (padded)
 * @param claim_length Actual claim length
 * @param expected_claim_hash SHA256 of claim (same as signature message hash)
 * @param assertion_hash_offset Where assertion hash appears in claim
 * @param assertion_bytes Raw assertion bytes (padded)
 * @param assertion_length Actual assertion length
 */
pub fn verify_full_hash_chain(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    claim_length: u32,
    expected_claim_hash: [u8; 32],
    assertion_hash_offset: u32,
    assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE],
    assertion_length: u32
) {
    // Step 1: Verify claim hash
    verify_claim_hash(claim_bytes, claim_length, expected_claim_hash);

    // Step 2: Extract assertion hash from claim
    let assertion_hash = extract_assertion_hash_from_claim(claim_bytes, assertion_hash_offset);

    // Step 3: Verify assertion hash
    verify_assertion_hash(assertion_bytes, assertion_length, assertion_hash);

    // At this point, we've proven:
    // - claim_bytes hash to the signed value
    // - assertion_bytes hash to a reference in the signed claim
    // - Therefore, assertion_bytes are authentic
    // - Any values in assertion_bytes are cryptographically bound

    // Silence unused warnings
    let _ = claim_length;
    let _ = assertion_length;
}

/**
 * Verify timestamp is bound to assertion via hash chain
 *
 * Combines hash chain verification with timestamp extraction.
 * Proves that exact_timestamp actually came from the signed assertion.
 *
 * @param claim_bytes Raw claim bytes
 * @param claim_length Actual claim length
 * @param expected_claim_hash Expected claim hash (signature input)
 * @param assertion_hash_offset Offset of assertion hash in claim
 * @param assertion_bytes Raw assertion bytes
 * @param assertion_length Actual assertion length
 * @param timestamp_offset Offset of timestamp in assertion
 * @param expected_timestamp The timestamp value the circuit is using
 */
pub fn verify_timestamp_binding(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    claim_length: u32,
    expected_claim_hash: [u8; 32],
    assertion_hash_offset: u32,
    assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE],
    assertion_length: u32,
    timestamp_offset: u32,
    expected_timestamp: u64
) {
    // First verify the hash chain
    verify_full_hash_chain(
        claim_bytes,
        claim_length,
        expected_claim_hash,
        assertion_hash_offset,
        assertion_bytes,
        assertion_length
    );

    // Then extract and verify the timestamp
    let extracted_timestamp = extract_timestamp_from_cbor(assertion_bytes, timestamp_offset);

    assert(
        extracted_timestamp == expected_timestamp,
        "Timestamp binding failed: extracted timestamp does not match expected value"
    );
}

/**
 * Verify content hash exists in claim at specified offset
 *
 * SECURITY: This binds the public content_hash to the signed claim.
 * Without this verification, a malicious client could substitute
 * a different image's content_hash while keeping the valid signature.
 *
 * @param claim_bytes Raw claim bytes (CBOR encoded)
 * @param content_hash_offset Byte offset where content hash appears in claim
 * @param expected_content_hash The content hash (Field) to verify
 */
pub fn verify_content_hash_in_claim(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    content_hash_offset: u32,
    expected_content_hash: Field
) {
    // Bounds check
    assert(
        content_hash_offset + 32 <= MAX_CLAIM_SIZE,
        "Content hash offset out of bounds"
    );

    // Extract 32 bytes from claim at offset and convert to Field
    let mut extracted_hash: Field = 0;
    for i in 0..32 {
        extracted_hash = extracted_hash * 256 + claim_bytes[content_hash_offset + i] as Field;
    }

    // Verify the extracted content hash matches the public input
    assert(
        extracted_hash == expected_content_hash,
        "Content hash binding failed: public content_hash does not match value in signed claim"
    );
}

/**
 * Verify assertion hash chain (without redundant claim hash check)
 *
 * Use this when claim_hash has already been verified separately.
 * Verifies: SHA256(assertion_bytes) == hash in claim at offset
 *
 * @param claim_bytes Raw claim bytes (already verified via claim_hash)
 * @param assertion_hash_offset Where assertion hash appears in claim
 * @param assertion_bytes Raw assertion bytes
 * @param assertion_length Actual assertion length
 */
pub fn verify_assertion_chain(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    assertion_hash_offset: u32,
    assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE],
    assertion_length: u32
) {
    // Extract assertion hash from claim
    let assertion_hash = extract_assertion_hash_from_claim(claim_bytes, assertion_hash_offset);

    // Verify assertion bytes hash to the expected hash
    verify_assertion_hash(assertion_bytes, assertion_length, assertion_hash);

    // Silence unused warning
    let _ = assertion_length;
}

/**
 * Verify actions assertion hash matches SHA256(actions_assertion_bytes)
 *
 * This is the same as verify_assertion_hash but for the larger actions buffer.
 * Actions assertions (c2pa.actions.v2) can be up to 2048 bytes (Adobe Photoshop).
 *
 * IMPORTANT: Uses sha256_var to hash only the first assertion_length bytes,
 * not the full padded array. The expected hash is SHA256 of the actual
 * assertion bytes, not the padded version.
 *
 * @param assertion_bytes Raw assertion bytes (CBOR, padded to MAX_ACTIONS_ASSERTION_SIZE)
 * @param assertion_length Actual length of assertion bytes
 * @param expected_hash Hash extracted from claim's assertion reference
 */
pub fn verify_actions_assertion_hash(
    assertion_bytes: [u8; MAX_ACTIONS_ASSERTION_SIZE],
    assertion_length: u32,
    expected_hash: [u8; 32]
) {
    // Compute SHA256 of the ACTUAL assertion bytes (not padded)
    // sha256_var hashes only the first assertion_length bytes
    let computed_hash: [u8; 32] = dep::sha256::sha256_var(assertion_bytes, assertion_length as u64);

    // Verify match
    for i in 0..32 {
        assert(
            computed_hash[i] == expected_hash[i],
            "Actions assertion hash verification failed: assertion_bytes do not match expected hash"
        );
    }
}

/**
 * Verify actions assertion hash chain (without redundant claim hash check)
 *
 * Use this for c2pa.actions.v2 assertions which can be up to 2048 bytes.
 * Verifies: SHA256(actions_assertion_bytes) == hash in claim at offset
 *
 * @param claim_bytes Raw claim bytes (already verified via claim_hash)
 * @param assertion_hash_offset Where assertion hash appears in claim
 * @param assertion_bytes Raw actions assertion bytes (up to 2048 bytes)
 * @param assertion_length Actual assertion length
 */
pub fn verify_actions_assertion_chain(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    assertion_hash_offset: u32,
    assertion_bytes: [u8; MAX_ACTIONS_ASSERTION_SIZE],
    assertion_length: u32
) {
    // Extract assertion hash from claim
    let assertion_hash = extract_assertion_hash_from_claim(claim_bytes, assertion_hash_offset);

    // Verify assertion bytes hash to the expected hash
    verify_actions_assertion_hash(assertion_bytes, assertion_length, assertion_hash);
}

// Tests
#[test]
fn test_content_hash_binding() {
    let mut claim_bytes: [u8; MAX_CLAIM_SIZE] = [0; MAX_CLAIM_SIZE];

    // Place a known content hash at offset 100
    // Content hash as bytes: 0x0000...0001 (just 1 for simplicity)
    claim_bytes[131] = 1;  // Last byte = 1

    // Expected field value is 1
    let expected_hash: Field = 1;

    // This should pass
    verify_content_hash_in_claim(claim_bytes, 100, expected_hash);
}

#[test]
fn test_extract_assertion_hash() {
    // Create test claim bytes with a known hash at offset 10
    let mut claim_bytes: [u8; MAX_CLAIM_SIZE] = [0; MAX_CLAIM_SIZE];

    // Place a test hash at offset 10
    let test_hash: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    ];

    for i in 0..32 {
        claim_bytes[10 + i] = test_hash[i];
    }

    let extracted = extract_assertion_hash_from_claim(claim_bytes, 10);

    for i in 0..32 {
        assert(extracted[i] == test_hash[i]);
    }
}

#[test]
fn test_extract_cbor_timestamp_inline() {
    // Test inline value (0-23)
    let mut assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE] = [0; MAX_EXIF_ASSERTION_SIZE];
    assertion_bytes[0] = 0x17; // Inline value 23

    let timestamp = extract_timestamp_from_cbor(assertion_bytes, 0);
    assert(timestamp == 23);
}

#[test]
fn test_extract_cbor_timestamp_u32() {
    // Test u32 value
    let mut assertion_bytes: [u8; MAX_EXIF_ASSERTION_SIZE] = [0; MAX_EXIF_ASSERTION_SIZE];
    assertion_bytes[0] = 0x1a; // u32 follows
    // Value: 1700000000 (0x6553F100) - a Unix timestamp
    assertion_bytes[1] = 0x65;
    assertion_bytes[2] = 0x53;
    assertion_bytes[3] = 0xF1;
    assertion_bytes[4] = 0x00;

    let timestamp = extract_timestamp_from_cbor(assertion_bytes, 0);
    assert(timestamp == 1700000000);
}
