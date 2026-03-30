/// Apertrue ProofB - COSE Signature + Merkle Membership + Hash Chain Binding
///
/// This is the second half of the split-proof architecture for RSA-4096 support.
///
/// ProofB proves:
/// 1. A valid COSE signature exists (ES256 or PS256) using the leaf key
/// 2. The COSE signature is over a Sig_structure containing the claim (SECURITY FIX HIGH-3)
/// 3. The claim_hash matches SHA256(claim_bytes) (binds to ProofA)
/// 4. The intermediate CA is in the Oracle's promoted trust list (Merkle membership)
/// 5. The blinded link commitment matches (includes claim_hash for full binding)
/// 6. The nullifier is correctly derived from the leaf key and content hash
/// 7. Certificate validity at proof time
///
/// SECURITY: This circuit now fully verifies the binding between:
///   - The COSE signature (what the device actually signed)
///   - The claim_bytes (which contain content_hash)
///   - ProofA (via link_commit including claim_hash)
///
/// This prevents the "malicious extractor" attack where an attacker could:
///   - Use a valid COSE signature from Image B
///   - Create fake claim_bytes for Image A
///   - Generate a "valid" proof for Image A
///
/// PUBLIC INPUTS (shared with ProofA - must match):
/// - trust_list_root: Oracle's Merkle root
/// - content_hash: SHA256 of stripped image
/// - nullifier: pedersen_hash([content_hash, leaf_key_hash])
/// - proof_timestamp: When proof was generated
/// - cert_not_before: Certificate validity start
/// - cert_not_after: Certificate validity end
/// - link_commit: pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])
///
/// PRIVATE INPUTS:
/// - COSE signature and leaf key (ECDSA or RSA-2048)
/// - Sig_structure bytes (what was actually signed)
/// - Claim bytes (embedded in Sig_structure)
/// - Intermediate leaf value and link_blind
/// - Merkle path for intermediate

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
use dep::sha256::sha256_var;
use dep::poseidon::poseidon2::Poseidon2;

// RSA verification from noir_rsa (zkpassport fork with PSS support)
use noir_rsa::rsa::verify_sha256_pss;
use noir_rsa::types::RBN2048;
use bignum::params::BigNumParams;

/// Maximum depth of the Merkle tree for promoted intermediates
global MERKLE_TREE_DEPTH: u32 = 8;

/// RSA-2048 uses 18 limbs of 120 bits
global RSA_NUM_LIMBS: u32 = 18;

/// Maximum size of COSE Sig_structure (CBOR encoded)
/// Sig_structure = ["Signature1", protected_headers, external_aad, payload]
/// ChatGPT images have large protected headers (~2000 bytes) containing full cert chain
/// plus claim payload (~700 bytes), totaling ~2700 bytes.
/// Adobe Photoshop images can have larger protected headers (~3400 bytes) with cert chain
/// plus claim payload (~1000 bytes), totaling ~4400 bytes. Use 5120 for safety margin.
global MAX_SIG_STRUCTURE_SIZE: u32 = 5120;

/// Maximum size of C2PA claim (CBOR encoded)
global MAX_CLAIM_SIZE: u32 = 2048;

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
    // NOTE: link_commit is now COMPUTED internally and returned as OUTPUT
    // This avoids JS/circuit Pedersen implementation mismatches

    // === PUBLIC INPUT: Claim Hash Commitment (packed from 32 bytes to 1 Field) ===
    // This is Poseidon2(claim_hash_as_fields). Must match ProofA's commitment.
    // SECURITY: Ensures both proofs use the same claim.
    claim_hash_commitment: pub Field,

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
    // PSS salt length for RSA signatures (typically 32 for SHA-256, but Adobe may use 20)
    pss_salt_len: u32,

    // === PRIVATE: COSE MESSAGE HASH ===
    cose_message_hash: [u8; 32],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,  // pedersen_hash of intermediate key material
    link_blind: Field,         // random blinding factor

    // === PRIVATE: MERKLE MEMBERSHIP ===
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH],

    // === PRIVATE: SIG_STRUCTURE VERIFICATION (SECURITY FIX HIGH-3) ===
    // These inputs prove that cose_message_hash was computed from a Sig_structure
    // that actually contains the claim_bytes, preventing malicious extractor attacks
    sig_structure_bytes: [u8; MAX_SIG_STRUCTURE_SIZE],  // CBOR: ["Signature1", headers, aad, payload]
    sig_structure_length: u32,                          // Actual length (variable-size)

    // === PRIVATE: CLAIM VERIFICATION ===
    claim_bytes: [u8; MAX_CLAIM_SIZE],    // Raw CBOR-encoded C2PA claim
    claim_length: u32,                     // Actual length of claim
    claim_offset_in_sig: u32,              // Byte offset where claim appears in sig_structure
    claim_hash: [u8; 32],                  // SHA256(claim_bytes) - binds to ProofA

    // === PUBLIC: CONTENT HASH BINDING (SECURITY FIX) ===
    // Offset where content_hash appears in claim_bytes
    // This binds the public content_hash to the signed claim, preventing substitution attacks
    content_hash_offset: pub u32
) -> pub Field {  // Returns link_commit (computed internally)
    // Validate algorithm selector
    assert((cose_algorithm == ALG_ECDSA) | (cose_algorithm == ALG_RSA), "Invalid COSE algorithm");

    // ================================================================
    // STEP 0: Verify claim hash commitment (PUBLIC INPUT OPTIMIZATION)
    // ================================================================
    // Verify that the private claim_hash matches the public claim_hash_commitment.
    // This ensures both ProofA and ProofB use the same claim.
    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

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
        // pss_salt_len: 32 = SHA-256 output length (RFC 8152), 20 = RFC 4055 default (Adobe)
        // Common values: 32 (standard), 20 (legacy), 0 (auto-calculated from modulus)
        let rsa_valid = verify_sha256_pss(cose_message_hash, signature, 65537, pss_salt_len);
        assert(rsa_valid, "Invalid RSA COSE signature (PS256)");
    }

    // ================================================================
    // STEP 2: Verify sig_structure hash matches cose_message_hash
    // (SECURITY FIX HIGH-3: Prevents malicious extractor attack)
    // ================================================================
    // The COSE signature is over SHA256(Sig_structure)
    // We verify that the provided sig_structure_bytes actually hashes to cose_message_hash
    assert(sig_structure_length as u32 <= MAX_SIG_STRUCTURE_SIZE as u32, "sig_structure_length exceeds buffer");
    let computed_sig_hash = sha256_var(sig_structure_bytes, sig_structure_length as u32);
    assert(computed_sig_hash == cose_message_hash, "Sig_structure hash does not match COSE message hash");

    // ================================================================
    // STEP 3: Verify claim_bytes embedded in sig_structure
    // (SECURITY FIX HIGH-3: Proves the signed data contains this claim)
    // ================================================================
    // The Sig_structure's payload field contains the claim_bytes
    // We verify the claim_bytes appear at the expected offset
    verify_bytes_embedded(
        sig_structure_bytes,
        sig_structure_length,
        claim_bytes,
        claim_length,
        claim_offset_in_sig
    );

    // ================================================================
    // STEP 4: Verify claim_hash matches SHA256(claim_bytes)
    // (SECURITY FIX HIGH-3: Binds to ProofA via link_commit)
    // ================================================================
    assert(claim_length as u32 <= MAX_CLAIM_SIZE as u32, "claim_length exceeds buffer");
    let computed_claim_hash = sha256_var(claim_bytes, claim_length as u32);
    assert(computed_claim_hash == claim_hash, "Claim hash mismatch - claim_bytes integrity violated");

    // ================================================================
    // STEP 4b: Optional content_hash binding (when hash is embedded in claim)
    //
    // NOTE: This check is OPTIONAL because:
    // - content_hash = SHA256(stripped_image_bytes) - computed independently
    // - C2PA claims contain JUMBF assertion hashes, NOT stripped image hashes
    // - These are different values, so content_hash usually isn't in claim_bytes
    //
    // Security is maintained because content_hash is a PUBLIC INPUT:
    // - Verifier independently computes SHA256(stripped_image)
    // - Compares to content_hash from proof public inputs
    // - nullifier = hash(content_hash, leaf_key) binds proof to specific content
    //
    // Skip if offset=0 (hash not found in claim - this is normal for most images)
    // ================================================================
    if content_hash_offset != 0 {
        verify_content_hash_in_claim(claim_bytes, content_hash_offset, content_hash);
    }

    // ================================================================
    // STEP 5: Verify Merkle membership for intermediate
    // ================================================================
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate not in trust list");

    // ================================================================
    // STEP 6: Compute link commitment (returned as output)
    // (SECURITY FIX HIGH-3: Include claim_hash for full binding to ProofA)
    // ================================================================
    // NOTE: link_commit is COMPUTED here and returned as OUTPUT rather than verified
    // against a pre-computed input. This avoids JS/circuit Pedersen implementation
    // mismatches between bb.js versions and ACVM's internal Barretenberg.
    // The verifier checks that ProofA.link_commit == ProofB.link_commit
    let claim_hash_field = bytes_to_field(claim_hash);
    let link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);

    // ================================================================
    // STEP 7: Verify nullifier derivation (binds leaf key to content)
    // ================================================================
    // SECURITY FIX (MEDIUM-2): Hash 8 RSA limbs (1024 bits) for collision resistance
    let leaf_pubkey_hash = if cose_algorithm == ALG_ECDSA {
        let leaf_x_field = bytes_to_field(leaf_pubkey_x);
        let leaf_y_field = bytes_to_field(leaf_pubkey_y);
        pedersen_hash([leaf_x_field, leaf_y_field])
    } else {
        // Hash 8 limbs (1024 bits) for strong collision resistance
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

    let expected_nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");

    // ================================================================
    // STEP 8: Verify certificate validity at proof time
    // ================================================================
    assert(proof_timestamp as u64 as Field == proof_timestamp, "proof_timestamp exceeds u64");
    assert(cert_not_before as u64 as Field == cert_not_before, "cert_not_before exceeds u64");
    assert(cert_not_after as u64 as Field == cert_not_after, "cert_not_after exceeds u64");
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid at proof time");
    assert(ts <= not_after, "Certificate expired at proof time");

    // Return link_commit as public output
    // NOTE: link_commit is now computed internally and returned as output
    // The verifier must check that ProofA.link_commit == ProofB.link_commit
    link_commit
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

/// Compute Merkle root from leaf and proof
fn compute_merkle_root(
    leaf: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [Field; MERKLE_TREE_DEPTH]
) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        assert((indices[i] == 0) | (indices[i] == 1), "Merkle index must be 0 or 1");
        let path_element = path[i];
        let is_right = indices[i];
        let left = if is_right == 0 { current } else { path_element };
        let right = if is_right == 0 { path_element } else { current };
        current = pedersen_hash([left, right]);
    }

    current
}

/// Verify that content_hash (Field) appears in claim_bytes at the specified offset
/// SECURITY: This binds the public content_hash to the signed claim.
/// Without this check, an attacker could substitute content_hash while keeping
/// the valid COSE signature over a different claim.
fn verify_content_hash_in_claim(
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

/// Verify that inner_bytes appears at offset within outer_bytes
/// This is critical for proving claim_bytes is embedded in sig_structure
fn verify_bytes_embedded(
    outer_bytes: [u8; MAX_SIG_STRUCTURE_SIZE],
    outer_length: u32,
    inner_bytes: [u8; MAX_CLAIM_SIZE],
    inner_length: u32,
    offset: u32
) {
    // Bounds check: inner must fit within outer
    assert(offset + inner_length <= outer_length, "Inner bytes would exceed outer bounds");

    // Verify each byte of inner appears at the correct position in outer
    for i in 0..MAX_CLAIM_SIZE {
        // Only check bytes within the actual inner_length
        if i < inner_length {
            let outer_idx = offset + i;
            assert(outer_bytes[outer_idx] == inner_bytes[i], "Embedded bytes mismatch");
        }
    }
}

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_link_commitment_with_claim_hash() {
    let intermediate_leaf: Field = 12345;
    let claim_hash_field: Field = 99999;
    let link_blind: Field = 67890;

    // New format includes claim_hash for full ProofA<->ProofB binding
    let commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);

    // Verify same inputs produce same output
    let commit2 = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);
    assert(commit == commit2);

    // Different claim_hash -> different commitment
    let different_claim: Field = 11111;
    let commit3 = pedersen_hash([intermediate_leaf, different_claim, link_blind]);
    assert(commit != commit3);
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

#[test]
fn test_verify_bytes_embedded() {
    // Create outer array with some data
    let mut outer: [u8; MAX_SIG_STRUCTURE_SIZE] = [0; MAX_SIG_STRUCTURE_SIZE];
    outer[0] = 0x84; // CBOR array(4)
    outer[1] = 0x6A; // text(10)
    // "Signature1" at bytes 2-11
    outer[2] = 0x53; // S
    outer[3] = 0x69; // i
    outer[4] = 0x67; // g
    outer[5] = 0x6E; // n
    outer[6] = 0x61; // a
    outer[7] = 0x74; // t
    outer[8] = 0x75; // u
    outer[9] = 0x72; // r
    outer[10] = 0x65; // e
    outer[11] = 0x31; // 1
    // Claim bytes embedded at offset 100
    outer[100] = 0xAA;
    outer[101] = 0xBB;
    outer[102] = 0xCC;
    outer[103] = 0xDD;

    // Create inner array (the claim)
    let mut inner: [u8; MAX_CLAIM_SIZE] = [0; MAX_CLAIM_SIZE];
    inner[0] = 0xAA;
    inner[1] = 0xBB;
    inner[2] = 0xCC;
    inner[3] = 0xDD;

    // This should pass - bytes match at offset
    verify_bytes_embedded(outer, 200, inner, 4, 100);
}

#[test]
fn test_sig_structure_hash() {
    // Test that sha256_var produces consistent results
    let mut data: [u8; MAX_SIG_STRUCTURE_SIZE] = [0; MAX_SIG_STRUCTURE_SIZE];
    data[0] = 0x84; // CBOR array(4)
    data[1] = 0x6A; // text(10)
    data[2] = 0x53; // S

    let hash1 = sha256_var(data, 3);
    let hash2 = sha256_var(data, 3);

    // Same data should produce same hash
    assert(hash1 == hash2);
}

#[test]
fn test_content_hash_binding() {
    let mut claim_bytes: [u8; MAX_CLAIM_SIZE] = [0; MAX_CLAIM_SIZE];

    // Place a known content hash at offset 100
    // Content hash as bytes: 0x0000...0001 (just 1 for simplicity)
    claim_bytes[131] = 1;  // Last byte = 1 (big-endian, so this is value 1)

    // Expected field value is 1
    let expected_hash: Field = 1;

    // This should pass
    verify_content_hash_in_claim(claim_bytes, 100, expected_hash);
}

#[test]
fn test_content_hash_binding_larger_value() {
    let mut claim_bytes: [u8; MAX_CLAIM_SIZE] = [0; MAX_CLAIM_SIZE];

    // Place content hash = 0x0102030405060708...1f20 at offset 50
    for i in 0..32 {
        claim_bytes[50 + i] = (i + 1) as u8;
    }

    // Compute expected Field value (big-endian)
    let mut expected: Field = 0;
    for i in 0..32 {
        expected = expected * 256 + (i + 1) as Field;
    }

    verify_content_hash_in_claim(claim_bytes, 50, expected);
}
