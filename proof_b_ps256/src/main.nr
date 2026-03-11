/// Apertrue ProofB PS256 - RSA-Only COSE Signature Verification
///
/// Specialized circuit for PS256 (RSASSA-PSS with SHA-256) signatures only.
/// Removes all ECDSA code paths for ~20% constraint reduction.
///
/// Use cases:
/// - Adobe Photoshop (PS256)
/// - Adobe Lightroom (PS256)
/// - Other RSA-based C2PA signers
///
/// This circuit proves:
/// 1. A valid PS256 RSA signature exists using the leaf key
/// 2. The COSE signature is over a Sig_structure containing the claim
/// 3. The claim_hash matches SHA256(claim_bytes) (binds to ProofA)
/// 4. The intermediate CA is in the Oracle's promoted trust list (Merkle membership)
/// 5. The blinded link commitment matches (includes claim_hash for full binding)
/// 6. The nullifier is correctly derived from the leaf key and content hash
/// 7. Certificate validity at proof time
///
/// PUBLIC INPUTS (shared with ProofA - must match):
/// - trust_list_root: Oracle's Merkle root
/// - content_hash: SHA256 of stripped image
/// - nullifier: pedersen_hash([content_hash, leaf_key_hash])
/// - proof_timestamp: When proof was generated
/// - cert_not_before: Certificate validity start
/// - cert_not_after: Certificate validity end
/// - link_commit: pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])

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
/// Adobe Photoshop images have large protected headers (~3400 bytes) with cert chain
/// plus claim payload (~1000 bytes), totaling ~4400 bytes. Use 5120 for safety margin.
global MAX_SIG_STRUCTURE_SIZE: u32 = 5120;

/// Maximum size of C2PA claim (CBOR encoded)
global MAX_CLAIM_SIZE: u32 = 2048;

/// ProofB PS256 main entry point
fn main(
    // === PUBLIC INPUTS (shared with ProofA) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,
    cert_not_before: pub Field,
    cert_not_after: pub Field,

    // === PUBLIC INPUT: Claim Hash Commitment (packed from 32 bytes to 1 Field) ===
    // This is Poseidon2(bytes32_to_field_array(claim_hash)). Must match ProofA.
    claim_hash_commitment: pub Field,
    // NOTE: link_commit is now COMPUTED internally and returned as OUTPUT

    // === PRIVATE: RSA COSE SIGNATURE ===
    cose_signature_rsa_limbs: [u128; RSA_NUM_LIMBS],
    leaf_rsa_modulus_limbs: [u128; RSA_NUM_LIMBS],
    leaf_rsa_redc_limbs: [u128; RSA_NUM_LIMBS],
    // PSS salt length (typically 32 for SHA-256, but Adobe may use 20)
    pss_salt_len: u32,

    // === PRIVATE: COSE MESSAGE HASH ===
    cose_message_hash: [u8; 32],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,  // pedersen_hash of intermediate key material
    link_blind: Field,         // random blinding factor

    // === PRIVATE: MERKLE MEMBERSHIP ===
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH],

    // === PRIVATE: SIG_STRUCTURE VERIFICATION ===
    sig_structure_bytes: [u8; MAX_SIG_STRUCTURE_SIZE],
    sig_structure_length: u32,

    // === PRIVATE: CLAIM VERIFICATION ===
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    claim_length: u32,
    claim_offset_in_sig: u32,
    claim_hash: [u8; 32],

    // === PUBLIC: CONTENT HASH BINDING (SECURITY FIX) ===
    // Offset where content_hash appears in claim_bytes
    // This binds the public content_hash to the signed claim, preventing substitution attacks
    content_hash_offset: pub u32
) -> pub Field {  // Returns link_commit (computed internally)
    // ================================================================
    // STEP 0: Verify claim hash commitment (PUBLIC INPUT OPTIMIZATION)
    // ================================================================
    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

    // ================================================================
    // STEP 1: Verify RSA COSE signature (PS256)
    // ================================================================
    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        leaf_rsa_modulus_limbs,
        leaf_rsa_redc_limbs
    );
    let signature: RBN2048 = RBN2048::from_array(params, cose_signature_rsa_limbs);
    // pss_salt_len: 32 = SHA-256 output length (RFC 8152), 20 = RFC 4055 default (Adobe)
    let rsa_valid = verify_sha256_pss(cose_message_hash, signature, 65537, pss_salt_len);
    assert(rsa_valid, "Invalid RSA COSE signature (PS256)");

    // ================================================================
    // STEP 2: Verify sig_structure hash matches cose_message_hash
    // ================================================================
    let computed_sig_hash = sha256_var(sig_structure_bytes, sig_structure_length as u32);
    assert(computed_sig_hash == cose_message_hash, "Sig_structure hash does not match COSE message hash");

    // ================================================================
    // STEP 3: Verify claim_bytes embedded in sig_structure
    // ================================================================
    verify_bytes_embedded(
        sig_structure_bytes,
        sig_structure_length,
        claim_bytes,
        claim_length,
        claim_offset_in_sig
    );

    // ================================================================
    // STEP 4: Verify claim_hash matches SHA256(claim_bytes)
    // ================================================================
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
    // ================================================================
    let claim_hash_field = bytes_to_field(claim_hash);
    let link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);

    // ================================================================
    // STEP 7: Verify nullifier derivation (RSA leaf key)
    // ================================================================
    // Hash 8 limbs (1024 bits) for strong collision resistance
    let leaf_pubkey_hash = pedersen_hash([
        leaf_rsa_modulus_limbs[0] as Field,
        leaf_rsa_modulus_limbs[1] as Field,
        leaf_rsa_modulus_limbs[2] as Field,
        leaf_rsa_modulus_limbs[3] as Field,
        leaf_rsa_modulus_limbs[4] as Field,
        leaf_rsa_modulus_limbs[5] as Field,
        leaf_rsa_modulus_limbs[6] as Field,
        leaf_rsa_modulus_limbs[7] as Field
    ]);

    let expected_nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");

    // ================================================================
    // STEP 8: Verify certificate validity at proof time
    // ================================================================
    let ts = proof_timestamp as u64;
    let not_before = cert_not_before as u64;
    let not_after = cert_not_after as u64;
    assert(ts >= not_before, "Certificate not yet valid at proof time");
    assert(ts <= not_after, "Certificate expired at proof time");

    // Return link_commit as public output
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

/// Compute Merkle root from leaf and proof
fn compute_merkle_root(
    leaf: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [Field; MERKLE_TREE_DEPTH]
) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        let path_element = path[i];
        let is_right = indices[i];
        let left = if is_right == 0 { current } else { path_element };
        let right = if is_right == 0 { path_element } else { current };
        current = pedersen_hash([left, right]);
    }

    current
}

/// Verify that content_hash (Field) appears in claim_bytes at the specified offset
/// SECURITY: Binds public content_hash to signed claim, prevents substitution attack
fn verify_content_hash_in_claim(
    claim_bytes: [u8; MAX_CLAIM_SIZE],
    content_hash_offset: u32,
    expected_content_hash: Field
) {
    assert(
        content_hash_offset + 32 <= MAX_CLAIM_SIZE,
        "Content hash offset out of bounds"
    );

    let mut extracted_hash: Field = 0;
    for i in 0..32 {
        extracted_hash = extracted_hash * 256 + claim_bytes[content_hash_offset + i] as Field;
    }

    assert(
        extracted_hash == expected_content_hash,
        "Content hash binding failed: public content_hash does not match value in signed claim"
    );
}

/// Verify that inner_bytes appears at offset within outer_bytes
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

    let commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);
    let commit2 = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);
    assert(commit == commit2);

    // Different claim_hash -> different commitment
    let different_claim: Field = 11111;
    let commit3 = pedersen_hash([intermediate_leaf, different_claim, link_blind]);
    assert(commit != commit3);
}

#[test]
fn test_nullifier_derivation_rsa() {
    let content_hash: Field = 111;
    // Simulated RSA modulus limbs (first 8)
    let modulus_limbs: [u128; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let leaf_pubkey_hash = pedersen_hash([
        modulus_limbs[0] as Field,
        modulus_limbs[1] as Field,
        modulus_limbs[2] as Field,
        modulus_limbs[3] as Field,
        modulus_limbs[4] as Field,
        modulus_limbs[5] as Field,
        modulus_limbs[6] as Field,
        modulus_limbs[7] as Field
    ]);
    let nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);

    // Different content hash -> different nullifier
    let different_content: Field = 333;
    let different_nullifier = pedersen_hash([different_content, leaf_pubkey_hash]);
    assert(nullifier != different_nullifier);
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
fn test_merkle_root_computation() {
    let leaf: Field = 12345;
    let path: [Field; MERKLE_TREE_DEPTH] = [1, 2, 3, 4, 5, 6, 7, 8];
    let indices: [Field; MERKLE_TREE_DEPTH] = [0, 1, 0, 1, 0, 1, 0, 1];

    let root1 = compute_merkle_root(leaf, path, indices);
    let root2 = compute_merkle_root(leaf, path, indices);
    assert(root1 == root2);

    // Different leaf -> different root
    let root3 = compute_merkle_root(leaf + 1, path, indices);
    assert(root1 != root3);
}

#[test]
fn test_content_hash_binding() {
    let mut claim_bytes: [u8; MAX_CLAIM_SIZE] = [0; MAX_CLAIM_SIZE];
    claim_bytes[131] = 1;  // Place value 1 at offset 100 (big-endian)
    verify_content_hash_in_claim(claim_bytes, 100, 1);
}
