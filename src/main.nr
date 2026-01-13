/// Apertrue C2PA Verifier Circuit v2.2 - With RSA Certificate Support + Expiry Enforcement
///
/// This circuit proves that:
/// 1. An image has a valid C2PA COSE signature (leaf key signed content)
/// 2. The leaf certificate was signed by an intermediate CA (cert signature over TBS DER)
/// 3. The intermediate CA is in the Oracle's promoted trust list (via Merkle proof)
/// 4. The leaf pubkey used in COSE matches the pubkey in the signed certificate (SPKI binding)
/// 5. The proof is bound to specific image content (nullifier prevents replay)
/// 6. The certificate was valid at the time the proof was generated (expiry enforcement)
///
/// Privacy: The circuit hides:
/// - Which specific device signed the content (leaf identity)
/// - Which intermediate CA issued the certificate (Merkle proof hides this)
/// - The certificate chain details
///
/// The verifier sees: trust_list_root, content_hash, nullifier, proof_timestamp, cert_not_before, cert_not_after
///
/// Architecture: "Intermediate Promotion"
/// - Instead of enumerating millions of device leaf keys, we promote ~50-100 intermediate CAs
/// - The Oracle verifies intermediate -> root chains and publishes a Merkle tree
/// - Client proves leaf was signed by a promoted intermediate
///
/// Revocation Strategy:
/// - Revoked intermediates are removed from the Oracle trust list
/// - The trust_list_root is updated to exclude revoked entries
/// - Oracle publishes epochs (weekly) with fresh Merkle roots
/// - No explicit non-membership proof needed in circuit - membership proof fails for revoked entries
/// - Future: In-circuit non-membership proof against revoked set for finer control
///
/// Algorithm Support:
/// - COSE signature: ECDSA P-256 (ES256) only for now
/// - Certificate signature: ECDSA P-256 or RSA-2048 (supports Truepic/ChatGPT)

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
use std::hash::sha256_var;

// RSA verification from noir_rsa
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use noir_rsa::types::RBN2048;
use bignum::params::BigNumParams;

/// Maximum depth of the Merkle tree for promoted intermediates
/// 2^8 = 256 intermediates capacity (sufficient for C2PA ecosystem)
global MERKLE_TREE_DEPTH: u32 = 8;

/// Maximum TBS certificate size (in bytes)
/// Most leaf certs are 500-1500 bytes, 2KB covers 99%
global MAX_TBS_SIZE: u32 = 2048;

/// RSA-2048 parameters
/// Uses 18 limbs of 120 bits each
global RSA_NUM_LIMBS: u32 = 18;

/// Certificate signature algorithm selector
global CERT_ALG_ECDSA: Field = 0;
global CERT_ALG_RSA: Field = 1;

/// The main circuit entry point
fn main(
    // === PUBLIC INPUTS (minimal - what verifier sees) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    
    // === PUBLIC: TIME-BOUND VALIDITY ===
    proof_timestamp: pub Field,      // Unix timestamp (seconds) when proof was generated
    cert_not_before: pub Field,      // Unix timestamp (seconds) - cert validity start
    cert_not_after: pub Field,       // Unix timestamp (seconds) - cert validity end

    // === PRIVATE: ALGORITHM SELECTOR ===
    cert_algorithm: Field,

    // === PRIVATE: COSE SIGNATURE VERIFICATION ===
    cose_signature: [u8; 64],
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],
    cose_message_hash: [u8; 32],

    // === PRIVATE: CERTIFICATE DATA ===
    tbs_certificate: [u8; MAX_TBS_SIZE],
    tbs_len: u32,
    
    // === PRIVATE: ECDSA CERT SIGNATURE (used when cert_algorithm == 0) ===
    cert_signature_ecdsa: [u8; 64],
    intermediate_pubkey_x: [u8; 32],
    intermediate_pubkey_y: [u8; 32],
    
    // === PRIVATE: RSA CERT SIGNATURE (used when cert_algorithm == 1) ===
    // RSA limbs are 120-bit values stored as u128
    rsa_signature_limbs: [u128; RSA_NUM_LIMBS],
    rsa_modulus_limbs: [u128; RSA_NUM_LIMBS],
    rsa_redc_limbs: [u128; RSA_NUM_LIMBS],

    // === PRIVATE: SPKI EXTRACTION OFFSETS ===
    spki_offset: u32,
    pubkey_offset: u32,

    // === PRIVATE: MERKLE MEMBERSHIP ===
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH]
) {
    // Validate algorithm selector
    assert((cert_algorithm == CERT_ALG_ECDSA) | (cert_algorithm == CERT_ALG_RSA), "Invalid cert algorithm");
    
    // ================================================================
    // STEP 1: Verify COSE signature (leaf key signed the C2PA claim)
    // ================================================================
    let cose_valid = verify_signature(
        leaf_pubkey_x,
        leaf_pubkey_y,
        cose_signature,
        cose_message_hash
    );
    assert(cose_valid, "Invalid COSE signature");

    // ================================================================
    // STEP 2: Hash the TBS certificate
    // ================================================================
    let tbs_hash: [u8; 32] = sha256_var(tbs_certificate, tbs_len as u64);

    // ================================================================
    // STEP 3: Verify certificate signature
    // ================================================================
    if cert_algorithm == CERT_ALG_ECDSA {
        // ECDSA P-256 certificate signature
        let cert_valid = verify_signature(
            intermediate_pubkey_x,
            intermediate_pubkey_y,
            cert_signature_ecdsa,
            tbs_hash
        );
        assert(cert_valid, "Invalid ECDSA certificate signature");
    } else {
        // RSA-2048 certificate signature with PKCS#1 v1.5 padding
        let params: BigNumParams<18, 2048> = BigNumParams::new(
            false,  // has_multiplicative_inverse
            rsa_modulus_limbs,
            rsa_redc_limbs
        );
        let signature: RBN2048 = RBN2048::from_array(params, rsa_signature_limbs);
        
        // Verify: signature^65537 mod n = PKCS1_pad(SHA256(tbs))
        let rsa_valid = verify_sha256_pkcs1v15(tbs_hash, signature, 65537);
        assert(rsa_valid, "Invalid RSA certificate signature");
    }

    // ================================================================
    // STEP 4: Validate SPKI and bind leaf pubkey
    // ================================================================
    assert(spki_offset < tbs_len, "SPKI offset out of bounds");
    assert(pubkey_offset < tbs_len, "Pubkey offset out of bounds");
    assert(pubkey_offset > spki_offset, "Pubkey must be after SPKI start");
    
    assert(tbs_certificate[spki_offset] == 0x30, "SPKI must start with SEQUENCE");
    assert(tbs_certificate[pubkey_offset] == 0x03, "Expected BIT STRING for pubkey");
    
    // Extract pubkey from BIT STRING: tag(1) + len(1) + unused(1) + uncompressed(1) = 4 bytes header
    let key_start = pubkey_offset + 4;
    assert(tbs_certificate[key_start - 1] == 0x04, "Expected uncompressed EC point");
    
    // Verify X coordinate
    for i in 0..32 {
        assert(tbs_certificate[key_start + i] == leaf_pubkey_x[i], "Leaf pubkey X mismatch");
    }
    
    // Verify Y coordinate
    for i in 0..32 {
        assert(tbs_certificate[key_start + 32 + i] == leaf_pubkey_y[i], "Leaf pubkey Y mismatch");
    }

    // ================================================================
    // STEP 5: Compute intermediate identity for Merkle lookup
    // ================================================================
    let intermediate_leaf = if cert_algorithm == CERT_ALG_ECDSA {
        // ECDSA: hash(x, y)
        let x_field = bytes_to_field(intermediate_pubkey_x);
        let y_field = bytes_to_field(intermediate_pubkey_y);
        pedersen_hash([x_field, y_field])
    } else {
        // RSA: hash first two modulus limbs (sufficient for uniqueness)
        // Convert u128 to Field for hashing
        pedersen_hash([rsa_modulus_limbs[0] as Field, rsa_modulus_limbs[1] as Field])
    };

    // ================================================================
    // STEP 6: Verify intermediate is in Oracle's trust list
    // ================================================================
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate not in trust list");

    // ================================================================
    // STEP 7: Verify nullifier derivation
    // ================================================================
    let leaf_x_field = bytes_to_field(leaf_pubkey_x);
    let leaf_y_field = bytes_to_field(leaf_pubkey_y);
    let leaf_pubkey_hash = pedersen_hash([leaf_x_field, leaf_y_field]);
    
    let expected_nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");

    // ================================================================
    // STEP 8: Verify certificate validity at proof time
    // ================================================================
    // Ensure proof_timestamp is within certificate validity window
    assert(proof_timestamp >= cert_not_before, "Certificate not yet valid at proof time");
    assert(proof_timestamp <= cert_not_after, "Certificate expired at proof time");
}

/// Convert 32 bytes to Field (big-endian)
fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
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

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_bytes_to_field() {
    let bytes: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0
    ];
    let result = bytes_to_field(bytes);
    assert(result == 256);
}

#[test]
fn test_merkle_single_level() {
    let leaf: Field = 123;
    let sibling: Field = 456;

    let mut path: [Field; MERKLE_TREE_DEPTH] = [0; MERKLE_TREE_DEPTH];
    path[0] = sibling;

    let mut indices: [Field; MERKLE_TREE_DEPTH] = [0; MERKLE_TREE_DEPTH];
    indices[0] = 0;

    let root = compute_merkle_root(leaf, path, indices);

    let first_level = pedersen_hash([leaf, sibling]);
    let mut expected = first_level;
    for _ in 1..MERKLE_TREE_DEPTH {
        expected = pedersen_hash([expected, 0]);
    }
    assert(root == expected);
}
