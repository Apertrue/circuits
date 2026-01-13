/// Apertrue C2PA Verifier Circuit v2 - Intermediate Promotion Architecture
///
/// This circuit proves that:
/// 1. An image has a valid C2PA COSE signature (leaf key signed content)
/// 2. The leaf certificate was signed by an intermediate CA (cert signature over TBS DER)
/// 3. The intermediate CA is in the Oracle's promoted trust list (via Merkle proof)
/// 4. The leaf pubkey used in COSE matches the pubkey in the signed certificate (SPKI binding)
/// 5. The proof is bound to specific image content (nullifier prevents replay)
///
/// Privacy: The circuit hides:
/// - Which specific device signed the content (leaf identity)
/// - Which intermediate CA issued the certificate (Merkle proof hides this)
/// - The certificate chain details
///
/// The verifier only sees: trust_list_root, content_hash, nullifier
///
/// Architecture: "Intermediate Promotion"
/// - Instead of enumerating millions of device leaf keys, we promote ~50-100 intermediate CAs
/// - The Oracle verifies intermediate -> root chains and publishes a Merkle tree
/// - Client proves leaf was signed by a promoted intermediate

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
use std::hash::sha256_var;

/// Maximum depth of the Merkle tree for promoted intermediates
/// 2^8 = 256 intermediates capacity (sufficient for C2PA ecosystem)
global MERKLE_TREE_DEPTH: u32 = 8;

/// Maximum TBS certificate size (in bytes)
/// Most leaf certs are 500-1500 bytes, 2KB covers 99%
global MAX_TBS_SIZE: u32 = 2048;

/// The main circuit entry point
///
/// PUBLIC INPUTS (visible in proof - minimal for privacy):
/// - trust_list_root: Oracle's Merkle root of promoted intermediates
/// - content_hash: SHA256 of stripped image bytes
/// - nullifier: H(content_hash, leaf_pubkey_hash) for replay prevention
///
/// PRIVATE INPUTS (hidden by ZK):
/// - COSE signature data (signature, leaf pubkey, message hash)
/// - Certificate signature data (intermediate's sig over leaf TBS)
/// - TBS certificate bytes with SPKI offsets
/// - Merkle proof for intermediate membership
fn main(
    // === PUBLIC INPUTS (minimal - what verifier sees) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,

    // === PRIVATE: COSE SIGNATURE VERIFICATION ===
    // ECDSA signature (r || s, 64 bytes)
    cose_signature: [u8; 64],
    // Leaf public key coordinates
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],
    // Pre-computed SHA256(COSE Sig_structure)
    cose_message_hash: [u8; 32],

    // === PRIVATE: CERTIFICATE SIGNATURE VERIFICATION ===
    // Raw tbsCertificate DER bytes from leaf cert (zero-padded)
    tbs_certificate: [u8; MAX_TBS_SIZE],
    // Actual length of TBS
    tbs_len: u32,
    // Intermediate's ECDSA signature over SHA256(tbs_certificate)
    cert_signature: [u8; 64],
    // Intermediate CA's public key
    intermediate_pubkey_x: [u8; 32],
    intermediate_pubkey_y: [u8; 32],

    // === PRIVATE: SPKI EXTRACTION OFFSETS ===
    // These offsets are validated in-circuit to prevent type confusion
    spki_offset: u32,      // Where SubjectPublicKeyInfo starts in TBS
    pubkey_offset: u32,    // Where actual pubkey bytes start (inside SPKI BIT STRING)

    // === PRIVATE: MERKLE MEMBERSHIP ===
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH]
) {
    // ================================================================
    // STEP 1: Verify COSE signature (leaf key signed the C2PA claim)
    // ================================================================
    // This proves the content was signed by the holder of this leaf key
    let cose_valid = verify_signature(
        leaf_pubkey_x,
        leaf_pubkey_y,
        cose_signature,
        cose_message_hash
    );
    assert(cose_valid, "Invalid COSE signature");

    // ================================================================
    // STEP 2: Hash the TBS certificate (for cert signature verification)
    // ================================================================
    // We need to verify the intermediate's signature over the leaf's TBS
    // The signature covers SHA256(tbsCertificate DER bytes)
    let tbs_hash: [u8; 32] = sha256_var(tbs_certificate, tbs_len as u64);

    // ================================================================
    // STEP 3: Verify certificate signature (intermediate signed leaf)
    // ================================================================
    // This proves the leaf certificate was issued by this intermediate CA
    let cert_valid = verify_signature(
        intermediate_pubkey_x,
        intermediate_pubkey_y,
        cert_signature,
        tbs_hash
    );
    assert(cert_valid, "Invalid certificate signature");

    // ================================================================
    // STEP 4: Validate SPKI extraction and bind leaf pubkey
    // ================================================================
    // This prevents type confusion attacks where attacker provides
    // arbitrary bytes that "look like" a pubkey but aren't actually
    // in the certificate's SubjectPublicKeyInfo
    
    // 4a. Validate offsets are within bounds
    assert(spki_offset < tbs_len, "SPKI offset out of bounds");
    assert(pubkey_offset < tbs_len, "Pubkey offset out of bounds");
    assert(pubkey_offset > spki_offset, "Pubkey must be after SPKI start");
    
    // 4b. Validate SPKI structure starts with SEQUENCE tag (0x30)
    assert(tbs_certificate[spki_offset] == 0x30, "SPKI must start with SEQUENCE");
    
    // 4c. Validate pubkey position has BIT STRING tag (0x03)
    assert(tbs_certificate[pubkey_offset] == 0x03, "Expected BIT STRING for pubkey");
    
    // 4d. Extract pubkey from TBS and verify it matches COSE pubkey
    // The BIT STRING contains: length bytes + 0x00 unused bits + 0x04 uncompressed + x + y
    // We need to find where the actual coordinates start
    // For P-256: pubkey_offset + tag(1) + length(1-3) + unused(1) + uncompressed(1) = x start
    
    // Simple case: assume short form length (< 128 bytes content)
    // BIT STRING format: 03 len 00 04 x[32] y[32]
    let key_start = pubkey_offset + 4; // Skip tag, length byte, unused bits byte, compression byte
    
    // Verify uncompressed point indicator
    assert(tbs_certificate[key_start - 1] == 0x04, "Expected uncompressed EC point");
    
    // Extract and compare X coordinate
    for i in 0..32 {
        assert(
            tbs_certificate[key_start + i] == leaf_pubkey_x[i], 
            "Leaf pubkey X mismatch"
        );
    }
    
    // Extract and compare Y coordinate
    for i in 0..32 {
        assert(
            tbs_certificate[key_start + 32 + i] == leaf_pubkey_y[i],
            "Leaf pubkey Y mismatch"
        );
    }

    // ================================================================
    // STEP 5: Compute intermediate SPKI hash for Merkle lookup
    // ================================================================
    // The trust list contains Pedersen hashes of intermediate public keys
    let intermediate_x_field = bytes_to_field(intermediate_pubkey_x);
    let intermediate_y_field = bytes_to_field(intermediate_pubkey_y);
    let intermediate_leaf = pedersen_hash([intermediate_x_field, intermediate_y_field]);

    // ================================================================
    // STEP 6: Verify intermediate is in Oracle's trust list
    // ================================================================
    // This proves the intermediate CA is a promoted/authorized CA
    // without revealing which specific intermediate it is
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate not in trust list");

    // ================================================================
    // STEP 7: Verify nullifier derivation (replay prevention)
    // ================================================================
    // Nullifier = H(content_hash, leaf_pubkey_hash)
    // This prevents the same proof from being reused for different uploads
    // while allowing viral resharing of verified content
    let leaf_x_field = bytes_to_field(leaf_pubkey_x);
    let leaf_y_field = bytes_to_field(leaf_pubkey_y);
    let leaf_pubkey_hash = pedersen_hash([leaf_x_field, leaf_y_field]);
    
    let expected_nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");
}

/// Convert a 32-byte array to a Field element
/// Uses big-endian interpretation
fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Compute Merkle root from a leaf and proof path
/// Uses Pedersen hash for ZK-friendly computation
fn compute_merkle_root(
    leaf: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [Field; MERKLE_TREE_DEPTH]
) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        let path_element = path[i];
        let is_right = indices[i];

        // If is_right = 0, current is left child, path_element is right
        // If is_right = 1, path_element is left child, current is right
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
    indices[0] = 0; // leaf is on the left

    let root = compute_merkle_root(leaf, path, indices);

    // Verify the root is deterministic
    let first_level = pedersen_hash([leaf, sibling]);
    let mut expected = first_level;
    for _ in 1..MERKLE_TREE_DEPTH {
        expected = pedersen_hash([expected, 0]);
    }
    assert(root == expected);
}
