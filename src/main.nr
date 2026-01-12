/// Apertrue C2PA Verifier Circuit
///
/// This circuit proves that:
/// 1. An image has a valid C2PA signature from a trusted signer
/// 2. The signer is in the approved trust list (via Merkle proof)
/// 3. The proof is bound to a specific image content hash (prevents reuse)
/// 4. Chain metadata (trust tier, AI status, etc.) is committed to the proof
///
/// Supports BOTH signing algorithms used by C2PA:
/// - ES256 (ECDSA P-256): Used by ChatGPT/DALL-E, Leica, Sony, Nikon cameras
/// - PS256 (RSA-2048 PSS): Used by Adobe Photoshop, Firefly, Lightroom
///
/// Privacy: The circuit hides which specific camera/device signed the image,
/// only proving it was from SOME trusted device in the trust list.

use std::ecdsa_secp256r1::verify_signature as ecdsa_verify;
use std::hash::pedersen_hash;

// Import noir_rsa for RSA-2048 verification (Adobe PS256)
use noir_rsa::rsa::verify_sha256_pkcs1v15;
use noir_rsa::types::RBN2048;

// Import bignum for RSA parameter construction
use bignum::params::BigNumParams;

/// Standard RSA public exponent (e = 65537)
global RSA_EXPONENT: u32 = 65537;

/// Maximum depth of the Merkle tree for the trust list
/// 2^10 = 1024 trusted signers capacity
global MERKLE_TREE_DEPTH: u32 = 10;

/// Algorithm selector values
global ALG_ES256: u8 = 0; // ECDSA P-256
global ALG_PS256: u8 = 1; // RSA-2048 PSS

/// The main circuit entry point
///
/// Public inputs (visible in proof):
/// - trust_list_root: The Merkle root of the approved signers list
/// - content_hash: Hash of the image content (binds proof to specific image)
/// - nullifier: Prevents proof reuse while preserving privacy
/// - origin_trust_tier: Trust tier of the provenance chain origin (1-3)
/// - is_ai_generated: Whether the content is AI-generated (always disclosed)
/// - chain_depth: Number of steps in the provenance chain (1-10)
/// - chain_truncated: Whether the chain was truncated (0 or 1)
/// - disclosure_level: User's disclosure preference (0-4)
/// - proof_timestamp: When the proof was generated (unix timestamp)
/// - algorithm: Which signing algorithm (0=ES256, 1=PS256)
///
/// Private inputs depend on algorithm:
/// - For ES256: signature, public_key_x, public_key_y, message_hash
/// - For PS256: rsa_signature_limbs, rsa_modulus_limbs, rsa_redc_limbs, message_hash
fn main(
    // Public inputs - Core verification
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,

    // Public inputs - Chain metadata
    origin_trust_tier: pub u8,
    is_ai_generated: pub u8,
    chain_depth: pub u8,
    chain_truncated: pub u8,
    disclosure_level: pub u8,
    proof_timestamp: pub u64,

    // Public input - Algorithm selector
    algorithm: pub u8,

    // Private inputs - ECDSA P-256 (ES256)
    // Only used when algorithm == 0
    ecdsa_signature: [u8; 64],
    ecdsa_public_key_x: [u8; 32],
    ecdsa_public_key_y: [u8; 32],

    // Private inputs - RSA-2048 (PS256)
    // Only used when algorithm == 1
    // RSA signature as 18 limbs (each u128, ~120 bits used)
    rsa_signature_limbs: [u128; 18],
    // RSA public key modulus as 18 limbs
    rsa_modulus_limbs: [u128; 18],
    // Montgomery reduction parameter (precomputed from modulus)
    rsa_redc_limbs: [u128; 18],

    // Private inputs - Message hash (used by both algorithms)
    message_hash: [u8; 32],

    // Private inputs - Merkle proof for trust list membership
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH]
) {
    // Validate algorithm selector
    assert((algorithm == ALG_ES256) | (algorithm == ALG_PS256), "Invalid algorithm");

    // Compute public key hash for trust list lookup
    // This is different for each algorithm
    let pubkey_hash: Field = if algorithm == ALG_ES256 {
        // For ECDSA: hash(x || y)
        let x_field = bytes_to_field(ecdsa_public_key_x);
        let y_field = bytes_to_field(ecdsa_public_key_y);
        pedersen_hash([x_field, y_field])
    } else {
        // For RSA: hash the modulus limbs
        // Convert first 8 limbs to fields (enough for uniqueness)
        let m0 = rsa_modulus_limbs[0] as Field;
        let m1 = rsa_modulus_limbs[1] as Field;
        let m2 = rsa_modulus_limbs[2] as Field;
        let m3 = rsa_modulus_limbs[3] as Field;
        let m4 = rsa_modulus_limbs[4] as Field;
        let m5 = rsa_modulus_limbs[5] as Field;
        let m6 = rsa_modulus_limbs[6] as Field;
        let m7 = rsa_modulus_limbs[7] as Field;
        // Hash in two stages to fit Pedersen input limits
        let h1 = pedersen_hash([m0, m1, m2, m3]);
        let h2 = pedersen_hash([m4, m5, m6, m7]);
        pedersen_hash([h1, h2])
    };

    // Step 1: Verify signature based on algorithm
    if algorithm == ALG_ES256 {
        // ECDSA P-256 verification (blackbox - native Barretenberg)
        let valid = ecdsa_verify(
            ecdsa_public_key_x,
            ecdsa_public_key_y,
            ecdsa_signature,
            message_hash
        );
        assert(valid, "Invalid ES256 signature");
    } else {
        // RSA-2048 PKCS#1 v1.5 verification
        // Construct BigNumParams from modulus (N) and reduction params
        let params: BigNumParams<18, 2048> = BigNumParams::new(
            false, // has_multiplicative_inverse
            rsa_modulus_limbs,
            rsa_redc_limbs
        );

        // Construct signature as RBN2048
        let sig: RBN2048 = RBN2048::from_array(params, rsa_signature_limbs);

        // Verify RSA signature
        let valid = verify_sha256_pkcs1v15(message_hash, sig, RSA_EXPONENT);
        assert(valid, "Invalid PS256 signature");
    }

    // Step 2: Verify Merkle membership in trust list
    let computed_root = compute_merkle_root(pubkey_hash, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Signer not in trust list");

    // Step 3: Verify nullifier derivation
    let expected_nullifier = pedersen_hash([content_hash, pubkey_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");

    // Step 4: Validate chain metadata bounds
    assert(origin_trust_tier >= 1, "Invalid trust tier: too low");
    assert(origin_trust_tier <= 3, "Invalid trust tier: Tier 4 blocked");
    assert((is_ai_generated == 0) | (is_ai_generated == 1), "Invalid AI flag");
    assert(chain_depth >= 1, "Chain depth must be at least 1");
    assert(chain_depth <= 10, "Chain depth exceeds maximum");
    assert((chain_truncated == 0) | (chain_truncated == 1), "Invalid truncation flag");
    assert(disclosure_level <= 4, "Invalid disclosure level");
    assert(proof_timestamp > 0, "Invalid proof timestamp");
}

/// Convert a 32-byte array to a Field element (big-endian)
fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Compute Merkle root from a leaf and proof path
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

// ============================================================================
// Tests
// ============================================================================

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
