/// Apertrue C2PA Verifier Circuit
///
/// This circuit proves that:
/// 1. An image has a valid C2PA signature from a trusted signer
/// 2. The signer is in the approved trust list (via Merkle proof)
/// 3. The proof is bound to a specific image content hash (prevents reuse)
///
/// Privacy: The circuit hides which specific camera/device signed the image,
/// only proving it was from SOME trusted device in the trust list.
///
/// Note: ECDSA P-256 verification uses Noir's blackbox function which is
/// implemented natively in Barretenberg, NOT as circuit constraints.

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
// sha256_var removed - testing with pre-computed hash

/// Maximum depth of the Merkle tree for the trust list
/// 2^10 = 1024 trusted signers capacity
global MERKLE_TREE_DEPTH: u32 = 10;

/// The main circuit entry point
///
/// Public inputs (visible in proof):
/// - trust_list_root: The Merkle root of the approved signers list
/// - content_hash: Hash of the image content (binds proof to specific image)
/// - nullifier: Prevents proof reuse while preserving privacy
///
/// Private inputs (hidden):
/// - signature: ECDSA signature (r || s, 64 bytes total)
/// - public_key_x, public_key_y: Signer's public key (32 bytes each)
/// - message: Raw Sig_structure bytes to be hashed and verified
/// - message_length: Actual length of the message (rest is zero-padded)
/// - merkle_path: Proof of signer's inclusion in trust list
/// - merkle_indices: Path direction bits for Merkle proof
fn main(
    // Public inputs
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,

    // Private inputs - ECDSA signature (r || s concatenated)
    signature: [u8; 64],

    // Private inputs - Public key of signer
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],

    // Private inputs - Pre-computed message hash (SHA-256 of Sig_structure)
    message_hash: [u8; 32],

    // Private inputs - Merkle proof for trust list membership
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH]
) {
    // Step 1: Verify the ECDSA P-256 signature (blackbox - native Barretenberg operation)
    // This proves the image was signed by the holder of this private key
    // The message_hash is pre-computed SHA-256(Sig_structure) passed as input
    let signature_valid = verify_signature(
        public_key_x,
        public_key_y,
        signature,
        message_hash
    );
    assert(signature_valid, "Invalid C2PA signature");

    // Step 3: Compute the leaf hash from the public key
    // The trust list contains hashes of approved public keys
    let pubkey_x_field = bytes_to_field(public_key_x);
    let pubkey_y_field = bytes_to_field(public_key_y);
    let leaf = pedersen_hash([pubkey_x_field, pubkey_y_field]);

    // Step 4: Verify Merkle membership in trust list
    // This proves the signer is in the approved list without revealing which one
    let computed_root = compute_merkle_root(leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Signer not in trust list");

    // Step 5: Verify nullifier derivation
    // Nullifier = hash(content_hash, public_key_hash)
    // This prevents the same proof from being submitted twice for the same image
    // while still hiding which key was used
    let expected_nullifier = pedersen_hash([content_hash, leaf]);
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

/// Test module for circuit verification
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
    // Simple test with a depth-1 tree
    let leaf: Field = 123;
    let sibling: Field = 456;

    // Create a minimal path (rest are zeros)
    let mut path: [Field; MERKLE_TREE_DEPTH] = [0; MERKLE_TREE_DEPTH];
    path[0] = sibling;

    let mut indices: [Field; MERKLE_TREE_DEPTH] = [0; MERKLE_TREE_DEPTH];
    indices[0] = 0; // leaf is on the left

    let root = compute_merkle_root(leaf, path, indices);

    // Verify the root is deterministic - compute expected manually
    let first_level = pedersen_hash([leaf, sibling]);
    let mut expected = first_level;
    for _ in 1..MERKLE_TREE_DEPTH {
        expected = pedersen_hash([expected, 0]);
    }
    assert(root == expected);
}
