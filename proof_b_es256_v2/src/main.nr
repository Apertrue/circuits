/// Apertrue ProofB ES256 v2 - standard size class
///
/// Thin bin over proof_b_es256_v2_core (shared logic, see its lib.nr).
/// Buffers: MAX_SIG_STRUCTURE_SIZE 3072, MAX_CLAIM_SIZE 1280.
/// Other size class: proof_b_es256_v2_large (8192 / 2048). Both have the same public layout.
///
/// Pairs with ProofA v2 (proof_a_ecdsa_p256_v2, proof_a_ecdsa_p384_v2).
/// Versus proof_b_es256 (v1): cert_not_before and cert_not_after are removed
/// from the public inputs and the in-circuit validity check is dropped;
/// ProofA v2 checks proof_timestamp against dates parsed from the CA-signed
/// leaf TBSCertificate.
///
/// PUBLIC LAYOUT (index: name; one Field each)
///  0 trust_list_root
///  1 content_hash
///  2 nullifier              pedersen_hash([content_hash, pedersen_hash([leaf_x, leaf_y])])
///  3 proof_timestamp        (range checked to u64 only)
///  4 claim_hash_commitment  Poseidon2(bytes32_to_field_array(claim_hash))
///  5 content_hash_offset    (0 = content hash not embedded in the claim)
/// Return value:
///  6 link_commit            pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])
/// Total 7. Versus v1 (9): cert_not_before (4) and cert_not_after (5) are
/// removed; the shared inputs keep their meaning and relative order.
///
/// Shared with ProofA v2 (must be equal across the pair): trust_list_root,
/// content_hash, nullifier, proof_timestamp, claim_hash_commitment,
/// content_hash_offset, link_commit.

use proof_b_es256_v2_core::{verify_proof_b_es256, MERKLE_TREE_DEPTH};

/// Maximum size of COSE Sig_structure (CBOR encoded)
global MAX_SIG_STRUCTURE_SIZE: u32 = 3072;

/// Maximum size of C2PA claim (CBOR encoded)
global MAX_CLAIM_SIZE: u32 = 1280;

fn main(
    // === PUBLIC INPUTS (shared with ProofA) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,

    // === PUBLIC INPUT: Claim Hash Commitment (must match ProofA) ===
    claim_hash_commitment: pub Field,

    // === PRIVATE: ECDSA COSE SIGNATURE ===
    cose_signature_ecdsa: [u8; 64],
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],

    // === PRIVATE: COSE MESSAGE HASH ===
    cose_message_hash: [u8; 32],

    // === PRIVATE: LINKING WITNESS ===
    intermediate_leaf: Field,
    link_blind: Field,

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

    // === PUBLIC: CONTENT HASH BINDING ===
    content_hash_offset: pub u32,
) -> pub Field {
    verify_proof_b_es256(
        trust_list_root,
        content_hash,
        nullifier,
        proof_timestamp,
        claim_hash_commitment,
        cose_signature_ecdsa,
        leaf_pubkey_x,
        leaf_pubkey_y,
        cose_message_hash,
        intermediate_leaf,
        link_blind,
        merkle_path,
        merkle_indices,
        sig_structure_bytes,
        sig_structure_length,
        claim_bytes,
        claim_length,
        claim_offset_in_sig,
        claim_hash,
        content_hash_offset,
    )
}
