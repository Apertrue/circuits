// TreeAggregator Circuit
//
// Combines 2 proofs into 1 proof for binary tree aggregation.
// This circuit is REUSED at every level of the aggregation tree.
//
// Tree structure for 8 images:
// Level 0: [ImgProof1] [ImgProof2] [ImgProof3] [ImgProof4] [ImgProof5] [ImgProof6] [ImgProof7] [ImgProof8]
//              |           |           |           |           |           |           |           |
//              +-----+-----+           +-----+-----+           +-----+-----+           +-----+-----+
//                    |                       |                       |                       |
// Level 1:      [Agg_1_2]               [Agg_3_4]               [Agg_5_6]               [Agg_7_8]
//                    |                       |                       |                       |
//                    +-----------+-----------+                       +-----------+-----------+
//                                |                                               |
// Level 2:                 [Agg_1234]                                      [Agg_5678]
//                                |                                               |
//                                +---------------------+-------------------------+
//                                                      |
// Level 3:                                      [FINAL_PROOF]
//
// At each level, TreeAggregator:
// 1. Verifies left child proof
// 2. Verifies right child proof
// 3. Combines their commitments into a new combined_commitment
//
// Estimated constraints: ~50k (2x verify_proof + Poseidon hash)

use dep::bb_proof_verification::{
    UltraHonkZKProof,
    UltraHonkVerificationKey,
    verify_honk_proof,
};
use dep::poseidon::poseidon2::Poseidon2;

// Main entry point for TreeAggregator
//
// PUBLIC INPUTS:
// - combined_commitment: The expected Poseidon2([commitment_left, commitment_right])
//   This is public so verifiers can check the tree structure.
//
// PRIVATE INPUTS:
// - proof_left: Left child proof (ImageProof or previous TreeProof)
// - proof_right: Right child proof (ImageProof or previous TreeProof)
// - vk: Verification key (same for both - they're from the same circuit type)
// - vk_hash: Hash of the VK for recursive verification
// - commitment_left: The commitment output from the left child proof
// - commitment_right: The commitment output from the right child proof
//
// PUBLIC OUTPUT:
// - Returns the combined_commitment (passed through for chaining)
fn main(
    // === PUBLIC INPUTS ===
    combined_commitment: pub Field,

    // === PRIVATE INPUTS: PROOFS ===
    proof_left: UltraHonkZKProof,
    proof_right: UltraHonkZKProof,

    // === PRIVATE INPUTS: VERIFICATION KEY ===
    // Note: Same VK for both proofs since they're from the same circuit
    // (either both ImageAggregator proofs or both TreeAggregator proofs)
    vk: UltraHonkVerificationKey,
    vk_hash: Field,

    // === PRIVATE INPUTS: CHILD COMMITMENTS ===
    commitment_left: Field,
    commitment_right: Field,
) -> pub Field {
    // ================================================================
    // STEP 1: Verify left child proof
    // ================================================================
    // The left child's public output is its commitment
    verify_honk_proof(
        vk,
        proof_left,
        [commitment_left],
        vk_hash,
    );

    // ================================================================
    // STEP 2: Verify right child proof
    // ================================================================
    // The right child's public output is its commitment
    verify_honk_proof(
        vk,
        proof_right,
        [commitment_right],
        vk_hash,
    );

    // ================================================================
    // STEP 3: Compute and verify combined commitment
    // ================================================================
    // The combined commitment is the Poseidon hash of both child commitments.
    // This creates a Merkle-like structure where the root commitment
    // represents all verified images in the batch.
    let computed_combined = Poseidon2::hash(
        [commitment_left, commitment_right],
        2
    );

    // Verify the computed combined commitment matches the public input
    // This ensures the tree structure is valid
    assert(
        computed_combined == combined_commitment,
        "Combined commitment mismatch: tree structure invalid"
    );

    // Return the combined commitment as public output
    // This allows the next level of aggregation to verify it
    combined_commitment
}

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_combined_commitment_deterministic() {
    // Test that combined commitment is deterministic for same inputs
    let left: Field = 12345678901234567890;
    let right: Field = 98765432109876543210;

    let commit1 = Poseidon2::hash([left, right], 2);
    let commit2 = Poseidon2::hash([left, right], 2);

    assert(commit1 == commit2, "Combined commitment should be deterministic");
}

#[test]
fn test_order_matters() {
    // Test that order of children matters (not commutative)
    let a: Field = 11111111111111111111;
    let b: Field = 22222222222222222222;

    let commit_ab = Poseidon2::hash([a, b], 2);
    let commit_ba = Poseidon2::hash([b, a], 2);

    assert(commit_ab != commit_ba, "Order of children should matter");
}

#[test]
fn test_different_children_different_commitment() {
    let left1: Field = 11111111111111111111;
    let left2: Field = 33333333333333333333;
    let right: Field = 22222222222222222222;

    let commit1 = Poseidon2::hash([left1, right], 2);
    let commit2 = Poseidon2::hash([left2, right], 2);

    assert(commit1 != commit2, "Different children should produce different commitment");
}
