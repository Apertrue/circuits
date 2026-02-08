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
// IMPORTANT: At level 0, we verify ImageAggregator proofs which have 5 public values:
// [trust_list_root, content_hash, nullifier, proof_timestamp, image_commitment]
// At level 1+, we verify TreeAggregator proofs which also have 5 public values:
// [0, 0, 0, 0, combined_commitment]  (padded to match ImageAggregator layout)
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

// Number of public values for ImageAggregator (4 inputs + 1 output)
global IMAGE_AGG_PUBLIC_VALUES: u32 = 5;

// Main entry point for TreeAggregator
//
// PUBLIC INPUTS (4 padding fields, forced to zero):
// - pad_0..pad_3: Must be zero. These exist so TreeAggregator has 5 public
//   values (4 inputs + 1 return) matching ImageAggregator's layout. This
//   ensures verify_honk_proof works identically at every tree level.
//
// PRIVATE INPUTS:
// - combined_commitment: The expected Poseidon2([commitment_left, commitment_right])
//   Made private to keep it at index 4 of public values (as the return value).
// - proof_left: Left child proof (ImageProof or previous TreeProof)
// - proof_right: Right child proof (ImageProof or previous TreeProof)
// - vk: Verification key (same for both - they're from the same circuit type)
// - vk_hash: Hash of the VK for recursive verification
// - public_values_left: All public values from left child proof (5 values)
// - public_values_right: All public values from right child proof (5 values)
//
// PUBLIC OUTPUT:
// - Returns the combined_commitment at index 4
//   Public values layout: [0, 0, 0, 0, combined_commitment]
fn main(
    // === PUBLIC INPUTS (padding - must be zero) ===
    pad_0: pub Field,
    pad_1: pub Field,
    pad_2: pub Field,
    pad_3: pub Field,

    // === PRIVATE INPUTS ===
    combined_commitment: Field,

    // === PRIVATE INPUTS: PROOFS ===
    proof_left: UltraHonkZKProof,
    proof_right: UltraHonkZKProof,

    // === PRIVATE INPUTS: VERIFICATION KEYS ===
    // Separate VKs for left/right: when an odd image count causes promotion,
    // a promoted ImageAggregator proof may be paired with a TreeAggregator proof.
    vk_left: UltraHonkVerificationKey,
    vk_right: UltraHonkVerificationKey,
    vk_hash_left: Field,
    vk_hash_right: Field,

    // === PRIVATE INPUTS: ALL PUBLIC VALUES FROM CHILD PROOFS ===
    // For ImageAggregator proofs (level 0): 5 values each
    // [0] trust_list_root
    // [1] content_hash
    // [2] nullifier
    // [3] proof_timestamp
    // [4] image_commitment (the output we care about)
    //
    // For TreeAggregator proofs (level 1+): [0, 0, 0, 0, combined_commitment]
    public_values_left: [Field; 5],
    public_values_right: [Field; 5],
) -> pub Field {
    // ================================================================
    // STEP 0: Enforce padding fields are zero
    // ================================================================
    assert(pad_0 == 0, "pad_0 must be zero");
    assert(pad_1 == 0, "pad_1 must be zero");
    assert(pad_2 == 0, "pad_2 must be zero");
    assert(pad_3 == 0, "pad_3 must be zero");

    // ================================================================
    // STEP 1: Verify left child proof
    // ================================================================
    // Pass ALL public values to verify_honk_proof
    verify_honk_proof(
        vk_left,
        proof_left,
        public_values_left,
        vk_hash_left,
    );

    // ================================================================
    // STEP 2: Verify right child proof
    // ================================================================
    // Pass ALL public values to verify_honk_proof
    verify_honk_proof(
        vk_right,
        proof_right,
        public_values_right,
        vk_hash_right,
    );

    // ================================================================
    // STEP 3: Compute and verify combined commitment
    // ================================================================
    // The commitment is always the LAST value in the public values array
    // For ImageAggregator: index 4 (image_commitment)
    // For TreeAggregator: index 4 (combined_commitment, padded to position 4)
    let commitment_left = public_values_left[4];
    let commitment_right = public_values_right[4];

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
    // Commitment is at index 4 in the public values array
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

#[test]
fn test_commitment_index_location() {
    // Verify that commitment is correctly extracted from index 4
    let public_values: [Field; 5] = [
        111, // trust_list_root
        222, // content_hash
        333, // nullifier
        444, // proof_timestamp
        555, // image_commitment (this is what we use)
    ];

    let commitment = public_values[4];
    assert(commitment == 555, "Commitment should be at index 4");
}
