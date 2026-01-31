// ImageAggregator Circuit
//
// Combines ProofA (certificate chain verification) and ProofB (COSE signature verification)
// for a single image into a single ImageProof.
//
// This is Phase 1 of the binary tree aggregation architecture:
// - Verifies both ProofA and ProofB are valid
// - Verifies linkCommit binding (ProofA.linkCommit == ProofB.linkCommit)
// - Outputs an image_commitment for tree aggregation
//
// Security Properties:
// - Prevents proof substitution attacks via linkCommit binding
// - Maintains content_hash binding to actual image
// - Preserves nullifier for replay prevention
//
// IMPORTANT: verify_honk_proof requires ALL public inputs+outputs from the inner proof.
// ProofA has 161 public values, ProofB has 8 public values.
//
// Estimated constraints: ~100k (2x verify_proof + Poseidon hash)

use dep::bb_proof_verification::{
    UltraHonkZKProof,
    UltraHonkVerificationKey,
    verify_honk_proof,
};
use dep::poseidon::poseidon2::Poseidon2;

// Number of public values for each proof (inputs + outputs)
// ProofA: 126 inputs + 35 outputs = 161
// ProofB: 7 inputs + 1 output = 8
global PROOF_A_PUBLIC_VALUES: u32 = 161;
global PROOF_B_PUBLIC_VALUES: u32 = 8;

// Main entry point for ImageAggregator
//
// This circuit verifies both ProofA and ProofB by passing all their public values
// to verify_honk_proof.
//
// PUBLIC INPUTS:
// - trust_list_root: Oracle's Merkle root of trusted intermediates
// - content_hash: SHA256 of stripped image bytes
// - nullifier: H(content_hash, leaf_key_hash) for replay prevention
// - proof_timestamp: When proofs were generated (Unix seconds)
//
// PUBLIC OUTPUT:
// - image_commitment: Poseidon2([trust_list_root, content_hash, nullifier, proof_timestamp])
fn main(
    // === PUBLIC INPUTS (must match shared fields in ProofA/ProofB) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,

    // === PRIVATE INPUTS: PROOFS ===
    proof_a: UltraHonkZKProof,
    proof_b: UltraHonkZKProof,

    // === PRIVATE INPUTS: VERIFICATION KEYS ===
    vk_a: UltraHonkVerificationKey,
    vk_b: UltraHonkVerificationKey,
    vk_a_hash: Field,
    vk_b_hash: Field,

    // === PRIVATE INPUTS: ALL PROOF_A PUBLIC VALUES (161 total) ===
    // These must be passed to verify_honk_proof in exact order
    //
    // ProofA PUBLIC INPUTS (126 total):
    // [0] trust_list_root: Field
    // [1] content_hash: Field
    // [2] nullifier: Field
    // [3] proof_timestamp: Field
    // [4] cert_not_before: Field
    // [5] cert_not_after: Field
    // [6] time_min: Field
    // [7] time_max: Field
    // [8] center_lat_scaled: Field
    // [9] center_lon_scaled: Field
    // [10] center_lat_is_negative: Field (u8 as Field)
    // [11] center_lon_is_negative: Field (u8 as Field)
    // [12] radius_squared_scaled: Field
    // [13..45] tbs_hash_bytes: [Field; 32] (u8 as Field)
    // [45..93] tbs_hash_sha384: [Field; 48] (u8 as Field)
    // [93..125] claim_hash: [Field; 32] (u8 as Field)
    // [125] content_hash_offset: Field (u32 as Field)
    //
    // ProofA PUBLIC OUTPUTS (35 total):
    // [126] link_commit: Field
    // [127] location_commitment: Field
    // [128] time_commitment: Field
    // [129..161] actions_assertion_hash: [Field; 32] (u8 as Field)
    proof_a_public_values: [Field; 161],

    // === PRIVATE INPUTS: ALL PROOF_B PUBLIC VALUES (8 total) ===
    //
    // ProofB PUBLIC INPUTS (7 total):
    // [0] trust_list_root: Field
    // [1] content_hash: Field
    // [2] nullifier: Field
    // [3] proof_timestamp: Field
    // [4] cert_not_before: Field
    // [5] cert_not_after: Field
    // [6] content_hash_offset: Field (u32 as Field)
    //
    // ProofB PUBLIC OUTPUT (1 total):
    // [7] link_commit: Field
    proof_b_public_values: [Field; 8],
) -> pub Field {
    // ================================================================
    // STEP 1: Verify ProofA (certificate chain verification)
    // ================================================================
    // Pass ALL 161 public values to verify_honk_proof
    verify_honk_proof(
        vk_a,
        proof_a,
        proof_a_public_values,
        vk_a_hash,
    );

    // ================================================================
    // STEP 2: Verify ProofB (COSE signature verification)
    // ================================================================
    // Pass ALL 8 public values to verify_honk_proof
    verify_honk_proof(
        vk_b,
        proof_b,
        proof_b_public_values,
        vk_b_hash,
    );

    // ================================================================
    // STEP 3: Verify shared public inputs match
    // ================================================================
    // SECURITY: Ensure both proofs were generated for the same image
    // Check that shared public inputs are consistent
    assert(
        proof_a_public_values[0] == proof_b_public_values[0],
        "trust_list_root mismatch between ProofA and ProofB"
    );
    assert(
        proof_a_public_values[1] == proof_b_public_values[1],
        "content_hash mismatch between ProofA and ProofB"
    );
    assert(
        proof_a_public_values[2] == proof_b_public_values[2],
        "nullifier mismatch between ProofA and ProofB"
    );
    assert(
        proof_a_public_values[3] == proof_b_public_values[3],
        "proof_timestamp mismatch between ProofA and ProofB"
    );

    // Also verify these match our own public inputs
    assert(
        proof_a_public_values[0] == trust_list_root,
        "ProofA trust_list_root doesn't match aggregator public input"
    );
    assert(
        proof_a_public_values[1] == content_hash,
        "ProofA content_hash doesn't match aggregator public input"
    );
    assert(
        proof_a_public_values[2] == nullifier,
        "ProofA nullifier doesn't match aggregator public input"
    );
    assert(
        proof_a_public_values[3] == proof_timestamp,
        "ProofA proof_timestamp doesn't match aggregator public input"
    );

    // ================================================================
    // STEP 4: Verify linkCommit binding
    // ================================================================
    // SECURITY: This prevents proof substitution attacks where an attacker
    // could mix ProofA from image A with ProofB from image B.
    //
    // ProofA link_commit is at index 126 (first output)
    // ProofB link_commit is at index 7 (only output)
    let link_commit_a = proof_a_public_values[126];
    let link_commit_b = proof_b_public_values[7];

    assert(
        link_commit_a == link_commit_b,
        "Link commitment mismatch: ProofA and ProofB were not generated from the same image"
    );

    // ================================================================
    // STEP 5: Compute image_commitment for tree aggregation
    // ================================================================
    // This commitment uniquely identifies this verified image in the aggregation tree.
    let image_commitment = Poseidon2::hash(
        [trust_list_root, content_hash, nullifier, proof_timestamp],
        4
    );

    image_commitment
}

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_image_commitment_deterministic() {
    let trust_list_root: Field = 11111111111111111111;
    let content_hash: Field = 12345678901234567890;
    let nullifier: Field = 98765432109876543210;
    let proof_timestamp: Field = 1706745600;

    let commit1 = Poseidon2::hash([trust_list_root, content_hash, nullifier, proof_timestamp], 4);
    let commit2 = Poseidon2::hash([trust_list_root, content_hash, nullifier, proof_timestamp], 4);

    assert(commit1 == commit2, "Image commitment should be deterministic");
}

#[test]
fn test_different_inputs_different_commitment() {
    let trust_list_root: Field = 11111111111111111111;
    let content_hash1: Field = 11111111111111111111;
    let content_hash2: Field = 22222222222222222222;
    let nullifier: Field = 99999999999999999999;
    let timestamp: Field = 1706745600;

    let commit1 = Poseidon2::hash([trust_list_root, content_hash1, nullifier, timestamp], 4);
    let commit2 = Poseidon2::hash([trust_list_root, content_hash2, nullifier, timestamp], 4);

    assert(commit1 != commit2, "Different content_hash should produce different commitment");
}
