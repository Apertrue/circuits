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
// ProofA has 55 public values (19 inputs + 36 outputs), ProofB has 9 public values (8 inputs + 1 output).
//
// Public values layout (12 total = 4 inputs + 8 outputs):
// [0] trust_list_root (input)
// [1] content_hash (input)
// [2] nullifier (input)
// [3] proof_timestamp (input)
// [4] location_commitment (output)
// [5] time_commitment (output)
// [6] edit_time_commitment (output)
// [7] link_commit (output)
// [8] actions_hash_field (output)
// [9] image_commitment (output)
// [10] vk_a_hash (output)
// [11] vk_b_hash (output)
//
// Estimated constraints: ~100k (2x verify_proof + Poseidon hash)

use dep::bb_proof_verification::{
    UltraHonkZKProof,
    UltraHonkVerificationKey,
    verify_honk_proof,
};
use dep::poseidon::poseidon2::Poseidon2;

// Number of public values for each proof (inputs + outputs)
// ProofA: 19 inputs + 36 outputs = 55 (after public input packing + edit time + skip flags)
// ProofB: 8 inputs + 1 output = 9 (added claim_hash_commitment)
global PROOF_A_PUBLIC_VALUES: u32 = 55;
global PROOF_B_PUBLIC_VALUES: u32 = 9;

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
// PUBLIC OUTPUTS:
// - location_commitment: Poseidon2 commitment to exact GPS + salt (from ProofA)
// - time_commitment: Poseidon2 commitment to exact timestamp + salt (from ProofA)
// - edit_time_commitment: Poseidon2 commitment to exact edit timestamp + salt (from ProofA, 0 if no edit)
// - link_commit: Device identity binding (Pedersen hash from ProofA)
// - actions_hash_field: Poseidon2 reduction of C2PA actions SHA-256 hash (from ProofA)
// - image_commitment: Poseidon2([trust_list_root, content_hash, nullifier, proof_timestamp,
//                                location_commitment, time_commitment, edit_time_commitment,
//                                link_commit, actions_hash_field])
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

    // === PRIVATE INPUTS: ALL PROOF_A PUBLIC VALUES (55 total) ===
    // These must be passed to verify_honk_proof in exact order
    //
    // ProofA PUBLIC INPUTS (19 total, after packing optimization + edit time + skip flags):
    // [0] trust_list_root: Field
    // [1] content_hash: Field
    // [2] nullifier: Field
    // [3] proof_timestamp: Field
    // [4] cert_not_before: Field
    // [5] cert_not_after: Field
    // [6] time_min: Field
    // [7] time_max: Field
    // [8] edit_time_min: Field
    // [9] edit_time_max: Field
    // [10] center_lat_scaled: Field
    // [11] center_lon_scaled: Field
    // [12] location_flags: Field (u8 as Field, bit 0=lat neg, bit 1=lon neg)
    // [13] radius_squared_scaled: Field
    // [14] tbs_hash_commitment: Field (Poseidon2 of TBS hash bytes)
    // [15] claim_hash_commitment: Field (Poseidon2 of claim hash bytes)
    // [16] content_hash_offset: Field (u32 as Field)
    // [17] skip_flag_a: Field
    // [18] skip_flag_b: Field
    //
    // ProofA PUBLIC OUTPUTS (36 total):
    // [19] link_commit: Field
    // [20] location_commitment: Field
    // [21] time_commitment: Field
    // [22] edit_time_commitment: Field
    // [23..55] actions_assertion_hash: [Field; 32] (u8 as Field)
    proof_a_public_values: [Field; 55],

    // === PRIVATE INPUTS: ALL PROOF_B PUBLIC VALUES (9 total) ===
    //
    // ProofB PUBLIC INPUTS (8 total, after adding claim_hash_commitment):
    // [0] trust_list_root: Field
    // [1] content_hash: Field
    // [2] nullifier: Field
    // [3] proof_timestamp: Field
    // [4] cert_not_before: Field
    // [5] cert_not_after: Field
    // [6] claim_hash_commitment: Field (Poseidon2 of claim hash bytes)
    // [7] content_hash_offset: Field (u32 as Field)
    //
    // ProofB PUBLIC OUTPUT (1 total):
    // [8] link_commit: Field
    proof_b_public_values: [Field; 9],
) -> pub (Field, Field, Field, Field, Field, Field, Field, Field) {
    // ================================================================
    // STEP 1: Verify ProofA (certificate chain verification)
    // ================================================================
    // Pass ALL 55 public values to verify_honk_proof
    verify_honk_proof(
        vk_a,
        proof_a,
        proof_a_public_values,
        vk_a_hash,
    );

    // ================================================================
    // STEP 2: Verify ProofB (COSE signature verification)
    // ================================================================
    // Pass ALL 9 public values to verify_honk_proof
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

    // SECURITY: Verify claim_hash_commitment matches between proofs
    // ProofA claim_hash_commitment is at index 15 (shifted +2 for edit_time_min/max)
    // ProofB claim_hash_commitment is at index 6
    // This ensures both proofs reference the same signed C2PA claim
    assert(
        proof_a_public_values[15] == proof_b_public_values[6],
        "claim_hash_commitment mismatch between ProofA and ProofB"
    );

    // SECURITY: Verify cert validity period matches
    assert(
        proof_a_public_values[4] == proof_b_public_values[4],
        "cert_not_before mismatch between ProofA and ProofB"
    );
    assert(
        proof_a_public_values[5] == proof_b_public_values[5],
        "cert_not_after mismatch between ProofA and ProofB"
    );

    // SECURITY: Verify content_hash_offset matches
    assert(
        proof_a_public_values[16] == proof_b_public_values[7],
        "content_hash_offset mismatch between ProofA and ProofB"
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
    // ProofA link_commit is at index 19 (first output after 19 inputs)
    // ProofB link_commit is at index 8 (first output after 8 inputs)
    let link_commit_a = proof_a_public_values[19];
    let link_commit_b = proof_b_public_values[8];

    assert(
        link_commit_a == link_commit_b,
        "Link commitment mismatch: ProofA and ProofB were not generated from the same image"
    );
    assert(link_commit_a != 0, "link_commit must not be zero");

    // ================================================================
    // STEP 5: Extract ProofA commitment outputs
    // ================================================================
    // ProofA outputs at indices 19-22 are commitment fields:
    // [19] link_commit, [20] location_commitment, [21] time_commitment, [22] edit_time_commitment
    let link_commit = proof_a_public_values[19];
    let location_commitment = proof_a_public_values[20];
    let time_commitment = proof_a_public_values[21];
    let edit_time_commitment = proof_a_public_values[22];

    // ProofA outputs at indices 23-54 are actions_assertion_hash [u8; 32] as Fields.
    // Reduce to a single Field via Poseidon2 for inclusion in image_commitment.
    let mut actions_bytes: [Field; 32] = [0; 32];
    for i in 0..32 {
        actions_bytes[i] = proof_a_public_values[23 + i];
    }
    let actions_hash_field = Poseidon2::hash(actions_bytes, 32);

    // ================================================================
    // STEP 6: Compute image_commitment for tree aggregation
    // ================================================================
    // This commitment uniquely identifies this verified image in the aggregation tree.
    // Expanded from 8 to 9 inputs to include edit_time_commitment.
    let image_commitment = Poseidon2::hash(
        [
            trust_list_root, content_hash, nullifier, proof_timestamp,
            location_commitment, time_commitment, edit_time_commitment,
            link_commit, actions_hash_field,
        ],
        9,
    );

    (location_commitment, time_commitment, edit_time_commitment, link_commit, actions_hash_field, image_commitment, vk_a_hash, vk_b_hash)
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
    let location_commitment: Field = 55555555555555555555;
    let time_commitment: Field = 66666666666666666666;
    let edit_time_commitment: Field = 44444444444444444444;
    let link_commit: Field = 77777777777777777777;
    let actions_hash_field: Field = 88888888888888888888;

    let commit1 = Poseidon2::hash(
        [trust_list_root, content_hash, nullifier, proof_timestamp,
         location_commitment, time_commitment, edit_time_commitment,
         link_commit, actions_hash_field],
        9,
    );
    let commit2 = Poseidon2::hash(
        [trust_list_root, content_hash, nullifier, proof_timestamp,
         location_commitment, time_commitment, edit_time_commitment,
         link_commit, actions_hash_field],
        9,
    );

    assert(commit1 == commit2, "Image commitment should be deterministic");
}

#[test]
fn test_different_inputs_different_commitment() {
    let trust_list_root: Field = 11111111111111111111;
    let content_hash1: Field = 11111111111111111111;
    let content_hash2: Field = 22222222222222222222;
    let nullifier: Field = 99999999999999999999;
    let timestamp: Field = 1706745600;
    let loc: Field = 55555555555555555555;
    let time: Field = 66666666666666666666;
    let edit_time: Field = 0;
    let link: Field = 77777777777777777777;
    let actions: Field = 88888888888888888888;

    let commit1 = Poseidon2::hash(
        [trust_list_root, content_hash1, nullifier, timestamp, loc, time, edit_time, link, actions],
        9,
    );
    let commit2 = Poseidon2::hash(
        [trust_list_root, content_hash2, nullifier, timestamp, loc, time, edit_time, link, actions],
        9,
    );

    assert(commit1 != commit2, "Different content_hash should produce different commitment");
}

#[test]
fn test_actions_hash_reduction() {
    // Test that Poseidon2 of 32 zero bytes produces a non-zero hash
    let zero_actions: [Field; 32] = [0; 32];
    let hash = Poseidon2::hash(zero_actions, 32);
    // Just verify it computes without error and is deterministic
    let hash2 = Poseidon2::hash(zero_actions, 32);
    assert(hash == hash2, "Actions hash reduction should be deterministic");
}
