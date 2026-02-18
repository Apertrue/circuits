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
// ProofA has 50 public values (15 inputs + 35 outputs), ProofB has 9 public values (8 inputs + 1 output).
//
// Public values layout (9 total = 4 inputs + 5 outputs):
// [0] trust_list_root (input)
// [1] content_hash (input)
// [2] nullifier (input)
// [3] proof_timestamp (input)
// [4] location_commitment (output)
// [5] time_commitment (output)
// [6] link_commit (output)
// [7] actions_hash_field (output)
// [8] image_commitment (output)
//
// Estimated constraints: ~100k (2x verify_proof + Poseidon hash)

use dep::bb_proof_verification::{
    UltraHonkZKProof,
    UltraHonkVerificationKey,
    verify_honk_proof,
};
use dep::poseidon::poseidon2::Poseidon2;

// Number of public values for each proof (inputs + outputs)
// ProofA: 15 inputs + 35 outputs = 50 (after public input packing optimization)
// ProofB: 8 inputs + 1 output = 9 (added claim_hash_commitment)
global PROOF_A_PUBLIC_VALUES: u32 = 50;
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
// - link_commit: Device identity binding (Pedersen hash from ProofA)
// - actions_hash_field: Poseidon2 reduction of C2PA actions SHA-256 hash (from ProofA)
// - image_commitment: Poseidon2([trust_list_root, content_hash, nullifier, proof_timestamp,
//                                location_commitment, time_commitment, link_commit, actions_hash_field])
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

    // === PRIVATE INPUTS: ALL PROOF_A PUBLIC VALUES (50 total) ===
    // These must be passed to verify_honk_proof in exact order
    //
    // ProofA PUBLIC INPUTS (15 total, after packing optimization):
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
    // [10] location_flags: Field (u8 as Field, bit 0=lat neg, bit 1=lon neg)
    // [11] radius_squared_scaled: Field
    // [12] tbs_hash_commitment: Field (Poseidon2 of TBS hash bytes)
    // [13] claim_hash_commitment: Field (Poseidon2 of claim hash bytes)
    // [14] content_hash_offset: Field (u32 as Field)
    //
    // ProofA PUBLIC OUTPUTS (35 total):
    // [15] link_commit: Field
    // [16] location_commitment: Field
    // [17] time_commitment: Field
    // [18..50] actions_assertion_hash: [Field; 32] (u8 as Field)
    proof_a_public_values: [Field; 50],

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
) -> pub (Field, Field, Field, Field, Field) {
    // ================================================================
    // STEP 1: Verify ProofA (certificate chain verification)
    // ================================================================
    // Pass ALL 50 public values to verify_honk_proof
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
    // ProofA claim_hash_commitment is at index 13
    // ProofB claim_hash_commitment is at index 6
    // This ensures both proofs reference the same signed C2PA claim
    assert(
        proof_a_public_values[13] == proof_b_public_values[6],
        "claim_hash_commitment mismatch between ProofA and ProofB"
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
    // ProofA link_commit is at index 15 (first output after 15 inputs)
    // ProofB link_commit is at index 8 (first output after 8 inputs)
    let link_commit_a = proof_a_public_values[15];
    let link_commit_b = proof_b_public_values[8];

    assert(
        link_commit_a == link_commit_b,
        "Link commitment mismatch: ProofA and ProofB were not generated from the same image"
    );

    // ================================================================
    // STEP 5: Extract ProofA commitment outputs
    // ================================================================
    // ProofA outputs at indices 15-17 are commitment fields:
    // [15] link_commit, [16] location_commitment, [17] time_commitment
    let link_commit = proof_a_public_values[15];
    let location_commitment = proof_a_public_values[16];
    let time_commitment = proof_a_public_values[17];

    // ProofA outputs at indices 18-49 are actions_assertion_hash [u8; 32] as Fields.
    // Reduce to a single Field via Poseidon2 for inclusion in image_commitment.
    let mut actions_bytes: [Field; 32] = [0; 32];
    for i in 0..32 {
        actions_bytes[i] = proof_a_public_values[18 + i];
    }
    let actions_hash_field = Poseidon2::hash(actions_bytes, 32);

    // ================================================================
    // STEP 6: Compute image_commitment for tree aggregation
    // ================================================================
    // This commitment uniquely identifies this verified image in the aggregation tree.
    // Expanded from 4 to 8 inputs to include all ProofA commitment outputs.
    let image_commitment = Poseidon2::hash(
        [
            trust_list_root, content_hash, nullifier, proof_timestamp,
            location_commitment, time_commitment, link_commit, actions_hash_field,
        ],
        8,
    );

    (location_commitment, time_commitment, link_commit, actions_hash_field, image_commitment)
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
    let link_commit: Field = 77777777777777777777;
    let actions_hash_field: Field = 88888888888888888888;

    let commit1 = Poseidon2::hash(
        [trust_list_root, content_hash, nullifier, proof_timestamp,
         location_commitment, time_commitment, link_commit, actions_hash_field],
        8,
    );
    let commit2 = Poseidon2::hash(
        [trust_list_root, content_hash, nullifier, proof_timestamp,
         location_commitment, time_commitment, link_commit, actions_hash_field],
        8,
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
    let link: Field = 77777777777777777777;
    let actions: Field = 88888888888888888888;

    let commit1 = Poseidon2::hash(
        [trust_list_root, content_hash1, nullifier, timestamp, loc, time, link, actions],
        8,
    );
    let commit2 = Poseidon2::hash(
        [trust_list_root, content_hash2, nullifier, timestamp, loc, time, link, actions],
        8,
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
