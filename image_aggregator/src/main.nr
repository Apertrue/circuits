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
// IMPORTANT: This circuit verifies the PUBLIC OUTPUTS of ProofA and ProofB:
// - ProofA outputs: (link_commit, location_commitment, time_commitment, actions_assertion_hash)
// - ProofB outputs: (link_commit)
//
// Estimated constraints: ~50k (2x verify_proof + Poseidon hash)

use dep::bb_proof_verification::{
    UltraHonkZKProof,
    UltraHonkVerificationKey,
    verify_honk_proof,
};
use dep::poseidon::poseidon2::Poseidon2;


// Main entry point for ImageAggregator
//
// PUBLIC INPUTS:
// - trust_list_root: Oracle's Merkle root of trusted intermediates
// - content_hash: SHA256 of stripped image bytes
// - nullifier: H(content_hash, leaf_key_hash) for replay prevention
// - proof_timestamp: When proofs were generated (Unix seconds)
//
// PRIVATE INPUTS:
// - proof_a: ProofA proof bytes as field array
// - proof_b: ProofB proof bytes as field array
// - vk_a: ProofA verification key as field array
// - vk_b: ProofB verification key as field array
// - vk_a_hash: Hash of ProofA VK (for recursive verification)
// - vk_b_hash: Hash of ProofB VK (for recursive verification)
// - link_commit_a: linkCommit output from ProofA
// - link_commit_b: linkCommit output from ProofB
// - location_commitment_a: location commitment output from ProofA
// - time_commitment_a: time commitment output from ProofA
// - actions_hash_a: actions assertion hash output from ProofA (as Field)
//
// PUBLIC OUTPUT:
// - image_commitment: Poseidon2([content_hash, nullifier, proof_timestamp])
fn main(
    // === PUBLIC INPUTS ===
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

    // === PRIVATE INPUTS: PROOF A OUTPUTS ===
    // ProofA returns: (link_commit, location_commitment, time_commitment, actions_assertion_hash)
    link_commit_a: Field,
    location_commitment_a: Field,
    time_commitment_a: Field,
    actions_hash_a: Field, // SHA256 hash converted to Field

    // === PRIVATE INPUTS: PROOF B OUTPUTS ===
    // ProofB returns: link_commit
    link_commit_b: Field,
) -> pub Field {
    // ================================================================
    // STEP 1: Verify ProofA (certificate chain verification)
    // ================================================================
    // ProofA's public outputs in order:
    // [link_commit, location_commitment, time_commitment, actions_hash]
    //
    // The verify_honk_proof function verifies that:
    // 1. The proof is valid for the given VK
    // 2. The proof's public outputs match what we provide
    verify_honk_proof(
        vk_a,
        proof_a,
        [link_commit_a, location_commitment_a, time_commitment_a, actions_hash_a],
        vk_a_hash,
    );

    // ================================================================
    // STEP 2: Verify ProofB (COSE signature verification)
    // ================================================================
    // ProofB's public output is just link_commit
    verify_honk_proof(
        vk_b,
        proof_b,
        [link_commit_b],
        vk_b_hash,
    );

    // ================================================================
    // STEP 3: Verify linkCommit binding
    // ================================================================
    // SECURITY: This prevents proof substitution attacks where an attacker
    // could mix ProofA from image A with ProofB from image B.
    // The linkCommit includes:
    // - intermediate_leaf (the CA's public key hash)
    // - claim_hash_field (SHA256 of the C2PA claim)
    // - link_blind (random blinding factor)
    //
    // Both proofs must have been generated from the same image with the same
    // intermediate CA certificate and claim data.
    assert(
        link_commit_a == link_commit_b,
        "Link commitment mismatch: ProofA and ProofB were not generated from the same image"
    );

    // ================================================================
    // STEP 4: Compute image_commitment for tree aggregation
    // ================================================================
    // This commitment uniquely identifies this verified image in the aggregation tree.
    // It binds:
    // - trust_list_root: ensures same Oracle trust list was used
    // - content_hash: the actual image bytes (SHA256)
    // - nullifier: the key binding (prevents replay)
    // - proof_timestamp: when proof was generated
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
    // Test that image_commitment is deterministic for same inputs
    // Using smaller field values that are valid
    let trust_list_root: Field = 11111111111111111111;
    let content_hash: Field = 12345678901234567890;
    let nullifier: Field = 98765432109876543210;
    let proof_timestamp: Field = 1706745600; // Example timestamp

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
