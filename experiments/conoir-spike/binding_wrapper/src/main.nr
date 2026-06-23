// Option A -- the coNoir binding wrapper (CLIENT-SIDE, off-MPC).
//
// Recursively verifies an apertrue proof (mirroring one branch of the
// aggregators), then emits a blinded commitment to the VERIFIED nullifier.
// Production proof_a/proof_b are untouched; this layers on top of their output.
//
//   - verify_honk_proof binds `public_values` to the authentic apertrue proof.
//   - the nullifier is public_values[2] (a verified output, NOT a free witness).
//   - output C = Poseidon2(nullifier, blind) is the public authenticity anchor
//     that the MPC opening check later binds the secret-shared nullifier to.

use dep::bb_proof_verification::{UltraHonkZKProof, UltraHonkVerificationKey, verify_honk_proof};
use poseidon::poseidon2::Poseidon2;

fn main(
    proof: UltraHonkZKProof,             // private: the apertrue proof (stand-in)
    vk: UltraHonkVerificationKey,        // private
    public_values: [Field; 12],          // private: inner proof's public outputs
    vk_hash: Field,                      // private
    blind: Field,                        // private: fresh random blind
) -> pub Field {                         // public: C = Commit(nullifier, blind)
    // 1. Recursively verify the apertrue proof; binds public_values to it.
    verify_honk_proof(vk, proof, public_values, vk_hash);

    // 2. The nullifier is the VERIFIED public output at index 2.
    let nullifier = public_values[2];

    // 3. Emit the hiding commitment to the authentic nullifier.
    Poseidon2::hash([nullifier, blind], 2)
}
