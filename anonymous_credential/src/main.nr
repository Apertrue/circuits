use binary_merkle_root::binary_merkle_root;
use ec::bjj::BabyJubJubParams;
use ec::Curve;
use ec::CurveTrait;
use ec::ScalarField;
use poseidon::poseidon::bn254::hash_2 as poseidon_hash;
use std::field::bn254::assert_lt;

pub global MAX_DEPTH: u32 = 20;

// Baby Jubjub subgroup order
global L: Field = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

fn main(
    // Private inputs
    secret_key: Field,
    index_bits: [u1; MAX_DEPTH],
    hash_path: [Field; MAX_DEPTH],
    merkle_proof_length: u32,
    // Public inputs
    hashed_scope: pub Field,
    hashed_message: pub Field,
) -> pub (Field, Field) {
    // 1. Range check: secret must be valid BJJ scalar (< subgroup order)
    assert_lt(secret_key, L);

    // 2. Derive Baby Jubjub public key from secret
    let generator: Curve<BabyJubJubParams> = CurveTrait::one();
    let secret_scalar: ScalarField<63> = ScalarField::from(secret_key);
    let pubkey = generator.mul(secret_scalar);

    // 3. Identity commitment = Poseidon(pubkey.x, pubkey.y)
    let identity_commitment = poseidon_hash([pubkey.x, pubkey.y]);

    // 4. Verify Merkle membership (variable depth, max 20)
    let root = binary_merkle_root(
        poseidon_hash,
        identity_commitment,
        merkle_proof_length,
        index_bits,
        hash_path,
    );

    // 5. Nullifier = Poseidon(scope, secret) -- deterministic per identity per scope
    let nullifier = poseidon_hash([hashed_scope, secret_key]);

    // 6. Constrain message (prevent proof malleability)
    let _msg_sq = hashed_message * hashed_message;

    (root, nullifier)
}

#[test]
fn test_nullifier_determinism() {
    // Same inputs should always produce the same nullifier
    let scope: Field = 12345;
    let secret: Field = 67890;
    let n1 = poseidon_hash([scope, secret]);
    let n2 = poseidon_hash([scope, secret]);
    assert(n1 == n2);
}

#[test]
fn test_different_scopes_different_nullifiers() {
    let secret: Field = 42;
    let n1 = poseidon_hash([1, secret]);
    let n2 = poseidon_hash([2, secret]);
    assert(n1 != n2);
}

#[test]
fn test_commitment_computation() {
    // Verify that BJJ scalar mul + Poseidon produces a valid commitment
    let secret: Field = 12345;
    let generator: Curve<BabyJubJubParams> = CurveTrait::one();
    let secret_scalar: ScalarField<63> = ScalarField::from(secret);
    let pubkey = generator.mul(secret_scalar);
    let commitment = poseidon_hash([pubkey.x, pubkey.y]);
    // Commitment should be non-zero
    assert(commitment != 0);
}
