use ec::bjj::BabyJubJubParams;
use ec::Curve;
use ec::CurveTrait;
use ec::ScalarField;
use poseidon::poseidon::bn254::hash_2 as poseidon_hash;
use std::field::bn254::assert_lt;

// Baby Jubjub subgroup order
global L: Field = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

fn main(secret_key: Field, commitment: pub Field) -> pub Field {
    // 1. Range check: secret must be valid BJJ scalar (< subgroup order)
    assert_lt(secret_key, L);

    // 2. Derive Baby Jubjub public key from secret
    let generator: Curve<BabyJubJubParams> = CurveTrait::one();
    let secret_scalar: ScalarField<63> = ScalarField::from(secret_key);
    let pubkey = generator.mul(secret_scalar);

    // 3. Compute commitment = Poseidon(pubkey.x, pubkey.y)
    let computed = poseidon_hash([pubkey.x, pubkey.y]);

    // 4. Verify computed commitment matches declared commitment
    assert(computed == commitment);

    computed
}

#[test]
fn test_valid_registration() {
    let secret: Field = 12345;
    let generator: Curve<BabyJubJubParams> = CurveTrait::one();
    let secret_scalar: ScalarField<63> = ScalarField::from(secret);
    let pubkey = generator.mul(secret_scalar);
    let commitment = poseidon_hash([pubkey.x, pubkey.y]);
    assert(commitment != 0);
    // This should pass since we compute the same commitment
    let result = main(secret, commitment);
    assert(result == commitment);
}
