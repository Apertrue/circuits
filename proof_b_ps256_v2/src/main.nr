/// Apertrue ProofB PS256 v2 - RSA-PSS COSE Signature Verification
///
/// For C2PA claims signed PS256 (RSASSA-PSS, SHA-256, MGF1-SHA-256) by an
/// RSA-2048 leaf key with e = 65537 (e.g. Adobe). Pairs with ProofA v2 RSA
/// variants (proof_a_rsa_2048_v2, proof_a_rsa_4096_v2), which take the leaf
/// modulus from the CA-signed leaf TBSCertificate and derive the same
/// nullifier.
///
/// Versus proof_b_ps256 (v1):
/// - The leaf key is the 256-byte big-endian modulus; limbs are derived
///   in-circuit (range-safe), not supplied as free u128 limbs.
/// - The nullifier key hash covers ALL 18 modulus limbs
///   (cert_binding::rsa_key_hash). v1 hashed only the 8 low limbs, which an
///   attacker can match with a 2048-bit modulus they can factor.
/// - cert_not_before / cert_not_after are removed; ProofA v2 checks
///   proof_timestamp against the dates parsed from the signed leaf TBS.
///
/// This proves:
/// 1. A valid PS256 signature by the leaf key over SHA-256(sig_structure)
/// 2. claim_bytes are embedded in sig_structure at claim_offset_in_sig
/// 3. claim_hash = SHA-256(claim_bytes), and its Poseidon2 packing is public
/// 4. Optional: content_hash appears in the claim at content_hash_offset
/// 5. The intermediate leaf is in the trust list (Merkle membership)
/// 6. nullifier = pedersen_hash([content_hash, rsa_key_hash(leaf_modulus)])
/// 7. Returns link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])
///
/// PUBLIC LAYOUT (index: name; one Field each) - same as proof_b_es256_v2
///  0 trust_list_root
///  1 content_hash
///  2 nullifier              pedersen_hash([content_hash, rsa_key_hash(modulus)])
///  3 proof_timestamp        (range checked to u64 only)
///  4 claim_hash_commitment  Poseidon2(bytes32_to_field_array(claim_hash))
///  5 content_hash_offset    (0 = content hash not embedded in the claim)
/// Return value:
///  6 link_commit            pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])
/// Total 7.
///
/// Buffers: MAX_SIG_STRUCTURE_SIZE 8192 (RSA chains in the protected header
/// are large), MAX_CLAIM_SIZE 2048, as in v1.

use std::hash::pedersen_hash;
use sha256::sha256_var;
use poseidon::poseidon2::Poseidon2;
use noir_rsa::rsa::verify_sha256_pss;
use noir_rsa::types::RBN2048;
use bignum::params::BigNumParams;
use cert_binding::{be_bytes_to_limbs, rsa_key_hash};
use proof_b_es256_v2_core::{
    bytes_to_field, bytes32_to_field_array, compute_merkle_root, verify_bytes_embedded,
    verify_content_hash_in_claim, MERKLE_TREE_DEPTH,
};

/// Maximum size of COSE Sig_structure (CBOR encoded)
global MAX_SIG_STRUCTURE_SIZE: u32 = 8192;

/// Maximum size of C2PA claim (CBOR encoded)
global MAX_CLAIM_SIZE: u32 = 2048;

/// RSA-2048 uses 18 limbs of 120 bits
global RSA_NUM_LIMBS: u32 = 18;

fn main(
    // === PUBLIC INPUTS (shared with ProofA) ===
    trust_list_root: pub Field,
    content_hash: pub Field,
    nullifier: pub Field,
    proof_timestamp: pub Field,

    // === PUBLIC INPUT: Claim Hash Commitment (must match ProofA) ===
    claim_hash_commitment: pub Field,

    // === PRIVATE: RSA-PSS COSE SIGNATURE ===
    cose_signature_rsa: [u8; 256],        // big-endian signature
    leaf_rsa_modulus: [u8; 256],          // big-endian modulus (must be 2048 bits)
    leaf_rsa_redc_limbs: [u128; RSA_NUM_LIMBS], // Barrett parameter floor(2^4102 / n)
    pss_salt_len: u32,                    // 32 for SHA-256 (RFC 8230); 20 is seen too

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
    verify_proof_b_ps256(
        trust_list_root,
        content_hash,
        nullifier,
        proof_timestamp,
        claim_hash_commitment,
        cose_signature_rsa,
        leaf_rsa_modulus,
        leaf_rsa_redc_limbs,
        pss_salt_len,
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

/// Full ProofB PS256 v2 check, generic over buffer sizes. Returns link_commit.
fn verify_proof_b_ps256<let S: u32, let C: u32>(
    trust_list_root: Field,
    content_hash: Field,
    nullifier: Field,
    proof_timestamp: Field,
    claim_hash_commitment: Field,
    cose_signature_rsa: [u8; 256],
    leaf_rsa_modulus: [u8; 256],
    leaf_rsa_redc_limbs: [u128; RSA_NUM_LIMBS],
    pss_salt_len: u32,
    cose_message_hash: [u8; 32],
    intermediate_leaf: Field,
    link_blind: Field,
    merkle_path: [Field; MERKLE_TREE_DEPTH],
    merkle_indices: [Field; MERKLE_TREE_DEPTH],
    sig_structure_bytes: [u8; S],
    sig_structure_length: u32,
    claim_bytes: [u8; C],
    claim_length: u32,
    claim_offset_in_sig: u32,
    claim_hash: [u8; 32],
    content_hash_offset: u32,
) -> Field {
    // STEP 0: claim hash commitment (public packing of claim_hash)
    let computed_claim_commitment = Poseidon2::hash(bytes32_to_field_array(claim_hash), 2);
    assert(computed_claim_commitment == claim_hash_commitment, "Claim hash commitment mismatch");

    // STEP 1: PS256 COSE signature by the leaf key (e = 65537)
    assert(leaf_rsa_modulus[0] >= 0x80, "RSA modulus is not 2048 bits");
    let modulus_limbs: [u128; RSA_NUM_LIMBS] = be_bytes_to_limbs(leaf_rsa_modulus);
    let params: BigNumParams<18, 2048> = BigNumParams::new(false, modulus_limbs, leaf_rsa_redc_limbs);
    let signature: RBN2048 = RBN2048::from_be_bytes(params, cose_signature_rsa);
    let rsa_valid = verify_sha256_pss(cose_message_hash, signature, 65537, pss_salt_len);
    assert(rsa_valid, "Invalid RSA COSE signature (PS256)");

    // STEP 2: the signed hash is SHA-256(sig_structure)
    assert(sig_structure_length <= S, "sig_structure_length exceeds buffer");
    let computed_sig_hash = sha256_var(sig_structure_bytes, sig_structure_length);
    assert(computed_sig_hash == cose_message_hash, "Sig_structure hash does not match COSE message hash");

    // STEP 3: claim_bytes embedded in sig_structure
    verify_bytes_embedded(
        sig_structure_bytes,
        sig_structure_length,
        claim_bytes,
        claim_length,
        claim_offset_in_sig,
    );

    // STEP 4: claim_hash = SHA-256(claim_bytes)
    assert(claim_length <= C, "claim_length exceeds buffer");
    let computed_claim_hash = sha256_var(claim_bytes, claim_length);
    assert(computed_claim_hash == claim_hash, "Claim hash mismatch - claim_bytes integrity violated");

    // STEP 4b: optional content_hash binding (offset 0 = not embedded)
    if content_hash_offset != 0 {
        verify_content_hash_in_claim(claim_bytes, content_hash_offset, content_hash);
    }

    // STEP 5: intermediate in trust list
    let computed_root = compute_merkle_root(intermediate_leaf, merkle_path, merkle_indices);
    assert(computed_root == trust_list_root, "Intermediate not in trust list");

    // STEP 6: link commitment (returned)
    let claim_hash_field = bytes_to_field(claim_hash);
    let link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind]);

    // STEP 7: nullifier from the FULL leaf modulus
    let leaf_key_hash = rsa_key_hash::<256, 18>(leaf_rsa_modulus);
    let expected_nullifier = pedersen_hash([content_hash, leaf_key_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");

    // STEP 8: proof_timestamp is shared with ProofA v2, which checks it
    // against the bound certificate dates. Here it is only range checked.
    assert(proof_timestamp as u64 as Field == proof_timestamp, "proof_timestamp exceeds u64");

    link_commit
}

// ====================================================================
// TESTS (synthetic PS256 vector at a small size class)
// ====================================================================

mod e2e {
    use super::{verify_proof_b_ps256, RSA_NUM_LIMBS};
    use cert_binding::rsa_key_hash;
    use cert_binding::rsa_vectors as rv;
    use proof_b_es256_v2_core::{bytes_to_field, bytes32_to_field_array, compute_merkle_root, MERKLE_TREE_DEPTH};
    use std::hash::pedersen_hash;
    use poseidon::poseidon2::Poseidon2;

    global S: u32 = 512;
    global C: u32 = 256;

    pub struct Case {
        trust_list_root: Field,
        content_hash: Field,
        nullifier: Field,
        proof_timestamp: Field,
        claim_hash_commitment: Field,
        sig: [u8; 256],
        modulus: [u8; 256],
        redc: [u128; RSA_NUM_LIMBS],
        salt_len: u32,
        msg_hash: [u8; 32],
        intermediate_leaf: Field,
        link_blind: Field,
        path: [Field; MERKLE_TREE_DEPTH],
        indices: [Field; MERKLE_TREE_DEPTH],
        sig_structure: [u8; S],
        sig_structure_len: u32,
        claim: [u8; C],
        claim_len: u32,
        claim_offset: u32,
        claim_hash: [u8; 32],
        content_hash_offset: u32,
    }

    fn pad<let M: u32, let B: u32>(a: [u8; M]) -> [u8; B] {
        let mut out: [u8; B] = [0; B];
        for i in 0..M {
            out[i] = a[i];
        }
        out
    }

    fn good() -> Case {
        let intermediate_leaf = pedersen_hash([7, 8]);
        let path: [Field; MERKLE_TREE_DEPTH] = [11, 12, 13, 14, 15, 16, 17, 18];
        let indices: [Field; MERKLE_TREE_DEPTH] = [1, 0, 1, 1, 0, 0, 1, 0];
        let content_hash = bytes_to_field(rv::PS_CONTENT_HASH);
        let leaf_hash = rsa_key_hash::<256, 18>(rv::SYN_RSA_LEAF_MODULUS);
        Case {
            trust_list_root: compute_merkle_root(intermediate_leaf, path, indices),
            content_hash,
            nullifier: pedersen_hash([content_hash, leaf_hash]),
            proof_timestamp: 1761572000,
            claim_hash_commitment: Poseidon2::hash(bytes32_to_field_array(rv::PS_CLAIM_SHA256), 2),
            sig: rv::PS_SIG,
            modulus: rv::SYN_RSA_LEAF_MODULUS,
            redc: rv::SYN_RSA_LEAF_REDC,
            salt_len: 32,
            msg_hash: rv::PS_SIG_STRUCTURE_SHA256,
            intermediate_leaf,
            link_blind: 424242,
            path,
            indices,
            sig_structure: pad(rv::PS_SIG_STRUCTURE),
            sig_structure_len: rv::PS_SIG_STRUCTURE_LEN,
            claim: pad(rv::PS_CLAIM),
            claim_len: rv::PS_CLAIM_LEN,
            claim_offset: rv::PS_CLAIM_OFFSET_IN_SIG,
            claim_hash: rv::PS_CLAIM_SHA256,
            content_hash_offset: rv::PS_CONTENT_HASH_OFFSET,
        }
    }

    fn run(c: Case) -> Field {
        verify_proof_b_ps256(
            c.trust_list_root,
            c.content_hash,
            c.nullifier,
            c.proof_timestamp,
            c.claim_hash_commitment,
            c.sig,
            c.modulus,
            c.redc,
            c.salt_len,
            c.msg_hash,
            c.intermediate_leaf,
            c.link_blind,
            c.path,
            c.indices,
            c.sig_structure,
            c.sig_structure_len,
            c.claim,
            c.claim_len,
            c.claim_offset,
            c.claim_hash,
            c.content_hash_offset,
        )
    }

    #[test]
    fn test_valid_vector_returns_link_commit() {
        let c = good();
        let expected = pedersen_hash([c.intermediate_leaf, bytes_to_field(c.claim_hash), c.link_blind]);
        assert(run(c) == expected);
    }

    // noir_rsa's PSS decoding fails an unlabelled internal assertion (e.g. the
    // 0xbc trailer) before returning false, so these use plain should_fail.
    #[test(should_fail)]
    fn test_other_leaf_key_rejected() {
        // Another RSA-2048 key did not make this signature.
        let mut c = good();
        c.modulus = rv::SYN_OTHER_RSA2048_MODULUS;
        c.redc = rv::SYN_OTHER_RSA2048_REDC;
        let _ = run(c);
    }

    #[test(should_fail_with = "Invalid nullifier")]
    fn test_nullifier_from_low_limbs_only_rejected() {
        // A nullifier built the v1 way (8 low limbs) does not match.
        let mut c = good();
        let l: [u128; 18] = cert_binding::be_bytes_to_limbs(rv::SYN_RSA_LEAF_MODULUS);
        let v1_hash = pedersen_hash([
            l[0] as Field, l[1] as Field, l[2] as Field, l[3] as Field,
            l[4] as Field, l[5] as Field, l[6] as Field, l[7] as Field,
        ]);
        c.nullifier = pedersen_hash([c.content_hash, v1_hash]);
        let _ = run(c);
    }

    #[test(should_fail_with = "Sig_structure hash does not match COSE message hash")]
    fn test_tampered_sig_structure_rejected() {
        let mut c = good();
        c.sig_structure[100] = c.sig_structure[100] ^ 0x01;
        let _ = run(c);
    }

    #[test(should_fail)]
    fn test_wrong_salt_len_rejected() {
        let mut c = good();
        c.salt_len = 20;
        let _ = run(c);
    }

    #[test(should_fail_with = "Content hash binding failed")]
    fn test_wrong_content_hash_rejected() {
        let mut c = good();
        c.content_hash = c.content_hash + 1;
        let _ = run(c);
    }
}
