/// proof_b_es256_v2_core: ProofB ES256 v2 logic, generic over buffer sizes.
///
/// The size-class bins (proof_b_es256_v2, proof_b_es256_v2_large) are thin
/// wrappers that fix MAX_SIG_STRUCTURE_SIZE / MAX_CLAIM_SIZE and call
/// verify_proof_b_es256.
///
/// Versus proof_b_es256 (v1): cert_not_before / cert_not_after are no longer
/// inputs and the validity check is gone. ProofA v2 checks proof_timestamp
/// against dates parsed from the CA-signed leaf TBSCertificate, and the pair
/// is tied by nullifier (leaf key) and link_commit (intermediate + claim).
/// proof_timestamp stays a shared public input, range checked to u64 here.
///
/// This proves:
/// 1. A valid ES256 signature by the leaf key over SHA-256(sig_structure)
/// 2. claim_bytes are embedded in sig_structure at claim_offset_in_sig
/// 3. claim_hash = SHA-256(claim_bytes), and its Poseidon2 packing is public
/// 4. Optional: content_hash appears in the claim at content_hash_offset
/// 5. The intermediate leaf is in the trust list (Merkle membership)
/// 6. nullifier = pedersen_hash([content_hash, pedersen_hash([leaf_x, leaf_y])])
/// 7. Returns link_commit = pedersen_hash([intermediate_leaf, claim_hash_field, link_blind])

use std::ecdsa_secp256r1::verify_signature;
use std::hash::pedersen_hash;
use sha256::sha256_var;
use poseidon::poseidon2::Poseidon2;

pub mod test_vectors;

/// Depth of the Merkle tree for promoted intermediates
pub global MERKLE_TREE_DEPTH: u32 = 8;

/// Full ProofB ES256 v2 check. Returns link_commit.
pub fn verify_proof_b_es256<let S: u32, let C: u32>(
    trust_list_root: Field,
    content_hash: Field,
    nullifier: Field,
    proof_timestamp: Field,
    claim_hash_commitment: Field,
    cose_signature_ecdsa: [u8; 64],
    leaf_pubkey_x: [u8; 32],
    leaf_pubkey_y: [u8; 32],
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

    // STEP 1: ES256 COSE signature by the leaf key
    let cose_valid = verify_signature(
        leaf_pubkey_x,
        leaf_pubkey_y,
        cose_signature_ecdsa,
        cose_message_hash,
    );
    assert(cose_valid, "Invalid ECDSA COSE signature (ES256)");

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

    // STEP 7: nullifier from the leaf key
    let leaf_x_field = bytes_to_field(leaf_pubkey_x);
    let leaf_y_field = bytes_to_field(leaf_pubkey_y);
    let leaf_pubkey_hash = pedersen_hash([leaf_x_field, leaf_y_field]);
    let expected_nullifier = pedersen_hash([content_hash, leaf_pubkey_hash]);
    assert(nullifier == expected_nullifier, "Invalid nullifier");

    // STEP 8: proof_timestamp is shared with ProofA v2, which checks it
    // against the bound certificate dates. Here it is only range checked.
    assert(proof_timestamp as u64 as Field == proof_timestamp, "proof_timestamp exceeds u64");

    link_commit
}

/// Convert 32 bytes to Field (big-endian)
pub fn bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

/// Convert 32 bytes to 2 Field elements for Poseidon2 hashing
pub fn bytes32_to_field_array(bytes: [u8; 32]) -> [Field; 2] {
    let mut f0: Field = 0;
    for i in 0..16 {
        f0 = f0 * 256 + bytes[i] as Field;
    }
    let mut f1: Field = 0;
    for i in 16..32 {
        f1 = f1 * 256 + bytes[i] as Field;
    }
    [f0, f1]
}

/// Compute Merkle root from leaf and proof
pub fn compute_merkle_root(
    leaf: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [Field; MERKLE_TREE_DEPTH],
) -> Field {
    let mut current = leaf;
    for i in 0..MERKLE_TREE_DEPTH {
        assert((indices[i] == 0) | (indices[i] == 1), "Merkle index must be 0 or 1");
        let path_element = path[i];
        let is_right = indices[i];
        let left = if is_right == 0 { current } else { path_element };
        let right = if is_right == 0 { path_element } else { current };
        current = pedersen_hash([left, right]);
    }
    current
}

/// Verify that content_hash (Field) appears in claim_bytes at the offset.
/// Binds the public content_hash to the signed claim.
pub fn verify_content_hash_in_claim<let C: u32>(
    claim_bytes: [u8; C],
    content_hash_offset: u32,
    expected_content_hash: Field,
) {
    assert(content_hash_offset + 32 <= C, "Content hash offset out of bounds");
    let mut extracted_hash: Field = 0;
    for i in 0..32 {
        extracted_hash = extracted_hash * 256 + claim_bytes[content_hash_offset + i] as Field;
    }
    assert(
        extracted_hash == expected_content_hash,
        "Content hash binding failed: public content_hash does not match value in signed claim",
    );
}

/// Verify that inner_bytes[0..inner_length] appears at offset within outer_bytes
pub fn verify_bytes_embedded<let S: u32, let C: u32>(
    outer_bytes: [u8; S],
    outer_length: u32,
    inner_bytes: [u8; C],
    inner_length: u32,
    offset: u32,
) {
    assert(offset + inner_length <= outer_length, "Inner bytes would exceed outer bounds");
    for i in 0..C {
        if i < inner_length {
            let outer_idx = offset + i;
            assert(outer_bytes[outer_idx] == inner_bytes[i], "Embedded bytes mismatch");
        }
    }
}

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_link_commitment_with_claim_hash() {
    let commit = pedersen_hash([12345, 99999, 67890]);
    assert(commit == pedersen_hash([12345, 99999, 67890]));
    assert(commit != pedersen_hash([12345, 11111, 67890]));
}

#[test]
fn test_nullifier_derivation_ecdsa() {
    let nullifier = pedersen_hash([111, 222]);
    assert(nullifier != pedersen_hash([333, 222]));
}

#[test]
fn test_bytes_to_field() {
    let mut bytes: [u8; 32] = [0; 32];
    bytes[31] = 1;
    assert(bytes_to_field(bytes) == 1);
    bytes[31] = 255;
    assert(bytes_to_field(bytes) == 255);
}

#[test]
fn test_merkle_root_computation() {
    let path: [Field; MERKLE_TREE_DEPTH] = [1, 2, 3, 4, 5, 6, 7, 8];
    let indices: [Field; MERKLE_TREE_DEPTH] = [0, 1, 0, 1, 0, 1, 0, 1];
    let root1 = compute_merkle_root(12345, path, indices);
    assert(root1 == compute_merkle_root(12345, path, indices));
    assert(root1 != compute_merkle_root(12346, path, indices));
}

#[test]
fn test_content_hash_binding() {
    let mut claim_bytes: [u8; 2048] = [0; 2048];
    claim_bytes[131] = 1;
    verify_content_hash_in_claim(claim_bytes, 100, 1);
}

// End-to-end tests on the synthetic ES256 vector, at a small size class.
mod e2e {
    use super::{
        verify_proof_b_es256, bytes_to_field, bytes32_to_field_array, compute_merkle_root,
        MERKLE_TREE_DEPTH,
    };
    use super::test_vectors as tv;
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
        sig: [u8; 64],
        leaf_x: [u8; 32],
        leaf_y: [u8; 32],
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
        let content_hash = bytes_to_field(tv::CONTENT_HASH);
        let leaf_hash = pedersen_hash([bytes_to_field(tv::LEAF_X), bytes_to_field(tv::LEAF_Y)]);
        Case {
            trust_list_root: compute_merkle_root(intermediate_leaf, path, indices),
            content_hash,
            nullifier: pedersen_hash([content_hash, leaf_hash]),
            proof_timestamp: 1761572000,
            claim_hash_commitment: Poseidon2::hash(bytes32_to_field_array(tv::CLAIM_SHA256), 2),
            sig: tv::SIG,
            leaf_x: tv::LEAF_X,
            leaf_y: tv::LEAF_Y,
            msg_hash: tv::SIG_STRUCTURE_SHA256,
            intermediate_leaf,
            link_blind: 424242,
            path,
            indices,
            sig_structure: pad(tv::SIG_STRUCTURE),
            sig_structure_len: tv::SIG_STRUCTURE_LEN,
            claim: pad(tv::CLAIM),
            claim_len: tv::CLAIM_LEN,
            claim_offset: tv::CLAIM_OFFSET_IN_SIG,
            claim_hash: tv::CLAIM_SHA256,
            content_hash_offset: tv::CONTENT_HASH_OFFSET,
        }
    }

    fn run(c: Case) -> Field {
        verify_proof_b_es256(
            c.trust_list_root,
            c.content_hash,
            c.nullifier,
            c.proof_timestamp,
            c.claim_hash_commitment,
            c.sig,
            c.leaf_x,
            c.leaf_y,
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

    #[test(should_fail_with = "Sig_structure hash does not match COSE message hash")]
    fn test_tampered_sig_structure_rejected() {
        let mut c = good();
        c.sig_structure[100] = c.sig_structure[100] ^ 0x01;
        let _ = run(c);
    }

    #[test(should_fail_with = "Embedded bytes mismatch")]
    fn test_wrong_claim_offset_rejected() {
        let mut c = good();
        c.claim_offset = c.claim_offset + 1;
        let _ = run(c);
    }

    #[test(should_fail_with = "Invalid ECDSA COSE signature (ES256)")]
    fn test_other_leaf_key_rejected() {
        let mut c = good();
        c.leaf_y = tv::OTHER_LEAF_Y;
        let _ = run(c);
    }

    #[test(should_fail_with = "Content hash binding failed")]
    fn test_wrong_content_hash_rejected() {
        let mut c = good();
        c.content_hash = c.content_hash + 1;
        let _ = run(c);
    }

    #[test(should_fail_with = "Invalid nullifier")]
    fn test_wrong_nullifier_rejected() {
        let mut c = good();
        c.nullifier = c.nullifier + 1;
        let _ = run(c);
    }

    #[test(should_fail_with = "proof_timestamp exceeds u64")]
    fn test_oversized_timestamp_rejected() {
        let mut c = good();
        c.proof_timestamp = 0x10000000000000000;
        let _ = run(c);
    }
}
