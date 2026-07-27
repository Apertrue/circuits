// proof_a_receivable -- Apertrue Quorum "Proof A" (per-party, single-prover, LOCAL).
//
// Replaces the off-circuit OpenSSL admission step with an in-circuit binding:
// it proves that an AUTHORISED, ROLE-BOUND signer put an ES256 signature on the
// receivable's canonical_id, and emits the role-stamped authenticity anchor as a
// PUBLIC output. That anchor becomes `candidate_anchor` for the joint
// `bound_receivables` MPC circuit -- so the one-bit answer provably rests on a
// real signer, not an asserted role.
//
//   canonical_id = Poseidon2([invoice_uuid, debtor_id, amount, issue_date], 4)
//   anchor       = Poseidon2([canonical_id, salt, signer_role], 3)
//
// The trust list binds (signer_key, role): a leaf is Poseidon2([x, y, role]), so a
// signer can only claim the role its authorised entry encodes (SdI root -> role 1,
// obligor root -> role 2). This closes "claim role 2 without being the obligor".
//
// Signature: ECDSA P-256 over the 32-byte big-endian encoding of canonical_id used
// directly as the digest (raw ECDSA; canonical_id is already a Poseidon2 commitment,
// so no extra SHA-256 wrapper is needed). The signer produces a raw ECDSA signature
// over be32(canonical_id) (e.g. `openssl pkeyutl -sign` over the 32-byte value).

use poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256r1::verify_signature;

global MERKLE_DEPTH: u32 = 8;

fn canonical_id(uuid: Field, debtor: Field, amount: Field, date: Field) -> Field {
    Poseidon2::hash([uuid, debtor, amount, date], 4)
}

fn anchor(cid: Field, salt: Field, signer_role: Field) -> Field {
    Poseidon2::hash([cid, salt, signer_role], 3)
}

// Interpret 32 big-endian bytes as a Field (reduces mod the BN254 prime, like proof_a).
fn be_bytes_to_field(b: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + b[i] as Field;
    }
    acc
}

// Depth-8 Poseidon2 Merkle root. indices[i] == 0 => current node is the LEFT child.
fn compute_merkle_root(
    leaf: Field,
    path: [Field; MERKLE_DEPTH],
    indices: [Field; MERKLE_DEPTH],
) -> Field {
    let mut current = leaf;
    for i in 0..MERKLE_DEPTH {
        let is_left = indices[i] == 0;
        let left = if is_left { current } else { path[i] };
        let right = if is_left { path[i] } else { current };
        current = Poseidon2::hash([left, right], 2);
    }
    current
}

fn main(
    // --- public ---
    trust_list_root: pub Field, // Quorum trust list (authorised signer (key,role) leaves)
    signer_role: pub Field,     // 1 = SdI clearance, 2 = obligor/debtor confirmation
    // --- private: the receivable ---
    invoice_uuid: Field,
    debtor_id: Field,
    amount: Field,
    issue_date: Field,
    salt: Field,
    // --- private: the signer's ES256 signature over canonical_id ---
    signer_pubkey_x: [u8; 32],
    signer_pubkey_y: [u8; 32],
    signature: [u8; 64],
    canonical_id_bytes: [u8; 32], // big-endian encoding of canonical_id (the signed message)
    // --- private: trust-list membership of (key, role) ---
    merkle_path: [Field; MERKLE_DEPTH],
    merkle_indices: [Field; MERKLE_DEPTH],
) -> pub Field {
    // 1. recompute canonical_id from the receivable fields
    let cid = canonical_id(invoice_uuid, debtor_id, amount, issue_date);

    // 2. the witnessed bytes must encode exactly that canonical_id (big-endian)
    assert(be_bytes_to_field(canonical_id_bytes) == cid, "canonical_id bytes != canonical_id");

    // 3. verify the signer's ECDSA P-256 signature over canonical_id (used as the digest)
    let sig_ok = verify_signature(signer_pubkey_x, signer_pubkey_y, signature, canonical_id_bytes);
    assert(sig_ok, "ECDSA P-256 signature over canonical_id failed");

    // 4. the (signer_key, role) pair must be an authorised leaf -> binds role to signer
    let x_f = be_bytes_to_field(signer_pubkey_x);
    let y_f = be_bytes_to_field(signer_pubkey_y);
    let leaf = Poseidon2::hash([x_f, y_f, signer_role], 3);
    let root = compute_merkle_root(leaf, merkle_path, merkle_indices);
    assert(root == trust_list_root, "signer (key, role) not in trust list");

    // 5. emit the role-stamped anchor -> becomes candidate_anchor for bound_receivables
    anchor(cid, salt, signer_role)
}
