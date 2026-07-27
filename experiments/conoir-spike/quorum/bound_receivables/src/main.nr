// bound_receivables -- Apertrue Quorum double-financing check, under MPC, with the
// acceptable-anchor allow-list and per-signer guarantee.
//
// "Before a lender advances cash, does this EXACT receivable already appear in any lender's
//  book across the network?" -> reveal ONE bit, plus WHICH guarantee the anchor carries.
//
// Two distinct signer roles defend different frauds (the spine of the thesis):
//   role 1 SdI clearance -> proves "uniquely identified, cleared, not financed elsewhere".
//                           Catches DOUBLE-PLEDGING of real invoices. Does NOT prove the
//                           debt is real -- a seller can clear a fabricated/inflated invoice.
//   role 2 obligor/debtor -> proves "the debt is genuinely owed". Also catches FABRICATION
//                            and INFLATION, because the debtor will not sign a lie.
// (First Brands was BOTH double-pledging AND fabricated/inflated invoices. Clearance alone
//  catches the former; the obligor catches the latter. Together = the honest answer.)
//
// Bindings enforced here:
//   1. the secret-shared fields open the public, ROLE-BOUND anchor (authenticated query);
//   2. the signer_role is in the acceptable-anchor ALLOW-LIST (a seller's own signature,
//      role 3, is rejected here -- the fraudster cannot be the trusted signer).
// The inner signature verification + role assignment happen OFF-MPC in admission (Layer 2),
// against the trust list; this circuit binds to its role-stamped output.

use poseidon::poseidon2::Poseidon2;

global BOOK_UNION: u32 = 6;    // already-financed fingerprints across the network
global ALLOW_LIST: u32 = 2;    // size of the acceptable-anchor allow-list

fn canonical_id(uuid: Field, debtor: Field, amount: Field, date: Field) -> Field {
    Poseidon2::hash([uuid, debtor, amount, date], 4)
}

fn anchor(cid: Field, salt: Field, signer_role: Field) -> Field {
    Poseidon2::hash([cid, salt, signer_role], 3)
}

fn main(
    // ---- PUBLIC ----
    candidate_anchor: pub Field,             // role-bound authenticity anchor (from admission)
    signer_role: pub Field,                  // 1 = SdI clearance, 2 = obligor
    accepted_roles: pub [Field; ALLOW_LIST], // the acceptable-anchor allow-list
    // ---- PRIVATE (secret-shared) ----
    invoice_uuid: Field,
    debtor_id: Field,
    amount: Field,
    issue_date: Field,
    salt: Field,
    financed: [Field; BOOK_UNION],           // network's already-financed fingerprints
) -> pub (bool, Field) {
    let cid = canonical_id(invoice_uuid, debtor_id, amount, issue_date);

    // 1. AUTHENTICATED QUERY: fields must open the role-bound anchor.
    assert(anchor(cid, salt, signer_role) == candidate_anchor, "candidate anchor opening failed");

    // 2. ALLOW-LIST: the signer role must be acceptable (rejects e.g. a seller self-signature).
    let mut role_ok: bool = false;
    for i in 0..ALLOW_LIST {
        role_ok = role_ok | (accepted_roles[i] == signer_role);
    }
    assert(role_ok, "signer role not in acceptable-anchor allow-list");

    // 3. DOUBLE-DIP: is this exact receivable already financed anywhere in the network?
    let mut already_financed: bool = false;
    for i in 0..BOOK_UNION {
        already_financed = already_financed | (financed[i] == cid);
    }

    // reveal the bit + the role (which fixes the guarantee the proof carries)
    (already_financed, signer_role)
}
