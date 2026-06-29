// commit_receivable -- off-MPC anchor generator for Apertrue Quorum (receivables).
//
// Mirrors Layer 1: a non-fraudster signs the receivable value over the CANONICAL FIELDS,
// C2PA carries it, and the local proof emits a PUBLIC, role-bound authenticity anchor:
//
//   canonical_id = Poseidon2([invoice_uuid, debtor_id, amount, issue_date], 4)
//   anchor       = Poseidon2([canonical_id, salt, signer_role], 3)
//
// signer_role binds WHO attested into the anchor itself, so an SdI-clearance anchor and an
// obligor (debtor-confirmation) anchor for the same receivable are DISTINCT values and
// cannot be swapped. The role determines the GUARANTEE the proof carries:
//   role 1 (SdI clearance) -> "uniquely-identified, cleared, not financed elsewhere"
//   role 2 (obligor/debtor) -> "the debt is genuinely owed"  (the stronger claim)
//
// Run headless with `nargo execute` to obtain (canonical_id, anchor).

use poseidon::poseidon2::Poseidon2;

fn canonical_id(uuid: Field, debtor: Field, amount: Field, date: Field) -> Field {
    Poseidon2::hash([uuid, debtor, amount, date], 4)
}

fn anchor(cid: Field, salt: Field, signer_role: Field) -> Field {
    Poseidon2::hash([cid, salt, signer_role], 3)
}

fn main(
    invoice_uuid: Field,
    debtor_id: Field,
    amount: Field,
    issue_date: Field,
    salt: Field,
    signer_role: Field, // 1 = SdI clearance, 2 = obligor/debtor confirmation
) -> pub [Field; 2] {
    let cid = canonical_id(invoice_uuid, debtor_id, amount, issue_date);
    [cid, anchor(cid, salt, signer_role)]
}
