// bound_aggregate -- Apertrue Quorum aggregate engine, under MPC (marine over-insurance).
//
// "Do the separate, legitimate lines of cover on this hull sum past its agreed value?"
//  -> reveal ONE bit, nothing else. No insurer sees another's line; the agreed value and
//     every line stay secret-shared; only over-insured / not crosses between them.
//
// Authenticity (the two-signer idea, adapted):
//   - each line is signed by the INSURER that wrote it (role 3): honest, free authenticity,
//     it vouches for its own exposure.
//   - the agreed value is signed by a VALUER (role 4), never the owner, who could inflate it.
// Both are bound to public, role-stamped anchors; a line signed with the wrong role, or an
// inflated value that does not open the valuer's anchor, is rejected.
//
// Same skeleton as the membership engine: bind authenticated inputs, run a predicate
// (here a sum against a threshold), reveal one bit. Simpler maths, no Merkle tree.

use poseidon::poseidon2::Poseidon2;

global N_LINES: u32 = 3;

fn anchor(value: Field, salt: Field, signer_role: Field) -> Field {
    Poseidon2::hash([value, salt, signer_role], 3)
}

fn main(
    // ---- PUBLIC ----
    line_anchor: pub [Field; N_LINES],   // each insurer's signed line anchor
    value_anchor: pub Field,             // the valuer-signed agreed-value anchor
    accepted_line_role: pub Field,       // allow-list: role an insurer line must carry (3)
    accepted_value_role: pub Field,      // allow-list: role the valuer must carry (4)
    // ---- PRIVATE (secret-shared) ----
    line: [Field; N_LINES],              // each insurer's cover amount
    line_salt: [Field; N_LINES],
    line_role: [Field; N_LINES],
    agreed_value: Field,                 // the valuer-attested hull value (never revealed)
    value_salt: Field,
    value_role: Field,
) -> pub bool {
    // bind each line to its insurer anchor, check the role, and total it up
    let mut total: Field = 0;
    for i in 0..N_LINES {
        assert(
            anchor(line[i], line_salt[i], line_role[i]) == line_anchor[i],
            "line anchor opening failed",
        );
        assert(line_role[i] == accepted_line_role, "line signer role not accepted");
        total = total + line[i];
    }

    // bind the agreed value to the valuer's anchor and check the role
    assert(anchor(agreed_value, value_salt, value_role) == value_anchor, "value anchor opening failed");
    assert(value_role == accepted_value_role, "value signer role not accepted");

    // over-insured if the lines sum past the agreed value
    (total as u64) > (agreed_value as u64)
}
