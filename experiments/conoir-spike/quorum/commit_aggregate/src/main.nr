// commit_aggregate -- off-MPC anchor generator for the aggregate engine (marine over-insurance).
//
// Each authentic quantity (an insurer's line of cover, or the valuer's agreed value) is
// committed with a role-stamped anchor, exactly as in the membership engine:
//   anchor = Poseidon2([value, salt, signer_role], 3)
// Roles here: 3 = insurer line (the insurer signs its own exposure, free authenticity),
//             4 = valuer (the agreed value is signed by a valuer, never the owner).
//
// Run with `nargo execute` to obtain the four public anchors (3 lines + 1 agreed value).

use poseidon::poseidon2::Poseidon2;

fn anchor(value: Field, salt: Field, signer_role: Field) -> Field {
    Poseidon2::hash([value, salt, signer_role], 3)
}

fn main(values: [Field; 4], salts: [Field; 4], roles: [Field; 4]) -> pub [Field; 4] {
    [
        anchor(values[0], salts[0], roles[0]),
        anchor(values[1], salts[1], roles[1]),
        anchor(values[2], salts[2], roles[2]),
        anchor(values[3], salts[3], roles[3]),
    ]
}
