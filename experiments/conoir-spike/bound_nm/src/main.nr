// Bound double-dip check (coNoir spike) -- the apertrue <-> coNoir seam.
//
// Demonstrates the binding that makes this "authenticated MPC":
//   - commitment  = Commit(nullifier, blind) is a PUBLIC authenticity anchor.
//     In the real system apertrue's C2PA proof attests this commitment off-MPC
//     (verifying it reveals only the commitment, which is hiding -> leaks nothing).
//   - The party secret-shares (nullifier, blind) into the MPC.
//   - A lightweight in-MPC OPENING check binds the secret-shared values to the
//     public commitment -- so the nullifier being checked is provably the
//     authenticated one, without any node ever seeing it.
//   - Non-membership (double-dip) runs on the deterministic secret-shared
//     nullifier; only the collision bit is revealed.
//
// No recursive proof verification in MPC -- just a Poseidon2 opening check.

global SET_SIZE: u32 = 4;

fn commit(value: Field, blind: Field) -> Field {
    std::hash::poseidon2_permutation::<4>([value, blind, 0, 0])[0]
}

fn main(
    nullifier: Field,                 // private, secret-shared
    blind: Field,                     // private, secret-shared
    commitment: pub Field,            // public authenticity anchor (hiding)
    existing: [Field; SET_SIZE],      // private, secret-shared registry
) -> pub bool {
    // BINDING: the secret-shared (nullifier, blind) must open the public anchor.
    assert(commit(nullifier, blind) == commitment, "commitment opening failed");

    // DOUBLE-DIP: is this authenticated nullifier already present?
    let mut collision: bool = false;
    for i in 0..SET_SIZE {
        collision = collision | (existing[i] == nullifier);
    }
    collision
}
