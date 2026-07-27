// Minimal cross-party double-dip check (coNoir spike).
//
// Mirrors the apertrue x coNoir primitive at its smallest:
//   - each party's authentic content yields a nullifier  n = Poseidon2([content, scope])
//   - the consortium holds a private set of existing nullifiers (secret-shared in MPC)
//   - we reveal ONLY whether n is already present (a double-dip)
//
// Uses Poseidon2 + field equality only -> inside coNoir's supported lane.

global SET_SIZE: u32 = 4;

fn main(
    // private: this party's authenticated content fingerprint (e.g. apertrue content_hash)
    candidate_content: Field,
    // context binding (consortium / epoch); kept private here, can be made public later
    scope: Field,
    // private: the consortium's existing nullifiers (secret-shared across the MPC parties)
    existing: [Field; SET_SIZE],
) -> pub bool {
    // derive the nullifier with the Poseidon2 blackbox (permutation form, supported in MPC)
    let nullifier: Field = std::hash::poseidon2_permutation::<4>([candidate_content, scope, 0, 0])[0];

    // membership scan: collision == true means the item is already used somewhere
    let mut collision: bool = false;
    for i in 0..SET_SIZE {
        collision = collision | (existing[i] == nullifier);
    }

    // the ONLY thing revealed: the double-dip bit
    collision
}
