// Minimal IMT non-membership primitive test for coNoir MPC.
//
// Isolates the two operations Colofon's check_non_membership needs that fall
// in coNoir's risk zone (bit-decomposition based):
//   1. Field::lt   -> the low-leaf range check (low_key < key < next_key)
//   2. to_le_bits  -> left/right selection while hashing the Merkle path
// Plus Poseidon2 (already proven supported). If this runs under MPC and
// verifies, the full Colofon IMT non-membership circuit will too.

global DEPTH: u32 = 8;

fn merkle_hash(l: Field, r: Field) -> Field {
    std::hash::poseidon2_permutation::<4>([l, r, 0, 0])[0]
}

fn main(
    key: Field,                       // candidate (query) key, the non-membership target
    low_key: Field,                   // low leaf's key
    next_key: Field,                  // low leaf's next key
    low_leaf_index: Field,            // low leaf's index in the tree
    sibling_path: [Field; DEPTH],     // non-membership Merkle opening for the low leaf
) -> pub Field {                      // returns the computed IMT root (public)
    // RISK OP 1: comparisons. Non-membership requires the key to sit strictly
    // inside the low leaf's gap. lt() lowers to bit decomposition.
    let in_range = low_key.lt(key) & key.lt(next_key);
    assert(in_range, "key not strictly within low-leaf gap");

    // RISK OP 2: to_le_bits drives left/right selection up the tree; Poseidon2 hashes.
    let low_leaf = merkle_hash(low_key, next_key);
    let mut node = low_leaf;
    let bits: [bool; DEPTH] = low_leaf_index.to_le_bits();
    for i in 0..DEPTH {
        let (a, b) = if bits[i] {
            (sibling_path[i], node)
        } else {
            (node, sibling_path[i])
        };
        node = merkle_hash(a, b);
    }
    node
}
