// Depth-32 IMT non-membership at Colofon scale, for the coNoir MPC perf number.
//
// Mirrors the dominant cost of Colofon's sbom_non_membership per component:
//   - leaf-preimage hash (value, next_value, next_index)  -> Poseidon2
//   - low-leaf range check (low < key < next)             -> Field::lt
//   - 32-level Merkle path to the CVE-tree root           -> to_le_bits + Poseidon2
// batched over CHECKS components (Colofon MAX_SBOM_COMPONENTS = 50).
//
// CHECKS is patched by the run harness to sweep N=1 and N=50.

global DEPTH: u32 = 32;
global CHECKS: u32 = 50;

fn merkle_hash(l: Field, r: Field) -> Field {
    std::hash::poseidon2_permutation::<4>([l, r, 0, 0])[0]
}

fn main(
    key: [Field; CHECKS],                         // query keys (non-membership targets)
    low_key: [Field; CHECKS],                     // low leaf key
    next_key: [Field; CHECKS],                    // low leaf next key
    next_index: [Field; CHECKS],                  // low leaf next index (part of preimage)
    low_leaf_index: [Field; CHECKS],              // low leaf position in the tree
    sibling_path: [[Field; DEPTH]; CHECKS],       // per-check non-membership opening
) -> pub Field {                                  // accumulated roots (keeps work live)
    let mut acc: Field = 0;
    for c in 0..CHECKS {
        // low-leaf range check
        let in_range = low_key[c].lt(key[c]) & key[c].lt(next_key[c]);
        assert(in_range, "key not within low-leaf gap");

        // leaf preimage hash: Poseidon2(Poseidon2(low_key, next_key), next_index)
        let low_leaf = merkle_hash(merkle_hash(low_key[c], next_key[c]), next_index[c]);

        // 32-level Merkle path to the root
        let mut node = low_leaf;
        let bits: [bool; DEPTH] = low_leaf_index[c].to_le_bits();
        for i in 0..DEPTH {
            let (a, b) = if bits[i] {
                (sibling_path[c][i], node)
            } else {
                (node, sibling_path[c][i])
            };
            node = merkle_hash(a, b);
        }
        acc = acc + node;
    }
    acc
}
