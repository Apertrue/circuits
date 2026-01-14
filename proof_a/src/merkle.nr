use std::hash::pedersen_hash;

global MERKLE_TREE_DEPTH: u32 = 8;

pub fn compute_merkle_root(
    leaf: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [Field; MERKLE_TREE_DEPTH]
) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        let path_element = path[i];
        let is_right = indices[i];
        let left = if is_right == 0 { current } else { path_element };
        let right = if is_right == 0 { path_element } else { current };
        current = pedersen_hash([left, right]);
    }

    current
}

pub fn verify_merkle_membership(
    leaf: Field,
    root: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [Field; MERKLE_TREE_DEPTH]
) -> bool {
    let computed_root = compute_merkle_root(leaf, path, indices);
    computed_root == root
}
