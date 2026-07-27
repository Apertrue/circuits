use poseidon::poseidon2::Poseidon2;
global MERKLE_DEPTH: u32 = 8;

fn be_bytes_to_field(b: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + b[i] as Field;
    }
    acc
}

fn compute_merkle_root(leaf: Field, path: [Field; MERKLE_DEPTH], indices: [Field; MERKLE_DEPTH]) -> Field {
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
    signer_pubkey_x: [u8; 32],
    signer_pubkey_y: [u8; 32],
    signer_role: Field,
    merkle_path: [Field; MERKLE_DEPTH],
    merkle_indices: [Field; MERKLE_DEPTH],
) -> pub Field {
    let x_f = be_bytes_to_field(signer_pubkey_x);
    let y_f = be_bytes_to_field(signer_pubkey_y);
    let leaf = Poseidon2::hash([x_f, y_f, signer_role], 3);
    compute_merkle_root(leaf, merkle_path, merkle_indices)
}
