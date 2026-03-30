use dep::poseidon::poseidon2::Poseidon2;

// Maximum Merkle tree depth (supports up to 256 images per batch)
global MAX_TREE_DEPTH: u32 = 8;

/// Selective Disclosure Circuit v2
///
/// Proves that a specific image commitment is included in a batch that was
/// verified on Aztec, without revealing the image's private data.
///
/// Trust chain:
///   image_commitment (recomputed from private inputs)
///   -> Merkle path to root_commitment (verified in-circuit)
///   -> root_commitment's nullifier exists on Aztec (checked externally)
///
/// The batch nullifier is a PUBLIC input -- the verifier checks its existence
/// in Aztec's global nullifier tree independently.
///
/// v2 expansion: Adds location bounding box proofs, time range proofs,
/// device identity disclosure, and provenance hash disclosure.
///
/// Public inputs (17 total):
///   root_commitment, nullifier, contract_address,
///   disclosed_content_hash, disclosed_trust_list_root, disclosed_proof_timestamp,
///   disclosed_lat_min, disclosed_lat_max, disclosed_lon_min, disclosed_lon_max,
///   disclosed_location_flags, disclosed_time_min, disclosed_time_max,
///   disclosed_edit_time_min, disclosed_edit_time_max,
///   disclosed_link_commit, disclosed_actions_hash
fn main(
    // === Public inputs (3 anchoring fields) ===
    root_commitment: pub Field,
    nullifier: pub Field,
    contract_address: pub Field,
    // === Selectively disclosed outputs (0 if hidden) ===
    disclosed_content_hash: pub Field,
    disclosed_trust_list_root: pub Field,
    disclosed_proof_timestamp: pub Field,
    // === NEW v2: Location bounding box (0 if hidden) ===
    disclosed_lat_min: pub Field,
    disclosed_lat_max: pub Field,
    disclosed_lon_min: pub Field,
    disclosed_lon_max: pub Field,
    disclosed_location_flags: pub Field,
    // === NEW v2: Time range (0 if hidden) ===
    disclosed_time_min: pub Field,
    disclosed_time_max: pub Field,
    // === NEW v2: Edit time range (0 if hidden or no edit) ===
    disclosed_edit_time_min: pub Field,
    disclosed_edit_time_max: pub Field,
    // === NEW v2: Device and provenance (0 if hidden) ===
    disclosed_link_commit: pub Field,
    disclosed_actions_hash: pub Field,
    // === Private inputs: original commitment fields ===
    trust_list_root: Field,
    content_hash: Field,
    image_nullifier: Field,
    proof_timestamp: Field,
    // === NEW v2: commitment fields from image aggregator ===
    location_commitment: Field,
    time_commitment: Field,
    link_commit: Field,
    actions_hash_field: Field,
    // === NEW v2: exact values for location range proof ===
    exact_lat_scaled: Field,
    exact_lon_scaled: Field,
    exact_lat_is_negative: Field,
    exact_lon_is_negative: Field,
    location_salt: Field,
    // === NEW v2: exact values for time range proof ===
    exact_timestamp: Field,
    time_salt: Field,
    // === NEW v2: edit time commitment fields ===
    edit_time_commitment: Field,
    exact_edit_timestamp: Field,
    edit_time_salt: Field,
    // === Merkle path (leaf to root) ===
    sibling_path: [Field; MAX_TREE_DEPTH],
    path_indices: [Field; MAX_TREE_DEPTH],
    path_depth: Field,
    // === Disclosure flags (0 or 1) ===
    disclose_content_hash: Field,
    disclose_trust_list_root: Field,
    disclose_proof_timestamp: Field,
    // === NEW v2: disclosure flags ===
    disclose_location_range: Field,
    disclose_time_range: Field,
    disclose_edit_time_range: Field,
    disclose_device: Field,
    disclose_actions: Field,
) {
    // Suppress unused warnings -- these are public inputs checked externally
    let _ = nullifier;
    let _ = contract_address;

    // --- 1. Recompute image commitment (must match image_aggregator v3 with edit_time) ---
    let image_commitment = Poseidon2::hash(
        [
            trust_list_root, content_hash, image_nullifier, proof_timestamp,
            location_commitment, time_commitment, edit_time_commitment,
            link_commit, actions_hash_field,
        ],
        9,
    );

    // --- 2. Walk Merkle path from leaf to root ---
    // For single-image batches (path_depth == 0), the leaf IS the root.
    let mut current = image_commitment;
    let depth = path_depth as u32;
    assert(path_depth as u32 as Field == path_depth, "path_depth does not fit in u32");
    assert(depth <= MAX_TREE_DEPTH, "path_depth exceeds MAX_TREE_DEPTH");

    for i in 0..MAX_TREE_DEPTH {
        if i < depth {
            let index = path_indices[i];
            assert((index == 0) | (index == 1), "path_indices must be 0 or 1");

            let sibling = sibling_path[i];

            let left = if index == 0 { current } else { sibling };
            let right = if index == 0 { sibling } else { current };

            current = Poseidon2::hash([left, right], 2);
        }
    }

    // --- 3. Assert computed root matches public root_commitment ---
    assert(current == root_commitment, "Merkle path does not lead to root_commitment");

    // --- 4. Enforce all disclosure flags are boolean ---
    assert(
        (disclose_content_hash == 0) | (disclose_content_hash == 1),
        "disclose_content_hash must be 0 or 1",
    );
    assert(
        (disclose_trust_list_root == 0) | (disclose_trust_list_root == 1),
        "disclose_trust_list_root must be 0 or 1",
    );
    assert(
        (disclose_proof_timestamp == 0) | (disclose_proof_timestamp == 1),
        "disclose_proof_timestamp must be 0 or 1",
    );
    assert(
        (disclose_location_range == 0) | (disclose_location_range == 1),
        "disclose_location_range must be 0 or 1",
    );
    assert(
        (disclose_time_range == 0) | (disclose_time_range == 1),
        "disclose_time_range must be 0 or 1",
    );
    assert(
        (disclose_device == 0) | (disclose_device == 1),
        "disclose_device must be 0 or 1",
    );
    assert(
        (disclose_edit_time_range == 0) | (disclose_edit_time_range == 1),
        "disclose_edit_time_range must be 0 or 1",
    );
    assert(
        (disclose_actions == 0) | (disclose_actions == 1),
        "disclose_actions must be 0 or 1",
    );

    // --- 5. Constrain original disclosed outputs (v1 fields) ---
    assert(
        disclosed_content_hash == content_hash * disclose_content_hash,
        "disclosed_content_hash mismatch",
    );
    assert(
        disclosed_trust_list_root == trust_list_root * disclose_trust_list_root,
        "disclosed_trust_list_root mismatch",
    );
    assert(
        disclosed_proof_timestamp == proof_timestamp * disclose_proof_timestamp,
        "disclosed_proof_timestamp mismatch",
    );

    // SECURITY: Constrain sign flags to boolean
    assert((exact_lat_is_negative == 0) | (exact_lat_is_negative == 1), "exact_lat_is_negative must be 0 or 1");
    assert((exact_lon_is_negative == 0) | (exact_lon_is_negative == 1), "exact_lon_is_negative must be 0 or 1");

    // --- 6. Verify location_commitment preimage ---
    // location_commitment = Poseidon2([lat, lon, lat_sign, lon_sign, salt], 5)
    let computed_location = Poseidon2::hash(
        [exact_lat_scaled, exact_lon_scaled, exact_lat_is_negative, exact_lon_is_negative, location_salt],
        5,
    );
    assert(
        computed_location == location_commitment,
        "location_commitment preimage mismatch",
    );

    // --- 7. Verify time_commitment preimage ---
    // time_commitment = Poseidon2([timestamp, salt], 2)
    let computed_time = Poseidon2::hash(
        [exact_timestamp, time_salt],
        2,
    );
    assert(
        computed_time == time_commitment,
        "time_commitment preimage mismatch",
    );

    // --- 7b. Verify edit_time_commitment preimage ---
    if exact_edit_timestamp != 0 {
        let computed_edit_time = Poseidon2::hash([exact_edit_timestamp, edit_time_salt], 2);
        assert(computed_edit_time == edit_time_commitment, "edit_time_commitment preimage mismatch");
    } else {
        assert(edit_time_commitment == 0, "edit_time_commitment must be 0 when no edit");
    }

    // --- 8. Location bounding box range proof ---
    // If disclosing location range: verify exact coords fall within disclosed bounds.
    // Sign bits in disclosed_location_flags encode whether bounds are negative.
    // All comparisons done via u64 cast (coordinates are scaled positive integers).
    if disclose_location_range == 1 {
        assert(exact_lat_scaled as u64 as Field == exact_lat_scaled, "exact_lat_scaled exceeds u64");
        assert(disclosed_lat_min as u64 as Field == disclosed_lat_min, "disclosed_lat_min exceeds u64");
        assert(disclosed_lat_max as u64 as Field == disclosed_lat_max, "disclosed_lat_max exceeds u64");
        assert(exact_lon_scaled as u64 as Field == exact_lon_scaled, "exact_lon_scaled exceeds u64");
        assert(disclosed_lon_min as u64 as Field == disclosed_lon_min, "disclosed_lon_min exceeds u64");
        assert(disclosed_lon_max as u64 as Field == disclosed_lon_max, "disclosed_lon_max exceeds u64");

        let lat = exact_lat_scaled as u64;
        let lat_min = disclosed_lat_min as u64;
        let lat_max = disclosed_lat_max as u64;
        assert(lat >= lat_min, "latitude below minimum bound");
        assert(lat <= lat_max, "latitude above maximum bound");

        let lon = exact_lon_scaled as u64;
        let lon_min = disclosed_lon_min as u64;
        let lon_max = disclosed_lon_max as u64;
        assert(lon >= lon_min, "longitude below minimum bound");
        assert(lon <= lon_max, "longitude above maximum bound");

        // Verify sign bits match actual signs
        // disclosed_location_flags encodes: bit0 = lat_neg, bit1 = lon_neg
        // The exact coordinate signs must match the disclosed signs.
        let disclosed_location_flags_u8 = disclosed_location_flags as u8;
        assert(disclosed_location_flags_u8 <= 3, "disclosed_location_flags must only use bits 0-1");
        let disclosed_lat_neg = (disclosed_location_flags_u8 & 1) as Field;
        let disclosed_lon_neg = ((disclosed_location_flags_u8 >> 1) & 1) as Field;
        assert(disclosed_lat_neg == exact_lat_is_negative, "disclosed latitude sign does not match exact latitude sign");
        assert(disclosed_lon_neg == exact_lon_is_negative, "disclosed longitude sign does not match exact longitude sign");
    } else {
        // When not disclosing: all location public inputs must be zero
        assert(disclosed_lat_min == 0, "disclosed_lat_min must be 0 when hidden");
        assert(disclosed_lat_max == 0, "disclosed_lat_max must be 0 when hidden");
        assert(disclosed_lon_min == 0, "disclosed_lon_min must be 0 when hidden");
        assert(disclosed_lon_max == 0, "disclosed_lon_max must be 0 when hidden");
        assert(disclosed_location_flags == 0, "disclosed_location_flags must be 0 when hidden");
    }

    // --- 9. Time range proof ---
    // If disclosing time range: verify exact timestamp falls within disclosed bounds.
    if disclose_time_range == 1 {
        assert(exact_timestamp as u64 as Field == exact_timestamp, "exact_timestamp exceeds u64");
        assert(disclosed_time_min as u64 as Field == disclosed_time_min, "disclosed_time_min exceeds u64");
        assert(disclosed_time_max as u64 as Field == disclosed_time_max, "disclosed_time_max exceeds u64");

        let ts = exact_timestamp as u64;
        let ts_min = disclosed_time_min as u64;
        let ts_max = disclosed_time_max as u64;
        assert(ts >= ts_min, "timestamp below minimum bound");
        assert(ts <= ts_max, "timestamp above maximum bound");
    } else {
        assert(disclosed_time_min == 0, "disclosed_time_min must be 0 when hidden");
        assert(disclosed_time_max == 0, "disclosed_time_max must be 0 when hidden");
    }

    // --- 9b. Edit time range proof ---
    if disclose_edit_time_range == 1 {
        assert(exact_edit_timestamp != 0, "Cannot disclose edit time with no edit");
        assert(exact_edit_timestamp as u64 as Field == exact_edit_timestamp, "exact_edit_timestamp exceeds u64");
        assert(disclosed_edit_time_min as u64 as Field == disclosed_edit_time_min, "disclosed_edit_time_min exceeds u64");
        assert(disclosed_edit_time_max as u64 as Field == disclosed_edit_time_max, "disclosed_edit_time_max exceeds u64");

        let ts = exact_edit_timestamp as u64;
        let ts_min = disclosed_edit_time_min as u64;
        let ts_max = disclosed_edit_time_max as u64;
        assert(ts >= ts_min, "edit timestamp below minimum");
        assert(ts <= ts_max, "edit timestamp above maximum");
    } else {
        assert(disclosed_edit_time_min == 0, "disclosed_edit_time_min must be 0 when hidden");
        assert(disclosed_edit_time_max == 0, "disclosed_edit_time_max must be 0 when hidden");
    }

    // --- 10. Device identity disclosure ---
    // If disclosing: disclosed value must equal actual link_commit
    // If hidden: disclosed value must be zero
    if disclose_device == 1 {
        assert(
            disclosed_link_commit == link_commit,
            "disclosed_link_commit does not match actual link_commit",
        );
    } else {
        assert(disclosed_link_commit == 0, "disclosed_link_commit must be 0 when hidden");
    }

    // --- 11. Actions/provenance hash disclosure ---
    if disclose_actions == 1 {
        assert(
            disclosed_actions_hash == actions_hash_field,
            "disclosed_actions_hash does not match actual actions_hash_field",
        );
    } else {
        assert(disclosed_actions_hash == 0, "disclosed_actions_hash must be 0 when hidden");
    }
}

// ====================================================================
// TESTS
// ====================================================================

#[test]
fn test_single_image_v2_all_disclosed() {
    // Single image: commitment IS the root (path_depth = 0)
    let trust_list_root = 0x1234;
    let content_hash = 0x5678;
    let image_nullifier = 0x9abc;
    let proof_timestamp = 0xdef0;
    let location_commitment_val = Poseidon2::hash([100, 200, 0, 1, 999], 5);
    let time_commitment_val = Poseidon2::hash([1706745600, 888], 2);
    let edit_time_commitment_val = Poseidon2::hash([1709000000, 777], 2);
    let link_commit_val: Field = 0xaaaa;
    let actions_bytes: [Field; 32] = [0; 32];
    let actions_hash_val = Poseidon2::hash(actions_bytes, 32);

    let commitment = Poseidon2::hash(
        [trust_list_root, content_hash, image_nullifier, proof_timestamp,
         location_commitment_val, time_commitment_val, edit_time_commitment_val,
         link_commit_val, actions_hash_val],
        9,
    );

    main(
        commitment,           // root_commitment = leaf commitment
        0xffff,               // nullifier (not checked in circuit)
        0xeeee,               // contract_address (not checked in circuit)
        content_hash,         // disclosed (flag=1)
        trust_list_root,      // disclosed (flag=1)
        proof_timestamp,      // disclosed (flag=1)
        50,                   // disclosed_lat_min
        150,                  // disclosed_lat_max
        100,                  // disclosed_lon_min
        300,                  // disclosed_lon_max
        2,                    // disclosed_location_flags (bit0=lat_neg=0, bit1=lon_neg=1)
        1706700000,           // disclosed_time_min
        1706800000,           // disclosed_time_max
        1708900000,           // disclosed_edit_time_min
        1709100000,           // disclosed_edit_time_max
        link_commit_val,      // disclosed device
        actions_hash_val,     // disclosed actions
        // Private inputs
        trust_list_root,
        content_hash,
        image_nullifier,
        proof_timestamp,
        location_commitment_val,
        time_commitment_val,
        link_commit_val,
        actions_hash_val,
        100,                  // exact_lat_scaled
        200,                  // exact_lon_scaled
        0,                    // exact_lat_is_negative
        1,                    // exact_lon_is_negative
        999,                  // location_salt
        1706745600,           // exact_timestamp
        888,                  // time_salt
        edit_time_commitment_val,
        1709000000,           // exact_edit_timestamp
        777,                  // edit_time_salt
        [0; MAX_TREE_DEPTH],
        [0; MAX_TREE_DEPTH],
        0,                    // path_depth = 0
        1, 1, 1,             // disclose v1 fields
        1, 1, 1, 1, 1,       // disclose v2 fields (+ edit_time_range)
    );
}

#[test]
fn test_single_image_v2_all_hidden() {
    let trust_list_root = 0x1234;
    let content_hash = 0x5678;
    let image_nullifier = 0x9abc;
    let proof_timestamp = 0xdef0;
    let location_commitment_val = Poseidon2::hash([100, 200, 0, 1, 999], 5);
    let time_commitment_val = Poseidon2::hash([1706745600, 888], 2);
    let edit_time_commitment_val: Field = 0;  // no edit
    let link_commit_val: Field = 0xaaaa;
    let actions_bytes: [Field; 32] = [0; 32];
    let actions_hash_val = Poseidon2::hash(actions_bytes, 32);

    let commitment = Poseidon2::hash(
        [trust_list_root, content_hash, image_nullifier, proof_timestamp,
         location_commitment_val, time_commitment_val, edit_time_commitment_val,
         link_commit_val, actions_hash_val],
        9,
    );

    main(
        commitment,
        0xffff,
        0xeeee,
        0, 0, 0,             // all v1 fields hidden
        0, 0, 0, 0, 0,       // all location fields hidden
        0, 0,                 // all time fields hidden
        0, 0,                 // edit time hidden
        0, 0,                 // device and actions hidden
        // Private inputs
        trust_list_root,
        content_hash,
        image_nullifier,
        proof_timestamp,
        location_commitment_val,
        time_commitment_val,
        link_commit_val,
        actions_hash_val,
        100, 200, 0, 1, 999,
        1706745600, 888,
        edit_time_commitment_val,
        0, 0,                 // no edit timestamp or salt
        [0; MAX_TREE_DEPTH],
        [0; MAX_TREE_DEPTH],
        0,
        0, 0, 0,             // hide v1 fields
        0, 0, 0, 0, 0,       // hide v2 fields (+ edit_time_range)
    );
}

#[test]
fn test_two_image_batch_v2() {
    let tlr = 0x1111;
    let ch_0 = 0x2222;
    let nul_0 = 0x3333;
    let ts_0 = 0x4444;
    let loc_0 = Poseidon2::hash([100, 200, 0, 0, 111], 5);
    let time_0 = Poseidon2::hash([1706745600, 222], 2);
    let edit_time_0: Field = 0;  // no edit
    let link_0: Field = 0x5555;
    let act_bytes: [Field; 32] = [0; 32];
    let act_0 = Poseidon2::hash(act_bytes, 32);

    let ch_1 = 0x6666;
    let nul_1 = 0x7777;
    let ts_1 = 0x8888;
    let loc_1 = Poseidon2::hash([300, 400, 1, 1, 333], 5);
    let time_1 = Poseidon2::hash([1706800000, 444], 2);
    let edit_time_1: Field = 0;  // no edit
    let link_1: Field = 0x9999;
    let act_1 = Poseidon2::hash(act_bytes, 32);

    let leaf_0 = Poseidon2::hash([tlr, ch_0, nul_0, ts_0, loc_0, time_0, edit_time_0, link_0, act_0], 9);
    let leaf_1 = Poseidon2::hash([tlr, ch_1, nul_1, ts_1, loc_1, time_1, edit_time_1, link_1, act_1], 9);

    let root = Poseidon2::hash([leaf_0, leaf_1], 2);

    let mut siblings: [Field; MAX_TREE_DEPTH] = [0; MAX_TREE_DEPTH];
    siblings[0] = leaf_1;

    main(
        root,
        0xaaaa,
        0xbbbb,
        ch_0,                 // disclose content hash
        tlr,                  // disclose trust list root
        ts_0,                 // disclose timestamp
        0, 0, 0, 0, 0,       // location hidden
        0, 0,                 // time hidden
        0, 0,                 // edit time hidden
        link_0,               // disclose device
        0,                    // actions hidden
        // Private inputs
        tlr,
        ch_0,
        nul_0,
        ts_0,
        loc_0,
        time_0,
        link_0,
        act_0,
        100, 200, 0, 0, 111,
        1706745600, 222,
        edit_time_0,
        0, 0,                 // no edit timestamp or salt
        siblings,
        [0; MAX_TREE_DEPTH],
        1,
        1, 1, 1,             // disclose v1
        0, 0, 0, 1, 0,       // only disclose device (+ edit_time_range slot)
    );
}

#[test(should_fail)]
fn test_wrong_root_fails_v2() {
    let trust_list_root = 0x1234;
    let content_hash = 0x5678;
    let image_nullifier = 0x9abc;
    let proof_timestamp = 0xdef0;
    let loc = Poseidon2::hash([100, 200, 0, 1, 999], 5);
    let time = Poseidon2::hash([1706745600, 888], 2);
    let edit_time: Field = 0;
    let link: Field = 0xaaaa;
    let act_bytes: [Field; 32] = [0; 32];
    let act = Poseidon2::hash(act_bytes, 32);

    main(
        0xdead,               // wrong root
        0xaaaa,
        0xbbbb,
        0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0,
        0, 0,                 // edit time hidden
        0, 0,
        trust_list_root,
        content_hash,
        image_nullifier,
        proof_timestamp,
        loc, time, link, act,
        100, 200, 0, 1, 999,
        1706745600, 888,
        edit_time, 0, 0,
        [0; MAX_TREE_DEPTH],
        [0; MAX_TREE_DEPTH],
        0,
        0, 0, 0,
        0, 0, 0, 0, 0,
    );
}

#[test(should_fail)]
fn test_location_out_of_range_fails() {
    let trust_list_root = 0x1234;
    let content_hash = 0x5678;
    let image_nullifier = 0x9abc;
    let proof_timestamp = 0xdef0;
    let loc = Poseidon2::hash([500, 200, 0, 1, 999], 5);
    let time = Poseidon2::hash([1706745600, 888], 2);
    let edit_time: Field = 0;
    let link: Field = 0xaaaa;
    let act_bytes: [Field; 32] = [0; 32];
    let act = Poseidon2::hash(act_bytes, 32);

    let commitment = Poseidon2::hash(
        [trust_list_root, content_hash, image_nullifier, proof_timestamp, loc, time, edit_time, link, act],
        9,
    );

    main(
        commitment,
        0xffff,
        0xeeee,
        0, 0, 0,
        100,                  // lat_min = 100
        200,                  // lat_max = 200 (actual lat is 500 -- OUT OF RANGE)
        0, 0, 0,
        0, 0,
        0, 0,                 // edit time hidden
        0, 0,
        trust_list_root,
        content_hash,
        image_nullifier,
        proof_timestamp,
        loc, time, link, act,
        500, 200, 0, 1, 999,  // exact_lat = 500
        1706745600, 888,
        edit_time, 0, 0,
        [0; MAX_TREE_DEPTH],
        [0; MAX_TREE_DEPTH],
        0,
        0, 0, 0,
        1, 0, 0, 0, 0,       // disclose_location_range = 1
    );
}

#[test(should_fail)]
fn test_time_out_of_range_fails() {
    let trust_list_root = 0x1234;
    let content_hash = 0x5678;
    let image_nullifier = 0x9abc;
    let proof_timestamp = 0xdef0;
    let loc = Poseidon2::hash([100, 200, 0, 1, 999], 5);
    let time = Poseidon2::hash([1706745600, 888], 2);
    let edit_time: Field = 0;
    let link: Field = 0xaaaa;
    let act_bytes: [Field; 32] = [0; 32];
    let act = Poseidon2::hash(act_bytes, 32);

    let commitment = Poseidon2::hash(
        [trust_list_root, content_hash, image_nullifier, proof_timestamp, loc, time, edit_time, link, act],
        9,
    );

    main(
        commitment,
        0xffff,
        0xeeee,
        0, 0, 0,
        0, 0, 0, 0, 0,
        1706700000,           // time_min
        1706710000,           // time_max (actual is 1706745600 -- OUT OF RANGE)
        0, 0,                 // edit time hidden
        0, 0,
        trust_list_root,
        content_hash,
        image_nullifier,
        proof_timestamp,
        loc, time, link, act,
        100, 200, 0, 1, 999,
        1706745600, 888,
        edit_time, 0, 0,
        [0; MAX_TREE_DEPTH],
        [0; MAX_TREE_DEPTH],
        0,
        0, 0, 0,
        0, 1, 0, 0, 0,       // disclose_time_range = 1
    );
}

#[test(should_fail)]
fn test_wrong_device_disclosure_fails() {
    let trust_list_root = 0x1234;
    let content_hash = 0x5678;
    let image_nullifier = 0x9abc;
    let proof_timestamp = 0xdef0;
    let loc = Poseidon2::hash([100, 200, 0, 1, 999], 5);
    let time = Poseidon2::hash([1706745600, 888], 2);
    let edit_time: Field = 0;
    let link: Field = 0xaaaa;
    let act_bytes: [Field; 32] = [0; 32];
    let act = Poseidon2::hash(act_bytes, 32);

    let commitment = Poseidon2::hash(
        [trust_list_root, content_hash, image_nullifier, proof_timestamp, loc, time, edit_time, link, act],
        9,
    );

    main(
        commitment,
        0xffff,
        0xeeee,
        0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0,
        0, 0,                 // edit time hidden
        0xbbbb,               // wrong link_commit disclosed
        0,
        trust_list_root,
        content_hash,
        image_nullifier,
        proof_timestamp,
        loc, time, link, act,
        100, 200, 0, 1, 999,
        1706745600, 888,
        edit_time, 0, 0,
        [0; MAX_TREE_DEPTH],
        [0; MAX_TREE_DEPTH],
        0,
        0, 0, 0,
        0, 0, 0, 1, 0,       // disclose_device = 1
    );
}
