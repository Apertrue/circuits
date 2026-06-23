// Faithful port test: the REAL colofon_imt lib (check_non_membership +
// CveLeafPreimage) compiled under nargo beta.20 and run under coNoir MPC.

use colofon_imt::cve_leaf_preimage::CveLeafPreimage;
use colofon_imt::membership::{check_non_membership, MembershipWitness};

global TREE_HEIGHT: u32 = 8;

fn main(
    key: Field,                          // non-membership target
    low_key: Field,                      // low leaf key
    next_key: Field,                     // low leaf next key
    next_index: Field,                   // low leaf next index
    low_leaf_index: Field,               // low leaf position
    sibling_path: [Field; TREE_HEIGHT],  // membership opening for the low leaf
    tree_root: pub Field,                // public IMT root
) -> pub bool {
    let low_leaf = CveLeafPreimage::new(low_key, next_key, next_index);
    let witness = MembershipWitness { leaf_index: low_leaf_index, sibling_path };
    let (non_existence, _valid, _exists) = check_non_membership(key, low_leaf, witness, tree_root);
    non_existence
}
