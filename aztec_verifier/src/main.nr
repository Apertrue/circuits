// Apertrue Private Verifier Contract
//
// Verifies aggregated ZK proofs inside Aztec private functions,
// creating encrypted notes only the user can read.
//
// Architecture:
// - Browser submits tree aggregator proof directly to Aztec (via PXE)
// - Private function calls verify_honk_proof (trustless, ~250k gates)
// - Creates VerifiedMediaNote in user's private storage
// - VK hash checked in private via PublicImmutable historical read
// - Backend is NEVER in the on-chain verification path
//
// Privacy guarantees:
// - No on-chain link between user address and verification data
// - Notes are encrypted to user's key; only they can read them
// - Nullifier derived from root_commitment prevents replay
// - Diversified addresses prevent cross-batch correlation

use dep::aztec::macros::aztec;

#[aztec]
pub contract ApertrueVerifier {
    use dep::aztec::{
        macros::{
            functions::{external, initializer, view},
            notes::note,
            storage::storage,
        },
        messages::message_delivery::MessageDelivery,
        oracle::notes::set_sender_for_tags,
        protocol_types::{
            address::AztecAddress,
            hash::poseidon2_hash,
            traits::{Deserialize, Packable, Serialize, ToField},
        },
        state_vars::{Owned, PrivateSet, PublicImmutable},
    };

    use dep::bb_proof_verification::{
        UltraHonkZKProof,
        UltraHonkVerificationKey,
        verify_honk_proof,
    };

    // ================================================================
    // NOTE TYPE: VerifiedMediaNote
    // ================================================================

    // A private note representing a verified media batch.
    // Only the owner can decrypt and read it.
    // Owner and randomness are handled by the Aztec framework,
    // not stored as note fields.
    //
    // Fields:
    //   root_commitment - Merkle root of all image commitments in this batch
    //   image_count     - Number of images verified
    //   trust_list_root - Oracle trust list root used during verification
    //   epoch_week      - ISO week number (coarse time, not exact timestamp)

    #[derive(Deserialize, Eq, Packable, Serialize)]
    #[note]
    pub struct VerifiedMediaNote {
        root_commitment: Field,
        image_count: Field,
        trust_list_root: Field,
        epoch_week: Field,
    }

    // ================================================================
    // STORAGE
    // ================================================================

    #[storage]
    struct Storage<Context> {
        // Admin address (set at deployment)
        admin: PublicImmutable<AztecAddress, Context>,
        // Tree aggregator verification key hash
        // Set once at deployment; readable from private via historical read
        vk_hash: PublicImmutable<Field, Context>,
        // Private notes per owner (Owned wraps PrivateSet for owner-keyed access)
        verified_notes: Owned<PrivateSet<VerifiedMediaNote, Context>, Context>,
    }

    // ================================================================
    // CONSTRUCTOR
    // ================================================================

    // Initialize with admin address and tree aggregator VK hash
    #[external("public")]
    #[initializer]
    fn constructor(admin: AztecAddress, initial_vk_hash: Field) {
        self.storage.admin.initialize(admin);
        self.storage.vk_hash.initialize(initial_vk_hash);
    }

    // ================================================================
    // PRIVATE FUNCTIONS
    // ================================================================

    // Verify a tree aggregator proof and create a private note.
    //
    // This is the core function: it cryptographically verifies the
    // aggregated ZK proof inside the private function, then stores
    // the result as an encrypted note only the caller can read.
    //
    // VK hash is checked in private context via PublicImmutable
    // historical read (no public call needed).
    //
    // Arguments:
    //   proof             - 508-field UltraHonkZK proof from tree aggregator
    //   vk                - 115-field verification key for tree aggregator circuit
    //   vk_hash           - Hash of VK (checked against stored immutable hash)
    //   public_values     - 5 public values from tree aggregator:
    //                        [0, 0, 0, 0, root_commitment]
    //   image_count       - Number of images in the batch
    //   trust_list_root   - Trust list root used during proving
    //   epoch_week        - ISO week number for coarse timing
    //   owner             - Note owner (caller's diversified address)
    //
    // Gate cost: ~250k for verify_honk_proof + ~30k for app logic
    #[external("private")]
    fn verify_and_store(
        proof: UltraHonkZKProof,
        vk: UltraHonkVerificationKey,
        vk_hash: Field,
        public_values: [Field; 5],
        image_count: Field,
        trust_list_root: Field,
        epoch_week: Field,
        owner: AztecAddress,
    ) {
        // ============================================================
        // INPUT VALIDATION
        // ============================================================
        assert(image_count as u64 > 0, "image_count must be > 0");
        assert(trust_list_root != 0, "trust_list_root must not be zero");
        assert(!owner.is_zero(), "owner must not be zero address");

        // Verify tree aggregator padding: public_values[0..4] must be zero
        assert(public_values[0] == 0, "public_values padding [0] must be zero");
        assert(public_values[1] == 0, "public_values padding [1] must be zero");
        assert(public_values[2] == 0, "public_values padding [2] must be zero");
        assert(public_values[3] == 0, "public_values padding [3] must be zero");
        assert(public_values[4] != 0, "root_commitment must not be zero");

        // ============================================================
        // VK HASH CHECK (private historical read of PublicImmutable)
        // ============================================================
        let stored_vk_hash = self.storage.vk_hash.read();
        assert(vk_hash == stored_vk_hash, "VK hash mismatch");

        // ============================================================
        // STEP 1: Cryptographically verify the tree aggregator proof
        // This is the trustless core -- no backend involvement
        // ============================================================
        verify_honk_proof(vk, proof, public_values, vk_hash);

        // ============================================================
        // STEP 2: Extract root_commitment from public values
        // Tree aggregator output: [0, 0, 0, 0, root_commitment]
        // ============================================================
        let root_commitment = public_values[4];

        // Replay prevention: derive nullifier from root_commitment
        // so the same batch cannot be verified twice
        let replay_nullifier = poseidon2_hash(
            [root_commitment, self.context.this_address().to_field()],
        );
        self.context.push_nullifier(replay_nullifier);

        // ============================================================
        // STEP 3: Create encrypted note only the owner can read
        // Owner/randomness handled by framework via Owned storage slot
        // ============================================================

        // Set the sender for note tags so the owner's PXE can discover
        // notes without needing this contract registered as a sender.
        // Required when TX does not go through an account entrypoint
        // (verify_and_store is proof-authorized, not account-authorized).
        unsafe { set_sender_for_tags(owner) };

        let note = VerifiedMediaNote {
            root_commitment,
            image_count,
            trust_list_root,
            epoch_week,
        };

        // Insert note into owner's private set; deliver via offchain oracle.
        // UNCONSTRAINED_OFFCHAIN avoids tail_to_public kernel (which requires
        // fee payment setup via account entrypoint). Notes are still encrypted
        // to the owner and discoverable by their PXE.
        self.storage.verified_notes.at(owner).insert(note).deliver(
            MessageDelivery.UNCONSTRAINED_OFFCHAIN,
        );
    }

    // ================================================================
    // VIEW FUNCTIONS (public, read-only)
    // ================================================================

    // Get the stored VK hash
    #[external("public")]
    #[view]
    fn get_vk_hash() -> Field {
        self.storage.vk_hash.read()
    }

    // Get the admin address
    #[external("public")]
    #[view]
    fn get_admin() -> AztecAddress {
        self.storage.admin.read()
    }
}
