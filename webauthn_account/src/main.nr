// WebAuthn Account Contract for Aztec
//
// Tier 1 account security: the passkey hardware IS the signing key.
// No extractable key material ever exists in JavaScript.
//
// Dual auth witness paths (discriminator at witness[0]):
//   0 = WebAuthn P-256: full biometric prompt every transaction
//   1 = Session key (Schnorr/Grumpkin): lightweight ephemeral key
//
// Session keys reduce biometric prompts after initial authorization.
// The ephemeral Grumpkin key lives only in JS memory (never persisted).
// authorize_session_key() stores a SessionKeyNote on-chain (requires
// biometric since it goes through the account entrypoint).
//
// WebAuthn envelope verification in-circuit:
// 1. Base64url encode challenge, verify it appears in clientDataJSON
// 2. SHA-256 hash clientDataJSON
// 3. Concatenate authenticatorData || SHA256(clientDataJSON)
// 4. SHA-256 hash the concatenation to get the signed message
// 5. Verify ECDSA secp256r1 signature over the signed message
//
// Vendored from olehmisar/noir_webauthn v0.37.2, adapted for:
// - sha256 v0.3.0 (noir-lang/sha256) instead of nodash::sha256
// - base64 v0.4.2 (noir-lang/noir_base64) instead of v0.4.1
// - Compatible with Noir 1.0.0-beta.18

use dep::aztec::macros::aztec;

#[aztec]
pub contract WebAuthnAccount {
    use dep::aztec::{
        authwit::{account::AccountActions, entrypoint::app::AppPayload},
        context::PrivateContext,
        macros::{
            functions::{external, initializer, noinitcheck, nophasecheck, view},
            notes::note,
            storage::storage,
        },
        messages::message_delivery::MessageDelivery,
        oracle::{
            auth_witness::get_auth_witness,
            notes::{get_sender_for_tags, set_sender_for_tags},
        },
        protocol_types::traits::{Deserialize, Packable, Serialize},
        state_vars::{Owned, PrivateSet, SinglePrivateImmutable},
    };

    use dep::sha256::sha256_var;
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    // Max byte lengths for WebAuthn data
    // clientDataJSON: ~120-150 bytes typical, 256 allows for long origins
    global CLIENT_DATA_JSON_MAX: u32 = 256;
    // authenticatorData: 37 bytes standard, 200 allows for extensions
    global AUTH_DATA_MAX: u32 = 200;
    // Auth witness total fields (max of both paths):
    //   WebAuthn: 1 (discriminator) + 523 (existing layout) = 524
    //   Session key: 1 (discriminator) + 2 (pubkey) + 64 (sig) = 67
    //   Use 524 (max); session key path ignores trailing zeros.
    global AUTH_WITNESS_LEN: u32 = 524;
    // Max number of concurrent session keys per account.
    // Used as compile-time loop bound for note iteration.
    global MAX_SESSION_KEYS: u32 = 5;

    // P-256 public key stored as an encrypted note.
    // Written once in constructor, read every time the account signs a TX.
    #[note]
    #[derive(Eq)]
    pub struct WebAuthnPublicKeyNote {
        x: [u8; 32],
        y: [u8; 32],
    }

    // Manual Packable: each [u8; 32] becomes 2 Fields (31 bytes + 1 byte)
    // because BN254 fields hold max ~254 bits (~31.75 bytes).
    impl Packable for WebAuthnPublicKeyNote {
        let N: u32 = 4;

        fn pack(self) -> [Field; Self::N] {
            let mut x: Field = 0;
            let mut y: Field = 0;
            let mut mul: Field = 1;

            for i in 1..32 {
                x = x + (self.x[31 - i] as Field * mul);
                y = y + (self.y[31 - i] as Field * mul);
                mul *= 256;
            }

            [x, self.x[31] as Field, y, self.y[31] as Field]
        }

        fn unpack(packed: [Field; Self::N]) -> Self {
            let mut x: [u8; 32] = [0; 32];
            let mut y: [u8; 32] = [0; 32];

            let part_x: [u8; 32] = packed[0].to_be_bytes();
            for i in 0..31 {
                x[i] = part_x[i + 1];
            }
            x[31] = packed[1].to_be_bytes::<32>()[31];

            let part_y: [u8; 32] = packed[2].to_be_bytes();
            for i in 0..31 {
                y[i] = part_y[i + 1];
            }
            y[31] = packed[3].to_be_bytes::<32>()[31];

            WebAuthnPublicKeyNote { x, y }
        }
    }

    // Ephemeral session key note (Schnorr/Grumpkin).
    // Stored on-chain via authorize_session_key(), read during session key auth.
    // Grumpkin public key coordinates are Field-native (embedded curve).
    //
    // SECURITY NOTE: expiry and scope are stored for future enforcement but
    // are NOT currently checked in-circuit (see TODOs in is_valid_impl).
    // Expiry is enforced client-side only. Scope is unused (0 = full access).
    #[derive(Deserialize, Eq, Packable, Serialize)]
    #[note]
    pub struct SessionKeyNote {
        pubkey_x: Field,
        pubkey_y: Field,
        expiry: Field,
        scope: Field,
    }

    #[storage]
    struct Storage<Context> {
        signing_public_key: SinglePrivateImmutable<WebAuthnPublicKeyNote, Context>,
        session_keys: Owned<PrivateSet<SessionKeyNote, Context>, Context>,
    }

    // Deploy with P-256 public key extracted from passkey credential
    #[external("private")]
    #[initializer]
    fn constructor(signing_pub_key_x: [u8; 32], signing_pub_key_y: [u8; 32]) {
        let pub_key_note = WebAuthnPublicKeyNote {
            x: signing_pub_key_x,
            y: signing_pub_key_y,
        };

        // Safety: tag sender only used for unconstrained shared secrets in log emission
        let original_sender = unsafe {
            // Safety: read-only oracle for note tag computation
            get_sender_for_tags().unwrap_or(self.address)
        };
        // Safety: sets tag sender for note discovery
        unsafe { set_sender_for_tags(self.address) };

        self.storage.signing_public_key.initialize(pub_key_note).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );

        // Safety: restore original tag sender
        unsafe { set_sender_for_tags(original_sender) };
    }

    // Standard account entrypoint: validates auth witness then executes payload
    #[external("private")]
    #[noinitcheck]
    #[nophasecheck]
    fn entrypoint(app_payload: AppPayload, fee_payment_method: u8, cancellable: bool) {
        // Safety: sets tag sender for note discovery
        unsafe { set_sender_for_tags(self.address) };
        let actions = AccountActions::init(self.context, is_valid_impl);
        actions.entrypoint(app_payload, fee_payment_method, cancellable);
    }

    #[external("private")]
    #[noinitcheck]
    #[view]
    fn verify_private_authwit(inner_hash: Field) -> Field {
        let actions = AccountActions::init(self.context, is_valid_impl);
        actions.verify_private_authwit(inner_hash)
    }

    // ================================================================
    // SESSION KEY MANAGEMENT
    // ================================================================

    // Authorize a session key on-chain.
    // This TX goes through the account entrypoint (requires biometric).
    // After this, subsequent TXs can use the session key path (no biometric).
    //
    // Auto-revokes ALL existing session key notes before inserting the new
    // one. This prevents orphaned notes accumulating when the browser page
    // is refreshed (in-memory key lost but on-chain note persists).
    #[external("private")]
    fn authorize_session_key(
        pubkey_x: Field,
        pubkey_y: Field,
        expiry: Field,
        scope: Field,
    ) {
        // Safety: sets tag sender for note discovery
        unsafe { set_sender_for_tags(self.address) };

        let owner = self.context.this_address();

        // Revoke all existing session key notes (prevents orphan accumulation)
        let mut options = dep::aztec::note::note_getter_options::NoteGetterOptions::new();
        options = options.set_limit(MAX_SESSION_KEYS);
        let existing = self.storage.session_keys.at(owner).get_notes(options);
        for i in 0..MAX_SESSION_KEYS {
            if i < existing.len() {
                self.storage.session_keys.at(owner).remove(existing.get(i));
            }
        }

        let note = SessionKeyNote { pubkey_x, pubkey_y, expiry, scope };
        self.storage.session_keys.at(owner).insert(note).deliver(
            MessageDelivery.CONSTRAINED_ONCHAIN,
        );
    }

    // Revoke a session key by nullifying its note.
    // Also goes through the account entrypoint (biometric required).
    #[external("private")]
    fn revoke_session_key(pubkey_x: Field, pubkey_y: Field) {
        // Safety: sets tag sender for note discovery
        unsafe { set_sender_for_tags(self.address) };

        let owner = self.context.this_address();
        let mut options = dep::aztec::note::note_getter_options::NoteGetterOptions::new();
        options = options.set_limit(MAX_SESSION_KEYS);
        let notes = self.storage.session_keys.at(owner).get_notes(options);
        for i in 0..MAX_SESSION_KEYS {
            if i < notes.len() {
                let retrieved = notes.get(i);
                if (retrieved.note.pubkey_x == pubkey_x) & (retrieved.note.pubkey_y == pubkey_y) {
                    self.storage.session_keys.at(owner).remove(retrieved);
                }
            }
        }
    }

    // ================================================================
    // WebAuthn signature verification (vendored from noir_webauthn)
    // ================================================================

    // SHA-256 hash a BoundedVec using sha256_var
    #[contract_library_method]
    fn sha256_bounded<let N: u32>(bv: BoundedVec<u8, N>) -> [u8; 32] {
        sha256_var(bv.storage(), bv.len())
    }

    // Concatenate BoundedVec<u8, N> with [u8; 32]
    #[contract_library_method]
    fn concat_bv<let N: u32>(
        a: BoundedVec<u8, N>,
        b: [u8; 32],
    ) -> BoundedVec<u8, N + 32> {
        let mut result = [0 as u8; N + 32];
        let mut j: u32 = 0;
        for i in 0..N {
            if i < a.len() {
                result[j] = a.get(i);
                j += 1;
            }
        }
        for i in 0..32 {
            result[j] = b[i];
            j += 1;
        }
        BoundedVec::from_parts(result, j)
    }

    // Verify base64url-encoded challenge appears at given index in clientDataJSON
    #[contract_library_method]
    fn verify_challenge_in_cdj<let H: u32>(
        cdj_storage: [u8; H],
        challenge_b64: [u8; 43],
        challenge_index: u32,
    ) {
        for i in 0..43 {
            // Skip base64 padding characters ('=' = 61)
            if challenge_b64[i] != 61 {
                assert(
                    cdj_storage[challenge_index + i] == challenge_b64[i],
                    "Challenge mismatch in clientDataJSON",
                );
            }
        }
    }

    // Dual-path auth witness verification.
    //
    // Auth witness layout (524 fields):
    //   [0]         discriminator: 0 = WebAuthn, 1 = session key
    //
    // Path 0 - WebAuthn (523 fields after discriminator):
    //   [1..65)     raw ECDSA signature (r || s, 64 bytes)
    //   [65..265)   authenticator_data (up to 200 bytes, zero-padded)
    //   [265]       authenticator_data actual length
    //   [266..522)  client_data_json (up to 256 bytes, zero-padded)
    //   [522]       client_data_json actual length
    //   [523]       challenge_index (byte offset of challenge in clientDataJSON)
    //
    // Path 1 - Session key (66 fields after discriminator):
    //   [1]         pubkey_x (Grumpkin point, Field)
    //   [2]         pubkey_y (Grumpkin point, Field)
    //   [3..67)     Schnorr signature (64 bytes: s[32] || e[32])
    #[contract_library_method]
    fn is_valid_impl(context: &mut PrivateContext, outer_hash: Field) -> bool {
        let storage = Storage::init(context);

        // Safety: read-only oracle fetching pre-stored auth witness
        let witness: [Field; AUTH_WITNESS_LEN] = unsafe {
            // Safety: oracle call to retrieve auth witness from PXE
            get_auth_witness(outer_hash)
        };

        let discriminator = witness[0] as u8;

        if discriminator == 1 {
            // ============================================================
            // PATH 1: Session key (Schnorr on Grumpkin)
            // ============================================================
            let sk_pubkey_x = witness[1];
            let sk_pubkey_y = witness[2];

            // Extract 64-byte Schnorr signature (s[32] || e[32])
            let mut sig: [u8; 64] = [0; 64];
            for i in 0..64 {
                sig[i] = witness[3 + i] as u8;
            }

            // Convert outer_hash to 32-byte message for Schnorr verification
            let message: [u8; 32] = outer_hash.to_be_bytes();

            // Read session key notes and verify one matches.
            // Use this_address() instead of msg_sender() because is_valid_impl
            // runs in the entrypoint context where msg_sender() is None.
            let this_addr = context.this_address();
            let mut options = dep::aztec::note::note_getter_options::NoteGetterOptions::new();
            options = options.set_limit(MAX_SESSION_KEYS);
            let notes = storage.session_keys.at(this_addr).get_notes(options);
            let mut found = false;
            for i in 0..MAX_SESSION_KEYS {
                if i < notes.len() {
                    let retrieved = notes.get(i);
                    if (retrieved.note.pubkey_x == sk_pubkey_x) & (retrieved.note.pubkey_y == sk_pubkey_y) {
                        found = true;
                    }
                }
            }
            assert(found, "Session key not authorized");

            // KNOWN LIMITATION: Expiry is not enforced in-circuit. block_number()
            // is unavailable in private context (Aztec v3.0.3). Expiry is checked
            // client-side only. Stolen session keys remain valid until explicitly
            // revoked via revoke_session_key(). Acceptable for MVP; revisit when
            // Aztec exposes block number in private.
            //
            // KNOWN LIMITATION: Scope is not enforced in-circuit. All scope values
            // are treated identically (scope=0 means full access). Scoped permissions
            // require comparing scope against app_payload, which is not accessible
            // in the entrypoint context. Acceptable for MVP.

            // Verify Schnorr signature over the outer_hash
            let pub_key = EmbeddedCurvePoint { x: sk_pubkey_x, y: sk_pubkey_y, is_infinite: false };
            dep::schnorr::verify_signature(pub_key, sig, message)
        } else {
            // ============================================================
            // PATH 0: WebAuthn P-256 (existing path, fields shifted by +1)
            // ============================================================
            let public_key = storage.signing_public_key.get_note();

            // Extract raw ECDSA signature (64 bytes: r[32] || s[32])
            let mut signature: [u8; 64] = [0; 64];
            for i in 0..64 {
                signature[i] = witness[1 + i] as u8;
            }

            // Extract authenticator_data as BoundedVec
            let auth_data_len = witness[1 + 264] as u32;
            let mut auth_data_arr: [u8; AUTH_DATA_MAX] = [0; AUTH_DATA_MAX];
            for i in 0..AUTH_DATA_MAX {
                auth_data_arr[i] = witness[1 + 64 + i] as u8;
            }
            let auth_data: BoundedVec<u8, AUTH_DATA_MAX> =
                BoundedVec::from_parts(auth_data_arr, auth_data_len);

            // Extract client_data_json as BoundedVec
            let cdj_len = witness[1 + 521] as u32;
            let mut cdj_arr: [u8; CLIENT_DATA_JSON_MAX] = [0; CLIENT_DATA_JSON_MAX];
            for i in 0..CLIENT_DATA_JSON_MAX {
                cdj_arr[i] = witness[1 + 265 + i] as u8;
            }
            let client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX> =
                BoundedVec::from_parts(cdj_arr, cdj_len);

            // Challenge index
            let challenge_index = witness[1 + 522] as u32;

            // Challenge = outer_hash as 32 big-endian bytes
            let challenge: [u8; 32] = outer_hash.to_be_bytes();

            // Step 1: Verify challenge is embedded in clientDataJSON (base64url)
            let challenge_b64: [u8; 43] = base64::BASE64_URL_ENCODER::encode(challenge);
            verify_challenge_in_cdj(client_data_json.storage(), challenge_b64, challenge_index);

            // Step 2: SHA-256 hash clientDataJSON
            let cdj_hash: [u8; 32] = sha256_bounded(client_data_json);

            // Step 3: Concatenate authenticatorData || SHA256(clientDataJSON)
            let concatenated: BoundedVec<u8, AUTH_DATA_MAX + 32> = concat_bv(auth_data, cdj_hash);

            // Step 4: SHA-256 the concatenation to get the signed message
            let hashed_message: [u8; 32] = sha256_bounded(concatenated);

            // Step 5: Verify ECDSA secp256r1 (P-256) signature
            std::ecdsa_secp256r1::verify_signature(
                public_key.x,
                public_key.y,
                signature,
                hashed_message,
            )
        }
    }
}
