// JWT Identity Verification Circuit
// Proves: "I have a verified email at domain X" via any OIDC provider
// without revealing which specific email address.
// Provider-agnostic: works with Google, Microsoft, Okta, any RS256 OIDC.

use noir_jwt::JWT;

global MAX_PARTIAL_DATA_LENGTH: u32 = 640;
global MAX_DOMAIN_LENGTH: u32 = 64;
global MAX_EMAIL_LENGTH: u32 = 128;

fn main(
    // JWT data (partial SHA mode)
    partial_data: BoundedVec<u8, MAX_PARTIAL_DATA_LENGTH>,
    partial_hash: [u32; 8],
    full_data_length: u32,
    base64_decode_offset: u32,
    // RSA-2048 public key (18 x 120-bit limbs as u128)
    pubkey_modulus_limbs: pub [u128; 18],
    pubkey_redc_limbs: [u128; 18],
    // RSA signature
    signature_limbs: [u128; 18],
    // Domain to verify (public)
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,
) {
    // Initialize JWT with partial SHA
    let jwt: JWT<MAX_PARTIAL_DATA_LENGTH> = JWT::init_with_partial_hash(
        partial_data,
        partial_hash,
        full_data_length,
        base64_decode_offset,
        pubkey_modulus_limbs,
        pubkey_redc_limbs,
        signature_limbs,
    );

    // Verify RSA-SHA256 signature
    jwt.verify();

    // Extract email claim (provider-agnostic)
    let email: BoundedVec<u8, MAX_EMAIL_LENGTH> = jwt.get_claim_string("email".as_bytes());

    // Find @ symbol position (ASCII 64)
    // Must iterate full MAX_EMAIL_LENGTH -- Noir does not short-circuit loops
    let mut at_pos: u32 = 0;
    let mut found_at = false;
    for i in 0..MAX_EMAIL_LENGTH {
        if i < email.len() {
            if (email.get(i) == 64) & (!found_at) {
                at_pos = i + 1;
                found_at = true;
            }
        }
    }
    assert(found_at, "No @ found in email");

    // Assert domain after @ matches the public domain input
    let domain_len = email.len() - at_pos;
    assert(domain_len == domain.len(), "Domain length mismatch");
    for i in 0..MAX_DOMAIN_LENGTH {
        if i < domain.len() {
            assert(email.get(at_pos + i) == domain.get(i), "Domain byte mismatch");
        }
    }

    // Assert email is verified by the OIDC provider
    jwt.assert_claim_bool("email_verified".as_bytes(), true);
}
