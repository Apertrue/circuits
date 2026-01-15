// P-384 ECDSA Verification Test Circuit
// Tests Google C2PA Mobile A ICA signature using Root CA public key

use noir_bigcurve::curves::secp384r1::{Secp384r1, Secp384r1Scalar, Secp384r1_Fq, Secp384r1_Fr};
use noir_bigcurve::BigCurve;

// Import BigNum trait for from_be_bytes, __invmod, one methods
use bignum::bignum::BigNum as BigNumTrait;

fn main(
    // Message hash (SHA-384 of TBS certificate) - 48 bytes
    message_hash: pub [u8; 48],
    // Public key X coordinate - 48 bytes
    pubkey_x: [u8; 48],
    // Public key Y coordinate - 48 bytes
    pubkey_y: [u8; 48],
    // Signature R - 48 bytes
    sig_r: [u8; 48],
    // Signature S - 48 bytes
    sig_s: [u8; 48]
) {
    let valid = verify_ecdsa_p384(message_hash, pubkey_x, pubkey_y, sig_r, sig_s);
    assert(valid, "ECDSA P-384 signature verification failed");
}

/// ECDSA P-384 verification
/// Returns true if signature (r,s) is valid for message_hash under public_key
pub fn verify_ecdsa_p384(
    message_hash: [u8; 48],
    pubkey_x: [u8; 48],
    pubkey_y: [u8; 48],
    sig_r: [u8; 48],
    sig_s: [u8; 48]
) -> bool {
    // Convert bytes to BigNum (big-endian)
    let pk_x: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(pubkey_x);
    let pk_y: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(pubkey_y);
    let r: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(sig_r);
    let s: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(sig_s);
    let e: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(message_hash);

    // For P-384 with SHA-384, no truncation needed (both are 384 bits)
    
    // Compute s^-1 mod n (unconstrained, then verify)
    // Safety: __invmod is unconstrained but result is verified by s * s_inv == 1 check below
    let s_inv = unsafe { s.__invmod() };
    
    // Verify inverse: s * s_inv == 1 (mod n)
    let check = s * s_inv;
    let one = Secp384r1_Fr::one();
    assert(check == one, "s inverse failed");

    // Compute u1 = e * s^-1 mod n
    let u1_bn = e * s_inv;
    let u1: Secp384r1Scalar = Secp384r1Scalar::from_bignum(u1_bn);

    // Compute u2 = r * s^-1 mod n
    let u2_bn = r * s_inv;
    let u2: Secp384r1Scalar = Secp384r1Scalar::from_bignum(u2_bn);

    // Public key point Q
    let q = Secp384r1 { x: pk_x, y: pk_y, is_infinity: false };
    q.validate_on_curve();

    // Generator point G
    let g = Secp384r1::one();

    // Compute R = u1*G + u2*Q using evaluate_linear_expression
    let r_point = Secp384r1::evaluate_linear_expression([g, q], [u1, u2], []);

    // Signature valid if R.x == r (mod n)
    // Convert R.x from Fq to Fr by re-interpreting limbs
    // Note: P-384 Fq and Fr have similar sizes but different moduli
    let rx_as_fr: Secp384r1_Fr = Secp384r1_Fr::from_limbs(r_point.x.get_limbs());
    
    // The signature is valid if rx mod n == r AND point is not infinity
    !r_point.is_infinity & (rx_as_fr == r)
}

#[test]
fn test_google_ica_signature() {
    // Test vectors extracted from Google C2PA Mobile A ICA certificate
    // Signed by Google C2PA Root CA G3
    
    // SHA-384 hash of TBS certificate
    let hash: [u8; 48] = [
        0xe9, 0xb7, 0xbe, 0x33, 0xa9, 0x27, 0x5f, 0x8c,
        0x71, 0x80, 0x82, 0x12, 0x8c, 0x6a, 0xb3, 0xe3,
        0x67, 0xbf, 0x4e, 0xe9, 0xcc, 0x58, 0x5c, 0x7f,
        0x63, 0x56, 0x70, 0xd4, 0xf9, 0x71, 0xb4, 0xc6,
        0x8b, 0x4c, 0xa5, 0xc5, 0x42, 0xe4, 0x33, 0x84,
        0x6a, 0xd3, 0xc6, 0xdc, 0x59, 0x23, 0xf5, 0x3f
    ];

    // Root CA public key X
    let pubkey_x: [u8; 48] = [
        0x86, 0xff, 0x5f, 0xfe, 0x3b, 0x8a, 0x70, 0xfa,
        0x5e, 0xdc, 0x59, 0xbb, 0x78, 0x02, 0x12, 0x32,
        0xe4, 0xb2, 0x4b, 0xeb, 0x41, 0xc6, 0x7d, 0x1a,
        0x60, 0x70, 0xbc, 0xdc, 0x9f, 0xaa, 0x02, 0xc1,
        0x56, 0x44, 0x41, 0x8d, 0xf6, 0x9e, 0x8f, 0x37,
        0xf3, 0x81, 0xa2, 0x8b, 0x8f, 0xce, 0x93, 0x85
    ];

    // Root CA public key Y
    let pubkey_y: [u8; 48] = [
        0x47, 0x1b, 0xeb, 0x95, 0x6a, 0x16, 0x98, 0x02,
        0x37, 0xa7, 0x59, 0x57, 0xc8, 0xf8, 0x38, 0x13,
        0x77, 0xa0, 0xed, 0x23, 0x42, 0x86, 0x0a, 0x29,
        0x50, 0x8a, 0x62, 0x84, 0x6b, 0xba, 0xaa, 0x58,
        0x4f, 0xf2, 0xb2, 0xd7, 0x7f, 0x7a, 0x7c, 0x6e,
        0x12, 0x39, 0x15, 0x34, 0x36, 0x31, 0xa1, 0x76
    ];

    // Signature R
    let sig_r: [u8; 48] = [
        0x63, 0x02, 0x3d, 0xb6, 0x6d, 0x7d, 0xef, 0x2a,
        0xcf, 0xf7, 0x43, 0x82, 0xb4, 0xa8, 0x4e, 0xe3,
        0x3f, 0x06, 0x37, 0x06, 0x58, 0xdc, 0x68, 0x6c,
        0xa1, 0x4e, 0x0f, 0x46, 0x93, 0xa9, 0xe2, 0xd3,
        0xed, 0xd3, 0xc6, 0xe9, 0x6e, 0x2c, 0x2a, 0xbe,
        0xcc, 0x84, 0xd7, 0x6a, 0xe1, 0xb4, 0xab, 0x2d
    ];

    // Signature S
    let sig_s: [u8; 48] = [
        0x57, 0xd2, 0xe1, 0xb5, 0x31, 0x29, 0xdc, 0x02,
        0x8d, 0x63, 0xa7, 0x6a, 0x62, 0xc2, 0x03, 0xdc,
        0x62, 0x68, 0xef, 0x36, 0x9b, 0x2d, 0x14, 0x37,
        0x49, 0x2f, 0xc4, 0xd3, 0x05, 0x7e, 0x52, 0xec,
        0x99, 0xe3, 0xb8, 0x3c, 0xbf, 0x8d, 0x23, 0xfb,
        0xb7, 0x10, 0x9d, 0xf8, 0xee, 0x8f, 0xb8, 0x8c
    ];

    main(hash, pubkey_x, pubkey_y, sig_r, sig_s);
}
