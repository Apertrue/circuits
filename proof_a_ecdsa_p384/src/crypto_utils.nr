// P-384 ECDSA imports (uses local vendored noir_bigcurve)
use crate::crypto::noir_bigcurve_vendor::curves::secp384r1::{Secp384r1, Secp384r1Scalar};
use crate::crypto::noir_bigcurve_vendor::BigCurve;
// Import BigNum trait from global dep
use dep::bignum::bignum::BigNum as BigNumTrait;
use dep::bignum::{Secp384r1_Fq, Secp384r1_Fr};

/// ECDSA P-384 verification
/// Verifies signature (r,s) on message_hash using public key (pk_x, pk_y)
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

    // Security: reject zero r or s (invalid per SEC1/FIPS 186-5)
    assert(r != Secp384r1_Fr::zero(), "ECDSA P-384 r must not be zero");
    assert(s != Secp384r1_Fr::zero(), "ECDSA P-384 s must not be zero");

    let e: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(message_hash);

    // Compute s^-1 mod n (unconstrained, then verify)
    // Safety: __invmod is unconstrained but result is verified by s * s_inv == 1 check below
    let s_inv = unsafe { s.__invmod() };

    // Verify inverse: s * s_inv == 1 (mod n)
    let check = s * s_inv;
    let one = Secp384r1_Fr::one();
    assert(check == one, "s inverse failed");

    // Compute u1 = e * s^-1 mod n
    let u1_bn = e * s_inv;
    let u1: Secp384r1Scalar = Secp384r1Scalar::from_bignum::<dep::bignum::Secp384r1_Fr>(u1_bn);

    // Compute u2 = r * s^-1 mod n
    let u2_bn = r * s_inv;
    let u2: Secp384r1Scalar = Secp384r1Scalar::from_bignum::<dep::bignum::Secp384r1_Fr>(u2_bn);

    // Public key point Q
    let q = Secp384r1 { x: pk_x, y: pk_y, is_infinity: false };
    q.validate_on_curve();

    // Generator point G
    let g = Secp384r1::one();

    // Compute R = u1*G + u2*Q using evaluate_linear_expression
    let r_point = Secp384r1::evaluate_linear_expression([g, q], [u1, u2], []);

    // Signature valid if R.x == r (mod n)
    let rx_as_fr: Secp384r1_Fr = Secp384r1_Fr::from_limbs(r_point.x.get_limbs());

    // The signature is valid if rx mod n == r AND point is not infinity
    !r_point.is_infinity & (rx_as_fr == r)
}
