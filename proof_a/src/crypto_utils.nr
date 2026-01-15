use dep::bignum::RuntimeBigNum;
use dep::bignum::params::BigNumParams;
use std::ops::Mul;

// SHA-384 OID Header (19 bytes)
global SHA384_OID: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
];

pub fn verify_sha384_pkcs1v15_2048(
    hash: [u8; 48],
    signature: RuntimeBigNum<18, 2048>,
    e: Field
) -> bool {
    // Assert e == 65537
    assert(e == 65537, "Does not support generic exponent, only 65537");

    // Compute s^65537 = s^(2^16 + 1) = (s^(2^16)) * s
    // Square 16 times
    let mut val = signature;
    for _i in 0..16 {
        val = val.mul(val);
    }
    let decrypted = val.mul(signature);

    let em = decrypted.to_be_bytes();

    // Verify Padding
    let mut valid = true;

    // A. Prefix
    if em[0] != 0 { valid = false; }
    if em[1] != 1 { valid = false; }

    // B. Padding (0xFF)
    for i in 2..188 {
        if em[i] != 0xff { valid = false; }
    }

    // C. Separator
    if em[188] != 0 { valid = false; }

    // D. OID Header
    for i in 0..19 {
        if em[189 + i] != SHA384_OID[i] { valid = false; }
    }

    // E. Hash (Digest)
    for i in 0..48 {
        if em[208 + i] != hash[i] { valid = false; }
    }

    valid
}
