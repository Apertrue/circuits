/// cert_binding: bind a leaf certificate's P-256 key and validity dates to
/// the exact bytes the issuing CA signed.
///
/// bind_leaf_cert(tbs, tbs_len) hashes tbs[0..tbs_len] with SHA-256 and walks
/// the DER TBSCertificate from offset 0. Every field location is derived from
/// the DER itself; there are no prover-supplied offsets. The caller must use
/// the returned sha256 as the message of the CA signature check, so the bytes
/// walked here are exactly the bytes the CA signed.
///
/// TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT Version DEFAULT v1,   (optional, tag 0xA0)
///     serialNumber        INTEGER,                       (0x02)
///     signature           AlgorithmIdentifier,           (0x30)
///     issuer              Name,                          (0x30)
///     validity            Validity,                      (0x30: two Time values)
///     subject             Name,                          (0x30)
///     subjectPublicKeyInfo SubjectPublicKeyInfo,         (fixed P-256 prefix)
///     ... }                                              (rest not read)
///
/// Strictness choices:
/// - DER lengths: short form, 0x81 (value >= 0x80) and 0x82 (value >= 0x100)
///   only; non-minimal long forms are rejected.
/// - The outer SEQUENCE must span exactly tbs_len bytes.
/// - The two Time values must exactly fill the Validity SEQUENCE.
/// - Each element read must end at or before tbs_len.
/// - SPKI must be byte-identical to the uncompressed P-256 id-ecPublicKey form.
/// - Times must be UTCTime (13 bytes) or GeneralizedTime (15 bytes), all
///   digits, trailing 'Z', month 1-12, day 1-31, hour <= 23, min/sec <= 59.
/// - Dates before 1970-01-01 are rejected (unix time is unsigned here).

use dep::sha256::sha256_var;
use dep::sha512::{sha384::sha384_var, sha512::sha512_var};

pub mod test_vectors;
pub mod synthetic_vectors;
pub mod proofmode_vectors;

/// Uncompressed P-256 SubjectPublicKeyInfo header (27 bytes), followed by
/// X (32 bytes) and Y (32 bytes).
global SPKI_P256_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

pub struct LeafCert {
    pub sha256: [u8; 32],
    pub pubkey_x: [u8; 32],
    pub pubkey_y: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

/// Read a DER TLV header at offset p and check its tag.
/// Returns (content_start, content_end). Asserts content_end <= tbs_len.
fn read_tlv<let N: u32>(tbs: [u8; N], tbs_len: u32, p: u32, tag: u8) -> (u32, u32) {
    assert(tbs[p] == tag, "DER: unexpected tag");
    let b1 = tbs[p + 1];
    let b2 = tbs[p + 2] as u32;
    let b3 = tbs[p + 3] as u32;
    let short = b1 < 0x80;
    let is81 = b1 == 0x81;
    let is82 = b1 == 0x82;
    assert(short | is81 | is82, "DER: unsupported length form");
    // DER minimal length encoding
    assert(!is81 | (b2 >= 0x80), "DER: non-minimal 0x81 length");
    assert(!is82 | (b2 >= 0x01), "DER: non-minimal 0x82 length");
    let hdr: u32 = if short { 2 } else if is81 { 3 } else { 4 };
    let len: u32 = if short { b1 as u32 } else if is81 { b2 } else { b2 * 256 + b3 };
    let start = p + hdr;
    let end = start + len;
    assert(end <= tbs_len, "DER: element exceeds tbs_len");
    (start, end)
}

/// One ASCII digit at tbs[p], checked.
fn digit<let N: u32>(tbs: [u8; N], p: u32) -> u64 {
    let c = tbs[p];
    assert((c >= 0x30) & (c <= 0x39), "Time: non-digit");
    (c - 0x30) as u64
}

fn two<let N: u32>(tbs: [u8; N], p: u32) -> u64 {
    digit(tbs, p) * 10 + digit(tbs, p + 1)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's
/// days_from_civil). Requires year >= 1970; earlier dates fail on underflow.
pub fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse a Time (UTCTime or GeneralizedTime) at offset p.
/// Returns (unix_seconds, offset just past the element).
fn read_time<let N: u32>(tbs: [u8; N], tbs_len: u32, p: u32) -> (u64, u32) {
    let tag = tbs[p];
    let len = tbs[p + 1];
    let is_utc = (tag == 0x17) & (len == 13);
    let is_gen = (tag == 0x18) & (len == 15);
    assert(is_utc | is_gen, "Time: expected UTCTime(13) or GeneralizedTime(15)");
    let end = p + 2 + len as u32;
    assert(end <= tbs_len, "Time: exceeds tbs_len");

    let b = p + 2;
    let yy = two(tbs, b);
    // For UTCTime positions b+2, b+3 are the month digits; reading them as
    // digits is still a valid check. Constant shape either way.
    let yy2 = two(tbs, b + 2);
    let year = if is_gen {
        yy * 100 + yy2
    } else if yy >= 50 {
        1900 + yy
    } else {
        2000 + yy
    };
    let r = if is_gen { b + 4 } else { b + 2 };
    let month = two(tbs, r);
    let day = two(tbs, r + 2);
    let hour = two(tbs, r + 4);
    let minute = two(tbs, r + 6);
    let second = two(tbs, r + 8);
    assert(tbs[r + 10] == 0x5a, "Time: missing trailing Z");
    assert((month >= 1) & (month <= 12), "Time: bad month");
    assert((day >= 1) & (day <= 31), "Time: bad day");
    assert(hour <= 23, "Time: bad hour");
    assert(minute <= 59, "Time: bad minute");
    assert(second <= 59, "Time: bad second");

    let days = days_from_civil(year, month, day);
    (days * 86400 + hour * 3600 + minute * 60 + second, end)
}

/// Field locations found by walking a DER TBSCertificate from offset 0.
/// All offsets are derived from the DER; none are prover-supplied.
pub struct TbsWalk {
    /// Content of the TBS `signature` AlgorithmIdentifier: [sig_alg_start, sig_alg_end)
    pub sig_alg_start: u32,
    pub sig_alg_end: u32,
    /// First byte of subjectPublicKeyInfo
    pub spki_start: u32,
    pub not_before: u64,
    pub not_after: u64,
}

/// Walk a DER TBSCertificate from offset 0 up to subjectPublicKeyInfo.
/// Does not hash; the caller must hash tbs[0..tbs_len] and use that digest
/// as the message of the issuer signature check.
pub fn walk_tbs<let N: u32>(tbs: [u8; N], tbs_len: u32) -> TbsWalk {
    assert(tbs_len <= N, "tbs_len exceeds buffer");

    // Outer SEQUENCE must cover exactly tbs_len bytes.
    let (body, outer_end) = read_tlv(tbs, tbs_len, 0, 0x30);
    assert(outer_end == tbs_len, "DER: TBS SEQUENCE does not span tbs_len");

    // Optional [0] EXPLICIT version.
    let mut p = body;
    if tbs[p] == 0xa0 {
        let (_, e) = read_tlv(tbs, tbs_len, p, 0xa0);
        p = e;
    }
    // serialNumber, signature AlgorithmIdentifier, issuer
    let (_, e1) = read_tlv(tbs, tbs_len, p, 0x02);
    let (sig_alg_start, e2) = read_tlv(tbs, tbs_len, e1, 0x30);
    let (_, e3) = read_tlv(tbs, tbs_len, e2, 0x30);

    // validity
    let (vs, ve) = read_tlv(tbs, tbs_len, e3, 0x30);
    let (not_before, t1) = read_time(tbs, tbs_len, vs);
    let (not_after, t2) = read_time(tbs, tbs_len, t1);
    assert(t2 == ve, "DER: Validity length mismatch");

    // subject
    let (_, e5) = read_tlv(tbs, tbs_len, ve, 0x30);

    TbsWalk { sig_alg_start, sig_alg_end: e2, spki_start: e5, not_before, not_after }
}

/// Read an uncompressed P-256 SubjectPublicKeyInfo at spki_start.
pub fn read_p256_spki<let N: u32>(tbs: [u8; N], tbs_len: u32, spki_start: u32) -> ([u8; 32], [u8; 32]) {
    assert(spki_start + 91 <= tbs_len, "SPKI exceeds tbs_len");
    for i in 0..27 {
        assert(tbs[spki_start + i] == SPKI_P256_PREFIX[i], "SPKI is not uncompressed P-256");
    }
    let mut pubkey_x: [u8; 32] = [0; 32];
    let mut pubkey_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        pubkey_x[i] = tbs[spki_start + 27 + i];
        pubkey_y[i] = tbs[spki_start + 59 + i];
    }
    (pubkey_x, pubkey_y)
}

/// Assert that the TBS `signature` AlgorithmIdentifier content is exactly
/// `expected` (the DER bytes inside the AlgorithmIdentifier SEQUENCE).
pub fn assert_sig_alg<let N: u32, let K: u32>(tbs: [u8; N], w: TbsWalk, expected: [u8; K]) {
    assert(w.sig_alg_end - w.sig_alg_start == K, "TBS signature algorithm mismatch");
    for i in 0..K {
        assert(tbs[w.sig_alg_start + i] == expected[i], "TBS signature algorithm mismatch");
    }
}

/// DER content of AlgorithmIdentifier for ecdsa-with-SHA256/384/512
/// (OID 1.2.840.10045.4.3.2/3/4, parameters absent).
pub global ALG_ECDSA_SHA256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
pub global ALG_ECDSA_SHA384: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
pub global ALG_ECDSA_SHA512: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];

/// SHA-384 of tbs[0..tbs_len]. Bytes past tbs_len are zeroed by
/// BoundedVec::from_parts, so prover padding cannot affect the digest.
pub fn tbs_sha384<let N: u32>(tbs: [u8; N], tbs_len: u32) -> [u8; 48] {
    sha384_var(BoundedVec::from_parts(tbs, tbs_len))
}

/// SHA-512 of tbs[0..tbs_len] (same padding rule as tbs_sha384).
pub fn tbs_sha512<let N: u32>(tbs: [u8; N], tbs_len: u32) -> [u8; 64] {
    sha512_var(BoundedVec::from_parts(tbs, tbs_len))
}

/// A P-256 leaf whose issuer signed with ecdsa-with-SHA384.
pub struct LeafCertSha384 {
    pub sha384: [u8; 48],
    pub pubkey_x: [u8; 32],
    pub pubkey_y: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

/// A P-256 leaf whose issuer signed with ecdsa-with-SHA512.
pub struct LeafCertSha512 {
    pub sha512: [u8; 64],
    pub pubkey_x: [u8; 32],
    pub pubkey_y: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

/// Hash (SHA-384) and parse a DER TBSCertificate whose subject key is P-256
/// and whose TBS signature algorithm is ecdsa-with-SHA384.
pub fn bind_leaf_cert_sha384<let N: u32>(tbs: [u8; N], tbs_len: u32) -> LeafCertSha384 {
    assert(tbs_len <= N, "tbs_len exceeds buffer");
    let sha384 = tbs_sha384(tbs, tbs_len);
    let w = walk_tbs(tbs, tbs_len);
    assert_sig_alg(tbs, w, ALG_ECDSA_SHA384);
    let (pubkey_x, pubkey_y) = read_p256_spki(tbs, tbs_len, w.spki_start);
    LeafCertSha384 { sha384, pubkey_x, pubkey_y, not_before: w.not_before, not_after: w.not_after }
}

/// Hash (SHA-512) and parse a DER TBSCertificate whose subject key is P-256
/// and whose TBS signature algorithm is ecdsa-with-SHA512.
pub fn bind_leaf_cert_sha512<let N: u32>(tbs: [u8; N], tbs_len: u32) -> LeafCertSha512 {
    assert(tbs_len <= N, "tbs_len exceeds buffer");
    let sha512 = tbs_sha512(tbs, tbs_len);
    let w = walk_tbs(tbs, tbs_len);
    assert_sig_alg(tbs, w, ALG_ECDSA_SHA512);
    let (pubkey_x, pubkey_y) = read_p256_spki(tbs, tbs_len, w.spki_start);
    LeafCertSha512 { sha512, pubkey_x, pubkey_y, not_before: w.not_before, not_after: w.not_after }
}

/// Hash and parse a DER TBSCertificate whose subject key is P-256.
/// This body is kept as originally written (rather than calling walk_tbs)
/// so the compiled v2 circuits, and their verification keys, do not change.
pub fn bind_leaf_cert<let N: u32>(tbs: [u8; N], tbs_len: u32) -> LeafCert {
    assert(tbs_len <= N, "tbs_len exceeds buffer");
    let sha256: [u8; 32] = sha256_var(tbs, tbs_len);

    // Outer SEQUENCE must cover exactly tbs_len bytes.
    let (body, outer_end) = read_tlv(tbs, tbs_len, 0, 0x30);
    assert(outer_end == tbs_len, "DER: TBS SEQUENCE does not span tbs_len");

    // Optional [0] EXPLICIT version.
    let mut p = body;
    if tbs[p] == 0xa0 {
        let (_, e) = read_tlv(tbs, tbs_len, p, 0xa0);
        p = e;
    }
    // serialNumber, signature AlgorithmIdentifier, issuer
    let (_, e1) = read_tlv(tbs, tbs_len, p, 0x02);
    let (_, e2) = read_tlv(tbs, tbs_len, e1, 0x30);
    let (_, e3) = read_tlv(tbs, tbs_len, e2, 0x30);

    // validity
    let (vs, ve) = read_tlv(tbs, tbs_len, e3, 0x30);
    let (not_before, t1) = read_time(tbs, tbs_len, vs);
    let (not_after, t2) = read_time(tbs, tbs_len, t1);
    assert(t2 == ve, "DER: Validity length mismatch");

    // subject
    let (_, e5) = read_tlv(tbs, tbs_len, ve, 0x30);

    // subjectPublicKeyInfo: fixed P-256 prefix + X + Y
    assert(e5 + 91 <= tbs_len, "SPKI exceeds tbs_len");
    for i in 0..27 {
        assert(tbs[e5 + i] == SPKI_P256_PREFIX[i], "SPKI is not uncompressed P-256");
    }
    let mut pubkey_x: [u8; 32] = [0; 32];
    let mut pubkey_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        pubkey_x[i] = tbs[e5 + 27 + i];
        pubkey_y[i] = tbs[e5 + 59 + i];
    }

    LeafCert { sha256, pubkey_x, pubkey_y, not_before, not_after }
}

// ====================================================================
// TESTS (real certificates from public C2PA sample files)
// ====================================================================

mod tests {
    use super::{bind_leaf_cert, bind_leaf_cert_sha384, bind_leaf_cert_sha512, days_from_civil, LeafCert};
    use super::proofmode_vectors as pm;
    use super::test_vectors as tv;
    use super::synthetic_vectors as sv;

    global BUF: u32 = 1280;

    pub fn pad<let M: u32>(a: [u8; M]) -> [u8; BUF] {
        let mut out: [u8; BUF] = [0; BUF];
        for i in 0..M {
            out[i] = a[i];
        }
        out
    }

    fn check(c: LeafCert, sha: [u8; 32], x: [u8; 32], y: [u8; 32], nb: u64, na: u64) {
        assert(c.sha256 == sha, "sha256 mismatch");
        assert(c.pubkey_x == x, "pubkey_x mismatch");
        assert(c.pubkey_y == y, "pubkey_y mismatch");
        assert(c.not_before == nb, "not_before mismatch");
        assert(c.not_after == na, "not_after mismatch");
    }

    #[test]
    fn test_days_from_civil() {
        assert(days_from_civil(1970, 1, 1) == 0);
        assert(days_from_civil(2000, 3, 1) == 11017);
        assert(days_from_civil(2024, 2, 29) == 19782);
        assert(days_from_civil(9999, 12, 31) == 2932896);
    }

    #[test]
    fn test_leica_leaf_generalized_time() {
        let c = bind_leaf_cert(pad(tv::LEICA_LEAF_TBS), tv::LEICA_LEAF_TBS_LEN);
        check(
            c,
            tv::LEICA_LEAF_SHA256,
            tv::LEICA_LEAF_PUB_X,
            tv::LEICA_LEAF_PUB_Y,
            tv::LEICA_LEAF_NOT_BEFORE,
            tv::LEICA_LEAF_NOT_AFTER,
        );
    }

    #[test]
    fn test_samsung_leaf_utc_time() {
        let c = bind_leaf_cert(pad(tv::SAMSUNG_LEAF_TBS), tv::SAMSUNG_LEAF_TBS_LEN);
        check(
            c,
            tv::SAMSUNG_LEAF_SHA256,
            tv::SAMSUNG_LEAF_PUB_X,
            tv::SAMSUNG_LEAF_PUB_Y,
            tv::SAMSUNG_LEAF_NOT_BEFORE,
            tv::SAMSUNG_LEAF_NOT_AFTER,
        );
    }

    #[test]
    fn test_leica_intermediate_parses() {
        // The Leica intermediate also carries a P-256 key; the walk must
        // land on its SPKI too.
        let c = bind_leaf_cert(pad(tv::LEICA_INTER_TBS), tv::LEICA_INTER_TBS_LEN);
        check(
            c,
            tv::LEICA_INTER_SHA256,
            tv::LEICA_INTER_PUB_X,
            tv::LEICA_INTER_PUB_Y,
            tv::LEICA_INTER_NOT_BEFORE,
            tv::LEICA_INTER_NOT_AFTER,
        );
    }

    #[test(should_fail_with = "SPKI is not uncompressed P-256")]
    fn test_samsung_p384_intermediate_rejected() {
        let _ = bind_leaf_cert(pad(tv::SAMSUNG_INTER_TBS), tv::SAMSUNG_INTER_TBS_LEN);
    }

    #[test(should_fail_with = "SPKI is not uncompressed P-256")]
    fn test_adobe_rsa_leaf_rejected() {
        let _ = bind_leaf_cert(pad(tv::ADOBE_LEAF_TBS), tv::ADOBE_LEAF_TBS_LEN);
    }

    #[test]
    fn test_flipped_byte_changes_hash() {
        // Flip one byte at offset 300 (inside the issuer/subject Names). The
        // DER still parses, but the hash no longer matches the pinned value,
        // so the CA signature check in ProofA would fail.
        let mut t = pad(tv::LEICA_LEAF_TBS);
        t[300] = t[300] ^ 0x01;
        let c = bind_leaf_cert(t, tv::LEICA_LEAF_TBS_LEN);
        assert(c.sha256 != tv::LEICA_LEAF_SHA256, "flipped byte must change hash");
    }

    #[test]
    fn test_padding_does_not_affect_hash() {
        // Bytes past tbs_len are prover-chosen; they must not matter.
        let mut t = pad(tv::LEICA_LEAF_TBS);
        t[1000] = 0xff;
        t[1279] = 0x30;
        let c = bind_leaf_cert(t, tv::LEICA_LEAF_TBS_LEN);
        assert(c.sha256 == tv::LEICA_LEAF_SHA256);
    }

    #[test(should_fail_with = "pubkey_x mismatch")]
    fn test_wrong_pubkey() {
        // Leica leaf parses to the Leica key, not the Samsung key.
        let c = bind_leaf_cert(pad(tv::LEICA_LEAF_TBS), tv::LEICA_LEAF_TBS_LEN);
        check(
            c,
            tv::LEICA_LEAF_SHA256,
            tv::SAMSUNG_LEAF_PUB_X,
            tv::SAMSUNG_LEAF_PUB_Y,
            tv::LEICA_LEAF_NOT_BEFORE,
            tv::LEICA_LEAF_NOT_AFTER,
        );
    }

    #[test(should_fail_with = "DER: element exceeds tbs_len")]
    fn test_truncated_length() {
        // One byte short: the outer SEQUENCE now runs past tbs_len.
        let _ = bind_leaf_cert(pad(tv::LEICA_LEAF_TBS), tv::LEICA_LEAF_TBS_LEN - 1);
    }

    #[test(should_fail_with = "DER: element exceeds tbs_len")]
    fn test_truncated_before_spki() {
        let _ = bind_leaf_cert(pad(tv::SAMSUNG_LEAF_TBS), 200);
    }

    #[test(should_fail_with = "DER: TBS SEQUENCE does not span tbs_len")]
    fn test_overlong_length() {
        // One trailing padding byte claimed as part of the TBS.
        let _ = bind_leaf_cert(pad(tv::LEICA_LEAF_TBS), tv::LEICA_LEAF_TBS_LEN + 1);
    }

    #[test(should_fail_with = "tbs_len exceeds buffer")]
    fn test_len_exceeds_buffer() {
        let _ = bind_leaf_cert(pad(tv::LEICA_LEAF_TBS), 1281);
    }

    #[test(should_fail_with = "Time: non-digit")]
    fn test_bad_time_digit() {
        // Find the first Time (GeneralizedTime, 0x18 0x0f) and corrupt a digit.
        let mut t = pad(tv::LEICA_LEAF_TBS);
        let mut off: u32 = 0;
        for i in 0..400 {
            if (off == 0) & (t[i] == 0x18) & (t[i + 1] == 0x0f) {
                off = i;
            }
        }
        assert(off != 0);
        t[off + 5] = 0x41; // 'A'
        let _ = bind_leaf_cert(t, tv::LEICA_LEAF_TBS_LEN);
    }

    #[test(should_fail_with = "Time: missing trailing Z")]
    fn test_bad_time_zulu() {
        let mut t = pad(tv::SAMSUNG_LEAF_TBS);
        let mut off: u32 = 0;
        for i in 0..400 {
            if (off == 0) & (t[i] == 0x17) & (t[i + 1] == 0x0d) {
                off = i;
            }
        }
        assert(off != 0);
        t[off + 14] = 0x30;
        let _ = bind_leaf_cert(t, tv::SAMSUNG_LEAF_TBS_LEN);
    }

    #[test(should_fail_with = "SPKI is not uncompressed P-256")]
    fn test_spki_curve_oid_altered() {
        // Change the curve OID's last byte (P-256 -> other) in a real leaf.
        let mut t = pad(tv::SAMSUNG_LEAF_TBS);
        let mut off: u32 = 0;
        for i in 0..900 {
            if (off == 0) & (t[i] == 0x30) & (t[i + 1] == 0x59) & (t[i + 2] == 0x30) & (t[i + 3] == 0x13) {
                off = i;
            }
        }
        assert(off != 0);
        t[off + 22] = 0x22;
        let _ = bind_leaf_cert(t, tv::SAMSUNG_LEAF_TBS_LEN);
    }

    #[test]
    fn test_sha384_leaf_binds() {
        let c = bind_leaf_cert_sha384(pad(sv::SYN_P384_SHA384_LEAF_TBS), sv::SYN_P384_SHA384_LEAF_TBS_LEN);
        assert(c.sha384 == sv::SYN_P384_SHA384_LEAF_SHA384, "sha384 mismatch");
        assert(c.pubkey_x == sv::SYN_P384_SHA384_LEAF_PUB_X);
        assert(c.pubkey_y == sv::SYN_P384_SHA384_LEAF_PUB_Y);
        assert(c.not_before == sv::SYN_P384_SHA384_LEAF_NOT_BEFORE);
        assert(c.not_after == sv::SYN_P384_SHA384_LEAF_NOT_AFTER);
    }

    #[test]
    fn test_sha384_padding_does_not_affect_hash() {
        let mut t = pad(sv::SYN_P384_SHA384_LEAF_TBS);
        t[sv::SYN_P384_SHA384_LEAF_TBS_LEN] = 0xff;
        t[1279] = 0x01;
        let c = bind_leaf_cert_sha384(t, sv::SYN_P384_SHA384_LEAF_TBS_LEN);
        assert(c.sha384 == sv::SYN_P384_SHA384_LEAF_SHA384);
    }

    #[test(should_fail_with = "TBS signature algorithm mismatch")]
    fn test_sha384_rejects_sha256_signed_leaf() {
        // Samsung leaf is signed ecdsa-with-SHA256; the SHA-384 path must refuse it.
        let _ = bind_leaf_cert_sha384(pad(tv::SAMSUNG_LEAF_TBS), tv::SAMSUNG_LEAF_TBS_LEN);
    }

    #[test]
    fn test_sha512_proofmode_leaf_binds() {
        let c = bind_leaf_cert_sha512(pad(pm::PROOFMODE_LEAF_TBS), pm::PROOFMODE_LEAF_TBS_LEN);
        assert(c.sha512 == pm::PROOFMODE_LEAF_SHA512, "sha512 mismatch");
        assert(c.pubkey_x == pm::PROOFMODE_LEAF_PUB_X);
        assert(c.pubkey_y == pm::PROOFMODE_LEAF_PUB_Y);
        assert(c.not_before == pm::PROOFMODE_LEAF_NOT_BEFORE);
        assert(c.not_after == pm::PROOFMODE_LEAF_NOT_AFTER);
    }

    #[test(should_fail_with = "TBS signature algorithm mismatch")]
    fn test_sha512_rejects_sha256_signed_leaf() {
        let _ = bind_leaf_cert_sha512(pad(tv::LEICA_LEAF_TBS), tv::LEICA_LEAF_TBS_LEN);
    }
}
