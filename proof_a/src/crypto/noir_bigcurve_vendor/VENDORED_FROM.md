# Vendored Library: noir_bigcurve

## Source
- **Repository**: https://github.com/noir-lang/noir_bigcurve
- **Tag**: v0.12.0
- **Commit**: 99ec9b0e2acf81e36bbc8362c9cf94ddb028bb55
- **Date Vendored**: 2026-01-15

## License
Upstream ships no license file as of v0.12.0 (nor on main at the time of
writing); noir-lang libraries are customarily MIT/Apache-2.0 and a license
clarification has been requested upstream. This directory is redistributed
on that basis and will be updated when upstream declares a license.

## Purpose
Provides generic elliptic curve arithmetic (point add, double, scalar mul) for ECDSA verification on arbitrary curves including secp384r1 (P-384).

## Modifications
- Extracted core files only (lib.nr as mod.nr, curve_jac.nr, scalar_field.nr, utils)
- Kept only the secp384r1 curve from upstream's curves/ directory (the curve
  definition and parameters are upstream's own, unmodified)
- Import paths rewritten to embed as a module (crate::crypto::noir_bigcurve_vendor)
- Disabled the derive_offset_generators module (unused at runtime) and its test
- Removed test_data.nr, bigcurve_test.nr, and benchmarks (not needed for production)

## Dependencies
- noir-bignum v0.8.2 (compatible with project's existing noir-bignum@v0.8.0)
