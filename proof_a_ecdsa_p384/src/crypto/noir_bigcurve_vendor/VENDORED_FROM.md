# Vendored Library: noir_bigcurve

## Source
- **Repository**: https://github.com/noir-lang/noir_bigcurve
- **Tag**: v0.12.0
- **Commit**: 99ec9b0e2acf81e36bbc8362c9cf94ddb028bb55
- **Date Vendored**: 2026-01-15

## License
MIT License (see original repository)

## Purpose
Provides generic elliptic curve arithmetic (point add, double, scalar mul) for ECDSA verification on arbitrary curves including secp384r1 (P-384).

## Modifications
- Extracted core files only (lib.nr, curve_jac.nr, scalar_field.nr)
- Added P-384 curve parameters in p384.nr
- Removed test_data.nr (large file not needed for production)

## Dependencies
- noir-bignum v0.8.2 (compatible with project's existing noir-bignum@v0.8.0)
