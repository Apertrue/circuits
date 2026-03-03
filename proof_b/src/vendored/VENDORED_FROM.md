# Vendored Library: noir_rsa (RSA-PSS verification)

## Source
- **Repository**: https://github.com/zkpassport/noir_rsa
- **Tag**: v0.9.2
- **License**: Apache 2.0

## Purpose
RSA-PSS signature verification for PS256 (Adobe, ChatGPT, ProofMode RSA) COSE signatures in the split-proof architecture.

## Why Vendored
The `rsa_pss.nr` file contains a modified PSS verification routine that differs from the upstream `verify_sha256_pss` function. The standard noir_rsa dependency is also used via Nargo.toml for RSA-PKCS1v1.5 verification.

## Modifications
- Adapted PSS encoding/verification for the specific field layout used in Apertrue's proof_b circuit inputs.
