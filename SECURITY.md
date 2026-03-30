# Security Model & Known Limitations

This document describes the trust assumptions and known limitations of Apertrue's ZK circuits. It is intended for auditors, security researchers, and anyone evaluating the soundness of the proof system.

## Trust Assumptions

### 1. Metadata values are client-extracted, not parsed in-circuit

GPS coordinates (`exact_lat_scaled`, `exact_lon_scaled`) and timestamps (`exact_timestamp`) are provided as private witness values. The circuit verifies that the EXIF assertion bytes are authentic (via the hash chain binding to the signed claim), but does **not** parse CBOR/EXIF to extract these values in-circuit.

**Why**: CBOR and EXIF parsing in Noir would add tens of thousands of constraints and is not feasible with current tooling.

**Mitigation**: The hash chain cryptographically binds the assertion bytes to the C2PA signature. A malicious prover cannot alter the assertion bytes, but could theoretically provide different extracted values from those bytes. The commitment scheme (Poseidon2 hash of exact values + salt) ensures that any disclosed values in selective disclosure must match what was originally committed.

### 2. Certificate validity timestamps are witness-provided

`cert_not_before` and `cert_not_after` are public inputs, not derived from X.509 certificate DER data in-circuit.

**Why**: X.509 DER/ASN.1 parsing in Noir is not feasible.

**Mitigation**: These are public inputs visible to verifiers. The backend and on-chain verifier should independently validate these timestamps against known certificate metadata. The image aggregator cross-checks that ProofA and ProofB agree on these values.

### 3. `bytes_to_field` can overflow BN254

SHA-256 outputs (256 bits) and P-384 coordinates (384 bits) exceed the BN254 scalar field (~254 bits). The `bytes_to_field` helper silently reduces modulo p, creating a theoretical collision space.

**Impact**: For SHA-256 hashes, approximately 1 in 2^2 values have a collision partner. For P-384 coordinates, the collision space is larger. Finding a meaningful collision (two valid certificates or hashes that map to the same field element) remains computationally infeasible.

**Future fix**: Split 32-byte values into two 128-bit field elements. This is a breaking change to the commitment scheme and requires coordinated migration.

### 4. Two-certificate chains (cert_algorithm == 5)

For 2-cert chains (e.g., ProofMode), the `intermediate_leaf` witness is not derived from certificate key material in-circuit. It is accepted as-is and checked against the trust list Merkle tree.

**Why**: 2-cert chains have a different structure (self-signed root → leaf) that doesn't fit the 3-cert chain verification logic. The intermediate identity needs to be derived from the issuer DN, which requires byte packing and hashing that is currently done client-side.

**Mitigation**: The trust list is curated and signed. An attacker would need to know a valid leaf in the trust list to exploit this. The `skip_content_hash_binding` and `skip_assertion_hash_verification` flags are now public inputs, so verifiers can see when these checks are skipped and apply appropriate trust policy.

### 5. Selective disclosure location range cannot cross equator or prime meridian

The location range proof uses magnitude + sign representation. A single bounding box cannot span the equator (latitude sign change) or prime meridian (longitude sign change).

**Impact**: A verifier requesting proof that a photo was taken in a region crossing these boundaries must use two separate range proofs.

## Security Fixes Applied

The following hardening measures were added based on internal audit:

- **Merkle index binary constraints**: All `merkle_indices[i]` values are asserted to be 0 or 1
- **Field-to-u64 range checks**: All Field values cast to u64 for comparisons include roundtrip assertions (`val as u64 as Field == val`)
- **Boolean sign flag constraints**: `exact_lat_is_negative` and `exact_lon_is_negative` are constrained to 0 or 1
- **Buffer length bounds checks**: `claim_length`, `assertion_length`, `sig_structure_length` are checked against their maximum buffer sizes
- **P-384 ECDSA r/s non-zero**: Signature components are asserted non-zero before verification
- **Leaf key type consistency**: `leaf_key_type` is constrained to match `cert_algorithm`
- **VK hash transparency**: Verification key hashes are exposed as public outputs from aggregator circuits for external allowlist checking
- **Skip flag transparency**: Content hash binding and assertion hash skip flags are public inputs
- **Cross-proof consistency**: Certificate validity period and content hash offset are cross-checked between ProofA and ProofB in the image aggregator
- **Link commitment non-zero**: Prevents vacuous binding between split proofs
- **Path depth bounds**: Selective disclosure path depth is range-checked and bounded by MAX_TREE_DEPTH

## Audit Status

These circuits have **not** been formally audited by a third party. The security hardening above was applied based on internal review. A formal audit is recommended before production use with high-stakes verification (legal evidence, insurance claims, etc.).
