# Apertrue ZK Circuits

Zero-knowledge circuits for C2PA media verification, written in [Noir](https://noir-lang.org/) (v1.0.0-beta.18).

These circuits prove that a photo or video has a valid C2PA signature from a trusted device — without revealing the device certificate, location, or any identifying metadata.

## Circuit Overview

### Split-Proof Circuits (Certificate Chain Verification)

The split-proof architecture separates verification into two independent proofs that run in parallel, enabling hardware-adaptive parallelism and supporting RSA-4096 keys that exceed single-circuit constraints.

| Circuit | Purpose | Signature Algorithms |
|---------|---------|---------------------|
| `proof_a_rsa_2048` | RSA-2048 certificate chain verification | RSA-2048 + SHA-256 |
| `proof_a_rsa_4096` | RSA-4096 certificate chain verification | RSA-4096 + SHA-256 |
| `proof_a_ecdsa_p256` | ECDSA P-256 certificate chain verification | ECDSA secp256r1 |
| `proof_a_ecdsa_p384` | ECDSA P-384 certificate chain verification | ECDSA secp384r1 |
| `proof_a_skip` | Development bypass (no signature check) | — |
| `proof_b` | COSE signature + trust list Merkle inclusion | — |
| `proof_b_es256` | COSE ES256 specialisation | ECDSA P-256 |
| `proof_b_ps256` | COSE PS256 specialisation | RSA-PSS + SHA-256 |

**ProofA** verifies the X.509 certificate chain signature (camera → intermediate CA → root).
**ProofB** verifies the COSE signature over the C2PA claim and proves the intermediate CA is in the trust list Merkle tree.

Both proofs bind to the same content hash and link commitment, preventing substitution.

### Aggregation Circuits

| Circuit | Purpose |
|---------|---------|
| `image_aggregator` | Combines ProofA + ProofB for a single image with link commitment binding |
| `tree_aggregator` | Binary tree aggregation — combines 2 proofs into 1 (reusable at any tree level) |

### Privacy & Identity Circuits

| Circuit | Purpose |
|---------|---------|
| `selective_disclosure` | Proves image was verified without revealing private metadata (on-chain) |
| `anonymous_credential` | Group membership proof for anonymous identity credentials |
| `credential_registration` | Identity commitment and nullifier derivation |
| `jwt_identity` | JWT claim verification for OIDC identity linking |

### Aztec Smart Contracts

| Contract | Purpose |
|----------|---------|
| `aztec_verifier` | On-chain proof verification + verification record storage |
| `webauthn_account` | WebAuthn P-256 account contract with session key support |

Both target Aztec Network v3.0.3.

## Building

### Prerequisites

- [Nargo](https://noir-lang.org/docs/getting_started/installation/) v1.0.0-beta.18
- Docker (for Aztec contract transpilation)

### Compile All Circuits

```bash
# From repo root
./scripts/build-all-circuits.sh

# Or compile a single circuit
cd circuits/proof_a_rsa_2048
nargo compile
```

### Run Tests

```bash
cd circuits/proof_a_rsa_2048
nargo test
```

### Build Aztec Contracts

```bash
cd circuits/aztec_verifier
./build.sh           # Full pipeline: compile → AVM transpile → VK generation → TS codegen
./build.sh --skip-compile  # Reprocess without recompiling
```

The build script runs `bb-avm aztec_process` in Docker for AVM transpilation and verification key generation.

## Dependencies

Key Noir libraries used across circuits:

| Library | Version | Purpose |
|---------|---------|---------|
| `noir_rsa` | 0.9.2 (zkpassport fork) | RSA signature verification with PSS support |
| `bignum` | 0.8.0 | Big integer arithmetic for RSA modular exponentiation |
| `sha256` | 0.2.1 | SHA-256 hash computation |
| `poseidon` | 0.1.1 | Poseidon hash for ZK-friendly commitments |
| `bb_proof_verification` | 3.0.3 | Recursive proof verification (aggregation circuits) |

## Security Model

- Certificate chains are verified in-circuit — invalid signatures produce unsatisfiable constraints
- Content hash binding prevents proof reuse across different images
- Nullifiers (content hash + leaf key hash) prevent replay attacks
- Commitment salts are never revealed in the proof — only Poseidon hashes are public
- Trust list inclusion uses Merkle proofs against a signed oracle bundle

## License

Apache 2.0 — see [LICENSE](../LICENSE).
