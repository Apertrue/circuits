# coNoir spike — authenticated-nullifier double-dip check under MPC

Proof-of-life for the **apertrue × coNoir** primitive: prove whether an authenticated
nullifier already exists in a consortium's private set, revealing **only** a yes/no bit,
with the candidate and the set kept secret-shared across the MPC parties.

## Result (2026-06-23)
Ran the full 3-party REP3 MPC pipeline (split-input → witness → proving-key → vk → proof → verify)
on `nullifier_check`:

| Case | Public output | Verified |
|------|---------------|----------|
| candidate not in set      | `0` (false) | ✅ |
| candidate in set (double-dip) | `1` (true)  | ✅ |

Whole pipeline ~1s for this tiny circuit (proving ~77ms, verify ~2ms). Only the bit was revealed.

## Circuit
`nullifier_check/src/main.nr` — derives `n = Poseidon2([content, scope])`, scans a private
set for membership, returns the collision bit. Poseidon2 + field equality only → inside coNoir's
supported MPC lane (no RSA/ECDSA, which stay in apertrue's local C2PA proof).

## Versions
- co-noir **0.7.0** (built from `github.com/TaceoLabs/co-snarks`).
- nargo **1.0.0-beta.20** (coNoir's target; apertrue is on beta.18 — small gap).
- bn254 CRS from the co-snarks repo.

## Reproduce
`run_nullifier_check.sh` is preserved **as a reference**. Its relative paths assume it sits in
`co-noir/co-noir/examples/` of a co-snarks clone (it points at `../../../target/release/co-noir`
and `../../co-noir-common/src/crs/*`). To re-run: clone co-snarks, `cargo build --release --bin
co-noir`, drop `nullifier_check/` into `examples/test_vectors/`, place this script in `examples/`,
and run it. Compile the circuit with nargo beta.20 first (`nargo execute`).

## IMT non-membership primitive (2026-06-23)
`imt_nm_mini` isolates the two operations Colofon's `check_non_membership` needs that fall in
coNoir's risk zone (bit-decomposition based): `Field::lt` (the low-leaf range check) and
`to_le_bits` (Merkle-path left/right selection), plus Poseidon2. Depth-8, single check,
221 ACIR opcodes / 3845 gates.

Ran under 3-party REP3 MPC -> **proof verified**. So coNoir's co-brillig/co-acvm handle those ops;
the full Colofon IMT non-membership will port. Perf: build-proving-key ~2.0s (dominant, scales with
circuit size), generate-proof ~0.6s, verify ~3ms, ~4s total.

beta.20 migration notes for the real port: `u1` is removed (use `bool`); `to_le_bits` returns
`[bool; N]` (Colofon's `root.nr` still uses the old `[u1; N]`).

## Next step
Wire up the **real `colofon_imt` lib** (traits/generics + CveLeafPreimage + a real tree witness) at
depth-32 / up to 50 checks to get the true-scale MPC proving time. Still all-local nodes so far
(no network latency in these numbers).
