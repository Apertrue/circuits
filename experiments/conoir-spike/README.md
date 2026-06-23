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

## Depth-32 scale perf (2026-06-23)
`imt_nm_scale` mirrors Colofon's per-component non-membership shape (leaf-preimage hash + low-leaf
`lt` + 32-level Merkle path), batched over N checks. `bench_imt_scale.sh N` patches `CHECKS`,
generates the witness, compiles, counts gates, and runs the timed 3-party MPC pipeline.

| N (checks) | gates | witness | proving-key | proof | verify | total |
|------------|-------|---------|-------------|-------|--------|-------|
| 1          | 5,798 | 0.6s    | 2.3s        | 1.2s  | 29ms   | ~4.1s |
| 50 (full)  | 153,843 | 23s   | 107s        | 30s   | 29ms   | ~160s (~2.7 min) |

~3k gates per added depth-32 check; proving-key dominant + slightly super-linear; **verify constant
29ms regardless of scale.** Full-scale double-dip ≈ 2.7 min to prove, instant to verify — fine for a
batch/async fraud check. Caveat: all 3 MPC nodes co-located, so NO network latency in these numbers.

## Binding / authenticated-MPC seam (2026-06-23)
`bound_nm` demonstrates the apertrue <-> coNoir binding. A public `commitment = Commit(nullifier,
blind)` is the authenticity anchor (in the real system apertrue's C2PA proof attests it off-MPC;
it is hiding so it leaks nothing). The party secret-shares `(nullifier, blind)`; a lightweight
in-MPC opening check binds them to the commitment; non-membership runs on the deterministic
secret-shared nullifier; only the collision bit is revealed. No recursive proof verification in MPC.

Ran under 3-party MPC:
- no-collision -> bit 0 (verified)
- collision (set contains the nullifier) -> bit 1 (verified)
- binding failure (substitute a nullifier that does NOT open the commitment) -> rejected,
  "Assertion failed: commitment opening failed"

The binding-failure case is the security property: a party cannot substitute an arbitrary nullifier;
it must open the authenticated commitment.

### Threat-model notes (from design review)
- MPC protects the registry AT REST (1 REP3 node can't read shares). The real attack is the
  membership ORACLE (guess a low-entropy ID, query, read the bit) -> require a C2PA-authenticated
  query too (can only test items you authentically hold).
- coNoir is **semi-honest** only (`mpc-core/src/lib.rs`): secure vs passive nodes, NOT vs actively
  deviating ones. For competing institutions, either run nodes under reputable/independent/audited
  operators (governance) or wait for malicious-secure REP3 (not yet implemented).
- Privacy rests on: honest-but-curious operators + no 2-of-3 collusion.

## Literal colofon_imt port (2026-06-23)
`imt_real` calls the REAL `colofon_imt` lib (`check_non_membership` + `CveLeafPreimage`), not a
reimplementation. It compiles under nargo beta.20 and runs under 3-party coNoir MPC: `non_existence`
proven true, verified, ~3.5s at depth-8. Confirms faithfulness end to end.

The port needs exactly two migrations to the lib (against beta.20):
1. `root.nr`: `[u1; N]` -> `[bool; N]` (and `if indices[i] == 1` -> `if indices[i]`) -- `u1` removed.
2. `Nargo.toml`: bump the `poseidon` dep `v0.1.1` -> `v0.3.0` (v0.1.1 fails under beta.20:
   "Comptime global RATE used in non-comptime code" + a Poseidon2::hash arity error).
`imt_real` here depends on a beta.20-migrated copy of `colofon_imt` (lib copy not committed; the two
migrations above are the whole delta).

## Remaining build items
- Networked 3-machine latency: NOT done -- needs real infra (3 machines / WAN). All numbers here are
  co-located, so no network-round latency is reflected. This is an infra task, not a code task.
- When a lighthouse is committed: graft the blinded-commitment output into production apertrue
  proof_a/proof_b (NOT done here -- a breaking change to the live proof format, premature pre-lighthouse).
