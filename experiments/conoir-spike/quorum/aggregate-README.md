# Apertrue Quorum — aggregate engine: marine over-insurance, under MPC (2026-06)

Runnable proof-of-life for the second fraud shape in `apertrue-quorum-plan.md`: not "has this
been seen before?" (membership) but "do separate, legitimate pieces sum past a limit?". The
case is a hull insured by several insurers past its agreed value, the point at which a ship is
worth more sunk than afloat. Answered under 3-party REP3 MPC, revealing **only one bit**.

## Circuits
- `commit_aggregate/` — Layer 1 (off-MPC). Role-stamped anchors `Poseidon2([value, salt,
  role])` for each insurer line (role 3) and the valuer-signed agreed value (role 4).
- `bound_aggregate/` — Layer 3 (MPC). Binds each secret-shared line to its insurer anchor and
  the secret-shared agreed value to the valuer anchor, checks both roles against the
  allow-list, sums the lines, and reveals only whether the sum exceeds the agreed value.

## Authenticity (two signers, adapted)
- Each **line** is signed by the **insurer** that wrote it (role 3): honest, free, it vouches
  for its own exposure.
- The **agreed value** is signed by a **valuer** (role 4), never the owner, who could inflate
  it. An inflated value does not open the valuer's anchor and is rejected.

## Result (full 3-party MPC, proof verified)
| Case | Setup | Output | Verified |
|------|-------|--------|----------|
| over-insured | lines 20M + 25M + 10M = 55M, value 50M | `over_insured = 1` | ✅ |
| within the limit | same lines, value 60M | `over_insured = 0` | ✅ |
| fabricated line | a line inflated to 30M, breaks its insurer anchor | — | ❌ rejected |
| wrong signer role | a line carrying the valuer role instead of an insurer's | — | ❌ rejected by the allow-list |

No insurer's line and no agreed value is revealed; only the bit crosses between the parties.
The fabricated and wrong-role cases fail at verification, exactly as in the membership engine.

## Scope
Same as the rest of the spike: the engine, the binding and the allow-list are real and run.
The certificates (insurer, valuer) are stand-in; the lines and value are sample figures.

## Reproduce
```
cd commit_aggregate && ~/.nargo/bin/nargo execute        # prints the four anchors
cd .. && ./run_bound_aggregate.sh                        # over-insured case, full MPC
./run_bound_aggregate.sh /path/to/variant_Prover.toml    # other cases
```
