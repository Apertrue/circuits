# Apertrue Quorum — P0/P1: double-financing check, two signer roles, under MPC

Runnable proof-of-life for the receivables product (`apertrue-quorum-plan.md`). Answers the
First Brands question — *has this exact receivable already been financed anywhere in the
network?* — under 3-party REP3 MPC, revealing **only one bit + which guarantee the anchor
carries**. Demonstrates the **two-signer thesis**: the signer is configurable per market,
and *which fraud you catch depends on who signs*.

## The First Brands correction (why two signers, not one)
First Brands was **not only** double-pledging of real invoices — it was **also** fabricated
and inflated invoices (invented sales; amounts inflated up to ~10×). So:
- **Clearance (SdI) alone** would have caught the double-pledge slice and **missed the
  fabrication slice** — a large part of the actual fraud.
- The **obligor (debtor)** signature catches fabrication/inflation, because the debtor will
  not sign a lie.
- **Together** they are the honest answer to "what would have caught First Brands."
  Clearance is *not* sufficient on its own; don't let any single-signer framing imply it is.

## Two signer roles → two different guarantees
| Role | Signer | Guarantee the proof carries | Catches |
|---|---|---|---|
| 1 | SdI clearance (Agenzia delle Entrate) | "uniquely identified, cleared, **not** financed elsewhere" — **NOT** proof the debt is real | double-pledging |
| 2 | Obligor / debtor confirmation | "the debt is **genuinely owed**" (stronger) | double-pledging **and** fabrication/inflation |

The role is **bound into the anchor** (`anchor = Poseidon2([canonical_id, salt, role])`), so
an SdI anchor and an obligor anchor for the same receivable are distinct and cannot be
swapped, and the role is never silently upgraded.

## Layers
- `commit_receivable/` — Layer 1: `canonical_id = Poseidon2([uuid,debtor,amount,date])`,
  role-bound `anchor`.
- `p1_provenance/admission/admission.sh` — Layer 2 **acceptable-anchor allow-list**
  (off-MPC). Real openssl cert chains; admits a submission only if the inner signature
  verifies **over the canonical_id** (so the signer vouches for exactly debtor∥amount∥id)
  **and** the signer chains to a trusted root; the root fixes the role. `p1_provenance/`
  also has a real C2PA-signed invoice PDF (via c2pie).
- `bound_receivables/` — Layer 3 (MPC): binds secret-shared fields to the role-bound anchor,
  enforces the role is in the allow-list, scans the network's financed fingerprints, reveals
  `(already_financed, role)`.

## Admission decisions (Layer 2, real cert chains)
```
obligor: true receivable            -> ADMITTED role=2  the debt is GENUINELY OWED
SdI: true receivable                -> ADMITTED role=1  cleared (NOT proof of debt)
SdI: INFLATED (seller cleared)      -> ADMITTED role=1  cleared (NOT proof of debt)   <- the gap
obligor: INFLATED (fabrication)     -> REJECTED  no obligor signature over the lie    <- fabrication caught
seller self-signed                  -> REJECTED  signer not in allow-list             <- fraudster can't self-vouch
```

## MPC results (Layer 3, full 3-party REP3, proof verified)
| # | Scenario | Output | Verified |
|---|----------|--------|----------|
| 1 | obligor, true, not financed | `already_financed=0`, role 2 — **owed** | ✅ |
| 2 | obligor, true, double-financed | `already_financed=1`, role 2 — **owed** | ✅ |
| 3 | SdI, **inflated** (seller cleared), not financed | `already_financed=0`, role 1 — **cleared, NOT owed** (the gap) | ✅ |
| 4 | seller self-signed (role 3) | — | ❌ rejected by MPC allow-list (defense in depth) |

Where each fraud is caught: **fabrication/inflation → at admission** (no obligor signature
over the lie). **Seller-as-signer → at admission *and* in-MPC allow-list** (defense in
depth). **Double-pledging → in-MPC membership** (bit = 1). The MPC binding alone proves
"these fields open this anchor"; it does **not** prove the signer was acceptable — that is
the admission/allow-list job, which is why both layers exist.

## Reproduce
```
cd p1_provenance/admission && ./admission.sh      # Layer 2 allow-list decisions
cd ../.. && ./run_quorum_scenarios.sh             # Layer 3 MPC, all four scenarios
```

## Still stand-in (needs a design partner / deeper C2PA build)
- Clearance + obligor certs are self-made CAs — real SdI / debtor certs need a partner.
- Asset is a PDF rendering (c2pie); raw-XML C2PA needs the data-hash sidecar API.
- Receivable fields carried as CreativeWork; custom assertion = c2pie programmatic API (P1.next).
