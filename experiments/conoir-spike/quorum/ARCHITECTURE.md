# Apertrue Quorum — Architecture Design

Consolidated from the authenticity analysis (C2PA vs PAdES/e-invoice/clearance,
canonicalisation, the two-signer model). This is the target production
architecture; it is deliberately **envelope-agnostic** with **pluggable input
adapters**, so we never fork the system per industry.

---

## 0. The one-line shape

```
source document → [INPUT ADAPTER] → {canonical fields, signatures, certs}
                → [CANONICALISATION] → canonical_id, anchor
                → [PROOF A, per party, in-circuit] → role-stamped anchor (+ proof)
                → [ENGINE, joint via coNoir] → one bit (+ portable proof)
```

The **core** (canonicalisation → Proof A → engine → coNoir) is shared across
every vertical. Only the **input adapter** changes per document format.

---

## 1. Invariants (do not break these)

1. **The core is envelope-agnostic.** It consumes `{canonical fields, signatures,
   trust anchors}` — never a specific document format. (Confirmed: the circuits
   already operate on canonical fields, never on C2PA.)
2. **Two guarantees, married:** authenticity (a non-gameable signature) **and**
   private joint computation (coNoir). Neither alone is enough.
3. **The trust is the *signer*, not the envelope.** C2PA/PAdES/e-invoice are
   transport; the trust comes from *who signed* the canonical fields.
4. **Per-vertical authenticity:** ride native rails where they exist
   (structured), use C2PA where they don't (unstructured/media). Never force a
   format onto producers.
5. **No operator ever holds the union.** Each party keeps its own book; only
   roots/commitments are public; only one bit leaves.

---

## 2. The core (shared) — mostly built

- `canonical_id = Poseidon2([canonical fields])`
- `anchor       = Poseidon2([canonical_id, salt, signer_role])`
- **Three engines**, pick per use case:
  - **Membership** (duplication / double-X) — `bound_receivables`, IMT non-membership.
  - **Aggregate** (sum vs a signed limit) — `bound_aggregate`.
  - **Relational** (distance / time / order) — `bound_geotime`.
- **Status:** built and proven under real 3-party REP3 MPC.

---

## 3. Proof A — the authenticity binding  **(PRIORITY BUILD — the soundness fix)**

**Today (stand-in):** the obligor signature is verified *off-circuit* (openssl in
admission); the circuit only consumes the role-stamped `anchor` and checks
`signer_role ∈ accepted_roles`. So the trustless proof does **not** itself attest
that a real obligor signed — a fabricated anchor claiming `role = obligor` would
pass the MPC.

**Target (sound):** Proof A runs **in-circuit**, per party, and:
1. verifies the **obligor's** ES256 signature **over `canonical_id`**,
2. verifies the **issuer/clearance** signature,
3. checks **both certs ∈ trust-list Merkle root**,
4. binds to the **role-stamped anchor**.

So the one-bit answer provably rests on a genuine, obligor-signed document.

**Reuse:** apertrue's `proof_a_ecdsa_p256` already does in-circuit ES256
verification + Merkle membership + nullifier binding. This is integration, not
new crypto.

**Two-signer model:**
- **issuer / clearance** signs → the invoice is *genuine* (catches fabricated documents).
- **obligor** signs → the debt is *owed* (catches fabricated debts; the non-gameable signer).
- Roles are bound into the anchor.

---

## 4. Input adapters (off-circuit, per vertical) — build at pilot

**Adapter contract (the interface every adapter satisfies):**

```
adapter(source_document) -> {
  canonical_fields,                       // the fields the canonicaliser hashes
  issuer:  { signature, cert_chain },     // signer #1 (genuine)
  obligor: { signature, cert_chain },     // signer #2 (owed)  — over canonical_id
}
```

Because every adapter emits this same shape, **Proof A and the engines never
change per vertical.**

- **Native-rail adapter** (structured: FatturaPA / UBL / CII / EDI): parse the
  e-invoice → canonical fields; ride the **clearance / AdES (XAdES/PAdES)**
  signature as *issuer*; source the **obligor** confirmation from a buyer
  acceptance / **approved-payables** confirmation. Lean on EN 16931 field
  definitions + existing parsers (e.g. Mustangproject) — map a few syntaxes to
  the canonical schema, not one per country.
- **C2PA adapter** (unstructured docs + media): read the signed **custom
  assertion** carrying canonical fields + obligor signature; verify the COSE
  manifest signature; bind via `c2pa.hash.data`. This is where C2PA is
  load-bearing (no native rail to ride).

**Do not pre-build adapters.** Build the one the first pilot's documents need.

---

## 5. Canonicalisation — the make-or-break

- A **deterministic spec**: exactly how each field normalises
  (VAT, `amount → cents`, `date → YYYYMMDD`, currency, ...) → `canonical_id`.
  Two parties must derive byte-identical ids from the same source.
- **Key move:** the **non-gameable signer emits *and* signs the canonical form**
  (`canonical_id`). Then verifying parties don't re-canonicalise — they verify the
  signature over the signed `canonical_id`. This solves determinism **and**
  binding at once. (The run-through already does this: the obligor signs
  `canonical_id`.)
- Where the signer only signs the native document, the adapter recomputes
  `canonical_id` from it under the shared spec and binds by matching hashes.
- Per-vertical field set; ride EN 16931 fields where available.

---

## 6. The signer — the partner-dependent crux (GTM, not crypto)

- **issuer/clearance:** a tax platform (SdI), an e-invoice clearance, or a
  verified platform.
- **obligor:** the customer who owes — sourced from a **buyer acceptance** or,
  strongest and already in production, an **approved-payables / supply-chain-
  finance confirmation**, where the anchor buyer already confirms invoices.
- **Today:** a self-made CA stand-in. A real non-gameable signer is the
  **critical path** — and likely lives in **approved-payables finance**, where
  *both* signers (cleared invoice + buyer confirmation) already exist.

---

## 7. Deployment & trust model

- coNoir runs on a **committee of independent, non-colluding operators** (REP3 /
  proof delegation, e.g. TACEO:Proof). No single operator — and not Apertrue —
  ever holds the union; each only sees a secret share.
- **Registry-of-roots:** each party publishes a committed root; the cross-party
  check is **non-membership against published roots** (indexed Merkle tree).
- **Freshness:** two financings in the same window before roots refresh can both
  read "not financed" — stated as an explicit **settlement-window** bound.
- **Liveness:** the always-on committee stands in for offline parties.

---

## 8. Honest status

| Component | State |
|---|---|
| Core engines (membership / aggregate / relational) | **built**, MPC-proven (3-party) |
| Canonicalisation (FatturaPA fields) | **real** for the demo |
| C2PA packaging (c2pie) | **real** (media-first tooling; PDF support nascent) |
| **Proof A — in-circuit signature binding** | **BUILT + e2e-proven** (`proof_a_receivable`; `run_proof_a.sh`) |
| **Obligor signature verified in-circuit** | **BUILT + e2e-proven** (ECDSA-P256 over `canonical_id`, role bound in trust-list leaf) |
| Adapter interface + FatturaPA reference adapter | **BUILT + e2e-proven** on the real invoice (`adapters/`); other verticals pilot-driven |
| Real non-gameable signer | **STAND-IN** (self-made CA; partner-dependent) |
| Committee / roots deployment | **DESIGN** (TACEO:Proof available) |

---

## 9. Build sequence

1. **In-circuit Proof A** — verify obligor + issuer signatures over
   `canonical_id`, signer ∈ trust root, role bound in leaf, emit role-stamped
   anchor. ✓ **DONE** — `proof_a_receivable` proves end-to-end, negative tests
   pass (bad sig, unauthorised role), anchor hands off to `bound_receivables`
   (`run_proof_a.sh`). Note: ECDSA needs low-s normalisation for Noir's verifier.
2. **Adapter interface** + the **first pilot's** adapter only (native-rail *or*
   C2PA, per the pilot vertical). ✓ **DONE (reference)** — interface formalised
   (`adapters/ADAPTER.md`) + FatturaPA adapter (`adapters/fattura_adapter.py`)
   proves the full pipeline on the real invoice (`run_fattura_pipeline.sh`).
   Other verticals' adapters remain pilot-driven.
3. **Canonicalisation spec** for that vertical, signer-emits-canonical-form.
4. Wire to the chosen **engine** + the **committee/roots** deployment for the pilot.
5. **Do not** pre-build other adapters/engines/verticals.

> The engine and pattern are proven; the priority is the in-circuit signature
> binding, and the bottleneck remains a real partner + a real non-gameable signer.

---

## 10. Open decisions (resolve before this is "production-correct")

Load-bearing and deliberately unresolved; some are pilot/scale-dependent.

1. **Proof A composition — local vs joint, and the recursion.** Signature
   verification belongs in a cheap **per-party local Proof A** (single-prover),
   recursively bound into the joint engine — **not** inside the joint MPC
   (in-MPC P-256 is prohibitive). Decide the binding: recursive in-circuit
   verification of each party's Proof A, vs. separately-checked proofs the
   relying party also validates. Drives both soundness and cost.
   **→ RESOLVED:** per-party *local* Proof A → emits the role-stamped `anchor`
   as a public output → fed to `bound_receivables` as `candidate_anchor` (the
   `binding_wrapper` "verify, then emit a public anchor" pattern). Signature
   verification stays out of the MPC. Recursion-into-one-proof is an optional
   later step. Built: `quorum/proof_a_receivable` (compiles, beta.20).
2. **Canonicalisation determinism across independently-received copies.** The
   "signer signs `canonical_id`" move requires the *same* signed `canonical_id`
   to reach every party who finances the invoice. Specify how it travels with
   the document so two lenders derive byte-identical ids.
3. **Decentralised registry-of-roots is research-adjacent.** Private
   non-membership against a published root *without the other party live* is
   key-transparency / accumulator territory. Near-term = the **committee model**;
   the roots model is a research track, not yet production.
4. **Freshness / simultaneity** is a bounded settlement-window limit, not solved.
   Choose: near-real-time roots, a mandatory pre-advance live check, or an
   openly-stated window.
5. **Toolchain reconciliation.** The coNoir spike uses nargo beta.20; apertrue's
   `proof_a` is beta.18. Reconcile versions before reusing `proof_a` in the
   Quorum flow.
