# Quorum Adapter Interface

A Quorum **adapter** turns a real-world receivable document (an Italian FatturaPA
e-invoice, an Indian IRP invoice, a UBL/PEPPOL bill, …) into one canonical object that
the in-circuit **Proof A** (`proof_a_receivable`) consumes. Proof A then proves, in
zero-knowledge, that an *authorised, role-bound* signer put an ECDSA P-256 signature on
this receivable's `canonical_id`, and emits the role-stamped authenticity **anchor** that
the joint `bound_receivables` MPC circuit binds to.

The adapter is the only document-format-specific code in the pipeline. Everything
downstream (`proof_a_receivable`, `commit_receivable`, `bound_receivables`) speaks only the
canonical object below, so a new document type = a new adapter, nothing else.

## 1. The interface contract (the object every adapter MUST emit)

```jsonc
{
  "canonical_fields": {
    "invoice_uuid": <int>,   // globally-unique receivable id (issuer-scoped)
    "debtor_id":    <int>,   // who owes the money
    "amount":       <int>,   // minor units (cents)
    "issue_date":   <int>    // YYYYMMDD
  },
  "canonical_id":       "0x..",        // Poseidon2([uuid, debtor, amount, date], 4)
  "canonical_id_bytes": [<u8>; 32],    // big-endian encoding of canonical_id (the SIGNED message)
  "obligor": {
    "pubkey_x":  [<u8>; 32],           // signer P-256 public key X (big-endian)
    "pubkey_y":  [<u8>; 32],           // signer P-256 public key Y (big-endian)
    "signature": [<u8>; 64],           // r||s, LOW-S normalised
    "signer_role": 2                   // 1 = SdI/clearance, 2 = obligor/debtor confirmation
  }
}
```

These map 1:1 onto Proof A's witness (`proof_a_receivable/src/main.nr`):
`signer_pubkey_x/y`, `signature`, `canonical_id_bytes`, the four canonical fields, plus
`signer_role` (public). The only inputs the adapter does **not** supply are the
trust-list witness (`merkle_path`, `merkle_indices`, `trust_list_root`) and the privacy
`salt` — those belong to the trust-list operator and the prover, not the document.

### Field semantics
- `canonical_id = Poseidon2([invoice_uuid, debtor_id, amount, issue_date], 4)` — the value
  the obligor vouches for and the value the network's double-financing check keys on.
- `anchor = Poseidon2([canonical_id, salt, signer_role], 3)` — Proof A's **public output**.
  Role-bound, so a clearance anchor and an obligor anchor for the same receivable are
  distinct values and cannot be swapped.

## 2. Signing spec (the Quorum standard)

**Raw ECDSA P-256 over the 32-byte big-endian `canonical_id`, used directly as the
digest. No SHA-256 wrapper.** `canonical_id` is already a Poseidon2 commitment, so a second
hash adds nothing; Proof A calls `std::ecdsa_secp256r1::verify_signature(x, y, sig,
canonical_id_bytes)` with the 32-byte message as the digest. Signatures MUST be
**low-S normalised** (`s = min(s, n-s)`) — Noir's verifier rejects high-S. The 64-byte
`signature` is `r||s`, each zero-left-padded to 32 bytes.

Practical note: `openssl pkeyutl -sign` (not `openssl dgst -sha256 -sign`) treats its input
bytes as the digest, which is exactly the raw-ECDSA form Proof A expects. The legacy
`admission.sh` produced its `*.sig` with `openssl dgst -sha256`, so those signatures do
**not** verify under this spec — the adapter (re-)signs `canonical_id` raw.

## 3. How the FatturaPA adapter satisfies the contract

`fattura_adapter.py <invoice.xml>` (driven end-to-end by `run_fattura_pipeline.sh`):

1. **Canonicalisation** (namespace-agnostic XML walk, identical to `p1_provenance`):
   - `invoice_uuid = CedentePrestatore/…/IdFiscaleIVA/IdCodice (01234567890) * 1e6 + DatiGeneraliDocumento/Numero (123)` → `1234567890000123`
   - `debtor_id    = CessionarioCommittente/…/CodiceFiscale (09876543210)` with leading zeros dropped → `9876543210`
   - `amount       = DatiRiepilogo/ImponibileImporto (5.00 EUR) * 100` → `500`
   - `issue_date   = DatiGeneraliDocumento/Data (2014-12-18)` → `20141218`
2. **canonical_id** — computed by running the `commit_receivable` circuit (proof_a's
   Poseidon2 scheme) so the adapter and the circuits cannot drift. For this invoice:
   `0x06cc60c66ce6389ea53783b55dc5ff1b480e9a43ecf4c942262f5d73d7a87280`, which equals the
   committed `admission/certs/obligor_true.cid` — confirming the real document reproduces
   the expected fingerprint.
3. **obligor signature** — raw-ECDSA-signs `canonical_id` (see §2), extracts `x`/`y` from
   the uncompressed public-key point, normalises the DER signature to low-S `r||s`.
4. Emits the JSON object above (`fattura_adapter_object.json`).

`run_fattura_pipeline.sh` then builds the depth-8 trust root from the obligor `(key, role)`
leaf via `_mkroot`, runs **Proof A** (in-circuit ECDSA verify + trust-list membership →
anchor), checks the proven anchor equals the `commit_receivable` anchor for the same
`(salt=42, role=2)`, and hands the anchor to `bound_receivables` (clean → `false`,
double-financed → `true`).

## 3b. C2PA-document adapter (warehouse receipt) — the *carrier* path

The FatturaPA adapter reads canonical fields from a **native structured rail** (the
e-invoice XML). Many collateral documents have **no such rail** — a warehouse receipt,
a bill of lading, a deposit slip. For these, **C2PA is the load-bearing CARRIER**: the
signed canonical fields, the signer's public key, and the signer's raw-ECDSA signature
over `canonical_id` are embedded in a C2PA **custom assertion** and **hash-bound** to the
document, then read back out of the manifest. C2PA transports + binds; the *trust* is the
**signature**, verified in-circuit by Proof A — exactly as in the native-rail path.

`warehouse_adapter.py` (driven end-to-end by `run_warehouse_pipeline.sh`), modes `wrap` /
`read` / `both`:

1. **Canonical fields** (warehouse receipt, four fields, same structure as receivables;
   names are adapter-local, mapped onto the generic 4-field circuit slots):
   - `receipt_uuid = 7001234000042` (operator licence 7001234 · 1e6 + receipt no 42) → slot 1
   - `commodity_id = 74031100` (HS code, copper cathode grade A)               → slot 2
   - `quantity     = 25000` (250.00 metric tonnes, centi-tonnes)               → slot 3
   - `deposit_date = 20240315` (2024-03-15)                                    → slot 4
   - `canonical_id = 0x20adcccdd6e2e94b4a78a2cba482c287b37c3c840204f9412d5baa1cdb11a423`
     (computed by `commit_receivable`, salt=42, signer_role=2).
2. **WRAP (C2PA is genuinely created).** Renders a warehouse-receipt PDF (`cupsfilter`),
   then uses **c2pie** (the same tool as `p1_provenance/p1_next.py`) to embed a custom
   assertion **`org.apertrue.quorum.collateral`** carrying the canonical fields, the
   operator's `pubkey_x/y` (hex), and the **raw ECDSA P-256 signature over `canonical_id`**
   (low-s, `r‖s` hex; §2 signing spec), plus a `c2pa.hash.data` hard binding over the whole
   PDF. The manifest is signed with a stand-in RSA leaf→CA chain (PS256). Output:
   `warehouse_receipt_c2pa.pdf`.
3. **READ (C2PA is genuinely parsed).** Parses the manifest back with **c2patool**, recovers
   `{canonical_fields, pubkey_x, pubkey_y, signature, signer_role}`, **re-derives**
   `canonical_id` from the *recovered* fields and asserts it equals the embedded value, and
   emits `warehouse_adapter_object.json` (the **same interface shape** as fattura).
4. **Trust root + Proof A.** `_mkroot` builds the depth-8 Poseidon2 root from the operator
   `(x, y, role=2)` leaf; `proof_a_receivable` does the **in-circuit ECDSA verify + trust-list
   membership** over the C2PA-carried fields and emits the anchor; the proven anchor equals the
   `commit_receivable` anchor `0x2f458e5a…7744`.
5. **Handoff.** The anchor feeds `bound_receivables` (accepted_roles `[1,2]`): `financed`
   without the cid → `(false, 0x02)`, then with the cid → `(true, 0x02)` — anchor opens cleanly.

The exact carrier commands (proving C2PA is exercised, not faked):
- **wrap**: `c2pie_GenerateManifest([CustomJsonAssertion("org.apertrue.quorum.collateral", …),
  c2pie_GenerateHashDataAssertion(…)], rsa_leaf.key, rsa_chain.pem)` →
  `c2pie_EmplaceManifest(C2PA_ContentTypes.pdf, …)` (in `warehouse_adapter.py wrap`).
- **read**: `c2patool warehouse_receipt_c2pa.pdf` → JSON → pull the
  `org.apertrue.quorum.collateral` assertion (in `warehouse_adapter.py read`).

### Caveats specific to this adapter
- The **warehouse-operator P-256 key is a STAND-IN** (`adapters/keys/operator_standin.key`);
  the real operator/custodian key is the partner crux (same security note as §4.1).
- The **C2PA manifest signer is a stand-in RSA leaf→CA chain** (`adapters/keys/c2pa_leaf.*`,
  PS256); c2pie is the carrier tool. A production manifest would chain to a real C2PA CA.
- Proof A trusts the operator **leaf key directly** via the trust list (Poseidon2 `(x,y,role)`
  leaf → root), not an in-circuit X.509 chain — the same §4.2 follow-up applies.

## 4. Honest caveats (follow-ups for a design partner)

1. **The obligor key is a STAND-IN.** The real obligor private key (an Agenzia delle
   Entrate / SdI *ricevuta*, or an Indian IRP IRN authority) is not in the repo — only
   `admission/certs/obligor_leaf.pem/.pub` exist, without the private key. The adapter
   therefore mints a stand-in P-256 key+cert (`adapters/keys/obligor_standin.key`) and
   signs with it. This proves the *mechanism* end-to-end; the non-gameable signer is the
   partner crux. The security claim ("the debtor will not sign a lie, so fabrication/
   inflation cannot be admitted as role 2") only holds once the signer is a genuine
   authority.
2. **Proof A trusts the signer's LEAF key directly** via the trust list (a Poseidon2
   `(x, y, role)` leaf → root membership). It does **not** verify an X.509 certificate
   chain to a CA root in-circuit. Full production parity (cf. apertrue's `proof_a`, which
   performs in-circuit chain verification) would verify the obligor leaf cert chains to a
   trusted Quorum root inside the circuit, rather than trusting an enrolled leaf key. Noted
   follow-up.

## 5. Files

- `adapters/fattura_adapter.py`        — the FatturaPA adapter (native XML → interface object).
- `adapters/run_fattura_pipeline.sh`   — full end-to-end runner (idempotent).
- `adapters/fattura_adapter_object.json` — the emitted interface object for this invoice.
- `adapters/keys/obligor_standin.*`    — minted stand-in obligor key+cert (gitignored).
- `adapters/warehouse_adapter.py`      — the C2PA warehouse-receipt adapter (C2PA assertion → interface object); modes wrap/read/both. Needs a python with `c2pie`+`pypdf`.
- `adapters/run_warehouse_pipeline.sh` — full end-to-end runner (idempotent); auto-detects a c2pie python (or set `C2PIE_PY`).
- `adapters/warehouse_adapter_object.json` — the emitted interface object (recovered from the C2PA manifest).
- `adapters/warehouse_receipt.pdf` / `warehouse_receipt_c2pa.pdf` — the rendered receipt and its C2PA-signed form.
- `adapters/keys/operator_standin.*`   — minted stand-in warehouse-operator P-256 key+cert (gitignored).
- `adapters/keys/c2pa_leaf.* / c2pa_ca.*` — minted stand-in RSA chain that signs the C2PA manifest (gitignored).
