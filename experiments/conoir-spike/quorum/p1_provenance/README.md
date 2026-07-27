# Quorum P1 — real provenance adapter (FatturaPA → C2PA → anchor → MPC)

End-to-end with a **real Italian e-invoice**: parse it, render to PDF, bind a real C2PA
manifest, derive the canonical fingerprint + authenticity anchor, and feed that anchor into
the `bound_receivables` MPC proof. Closes the loop from a real document to the one-bit
double-financing answer.

## The real chain (what actually ran)
1. **Real FatturaPA invoice** — `IT01234567890_FPR01.xml` (SOCIETA' ALPHA SRL → DITTA BETA,
   no. 123, 2014-12-18, EUR; public sample, simevo/fattura-elettronica-json).
2. **Canonicalisation** (deterministic, the make-or-break field):
   - `invoice_uuid = supplierVAT(01234567890) * 1e6 + numero(123) = 1234567890000123`
   - `debtor_id    = buyer CF 09876543210 → 9876543210`
   - `amount       = 5.00 EUR → 500` (cents)   ·   `issue_date = 2014-12-18 → 20141218`
3. **Anchor** (`commit_receivable`, proof_a's scheme):
   - `canonical_id = Poseidon2([uuid, debtor, amount, date]) = 0x06cc60c6…87280`
   - `anchor       = Poseidon2([canonical_id, salt])         = 0x015dac17…48a3`
4. **Real C2PA-signed PDF** — `invoice_c2pa.pdf`, produced by **c2pie** (PS256, RSA cert
   chain). Contains `c2pa.claim`, `c2pa.hash.data` (hard binding to the PDF bytes),
   `c2pa.signature` (COSE), the CreativeWork assertion, in an embedded `manifest.c2pa`
   (`/AFRelationship /C2PA_Manifest`). Verified embedded via JUMBF markers.
5. **MPC** — anchor fed to `bound_receivables`, full 3-party REP3:
   - clean → `already_financed = 0` (verified) · double-financed → `1` (verified).

## What is REAL vs STAND-IN
| Element | State |
|---|---|
| FatturaPA invoice + fields + canonicalisation | **real** |
| canonical_id / anchor (proof_a Poseidon2 scheme) | **real** |
| C2PA manifest on a PDF, hard data-hash binding, COSE sig, cert chain | **real** (via c2pie) |
| MPC double-financing proof from this anchor | **real** (verified) |
| Clearance signer cert (Agenzia delle Entrate / SdI) | **stand-in** self-made CA — real cert needs a partner; validation_state untrusted until the CA is a known anchor |
| Asset format | PDF **rendering** of the invoice (+ could embed the XML as attachment); raw-XML C2PA needs the data-hash sidecar API (see tooling note) |

## Tooling notes
- Homebrew **c2patool 0.26.29 is media-only** — it maps `.xml`→SVG and reports PDF/generic
  "type is unsupported" (PDF/data-hash are non-default c2pa-rs features). So it cannot bind
  to a raw e-invoice XML or PDF.
- **c2pie** (TourmalineCore) fills the gap: Python, embeds C2PA into **PDF** (and JPG),
  PS256 + cert chains, with a hard `c2pa.hash.data` binding. No raw-XML / sidecar.
- For raw-**XML** C2PA (data-hash sidecar) the spec supports it; needs a c2pa-rs build with
  the data-hash feature, or the CAWG identity-assertion path. Tracked for P1.next.

## Reproduce
```
# render + sign a C2PA PDF (needs: c2pie in a venv, openssl)
python3 -m venv venv && . venv/bin/activate && pip install c2pie
cupsfilter invoice.txt > invoice.pdf
#   generate an RSA CA->leaf chain (emailProtection EKU), then:
python3 -c "from c2pie.signing import sign_file; \
  sign_file('invoice.pdf','invoice_c2pa.pdf','rsa_leaf.key','rsa_chain.pem','c2pie_schema.json')"
# derive anchor + run MPC
cd ../commit_receivable && ~/.nargo/bin/nargo execute --prover-name Prover_sdi
cd ../ && ./run_bound_receivables.sh bound_receivables/Prover_sdi.toml
```

## P1.next (done) — `p1_next.py` → `invoice_quorum.pdf`
Two of the three items are now real (the third needs a partner cert):

- ✅ **Custom C2PA assertion** `org.apertrue.quorum.receivable` (via c2pie's programmatic
  `interface` API, not just CreativeWork) carrying the canonical fields, the role-bound
  anchor, the signer role/guarantee, and the **inner obligor ES256 signature over the
  canonical_id**. Referenced twice in the file (assertion box + claim url) → bound by the
  claim signature.
- ✅ **Authoritative XML travels with the C2PA.** Embedded two ways:
  (a) inside the PDF (under the `c2pa.hash.data` hard binding — the XML bytes are physically
  present and hashed), and (b) — the robust path — inside the signed manifest itself as
  `org.apertrue.quorum.source_document` (base64 + sha256). Extracted back out of the
  manifest it **round-trips bit-perfectly** (4315 bytes == source).
  Note: c2pie's PDF incremental update clobbers the PDF *attachment* names tree (only
  `manifest.c2pa` remains navigable), which is why the manifest-embedded copy (b) is the
  load-bearing one.
- ⬜ **Real clearance/obligor cert** (genuine SdI *ricevuta* / India IRP IRN): still
  stand-in; needs a design partner. The inner-signature **verification** path exists
  (admission, openssl) and a proof_a-style in-circuit verify is the remaining step.

Note: anchors here are now **role-bound** (`Poseidon2([canonical_id, salt, role])`); the
obligor anchor is `0x276218a3…`, superseding the earlier pre-role `0x015dac17…`.

## Reproduce P1.next
```
. venv/bin/activate                       # c2pie + pypdf
cd admission && ./admission.sh            # regenerates certs + obligor signature
#   regenerate an RSA CA->leaf chain (rsa_leaf.key + rsa_chain.pem), then:
python3 ../p1_next.py rsa_leaf.key rsa_chain.pem
```
(Private keys are not committed — the scripts regenerate them.)
