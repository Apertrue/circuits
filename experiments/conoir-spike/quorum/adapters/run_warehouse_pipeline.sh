#!/usr/bin/env bash
# run_warehouse_pipeline.sh -- FULL Quorum pipeline on a C2PA WAREHOUSE RECEIPT.
#
# Parallel to run_fattura_pipeline.sh, but the canonical fields are NOT read from a
# native structured rail -- they are CARRIED BY C2PA. The adapter creates a warehouse
# receipt PDF, embeds the signed canonical fields + operator key + raw-ECDSA signature
# in a C2PA custom assertion (org.apertrue.quorum.collateral) hash-bound to the file,
# then READS them back out of the manifest. C2PA is the load-bearing carrier; the
# trust is the operator's signature, verified IN-CIRCUIT by Proof A.
#
#   warehouse receipt PDF + C2PA manifest (c2pie wrap)
#     -> warehouse_adapter.py read       (parse C2PA -> adapter-interface object)
#     -> commit_receivable               (expected role-bound anchor for the same fields/salt/role)
#     -> _mkroot                         (Poseidon2 depth-8 trust-list root for operator (key,role))
#     -> proof_a_receivable              (in-circuit: ECDSA verify + trust-list membership -> anchor)
#     -> commit anchor == proven anchor?
#     -> bound_receivables               (double-financing one-bit answer: clean=false, double=true)
#
# Idempotent: reuses the stand-in operator P-256 key + C2PA RSA chain, recomputes the rest.
# Requires: nargo (1.0.0-beta.20) at ~/.nargo/bin/nargo, openssl, c2patool, cupsfilter,
#           and a python with `c2pie` + `pypdf` importable (set C2PIE_PY, else auto-detected).
set -euo pipefail

NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # .../quorum/adapters
QUORUM="$(cd "$HERE/.." && pwd)"
SALT="${SALT:-42}"
SIGNER_ROLE="${SIGNER_ROLE:-2}"
OBJ="$HERE/warehouse_adapter_object.json"
C2PA_PDF="$HERE/warehouse_receipt_c2pa.pdf"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
hr()    { printf '\n==== %s ====\n' "$*"; }

# ---- locate a python that can import c2pie (the C2PA carrier tool) ----
find_c2pie_py() {
  local cand
  for cand in "${C2PIE_PY:-}" \
              "/private/tmp/claude-501/-Users-jamienewton/1c6e4848-1e0b-4678-af70-eb7bad88f949/scratchpad/c2pie_venv/bin/python3" \
              "$HERE/.c2pie_venv/bin/python3" \
              "$QUORUM/p1_provenance/venv/bin/python3" \
              "python3"; do
    [ -z "$cand" ] && continue
    if command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ]; then
      if "$cand" -c "import c2pie, pypdf" >/dev/null 2>&1; then echo "$cand"; return 0; fi
    fi
  done
  # last resort: build a local venv (needs network)
  local v="$HERE/.c2pie_venv"
  python3 -m venv "$v" >/dev/null 2>&1 || true
  "$v/bin/pip" install -q c2pie pypdf >/dev/null 2>&1 || true
  if "$v/bin/python3" -c "import c2pie, pypdf" >/dev/null 2>&1; then echo "$v/bin/python3"; return 0; fi
  return 1
}

C2PIE_PY="$(find_c2pie_py)" || { red "FATAL: no python with c2pie+pypdf. Set C2PIE_PY=/path/to/venv/python3"; exit 1; }
echo "c2pie python: $C2PIE_PY"

# ---------------------------------------------------------------------------
hr "STEP 1: WRAP -- build warehouse receipt PDF + embed signed fields in C2PA"
"$C2PIE_PY" "$HERE/warehouse_adapter.py" --mode wrap --salt "$SALT" --signer-role "$SIGNER_ROLE"
green "wrote C2PA-signed PDF: $C2PA_PDF"

# prove C2PA is genuinely exercised: show the embedded assertion labels via c2patool
echo "-- c2patool assertion labels (read from the signed PDF) --"
c2patool "$C2PA_PDF" 2>&1 | "$C2PIE_PY" -c \
  "import sys,json;d=json.load(sys.stdin);m=d['manifests'][d['active_manifest']];print('  ',[a['label'] for a in m['assertions']])"

# ---------------------------------------------------------------------------
hr "STEP 2: READ -- parse C2PA manifest back -> adapter-interface object"
"$C2PIE_PY" "$HERE/warehouse_adapter.py" --mode read --salt "$SALT" --signer-role "$SIGNER_ROLE" \
  --pdf "$C2PA_PDF" --out "$OBJ" >/dev/null
read -r RECEIPT_UUID COMMODITY_ID QUANTITY DEPOSIT_DATE CANONICAL_ID < <(python3 -c "
import json;o=json.load(open('$OBJ'));f=o['canonical_fields']
print(f['receipt_uuid'],f['commodity_id'],f['quantity'],f['deposit_date'],o['canonical_id'])")
X=$(python3   -c "import json;print(json.load(open('$OBJ'))['obligor']['pubkey_x'])")
Y=$(python3   -c "import json;print(json.load(open('$OBJ'))['obligor']['pubkey_y'])")
SIG=$(python3 -c "import json;print(json.load(open('$OBJ'))['obligor']['signature'])")
CIDB=$(python3 -c "import json;print(json.load(open('$OBJ'))['canonical_id_bytes'])")
echo "receipt_uuid = $RECEIPT_UUID   (recovered from C2PA assertion)"
echo "commodity_id = $COMMODITY_ID"
echo "quantity     = $QUANTITY"
echo "deposit_date = $DEPOSIT_DATE"
echo "canonical_id = $CANONICAL_ID   (re-derived from recovered fields, matches embedded)"

# ---------------------------------------------------------------------------
hr "STEP 3: commit_receivable -> expected role-bound anchor (same salt, role)"
cat > "$QUORUM/commit_receivable/Prover.toml" <<EOF
invoice_uuid = "$RECEIPT_UUID"
debtor_id    = "$COMMODITY_ID"
amount       = "$QUANTITY"
issue_date   = "$DEPOSIT_DATE"
salt         = "$SALT"
signer_role  = "$SIGNER_ROLE"
EOF
CR_OUT=$("$NARGO" execute --program-dir "$QUORUM/commit_receivable" 2>&1 | grep "Circuit output")
EXPECTED_ANCHOR=$(echo "$CR_OUT" | sed -E 's/.*\[(0x[0-9a-f]+), (0x[0-9a-f]+)\].*/\2/')
echo "expected anchor = $EXPECTED_ANCHOR"

# ---------------------------------------------------------------------------
hr "STEP 4: _mkroot -> trust_list_root for operator (key, role) leaf"
cat > "$QUORUM/_mkroot/Prover.toml" <<EOF
signer_pubkey_x = $X
signer_pubkey_y = $Y
signer_role = "$SIGNER_ROLE"
merkle_path = ["0","0","0","0","0","0","0","0"]
merkle_indices = ["0","0","0","0","0","0","0","0"]
EOF
ROOT=$("$NARGO" execute --program-dir "$QUORUM/_mkroot" 2>&1 | grep "Circuit output" | sed -E 's/.*(0x[0-9a-f]+).*/\1/')
echo "trust_list_root = $ROOT"

# ---------------------------------------------------------------------------
hr "STEP 5: proof_a_receivable -- in-circuit ECDSA verify + membership -> anchor"
cat > "$QUORUM/proof_a_receivable/Prover.toml" <<EOF
trust_list_root = "$ROOT"
signer_role = "$SIGNER_ROLE"
invoice_uuid = "$RECEIPT_UUID"
debtor_id = "$COMMODITY_ID"
amount = "$QUANTITY"
issue_date = "$DEPOSIT_DATE"
salt = "$SALT"
signer_pubkey_x = $X
signer_pubkey_y = $Y
signature = $SIG
canonical_id_bytes = $CIDB
merkle_path = ["0","0","0","0","0","0","0","0"]
merkle_indices = ["0","0","0","0","0","0","0","0"]
EOF
PROVEN_ANCHOR=$("$NARGO" execute --program-dir "$QUORUM/proof_a_receivable" 2>&1 | grep "Circuit output" | sed -E 's/.*(0x[0-9a-f]+).*/\1/')
echo "proven anchor   = $PROVEN_ANCHOR"
if [ "$PROVEN_ANCHOR" = "$EXPECTED_ANCHOR" ]; then
  green "PASS: proof_a anchor == commit_receivable anchor (in-circuit ECDSA over C2PA-carried fields)"
else
  red "FAIL: anchor mismatch (proven $PROVEN_ANCHOR vs expected $EXPECTED_ANCHOR)"; exit 1
fi

# ---------------------------------------------------------------------------
hr "STEP 6: bound_receivables -- double-financing one-bit answer (accepted_roles incl. 2)"
br_run () { # $1 = financed array contents, $2 = label, $3 = expected bool
  cat > "$QUORUM/bound_receivables/Prover.toml" <<EOF
candidate_anchor = "$PROVEN_ANCHOR"
signer_role = "$SIGNER_ROLE"
accepted_roles = ["1", "2"]
invoice_uuid = "$RECEIPT_UUID"
debtor_id = "$COMMODITY_ID"
amount = "$QUANTITY"
issue_date = "$DEPOSIT_DATE"
salt = "$SALT"
financed = [$1]
EOF
  OUT=$("$NARGO" execute --program-dir "$QUORUM/bound_receivables" 2>&1 | grep "Circuit output")
  echo "  $2 -> $OUT"
  echo "$OUT" | grep -q "($3," && green "  PASS: already_financed=$3 (anchor opened cleanly)" \
    || { red "  FAIL: expected already_financed=$3"; exit 1; }
}
br_run '"0x01","0x02","0x03","0x04","0x05","0x06"' "clean  (cid NOT in financed book)" "false"
br_run "\"0x01\",\"0x02\",\"$CANONICAL_ID\",\"0x04\",\"0x05\",\"0x06\"" "double (cid IS in financed book)" "true"

hr "ALL CHECKS PASSED -- C2PA warehouse receipt proven end-to-end (C2PA carried the fields)"
