#!/usr/bin/env bash
# run_fattura_pipeline.sh -- FULL Quorum pipeline on the REAL FatturaPA invoice.
#
#   real FatturaPA XML
#     -> fattura_adapter.py            (adapter-interface object: fields, canonical_id, obligor sig)
#     -> _mkroot                       (Poseidon2 depth-8 trust-list root for the obligor (key,role))
#     -> proof_a_receivable            (in-circuit: ECDSA verify + trust-list membership -> anchor)
#     -> commit_receivable             (expected anchor for the same fields/salt/role)  == proven anchor?
#     -> bound_receivables             (double-financing one-bit answer: clean=false, double=true)
#
# Idempotent: re-running reuses the stand-in obligor key and recomputes everything.
# Requires: nargo (1.0.0-beta.20) at ~/.nargo/bin/nargo, openssl, python3.
set -euo pipefail

NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # .../quorum/adapters
QUORUM="$(cd "$HERE/.." && pwd)"
XML="${1:-$QUORUM/p1_provenance/IT01234567890_FPR01.xml}"
SALT="${SALT:-42}"
SIGNER_ROLE="${SIGNER_ROLE:-2}"
OBJ="$HERE/fattura_adapter_object.json"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
hr()    { printf '\n==== %s ====\n' "$*"; }

# ---------------------------------------------------------------------------
hr "STEP 1: adapter -- FatturaPA XML -> adapter-interface object"
python3 "$HERE/fattura_adapter.py" "$XML" --salt "$SALT" --signer-role "$SIGNER_ROLE" --out "$OBJ" >/dev/null
# pull values out of the JSON into shell
read -r INVOICE_UUID DEBTOR_ID AMOUNT ISSUE_DATE CANONICAL_ID < <(python3 -c "
import json;o=json.load(open('$OBJ'));f=o['canonical_fields']
print(f['invoice_uuid'],f['debtor_id'],f['amount'],f['issue_date'],o['canonical_id'])")
X=$(python3   -c "import json;print(json.load(open('$OBJ'))['obligor']['pubkey_x'])")
Y=$(python3   -c "import json;print(json.load(open('$OBJ'))['obligor']['pubkey_y'])")
SIG=$(python3 -c "import json;print(json.load(open('$OBJ'))['obligor']['signature'])")
CIDB=$(python3 -c "import json;print(json.load(open('$OBJ'))['canonical_id_bytes'])")
echo "invoice_uuid = $INVOICE_UUID"
echo "debtor_id    = $DEBTOR_ID"
echo "amount       = $AMOUNT"
echo "issue_date   = $ISSUE_DATE"
echo "canonical_id = $CANONICAL_ID"

# confirm canonical_id matches the committed obligor_true.cid
EXPECT_CID="0x$(xxd -p "$QUORUM/p1_provenance/admission/certs/obligor_true.cid" | tr -d '\n')"
if [ "$CANONICAL_ID" = "$EXPECT_CID" ]; then
  green "PASS: canonical_id == obligor_true.cid ($EXPECT_CID)"
else
  red "FAIL: canonical_id $CANONICAL_ID != obligor_true.cid $EXPECT_CID"; exit 1
fi

# ---------------------------------------------------------------------------
hr "STEP 2: commit_receivable -> expected role-bound anchor (same salt, role)"
cat > "$QUORUM/commit_receivable/Prover.toml" <<EOF
invoice_uuid = "$INVOICE_UUID"
debtor_id    = "$DEBTOR_ID"
amount       = "$AMOUNT"
issue_date   = "$ISSUE_DATE"
salt         = "$SALT"
signer_role  = "$SIGNER_ROLE"
EOF
CR_OUT=$("$NARGO" execute --program-dir "$QUORUM/commit_receivable" 2>&1 | grep "Circuit output")
EXPECTED_ANCHOR=$(echo "$CR_OUT" | sed -E 's/.*\[(0x[0-9a-f]+), (0x[0-9a-f]+)\].*/\2/')
echo "expected anchor = $EXPECTED_ANCHOR"

# ---------------------------------------------------------------------------
hr "STEP 3: _mkroot -> trust_list_root for obligor (key, role) leaf"
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
hr "STEP 4: proof_a_receivable -- in-circuit ECDSA verify + membership -> anchor"
cat > "$QUORUM/proof_a_receivable/Prover.toml" <<EOF
trust_list_root = "$ROOT"
signer_role = "$SIGNER_ROLE"
invoice_uuid = "$INVOICE_UUID"
debtor_id = "$DEBTOR_ID"
amount = "$AMOUNT"
issue_date = "$ISSUE_DATE"
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
  green "PASS: proof_a anchor == commit_receivable anchor"
else
  red "FAIL: anchor mismatch (proven $PROVEN_ANCHOR vs expected $EXPECTED_ANCHOR)"; exit 1
fi

# ---------------------------------------------------------------------------
hr "STEP 5: bound_receivables -- double-financing one-bit answer"
br_run () { # $1 = financed array contents, $2 = label, $3 = expected bool
  cat > "$QUORUM/bound_receivables/Prover.toml" <<EOF
candidate_anchor = "$PROVEN_ANCHOR"
signer_role = "$SIGNER_ROLE"
accepted_roles = ["1", "2"]
invoice_uuid = "$INVOICE_UUID"
debtor_id = "$DEBTOR_ID"
amount = "$AMOUNT"
issue_date = "$ISSUE_DATE"
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

hr "ALL CHECKS PASSED -- real FatturaPA invoice proven end-to-end"
