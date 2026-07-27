#!/usr/bin/env bash
# run_proof_a.sh -- end-to-end test harness for the `proof_a_receivable` Noir circuit.
#
# Proves Proof A END-TO-END with a real OpenSSL ECDSA P-256 signature, runs two
# negative tests, and demonstrates that Proof A's anchor output feeds `bound_receivables`.
#
# Idempotent: regenerates a fresh P-256 key and recomputes the trust-list root each run.
# (The anchor is independent of the key -- it depends only on canonical_id, salt, role --
#  so the "executed anchor == expected anchor" check is stable across runs.)
#
# Requires: nargo (1.0.0-beta.20) at ~/.nargo/bin/nargo, openssl, python3.
set -euo pipefail

NARGO="${NARGO:-$HOME/.nargo/bin/nargo}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # .../quorum/proof_a_receivable
QUORUM="$(cd "$HERE/.." && pwd)"
WD="$(mktemp -d)"
trap 'rm -rf "$WD"' EXIT

# Fixed receivable + role used throughout.
INVOICE_UUID=1234567890000123
DEBTOR_ID=9876543210
AMOUNT=500
ISSUE_DATE=20141218
SALT=42
SIGNER_ROLE=2

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
hr()    { printf '\n==== %s ====\n' "$*"; }

# ---------------------------------------------------------------------------
hr "STEP 1/2: commit_receivable -> canonical_id, expected anchor"
cat > "$QUORUM/commit_receivable/Prover.toml" <<EOF
invoice_uuid = "$INVOICE_UUID"
debtor_id    = "$DEBTOR_ID"
amount       = "$AMOUNT"
issue_date   = "$ISSUE_DATE"
salt         = "$SALT"
signer_role  = "$SIGNER_ROLE"
EOF
CR_OUT=$("$NARGO" execute --program-dir "$QUORUM/commit_receivable" 2>&1 | grep "Circuit output")
# Circuit output: [0x..canonical_id.., 0x..anchor..]
CANONICAL_ID=$(echo "$CR_OUT" | sed -E 's/.*\[(0x[0-9a-f]+), (0x[0-9a-f]+)\].*/\1/')
EXPECTED_ANCHOR=$(echo "$CR_OUT" | sed -E 's/.*\[(0x[0-9a-f]+), (0x[0-9a-f]+)\].*/\2/')
echo "canonical_id   = $CANONICAL_ID"
echo "expected anchor = $EXPECTED_ANCHOR"

# ---------------------------------------------------------------------------
hr "STEP 3/4: P-256 key, pubkey x/y, raw-ECDSA sign of canonical_id digest"
# canonical_id -> 32 big-endian bytes (the signed digest)
CIDHEX=${CANONICAL_ID#0x}
CIDHEX=$(printf '%064s' "$CIDHEX" | tr ' ' '0')
python3 -c "import binascii;open('$WD/cid.bin','wb').write(binascii.unhexlify('$CIDHEX'))"

openssl ecparam -name prime256v1 -genkey -noout -out "$WD/key.pem"
# raw ECDSA over the 32-byte digest (pkeyutl -sign treats EC input as the digest)
openssl pkeyutl -sign -inkey "$WD/key.pem" -in "$WD/cid.bin" -out "$WD/sig.der"
openssl ec -in "$WD/key.pem" -pubout -conv_form uncompressed -outform DER -out "$WD/pub.der" 2>/dev/null

python3 - "$WD" <<'PY'
import sys
WD=sys.argv[1]
pub=open(WD+'/pub.der','rb').read()
point=pub[-65:]; assert point[0]==4, "not uncompressed point"
x=point[1:33]; y=point[33:65]
der=open(WD+'/sig.der','rb').read(); assert der[0]==0x30
def read_int(b,i):
    assert b[i]==0x02; ln=b[i+1]; return b[i+2:i+2+ln], i+2+ln
r,i=read_int(der,2); s,_=read_int(der,i)
# Noir's ecdsa_secp256r1::verify_signature requires LOW-S (canonical) form;
# OpenSSL does not enforce it, so normalise s -> min(s, n-s).
N=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
sv=int.from_bytes(s,'big')
if sv > N//2: sv = N - sv
s=sv.to_bytes(32,'big')
r=r.lstrip(b'\x00').rjust(32,b'\x00'); s=s.rjust(32,b'\x00')
sig=r+s
arr=lambda bb:"["+", ".join(str(c) for c in bb)+"]"
open(WD+'/x.txt','w').write(arr(x))
open(WD+'/y.txt','w').write(arr(y))
open(WD+'/sig.txt','w').write(arr(sig))
open(WD+'/cidbytes.txt','w').write(arr(open(WD+'/cid.bin','rb').read()))
PY
X=$(cat "$WD/x.txt"); Y=$(cat "$WD/y.txt"); SIG=$(cat "$WD/sig.txt"); CIDB=$(cat "$WD/cidbytes.txt")

# ---------------------------------------------------------------------------
hr "STEP 5: _mkroot -> trust_list_root (siblings=0, indices=0, leftmost leaf)"
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
hr "STEP 6: proof_a_receivable Prover.toml + execute"
cat > "$HERE/Prover.toml" <<EOF
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
cat "$HERE/Prover.toml"
PROVEN_ANCHOR=$("$NARGO" execute --program-dir "$HERE" 2>&1 | grep "Circuit output" | sed -E 's/.*(0x[0-9a-f]+).*/\1/')
echo "proven anchor   = $PROVEN_ANCHOR"
if [ "$PROVEN_ANCHOR" = "$EXPECTED_ANCHOR" ]; then
  green "PASS: proven anchor == expected anchor"
else
  red "FAIL: anchor mismatch"; exit 1
fi

cp "$HERE/Prover.toml" "$WD/good.toml"

# ---------------------------------------------------------------------------
hr "STEP 7a: NEGATIVE -- flip one signature byte (expect ECDSA failure)"
SIGBAD=$(echo "$SIG" | sed -E 's/^\[([0-9]+),/["bad",/' ; true)
# bump first signature byte by 1 (mod 256) to keep it a valid u8
FIRST=$(echo "$SIG" | sed -E 's/^\[([0-9]+),.*/\1/')
NEWFIRST=$(( (FIRST + 1) % 256 ))
sed -E "s/^signature = \[$FIRST,/signature = [$NEWFIRST,/" "$WD/good.toml" > "$HERE/Prover.toml"
if OUT=$("$NARGO" execute --program-dir "$HERE" 2>&1); then
  red "FAIL: expected ECDSA assertion failure but execute succeeded"; exit 1
else
  echo "$OUT" | grep -iE "Assertion failed: ECDSA" && green "PASS: ECDSA signature assertion fired"
fi

# ---------------------------------------------------------------------------
hr "STEP 7b: NEGATIVE -- signer_role=1 (leaf built for role 2; expect trust-list failure)"
sed -E 's/^signer_role = "2"/signer_role = "1"/' "$WD/good.toml" > "$HERE/Prover.toml"
if OUT=$("$NARGO" execute --program-dir "$HERE" 2>&1); then
  red "FAIL: expected trust-list assertion failure but execute succeeded"; exit 1
else
  echo "$OUT" | grep -iE "Assertion failed: signer \(key, role\) not in trust list" \
    && green "PASS: trust-list (key,role) assertion fired"
fi

# restore the good Prover.toml
cp "$WD/good.toml" "$HERE/Prover.toml"

# ---------------------------------------------------------------------------
hr "STEP 8: HANDOFF -- proven anchor feeds bound_receivables"
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
  echo "$OUT" | grep -q "($3," && green "  PASS: already_financed=$3 (anchor opened)" \
    || { red "  FAIL: expected already_financed=$3"; exit 1; }
}
br_run '"0x01","0x02","0x03","0x04","0x05","0x06"' "clean  (cid NOT financed)" "false"
br_run "\"0x01\",\"0x02\",\"$CANONICAL_ID\",\"0x04\",\"0x05\",\"0x06\"" "double (cid IS financed) " "true"

hr "ALL CHECKS PASSED"
