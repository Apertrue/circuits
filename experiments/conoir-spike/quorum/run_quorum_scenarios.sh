#!/usr/bin/env bash
# Apertrue Quorum -- the two-signer thesis, end to end under MPC.
# Anchors come from Layer-2 admission (p1_provenance/admission/admission.sh).
Q="$HOME/apertrue/circuits/experiments/conoir-spike/quorum"
cd "$Q"

OBL=0x276218a3095f1f2a85ee95ceeece1963fb83fbbc4da888208d85b2b3013822e5      # role 2, true (amount 500)
SDI_INFL=0x29b3212006ae841a7ad864218a471c73a7813f28140377223877cb26beef1180  # role 1, INFLATED (amount 5000)
SELLER=0x25bb81fa6fd90d294abd6719560ae8d74c88b559fee18245d9337ca23b54984e    # role 3, true (not in allow-list)
CID_TRUE='"0x06cc60c66ce6389ea53783b55dc5ff1b480e9a43ecf4c942262f5d73d7a87280"'
# exactly BOOK_UNION=6 entries; CLEAN5 = first 5 (leave a slot for the double-finance hit)
CLEAN5='"0x01a1111111111111111111111111111111111111111111111111111111111111","0x02b2222222222222222222222222222222222222222222222222222222222222","0x03c3333333333333333333333333333333333333333333333333333333333333","0x04d4444444444444444444444444444444444444444444444444444444444444","0x05e5555555555555555555555555555555555555555555555555555555555555"'
CLEAN="$CLEAN5,\"0x06f6666666666666666666666666666666666666666666666666666666666666\""

prover() { # anchor role amount financed_csv -> /tmp/q.toml
  cat > /tmp/q.toml <<TOML
candidate_anchor = "$1"
signer_role = "$2"
accepted_roles = ["1","2"]
invoice_uuid = "1234567890000123"
debtor_id    = "9876543210"
amount        = "$3"
issue_date    = "20141218"
salt          = "0x7777777777777777"
financed = [ $4 ]
TOML
}

run() { ./run_bound_receivables.sh /tmp/q.toml 2>&1 | grep -iE "verified|verification failed|=> already_financed|allow-list|opening failed" || true; }

echo "########## 1) OBLIGOR, true receivable, not financed  (expect 0, owed) ##########"
prover "$OBL" 2 500 "$CLEAN"; run
echo "########## 2) OBLIGOR, true receivable, DOUBLE-FINANCED  (expect 1, owed) ##########"
prover "$OBL" 2 500 "$CLEAN5,$CID_TRUE"; run
echo "########## 3) SdI, INFLATED invoice seller cleared, not financed  (expect 0, cleared-NOT-owed = THE GAP) ##########"
prover "$SDI_INFL" 1 5000 "$CLEAN"; run
echo "########## 4) SELLER self-signed (role 3) -> MPC allow-list rejects (defense in depth) ##########"
prover "$SELLER" 3 500 "$CLEAN"; run
rm -f /tmp/q.toml