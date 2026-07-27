#!/usr/bin/env bash
# Apertrue Quorum -- Layer 2 ADMISSION (off-MPC acceptable-anchor allow-list).
#
# Decides whether a receivable's authenticity signature is acceptable, and if so assigns a
# SIGNER ROLE and emits the role-bound anchor that the MPC circuit binds to.
#
#   trust list (allow-list of roots):  SdI root -> role 1 (clearance)
#                                      Obligor root -> role 2 (debtor confirmation)
#   NOT trusted:                       Seller root -> rejected (the fraudster cannot self-vouch)
#
# A submission is admitted only if: (a) the inner signature verifies over the CANONICAL_ID
# (so the signer vouched for exactly debtor|amount|id, the value the membership check keys
# on), AND (b) the signer's cert chains to a trusted root. The role comes from which root.
#
# The fabrication catch lives HERE: the obligor signs only the TRUE canonical_id; there is
# no obligor signature over an inflated/fictitious canonical_id, so an inflated invoice can
# never be admitted as role 2. (Clearance, role 1, will admit it -- it only proves "cleared".)
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS="$DIR/certs"; mkdir -p "$CERTS"
COMMIT="$HOME/apertrue/circuits/experiments/conoir-spike/quorum/commit_receivable"
NARGO="$HOME/.nargo/bin/nargo"

CID_TRUE=06cc60c66ce6389ea53783b55dc5ff1b480e9a43ecf4c942262f5d73d7a87280   # amount 500
CID_INFL=015e98c898078299bf9ed776c7855548a0207ec782c4b245d222fbdcd358bb03   # amount 5000 (inflated)

mkroot() { # name
  openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/$1.key" 2>/dev/null
  openssl req -new -x509 -key "$CERTS/$1.key" -out "$CERTS/$1.pem" -days 3650 \
    -subj "/CN=$1/O=Apertrue Quorum STANDIN" \
    -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
}
mkleaf() { # name rootname
  openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/$1.key" 2>/dev/null
  openssl req -new -key "$CERTS/$1.key" -out "$CERTS/$1.csr" -subj "/CN=$1/O=Apertrue Quorum STANDIN" 2>/dev/null
  printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\n" > "$CERTS/$1.ext"
  openssl x509 -req -in "$CERTS/$1.csr" -CA "$CERTS/$2.pem" -CAkey "$CERTS/$2.key" -CAcreateserial \
    -out "$CERTS/$1.pem" -days 3650 -extfile "$CERTS/$1.ext" 2>/dev/null
  openssl x509 -in "$CERTS/$1.pem" -pubkey -noout > "$CERTS/$1.pub" 2>/dev/null
}
sign_cid() { # leafname cidhex outname  -- signer vouches for the canonical_id
  printf "$2" | xxd -r -p > "$CERTS/$3.cid"
  openssl dgst -sha256 -sign "$CERTS/$1.key" -out "$CERTS/$3.sig" "$CERTS/$3.cid" 2>/dev/null
}

echo "### generate trust roots + signer leaves (one-time) ###"
mkroot sdi_root; mkroot obligor_root; mkroot seller_root
mkleaf sdi_leaf      sdi_root
mkleaf obligor_leaf  obligor_root
mkleaf seller_leaf   seller_root
cat "$CERTS/sdi_root.pem" "$CERTS/obligor_root.pem" > "$CERTS/trust_store.pem"   # allow-list

echo "### produce signatures (who vouches for what) ###"
sign_cid sdi_leaf      $CID_TRUE sdi_true        # SdI clears the true invoice
sign_cid sdi_leaf      $CID_INFL sdi_infl        # SdI also clears the INFLATED invoice (it only clears)
sign_cid obligor_leaf  $CID_TRUE obligor_true    # debtor confirms ONLY the true debt
sign_cid seller_leaf   $CID_TRUE seller_true     # seller self-attests (not acceptable)
# NOTE: there is deliberately NO obligor signature over CID_INFL -- the debtor won't sign a lie.

SDI_SUBJ=$(openssl x509 -in "$CERTS/sdi_root.pem" -noout -subject 2>/dev/null | sed 's/^subject=//')
OBL_SUBJ=$(openssl x509 -in "$CERTS/obligor_root.pem" -noout -subject 2>/dev/null | sed 's/^subject=//')

admit() { # label leafname cidhex tag
  local label="$1" leaf="$2" cid="$3" tag="$4"
  printf "$cid" | xxd -r -p > "$CERTS/_chk.cid"
  # (a) inner signature over the canonical_id?
  if ! openssl dgst -sha256 -verify "$CERTS/$leaf.pub" -signature "$CERTS/$tag.sig" "$CERTS/_chk.cid" >/dev/null 2>&1; then
    printf "%-34s -> REJECTED (no valid signature over this canonical_id)\n" "$label"; return; fi
  # (b) does the signer chain to a trusted root (allow-list)?
  if ! openssl verify -CAfile "$CERTS/trust_store.pem" "$CERTS/$leaf.pem" >/dev/null 2>&1; then
    printf "%-34s -> REJECTED (signer not in acceptable-anchor allow-list)\n" "$label"; return; fi
  # role from issuer
  local iss role guar
  iss=$(openssl x509 -in "$CERTS/$leaf.pem" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
  if [ "$iss" = "$SDI_SUBJ" ]; then role=1; guar='cleared + uniquely identified (NOT proof of debt)';
  elif [ "$iss" = "$OBL_SUBJ" ]; then role=2; guar='the debt is GENUINELY OWED';
  else printf "%-34s -> REJECTED (unknown issuer)\n" "$label"; return; fi
  # emit role-bound anchor
  printf "%-34s -> ADMITTED  role=%s  guarantee: %s\n" "$label" "$role" "$guar"
}

echo
echo "### ADMISSION DECISIONS ###"
admit "obligor: true receivable"      obligor_leaf $CID_TRUE obligor_true
admit "SdI: true receivable"          sdi_leaf     $CID_TRUE sdi_true
admit "SdI: INFLATED (seller cleared)" sdi_leaf    $CID_INFL sdi_infl
admit "obligor: INFLATED (fabrication)" obligor_leaf $CID_INFL sdi_infl   # no obligor sig exists -> rejected
admit "seller self-signed"            seller_leaf  $CID_TRUE seller_true
