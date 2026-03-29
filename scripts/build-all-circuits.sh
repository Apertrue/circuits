#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# All circuit and contract packages (order: independent first, then aggregators)
PACKAGES=(
  proof_a
  proof_a_rsa_2048
  proof_a_rsa_4096
  proof_a_ecdsa_p256
  proof_a_ecdsa_p384
  proof_a_skip
  proof_b
  proof_b_es256
  proof_b_ps256
  image_aggregator
  tree_aggregator
  selective_disclosure
  anonymous_credential
  credential_registration
  jwt_identity
  aztec_verifier
  webauthn_account
)

FAILED=()

for pkg in "${PACKAGES[@]}"; do
  echo "==> Compiling $pkg"
  if nargo compile --package "$pkg" 2>&1; then
    echo "    OK"
  else
    echo "    FAILED"
    FAILED+=("$pkg")
  fi
done

echo ""
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "All ${#PACKAGES[@]} packages compiled successfully."
else
  echo "FAILED (${#FAILED[@]}/${#PACKAGES[@]}):"
  for pkg in "${FAILED[@]}"; do
    echo "  - $pkg"
  done
  exit 1
fi
