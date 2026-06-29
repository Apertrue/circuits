#!/usr/bin/env bash
# Apertrue Quorum: run bound_receivables through the full 3-party REP3 MPC pipeline.
# Answers "is this receivable already financed anywhere in the network?" revealing one bit.
# Usage: ./run_bound_receivables.sh [Prover.toml]   (default: the clean case)
set -e
ROOT="$HOME/co-snarks-spike"; CO="$ROOT/target/release/co-noir"
EX="$ROOT/co-noir/co-noir/examples"; CFG="$EX/configs"
CRS1="$ROOT/co-noir/co-noir-common/src/crs/bn254_g1.dat"
CRS2="$ROOT/co-noir/co-noir-common/src/crs/bn254_g2.dat"
SRC="$HOME/apertrue/circuits/experiments/conoir-spike/quorum/bound_receivables"
TV="$EX/test_vectors/bound_receivables"
J="$TV/target/bound_receivables.json"
INPUT="${1:-$SRC/Prover.toml}"

# stage circuit into the co-snarks clone + compile (beta.20)
rm -rf "$TV"; mkdir -p "$TV/src"
cp "$SRC/Nargo.toml" "$TV/"; cp "$SRC/src/main.nr" "$TV/src/"; cp "$INPUT" "$TV/Prover.toml"
( cd "$TV" && PATH="$HOME/.nargo/bin:$PATH" nargo compile )

cd "$TV"
echo "### 1. split-input ###"
"$CO" split-input --circuit "$J" --input "$TV/Prover.toml" --protocol REP3 --out-dir "$TV"
echo "### 2. generate-witness (3 parties) ###"
for i in 0 1 2; do "$CO" generate-witness --input "$TV/Prover.toml.$i.shared" --circuit "$J" --protocol REP3 --config "$CFG/party$((i+1)).toml" --out "$TV/witness.$i.shared" & done; wait
echo "### 3. build-proving-key (3 parties) ###"
for i in 0 1 2; do "$CO" build-proving-key --witness "$TV/witness.$i.shared" --circuit "$J" --protocol REP3 --config "$CFG/party$((i+1)).toml" --out "$TV/pk.$i.shared" --crs "$CRS1" & done; wait
echo "### 4. create-vk ###"
"$CO" create-vk --circuit "$J" --crs "$CRS1" --hasher keccak --vk "$TV/vk"
echo "### 5. generate-proof (3 parties) ###"
"$CO" generate-proof --proving-key "$TV/pk.0.shared" --protocol REP3 --hasher keccak --config "$CFG/party1.toml" --crs "$CRS1" --out "$TV/proof.0.proof" --vk "$TV/vk" --public-input "$TV/public_input" &
for i in 1 2; do "$CO" generate-proof --proving-key "$TV/pk.$i.shared" --protocol REP3 --hasher keccak --config "$CFG/party$((i+1)).toml" --crs "$CRS1" --out "$TV/proof.$i.proof" --vk "$TV/vk" & done; wait
echo "### 6. verify ###"
"$CO" verify --proof "$TV/proof.0.proof" --public-input "$TV/public_input" --vk "$TV/vk" --hasher keccak --crs "$CRS2"
echo "--- public output (anchor, role, allow-list, bit, guarantee) ---"
PUB="$TV/public_input" python3 - <<'PY'
import os
b=open(os.environ["PUB"],"rb").read()
n=len(b)//32
vals=[int.from_bytes(b[i*32:(i+1)*32],"big") for i in range(n)]
# layout: [candidate_anchor, signer_role, accepted_roles[0..1], already_financed, signer_role_out]
def hexs(v): return str(v) if v<100000 else "0x"+("%064x"%v).lstrip("0")
labels=["candidate_anchor","IN  signer_role","accepted_role[0]","accepted_role[1]","OUT already_financed","OUT signer_role"]
for i,v in enumerate(vals):
    print("  %-22s = %s" % (labels[i] if i<len(labels) else "field[%d]"%i, hexs(v)))
role=vals[-1]; fin=vals[-2]
guar={1:"cleared + uniquely identified (NOT proof of debt)",2:"the debt is GENUINELY OWED"}.get(role,"?")
print("  => already_financed=%d | role=%d | guarantee: %s" % (fin, role, guar))
PY
