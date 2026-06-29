#!/usr/bin/env bash
# Apertrue Quorum -- aggregate engine (marine over-insurance) through full 3-party REP3 MPC.
set -e
ROOT="$HOME/co-snarks-spike"; CO="$ROOT/target/release/co-noir"
EX="$ROOT/co-noir/co-noir/examples"; CFG="$EX/configs"
CRS1="$ROOT/co-noir/co-noir-common/src/crs/bn254_g1.dat"
CRS2="$ROOT/co-noir/co-noir-common/src/crs/bn254_g2.dat"
SRC="$HOME/apertrue/circuits/experiments/conoir-spike/quorum/bound_aggregate"
TV="$EX/test_vectors/bound_aggregate"; J="$TV/target/bound_aggregate.json"
INPUT="${1:-$SRC/Prover.toml}"

rm -rf "$TV"; mkdir -p "$TV/src"
cp "$SRC/Nargo.toml" "$TV/"; cp "$SRC/src/main.nr" "$TV/src/"; cp "$INPUT" "$TV/Prover.toml"
( cd "$TV" && PATH="$HOME/.nargo/bin:$PATH" nargo compile )

cd "$TV"
"$CO" split-input --circuit "$J" --input "$TV/Prover.toml" --protocol REP3 --out-dir "$TV"
for i in 0 1 2; do "$CO" generate-witness --input "$TV/Prover.toml.$i.shared" --circuit "$J" --protocol REP3 --config "$CFG/party$((i+1)).toml" --out "$TV/witness.$i.shared" & done; wait
for i in 0 1 2; do "$CO" build-proving-key --witness "$TV/witness.$i.shared" --circuit "$J" --protocol REP3 --config "$CFG/party$((i+1)).toml" --out "$TV/pk.$i.shared" --crs "$CRS1" & done; wait
"$CO" create-vk --circuit "$J" --crs "$CRS1" --hasher keccak --vk "$TV/vk"
"$CO" generate-proof --proving-key "$TV/pk.0.shared" --protocol REP3 --hasher keccak --config "$CFG/party1.toml" --crs "$CRS1" --out "$TV/proof.0.proof" --vk "$TV/vk" --public-input "$TV/public_input" &
for i in 1 2; do "$CO" generate-proof --proving-key "$TV/pk.$i.shared" --protocol REP3 --hasher keccak --config "$CFG/party$((i+1)).toml" --crs "$CRS1" --out "$TV/proof.$i.proof" --vk "$TV/vk" & done; wait
"$CO" verify --proof "$TV/proof.0.proof" --public-input "$TV/public_input" --vk "$TV/vk" --hasher keccak --crs "$CRS2"
PUB="$TV/public_input" python3 - <<'PY'
import os
b=open(os.environ["PUB"],"rb").read(); n=len(b)//32
out=int.from_bytes(b[(n-1)*32:n*32],"big")
print("  => over_insured =", out)
PY
