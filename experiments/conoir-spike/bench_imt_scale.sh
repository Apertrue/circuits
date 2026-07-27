#!/usr/bin/env bash
# Benchmark imt_nm_scale at a given number of checks N.
# Usage: bench_imt_scale.sh N
set -e
cd "$(dirname "$(realpath "$0")")"
N="${1:-1}"
NARGO=~/.nargo/bin/nargo
CO=../../../target/release/co-noir
TV=test_vectors/imt_nm_scale
CRS1=../../co-noir-common/src/crs/bn254_g1.dat
CRS2=../../co-noir-common/src/crs/bn254_g2.dat
now(){ python3 -c 'import time;print(int(time.time()*1000))'; }

echo "########## N = $N ##########"

# 1. patch CHECKS in the circuit
sed -i '' "s/^global CHECKS: u32 = .*/global CHECKS: u32 = $N;/" "$TV/src/main.nr"

# 2. generate Prover.toml (N checks, depth 32; low_key < key < next_key)
node -e '
const N=+process.argv[1], D=32;
const arr=(f)=>"["+Array.from({length:N},(_,c)=>`"${f(c)}"`).join(", ")+"]";
let s="";
s+="key = "+arr(c=>c*1000+20)+"\n";
s+="low_key = "+arr(c=>c*1000+10)+"\n";
s+="next_key = "+arr(c=>c*1000+30)+"\n";
s+="next_index = "+arr(c=>c)+"\n";
s+="low_leaf_index = "+arr(c=>c)+"\n";
const paths=Array.from({length:N},(_,c)=>"["+Array.from({length:D},(_,i)=>`"${c*100+i+1}"`).join(", ")+"]");
s+="sibling_path = ["+paths.join(", ")+"]\n";
process.stdout.write(s);
' "$N" > "$TV/Prover.toml"

# 3. compile + gate count
( cd "$TV" && "$NARGO" execute >/dev/null 2>&1 )
GATES=$(bb gates -b "$TV/target/imt_nm_scale.json" 2>/dev/null | grep -oE '"circuit_size": *[0-9]+' | grep -oE '[0-9]+' | head -1)
echo "gates(circuit_size) = ${GATES:-unknown}"

# 4. timed MPC pipeline
t0=$(now)
"$CO" split-input --circuit "$TV/target/imt_nm_scale.json" --input "$TV/Prover.toml" --protocol REP3 --out-dir "$TV" >/dev/null 2>&1
for p in 0 1 2; do
  "$CO" generate-witness --input "$TV/Prover.toml.$p.shared" --circuit "$TV/target/imt_nm_scale.json" --protocol REP3 --config "configs/party$((p+1)).toml" --out "$TV/w.$p.shared" >/dev/null 2>&1 &
done; wait
tw=$(now)
for p in 0 1 2; do
  "$CO" build-proving-key --witness "$TV/w.$p.shared" --circuit "$TV/target/imt_nm_scale.json" --protocol REP3 --config "configs/party$((p+1)).toml" --out "$TV/pk.$p.shared" --crs "$CRS1" >/dev/null 2>&1 &
done; wait
tpk=$(now)
"$CO" create-vk --circuit "$TV/target/imt_nm_scale.json" --crs "$CRS1" --hasher keccak --vk "$TV/vk" >/dev/null 2>&1
for p in 0 1 2; do
  extra=""; [ "$p" = "0" ] && extra="--public-input $TV/public_input"
  "$CO" generate-proof --proving-key "$TV/pk.$p.shared" --protocol REP3 --hasher keccak --config "configs/party$((p+1)).toml" --crs "$CRS1" --out "$TV/proof.$p.proof" --vk "$TV/vk" $extra >/dev/null 2>&1 &
done; wait
tpf=$(now)
"$CO" verify --proof "$TV/proof.0.proof" --public-input "$TV/public_input" --vk "$TV/vk" --hasher keccak --crs "$CRS2" >/dev/null 2>&1 && echo "VERIFIED ok"
tv=$(now)

echo "witness:      $((tw-t0)) ms"
echo "proving-key:  $((tpk-tw)) ms"
echo "proof:        $((tpf-tpk)) ms (incl vk)"
echo "verify:       $((tv-tpf)) ms"
echo "TOTAL:        $((tv-t0)) ms"
