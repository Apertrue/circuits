#!/usr/bin/env bash
# coNoir spike: run the imt_nm_mini circuit through the full 3-party MPC pipeline.
# Mirrors run_all_steps_poseidon.sh, adapted for test_vectors/imt_nm_mini.
set -e
cd "$(dirname "$(realpath "$0")")"

CO=../../../target/release/co-noir         # built binary (faster than cargo run)
TV=test_vectors/imt_nm_mini
CRS1=../../co-noir-common/src/crs/bn254_g1.dat
CRS2=../../co-noir-common/src/crs/bn254_g2.dat

echo "### 1. split-input (REP3 secret-share the Prover.toml inputs) ###"
"$CO" split-input --circuit "$TV/target/imt_nm_mini.json" --input "$TV/Prover.toml" --protocol REP3 --out-dir "$TV"

echo "### 2. generate-witness in MPC (3 parties) ###"
"$CO" generate-witness --input "$TV/Prover.toml.0.shared" --circuit "$TV/target/imt_nm_mini.json" --protocol REP3 --config configs/party1.toml --out "$TV/witness.0.shared" &
"$CO" generate-witness --input "$TV/Prover.toml.1.shared" --circuit "$TV/target/imt_nm_mini.json" --protocol REP3 --config configs/party2.toml --out "$TV/witness.1.shared" &
"$CO" generate-witness --input "$TV/Prover.toml.2.shared" --circuit "$TV/target/imt_nm_mini.json" --protocol REP3 --config configs/party3.toml --out "$TV/witness.2.shared"
wait $(jobs -p)

echo "### 3. build-proving-key in MPC (3 parties) ###"
"$CO" build-proving-key --witness "$TV/witness.0.shared" --circuit "$TV/target/imt_nm_mini.json" --protocol REP3 --config configs/party1.toml --out "$TV/pk.0.shared" --crs "$CRS1" &
"$CO" build-proving-key --witness "$TV/witness.1.shared" --circuit "$TV/target/imt_nm_mini.json" --protocol REP3 --config configs/party2.toml --out "$TV/pk.1.shared" --crs "$CRS1" &
"$CO" build-proving-key --witness "$TV/witness.2.shared" --circuit "$TV/target/imt_nm_mini.json" --protocol REP3 --config configs/party3.toml --out "$TV/pk.2.shared" --crs "$CRS1"
wait $(jobs -p)

echo "### 4. create verification key ###"
"$CO" create-vk --circuit "$TV/target/imt_nm_mini.json" --crs "$CRS1" --hasher keccak --vk "$TV/vk"

echo "### 5. generate-proof in MPC (3 parties) ###"
"$CO" generate-proof --proving-key "$TV/pk.0.shared" --protocol REP3 --hasher keccak --config configs/party1.toml --crs "$CRS1" --out "$TV/proof.0.proof" --vk "$TV/vk" --public-input "$TV/public_input" &
"$CO" generate-proof --proving-key "$TV/pk.1.shared" --protocol REP3 --hasher keccak --config configs/party2.toml --crs "$CRS1" --out "$TV/proof.1.proof" --vk "$TV/vk" &
"$CO" generate-proof --proving-key "$TV/pk.2.shared" --protocol REP3 --hasher keccak --config configs/party3.toml --crs "$CRS1" --out "$TV/proof.2.proof" --vk "$TV/vk"
wait $(jobs -p)

echo "### 6. verify the proof + show public output ###"
"$CO" verify --proof "$TV/proof.0.proof" --public-input "$TV/public_input" --vk "$TV/vk" --hasher keccak --crs "$CRS2"
echo "--- public_input (the revealed collision bit) ---"
cat "$TV/public_input" 2>/dev/null || echo "(no public_input file)"
