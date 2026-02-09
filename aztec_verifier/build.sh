#!/usr/bin/env bash
# =============================================================================
# Aztec Verifier Contract Build Pipeline
#
# Automates the full pipeline from Noir source to deployment-ready artifact
# with TypeScript bindings:
#
#   1. nargo compile         -> raw ACIR artifact
#   2. bb-avm aztec_process  -> AVM transpilation + VK generation (v3.0.3)
#   3. strip name prefix     -> remove __aztec_nr_internals__ prefix
#   4. aztec-builder codegen -> TypeScript bindings
#
# Requirements:
#   - nargo (Noir compiler)
#   - Docker container 'aztec-submitter-aztec-1' running (v3.0.3 sandbox)
#   - npx aztec-builder (@aztec/builder package)
#   - python3
#
# Usage:
#   ./build.sh           # full pipeline
#   ./build.sh --skip-compile  # skip nargo compile (reprocess existing artifact)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
TARGET_DIR="$PROJECT_DIR/target"
ARTIFACT_NAME="apertrue_verifier-ApertrueVerifier.json"
ARTIFACT_PATH="$TARGET_DIR/$ARTIFACT_NAME"
ARTIFACTS_DIR="$PROJECT_DIR/artifacts"
SIDECAR_DIR="$SCRIPT_DIR/../../services/aztec-submitter/src"
DOCKER_CONTAINER="aztec-submitter-aztec-1"
BB_AVM="/usr/src/barretenberg/cpp/build/bin/bb-avm"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[build]${NC} $1"; }
warn() { echo -e "${YELLOW}[build]${NC} $1"; }
err() { echo -e "${RED}[build]${NC} $1" >&2; }

# Parse args
SKIP_COMPILE=false
for arg in "$@"; do
  case $arg in
    --skip-compile) SKIP_COMPILE=true ;;
    --help|-h)
      echo "Usage: $0 [--skip-compile]"
      echo "  --skip-compile  Skip nargo compile, reprocess existing artifact"
      exit 0
      ;;
  esac
done

# =============================================================================
# Step 1: Compile with nargo
# =============================================================================
if [ "$SKIP_COMPILE" = false ]; then
  log "Step 1/4: Compiling with nargo..."
  cd "$PROJECT_DIR"
  nargo compile
  log "Compilation complete."
else
  log "Step 1/4: Skipping nargo compile (--skip-compile)"
fi

if [ ! -f "$ARTIFACT_PATH" ]; then
  err "Artifact not found at $ARTIFACT_PATH"
  exit 1
fi

# =============================================================================
# Step 2: AVM transpilation + VK generation via bb-avm in Docker
# =============================================================================
log "Step 2/4: AVM transpilation + VK generation (bb-avm aztec_process)..."

# Verify Docker container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${DOCKER_CONTAINER}$"; then
  err "Docker container '$DOCKER_CONTAINER' is not running."
  err "Start it with: docker compose -f services/aztec-submitter/docker-compose.sandbox.yml up -d"
  exit 1
fi

# Copy artifact into container
docker cp "$ARTIFACT_PATH" "${DOCKER_CONTAINER}:/tmp/input_artifact.json"

# Run bb-avm aztec_process
docker exec "$DOCKER_CONTAINER" "$BB_AVM" aztec_process \
  -i /tmp/input_artifact.json \
  -o /tmp/processed_artifact.json

# Copy processed artifact back
docker cp "${DOCKER_CONTAINER}:/tmp/processed_artifact.json" "$ARTIFACT_PATH"

log "AVM transpilation complete."

# =============================================================================
# Step 3: Strip __aztec_nr_internals__ prefix from function names
# =============================================================================
log "Step 3/4: Stripping function name prefix..."

python3 -c "
import json, sys

artifact_path = '$ARTIFACT_PATH'

with open(artifact_path) as f:
    data = json.load(f)

PREFIX = '__aztec_nr_internals__'
stripped = 0

for fn in data.get('functions', []):
    name = fn.get('name', '')
    if name.startswith(PREFIX):
        fn['name'] = name[len(PREFIX):]
        stripped += 1

# Ensure transpiled flag is set
data['transpiled'] = True

with open(artifact_path, 'w') as f:
    json.dump(data, f, separators=(',', ':'))

print(f'  Stripped prefix from {stripped} functions')
print(f'  transpiled flag: True')
"

# Verify the result
python3 -c "
import json

with open('$ARTIFACT_PATH') as f:
    data = json.load(f)

fns = data.get('functions', [])
print(f'  Functions ({len(fns)}):')
for fn in fns:
    name = fn.get('name', '?')
    has_vk = bool(fn.get('verification_key', ''))
    attrs = fn.get('custom_attributes', [])
    print(f'    {name}: vk={has_vk}, attrs={attrs}')
print(f'  transpiled: {data.get(\"transpiled\", \"NOT SET\")}')
"

log "Name prefix stripped."

# =============================================================================
# Step 4: Generate TypeScript bindings via aztec-builder codegen
# =============================================================================
log "Step 4/4: Generating TypeScript bindings (aztec-builder codegen)..."

mkdir -p "$ARTIFACTS_DIR"

# Run codegen (pinned to v3.0.3 to match the rest of the Aztec stack)
npx --package @aztec/builder@3.0.3 aztec-builder codegen "$ARTIFACT_PATH" -o "$ARTIFACTS_DIR" --force

# Fix the import path in generated bindings
# codegen generates an absolute path to the artifact; replace with relative
CODEGEN_OUTPUT="$ARTIFACTS_DIR/ApertrueVerifier.ts"

if [ -f "$CODEGEN_OUTPUT" ]; then
  # Replace the import path with a relative path from artifacts/ to target/
  python3 -c "
import re

with open('$CODEGEN_OUTPUT') as f:
    content = f.read()

# Replace any absolute or wrong import path for the artifact JSON
# The codegen outputs something like:
#   import ApertrueVerifierContractArtifactJson from '/absolute/path/to/artifact.json'
# We want:
#   import ApertrueVerifierContractArtifactJson from '../target/$ARTIFACT_NAME'
content = re.sub(
    r\"import ApertrueVerifierContractArtifactJson from '[^']+'\",
    \"import ApertrueVerifierContractArtifactJson from '../target/$ARTIFACT_NAME'\",
    content
)

with open('$CODEGEN_OUTPUT', 'w') as f:
    f.write(content)

print('  Fixed artifact import path')
"

  # Copy to sidecar
  if [ -d "$SIDECAR_DIR" ]; then
    cp "$CODEGEN_OUTPUT" "$SIDECAR_DIR/ApertrueVerifier.ts"

    # Fix import path for sidecar (different relative path)
    python3 -c "
import re

sidecar_path = '$SIDECAR_DIR/ApertrueVerifier.ts'

with open(sidecar_path) as f:
    content = f.read()

content = re.sub(
    r\"import ApertrueVerifierContractArtifactJson from '[^']+'\",
    \"import ApertrueVerifierContractArtifactJson from '../../../circuits/aztec_verifier/target/$ARTIFACT_NAME'\",
    content
)

with open(sidecar_path, 'w') as f:
    f.write(content)

print('  Copied to sidecar with corrected import path')
"
  fi

  log "TypeScript bindings generated."
else
  err "Codegen output not found at $CODEGEN_OUTPUT"
  exit 1
fi

# =============================================================================
# Done
# =============================================================================
echo ""
log "Build complete!"
log "Artifact: $ARTIFACT_PATH"
log "Bindings: $CODEGEN_OUTPUT"
if [ -d "$SIDECAR_DIR" ]; then
  log "Sidecar:  $SIDECAR_DIR/ApertrueVerifier.ts"
fi
echo ""
log "Next steps:"
log "  1. Deploy: cd services/aztec-submitter && npx tsx src/deploy.ts"
log "  2. Test:   aztec-wallet simulate get_admin --contract-address <addr>"
