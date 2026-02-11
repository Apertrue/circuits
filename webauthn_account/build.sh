#!/usr/bin/env bash
# =============================================================================
# WebAuthn Account Contract Build Pipeline
#
# Same pipeline as aztec_verifier/build.sh adapted for the WebAuthn
# account contract:
#
#   1. nargo compile         -> raw ACIR artifact
#   2. bb-avm aztec_process  -> AVM transpilation + VK generation
#   3. strip name prefix     -> remove __aztec_nr_internals__ prefix
#   4. aztec-builder codegen -> TypeScript bindings
#   5. copy artifact         -> apps/web/public/contracts/
#
# Usage:
#   ./build.sh                 # full pipeline
#   ./build.sh --skip-compile  # skip nargo compile
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
TARGET_DIR="$PROJECT_DIR/target"
ARTIFACT_NAME="webauthn_account-WebAuthnAccount.json"
ARTIFACT_PATH="$TARGET_DIR/$ARTIFACT_NAME"
ARTIFACTS_DIR="$PROJECT_DIR/artifacts"
WEB_PUBLIC_DIR="$SCRIPT_DIR/../../apps/web/public/contracts"
DOCKER_CONTAINER="aztec-submitter-aztec-1"
BB_AVM="/usr/src/barretenberg/cpp/build/bin/bb-avm"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[build]${NC} $1"; }
warn() { echo -e "${YELLOW}[build]${NC} $1"; }
err() { echo -e "${RED}[build]${NC} $1" >&2; }

SKIP_COMPILE=false
for arg in "$@"; do
  case $arg in
    --skip-compile) SKIP_COMPILE=true ;;
    --help|-h)
      echo "Usage: $0 [--skip-compile]"
      exit 0
      ;;
  esac
done

# =============================================================================
# Step 1: Compile with nargo
# =============================================================================
if [ "$SKIP_COMPILE" = false ]; then
  log "Step 1/5: Compiling with nargo..."
  cd "$PROJECT_DIR"
  nargo compile
  log "Compilation complete."
else
  log "Step 1/5: Skipping nargo compile (--skip-compile)"
fi

if [ ! -f "$ARTIFACT_PATH" ]; then
  err "Artifact not found at $ARTIFACT_PATH"
  exit 1
fi

# =============================================================================
# Step 2: AVM transpilation + VK generation via bb-avm in Docker
# =============================================================================
log "Step 2/5: AVM transpilation + VK generation (bb-avm aztec_process)..."

if ! docker ps --format '{{.Names}}' | grep -q "^${DOCKER_CONTAINER}$"; then
  err "Docker container '$DOCKER_CONTAINER' is not running."
  err "Start it with: docker compose -f services/aztec-submitter/docker-compose.sandbox.yml up -d"
  exit 1
fi

docker cp "$ARTIFACT_PATH" "${DOCKER_CONTAINER}:/tmp/webauthn_input.json"

docker exec "$DOCKER_CONTAINER" "$BB_AVM" aztec_process \
  -i /tmp/webauthn_input.json \
  -o /tmp/webauthn_processed.json

docker cp "${DOCKER_CONTAINER}:/tmp/webauthn_processed.json" "$ARTIFACT_PATH"

log "AVM transpilation complete."

# =============================================================================
# Step 3: Strip __aztec_nr_internals__ prefix from function names
# =============================================================================
log "Step 3/5: Stripping function name prefix..."

python3 -c "
import json

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

data['transpiled'] = True

with open(artifact_path, 'w') as f:
    json.dump(data, f, separators=(',', ':'))

print(f'  Stripped prefix from {stripped} functions')
print(f'  transpiled flag: True')
"

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
log "Step 4/5: Generating TypeScript bindings (aztec-builder codegen)..."

mkdir -p "$ARTIFACTS_DIR"

npx --package @aztec/builder@3.0.3 aztec-builder codegen "$ARTIFACT_PATH" -o "$ARTIFACTS_DIR" --force

CODEGEN_OUTPUT="$ARTIFACTS_DIR/WebAuthnAccount.ts"

if [ -f "$CODEGEN_OUTPUT" ]; then
  python3 -c "
import re

with open('$CODEGEN_OUTPUT') as f:
    content = f.read()

content = re.sub(
    r\"import WebAuthnAccountContractArtifactJson from '[^']+'\",
    \"import WebAuthnAccountContractArtifactJson from '../target/$ARTIFACT_NAME'\",
    content
)

with open('$CODEGEN_OUTPUT', 'w') as f:
    f.write(content)

print('  Fixed artifact import path')
"
  log "TypeScript bindings generated."
else
  err "Codegen output not found at $CODEGEN_OUTPUT"
  exit 1
fi

# =============================================================================
# Step 5: Copy artifact to web app public directory
# =============================================================================
log "Step 5/5: Copying artifact to web app..."

mkdir -p "$WEB_PUBLIC_DIR"
cp "$ARTIFACT_PATH" "$WEB_PUBLIC_DIR/$ARTIFACT_NAME"

log "Artifact copied to $WEB_PUBLIC_DIR/$ARTIFACT_NAME"

# =============================================================================
# Done
# =============================================================================
echo ""
log "Build complete!"
log "Artifact:  $ARTIFACT_PATH"
log "Bindings:  $CODEGEN_OUTPUT"
log "Web app:   $WEB_PUBLIC_DIR/$ARTIFACT_NAME"
echo ""
log "Next steps:"
log "  1. Deploy: update deployment script for WebAuthn account contract"
log "  2. Test:   clear IndexedDB, register new passkey, verify TX flow"
