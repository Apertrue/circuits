#!/usr/bin/env bash
# =============================================================================
# Aztec Verifier Contract Build Pipeline
#
# Automates the full pipeline from Noir source to deployment-ready artifact
# with TypeScript bindings:
#
#   1. aztec compile          -> nargo compile + AVM transpilation + VK generation (v4.0.4)
#   2. strip name prefix      -> remove __aztec_nr_internals__ prefix
#   3. aztec codegen           -> TypeScript bindings
#
# Requirements:
#   - Aztec v4.0.4 toolchain (~/.aztec/versions/4.0.4/)
#   - bash 4+ (macOS: /opt/homebrew/bin/bash)
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
SIDECAR_DIR="$SCRIPT_DIR/../../services/aztec-submitter"
AZTEC_VERSION="4.0.4"
AZTEC_DIR="$HOME/.aztec/versions/$AZTEC_VERSION"
AZTEC_CLI="$AZTEC_DIR/node_modules/.bin/aztec"
AZTEC_NARGO="$AZTEC_DIR/bin/nargo"

# Detect platform architecture for bb binary
ARCH="$(uname -m)"
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
  if [ "$ARCH" = "arm64" ]; then
    BB_PLATFORM="arm64-macos"
  else
    BB_PLATFORM="x86_64-macos"
  fi
elif [ "$OS" = "Linux" ]; then
  BB_PLATFORM="x86_64-linux"
else
  err "Unsupported platform: $OS/$ARCH"
  exit 1
fi
AZTEC_BB="$AZTEC_DIR/node_modules/@aztec/bb.js/build/$BB_PLATFORM/bb"

# bash 4+ required by aztec CLI (macOS ships bash 3.2)
if [ -x "/opt/homebrew/bin/bash" ]; then
  BASH4="/opt/homebrew/bin/bash"
elif [ -x "/usr/local/bin/bash" ]; then
  BASH4="/usr/local/bin/bash"
else
  BASH4="bash"
fi

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
# Step 1: Compile + AVM transpilation + VK generation (aztec compile)
# =============================================================================

# Verify Aztec toolchain is installed
if [ ! -f "$AZTEC_CLI" ]; then
  err "Aztec v$AZTEC_VERSION toolchain not found at $AZTEC_DIR"
  err "Install with: VERSION=$AZTEC_VERSION bash -i <(curl -sL https://install.aztec.network/$AZTEC_VERSION)"
  exit 1
fi

if [ "$SKIP_COMPILE" = false ]; then
  log "Step 1/3: Compiling + AVM transpilation + VK generation (aztec compile)..."
  cd "$PROJECT_DIR"
  PATH="$AZTEC_DIR/bin:$AZTEC_DIR/node_modules/@aztec/bb.js/build/$BB_PLATFORM:$PATH" \
    "$BASH4" -c "$AZTEC_CLI compile --force"
  log "Compilation + transpilation complete."
else
  log "Step 1/3: Skipping compile (--skip-compile)"
fi

if [ ! -f "$ARTIFACT_PATH" ]; then
  err "Artifact not found at $ARTIFACT_PATH"
  exit 1
fi

# =============================================================================
# Step 3: Strip __aztec_nr_internals__ prefix from function names
# =============================================================================
log "Step 2/3: Stripping function name prefix..."

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
log "Step 3/3: Generating TypeScript bindings (aztec codegen)..."

mkdir -p "$ARTIFACTS_DIR"

# Run codegen via aztec CLI (v4)
"$BASH4" -c "$AZTEC_CLI codegen $ARTIFACT_PATH -o $ARTIFACTS_DIR --force"

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

  # Copy to sidecar: both the codegen bindings and the artifact JSON
  if [ -d "$SIDECAR_DIR" ]; then
    SIDECAR_ARTIFACTS="$SIDECAR_DIR/artifacts"
    mkdir -p "$SIDECAR_ARTIFACTS"

    # Copy artifact JSON so sidecar has its own copy (no cross-package imports)
    cp "$ARTIFACT_PATH" "$SIDECAR_ARTIFACTS/$ARTIFACT_NAME"

    # Copy codegen bindings to sidecar src/
    cp "$CODEGEN_OUTPUT" "$SIDECAR_DIR/src/ApertrueVerifier.ts"

    # Fix import path: sidecar imports from its local artifacts/ copy
    python3 -c "
import re

sidecar_path = '$SIDECAR_DIR/src/ApertrueVerifier.ts'

with open(sidecar_path) as f:
    content = f.read()

content = re.sub(
    r\"import ApertrueVerifierContractArtifactJson from '[^']+'\",
    \"import ApertrueVerifierContractArtifactJson from '../artifacts/$ARTIFACT_NAME'\",
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
