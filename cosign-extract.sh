#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 --type (slsa|cyclonedx|spdx) IMAGE[:TAG]"
  exit 1
fi

TYPE=$1
IMAGE=$2

case "$TYPE" in
  slsa)       PRED_TYPE="https://slsa.dev/provenance/v1" ;;
  cyclonedx)  PRED_TYPE="https://cyclonedx.org/bom" ;;
  spdx)       PRED_TYPE="https://spdx.dev/Document" ;;
  *) echo "Unknown type: $TYPE"; exit 1 ;;
esac

# Resolve tag -> digest
DIGEST=$(crane digest "$IMAGE")

# Find referrer by predicate type
REFERRER_DIGEST=$(oras discover "$IMAGE@$DIGEST" --format json \
  | jq -r --arg pt "$PRED_TYPE" '
      .referrers[]
      | select(.artifactType=="application/vnd.dev.sigstore.bundle.v0.3+json")
      | select(.annotations["dev.sigstore.bundle.predicateType"]==$pt)
      | .digest' | head -n1)

if [ -z "$REFERRER_DIGEST" ]; then
  echo "❌ No attestation found for type=$TYPE ($PRED_TYPE)"
  exit 1
fi

# Fetch manifest, get blob digest
LAYER_DIGEST=$(oras manifest fetch "$IMAGE@$REFERRER_DIGEST" | jq -r '.layers[0].digest')

# Fetch bundle
BUNDLE=$(mktemp)
oras blob fetch "$IMAGE@$LAYER_DIGEST" --output "$BUNDLE"

# Decode predicate
jq -r '.dsseEnvelope.payload' "$BUNDLE" | base64 -d | jq .

