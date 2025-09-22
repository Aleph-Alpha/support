#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 (slsa|cyclonedx|spdx|vuln|custom) IMAGE[:TAG] [index|all]"
  echo "  index = number of the attestation to extract"
  echo "  all   = dump all attestations of that type"
  exit 1
fi

TYPE=$1
IMAGE=$2
CHOICE=${3:-} # no default, we prompt if needed

case "$TYPE" in
  slsa)       PRED_TYPE="https://slsa.dev/provenance/v1" ;;
  cyclonedx)  PRED_TYPE="https://cyclonedx.org/bom" ;;
  spdx)       PRED_TYPE="https://spdx.dev/Document" ;;
  vuln)       PRED_TYPE="https://cosign.sigstore.dev/attestation/vuln/v1" ;;
  custom)     PRED_TYPE="custom" ;; # raw Trivy, license, triage, etc.
  *) echo "❌ Unknown type: $TYPE"; exit 1 ;;
esac

# Resolve tag -> digest
DIGEST=$(crane digest "$IMAGE")

# Find all referrers for this type
REFERRERS=$(oras discover "$IMAGE@$DIGEST" --format json \
  | jq -r --arg pt "$PRED_TYPE" '
      .referrers[]
      | select(.artifactType=="application/vnd.dev.sigstore.bundle.v0.3+json")
      | select(
          (.annotations["dev.sigstore.bundle.predicateType"]==$pt)
          or ($pt=="custom" and .annotations["dev.sigstore.bundle.predicateType"]=="https://cosign.sigstore.dev/attestation/v1")
        )
      | .digest')

if [ -z "$REFERRERS" ]; then
  echo "❌ No attestations found for type=$TYPE"
  exit 1
fi

# Collect digests into an array
DIGESTS=()
while IFS= read -r line; do
  DIGESTS+=("$line")
done <<< "$REFERRERS"

echo "🔎 Found ${#DIGESTS[@]} attestations for type=$TYPE:"
i=1
for d in "${DIGESTS[@]}"; do
  echo "  [$i] $d"
  i=$((i+1))
done

# Function to fetch + decode one attestation
fetch_attestation() {
  local ref_digest="$1"
  local bundle
  bundle=$(mktemp)

  # fetch manifest → get blob digest
  layer_digest=$(oras manifest fetch "$IMAGE@$ref_digest" | jq -r '.layers[0].digest')

  # fetch blob
  oras blob fetch "$IMAGE@$layer_digest" --output "$bundle"

  # decode predicate payload
  raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d)

  # If predicate.Data is JSON stringified, unstringify
  if echo "$raw" | jq -e '.predicate.Data' >/dev/null 2>&1; then
    data=$(echo "$raw" | jq -r '.predicate.Data')
    if echo "$data" | jq empty >/dev/null 2>&1; then
      # replace .predicate.Data with parsed JSON
      echo "$raw" | jq --argjson parsed "$data" '.predicate.Data=$parsed'
    else
      echo "$raw" | jq .
    fi
  else
    echo "$raw" | jq .
  fi
}

# Decide what to extract
if [ "$CHOICE" == "all" ]; then
  for d in "${DIGESTS[@]}"; do
    echo "----- Attestation $d -----"
    fetch_attestation "$d"
    echo ""
  done
else
  if [ ${#DIGESTS[@]} -eq 1 ]; then
    # only one, just fetch it
    fetch_attestation "${DIGESTS[0]}"
  else
    if [ -z "$CHOICE" ]; then
      echo -n "Select attestation [1-${#DIGESTS[@]}]: "
      read -r CHOICE
    fi

    INDEX=$((CHOICE-1))
    if [ $INDEX -lt 0 ] || [ $INDEX -ge ${#DIGESTS[@]} ]; then
      echo "❌ Invalid choice. Pick 1..${#DIGESTS[@]} or 'all'."
      exit 1
    fi
    fetch_attestation "${DIGESTS[$INDEX]}"
  fi
fi

