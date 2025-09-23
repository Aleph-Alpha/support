#!/usr/bin/env bash
set -euo pipefail

show_help() {
  cat <<EOF
Usage: $0 --type (slsa|cyclonedx|spdx|vuln|license|triage|custom) --image IMAGE[:TAG] [--choice index|all]

Options:
  --type       Type of attestation to extract (required unless --list)
  --image      Fully qualified image reference (required)
  --choice     Which attestation to fetch:
                 index = number of the attestation (1-based)
                 all   = dump all attestations of that type
  --list       List all available predicateTypes and their counts
  --show-null  When used with --list, include entries with missing predicateType
  -h, --help   Show this help
EOF
}

TYPE=""
IMAGE=""
CHOICE=""
LIST_ONLY=false
SHOW_NULL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type) TYPE="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --choice) CHOICE="$2"; shift 2 ;;
    --list) LIST_ONLY=true; shift ;;
    --show-null) SHOW_NULL=true; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) echo "❌ Unknown option: $1"; show_help; exit 1 ;;
  esac
done

if [[ -z "$TYPE" && "$LIST_ONLY" == "false" ]]; then
  echo "❌ Missing required --type"
  show_help
  exit 1
fi

if [[ -z "$IMAGE" ]]; then
  echo "❌ Missing required --image"
  show_help
  exit 1
fi

# Map type to predicateType
case "$TYPE" in
  slsa)       PRED_TYPE="https://slsa.dev/provenance/v1" ;;
  cyclonedx)  PRED_TYPE="https://cyclonedx.org/bom" ;;
  spdx)       PRED_TYPE="https://spdx.dev/Document" ;;
  vuln)       PRED_TYPE="https://cosign.sigstore.dev/attestation/vuln/v1" ;;
  license)    PRED_TYPE="https://aleph-alpha.com/attestations/license/v1" ;;
  triage)     PRED_TYPE="https://aleph-alpha.com/attestations/triage/v1" ;;
  custom)     PRED_TYPE="https://cosign.sigstore.dev/attestation/v1" ;;
  "")         PRED_TYPE="" ;; # allowed in --list mode
  *) echo "❌ Unknown type: $TYPE"; exit 1 ;;
esac

# Resolve tag -> digest
DIGEST=$(crane digest "$IMAGE")
echo "ℹ️  Using image digest: $DIGEST"

if $LIST_ONLY; then
  echo "🔎 Available predicateTypes for this image:"
  if $SHOW_NULL; then
    oras discover "$IMAGE@$DIGEST" --format json \
      | jq -r '.referrers[].annotations["dev.sigstore.bundle.predicateType"]' \
      | sort | uniq -c | sed 's/^/  /'
  else
    oras discover "$IMAGE@$DIGEST" --format json \
      | jq -r '.referrers[].annotations["dev.sigstore.bundle.predicateType"] // empty' \
      | sed '/^$/d' \
      | sort | uniq -c | sed 's/^/  /'
  fi
  exit 0
fi

DIGESTS=()

REFERRERS=$(oras discover "$IMAGE@$DIGEST" --format json \
  | jq -r --arg pt "$PRED_TYPE" '
      .referrers[]
      | select(.artifactType=="application/vnd.dev.sigstore.bundle.v0.3+json")
      | select(.annotations["dev.sigstore.bundle.predicateType"]==$pt)
      | .digest')

for d in $REFERRERS; do
  echo "🔎 Checking candidate referrer digest=$d"
  layer_digest=$(oras manifest fetch "$IMAGE@$d" | jq -r '.layers[0].digest')
  bundle=$(mktemp)
  oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null
  raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d)
  inner=$(echo "$raw" | jq -r '.predicateType')
  echo "   ↳ inner predicateType=$inner"
  rm -f "$bundle"

  if [ "$inner" = "$PRED_TYPE" ]; then
    DIGESTS+=("$d")
  fi
done

if [ ${#DIGESTS[@]} -eq 0 ]; then
  echo "❌ No attestations found for type=$TYPE (predicateType=$PRED_TYPE)"
  echo "ℹ️  Available predicateTypes for this image:"
  if $SHOW_NULL; then
    oras discover "$IMAGE@$DIGEST" --format json \
      | jq -r '.referrers[].annotations["dev.sigstore.bundle.predicateType"]' \
      | sort | uniq -c | sed 's/^/  /'
  else
    oras discover "$IMAGE@$DIGEST" --format json \
      | jq -r '.referrers[].annotations["dev.sigstore.bundle.predicateType"] // empty' \
      | sed '/^$/d' \
      | sort | uniq -c | sed 's/^/  /'
  fi
  exit 1
fi

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
  oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null

  # decode predicate payload
  raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d)

  # If predicate.Data is JSON stringified, unstringify
  if echo "$raw" | jq -e '.predicate.Data' >/dev/null 2>&1; then
    data=$(echo "$raw" | jq -r '.predicate.Data')
    if echo "$data" | jq empty >/dev/null 2>&1; then
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
