#!/usr/bin/env bash
set -euo pipefail

show_help() {
  cat <<EOF
Usage:
  $0 --type TYPE --image IMAGE[:TAG] [--choice index|all] [--output FILE]
  $0 --image IMAGE[:TAG] --choice all --output DIR      # extract ALL types
  $0 --image IMAGE[:TAG] --list [--show-null]
  $0 --image IMAGE[:TAG] --inspect-null

Options:
  --type TYPE     Attestation type (slsa|cyclonedx|spdx|vuln|license|triage|custom)
  --image IMAGE   Fully qualified image reference (required)
  --choice        Which attestation to fetch: index, all
  --output PATH   Output file (single type) or directory (all types)
  --list          List available predicateTypes and counts
  --show-null     Show entries missing predicateType in --list
  --inspect-null  Inspect referrers missing predicateType
  -h, --help      Show this help
EOF
}

TYPE=""
IMAGE=""
CHOICE=""
OUTPUT_FILE=""
LIST_ONLY=false
SHOW_NULL=false
INSPECT_NULL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type) TYPE="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --choice) CHOICE="$2"; shift 2 ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    --list) LIST_ONLY=true; shift ;;
    --show-null) SHOW_NULL=true; shift ;;
    --inspect-null) INSPECT_NULL=true; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) echo "❌ Unknown option: $1"; show_help; exit 1 ;;
  esac
done

if [[ -z "$IMAGE" ]]; then
  echo "❌ Missing required --image"
  show_help
  exit 1
fi

# Map type → predicateType
case "$TYPE" in
  slsa)       PRED_TYPE="https://slsa.dev/provenance/v1" ;;
  cyclonedx)  PRED_TYPE="https://cyclonedx.org/bom" ;;
  spdx)       PRED_TYPE="https://spdx.dev/Document" ;;
  vuln)       PRED_TYPE="https://cosign.sigstore.dev/attestation/vuln/v1" ;;
  license)    PRED_TYPE="https://aleph-alpha.com/attestations/license/v1" ;;
  triage)     PRED_TYPE="https://aleph-alpha.com/attestations/triage/v1" ;;
  custom)     PRED_TYPE="https://cosign.sigstore.dev/attestation/v1" ;;
  "")         PRED_TYPE="" ;; # allowed in --list/--inspect-null/all-types
  *) echo "❌ Unknown type: $TYPE"; exit 1 ;;
esac

if [[ -z "$TYPE" && "$CHOICE" != "all" && "$LIST_ONLY" == "false" && "$INSPECT_NULL" == "false" ]]; then
  echo "❌ Missing required --type (or use --choice all without --type to dump everything)"
  show_help
  exit 1
fi

# Map predicateType → nice filename
pretty_name() {
  case "$1" in
    "https://slsa.dev/provenance/v1") echo "slsa" ;;
    "https://cyclonedx.org/bom") echo "cyclonedx" ;;
    "https://spdx.dev/Document") echo "spdx" ;;
    "https://cosign.sigstore.dev/attestation/vuln/v1") echo "vuln" ;;
    "https://aleph-alpha.com/attestations/license/v1") echo "license" ;;
    "https://aleph-alpha.com/attestations/triage/v1") echo "triage" ;;
    *) echo "$(echo "$1" | sed 's|https\?://||; s|[^A-Za-z0-9._-]|_|g')" ;;
  esac
}

# Resolve tag -> digest
DIGEST=$(crane digest "$IMAGE")
echo "ℹ️  Using image digest: $DIGEST"

# --list mode
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

# --inspect-null mode
if $INSPECT_NULL; then
  echo "🔎 Inspecting referrers with missing predicateType..."
  NULL_REFS=$(oras discover "$IMAGE@$DIGEST" --format json \
    | jq -r '.referrers[] | select(.annotations["dev.sigstore.bundle.predicateType"]==null) | .digest')

  if [ -z "$NULL_REFS" ]; then
    echo "✅ No null predicateType referrers found."
    exit 0
  fi

  for d in $NULL_REFS; do
    echo "----- Referrer $d -----"
    layer_digest=$(oras manifest fetch "$IMAGE@$d" | jq -r '.layers[0].digest')
    bundle=$(mktemp)
    oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null

    if jq -e '.dsseEnvelope.payload' "$bundle" >/dev/null 2>&1; then
      raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d)
      echo "Inner predicateType: $(echo "$raw" | jq -r '.predicateType')"
      echo "Predicate (truncated):"
      echo "$raw" | jq '.predicate' | head -20
    else
      echo "⚠️ Not an attestation bundle (likely signature/raw blob)"
      jq . "$bundle" | head -20
    fi
    rm -f "$bundle"
  done
  exit 0
fi

# Special case: extract ALL types
if [[ -z "$TYPE" && "$CHOICE" == "all" ]]; then
  if [ -z "$OUTPUT_FILE" ]; then
    echo "❌ When extracting all types, you must provide --output <directory>"
    exit 1
  fi
  if [[ "$OUTPUT_FILE" =~ \.json$ ]]; then
    echo "❌ --output must be a directory in all-types mode (got something ending with .json: $OUTPUT_FILE)"
    exit 1
  fi
  if [ -e "$OUTPUT_FILE" ] && [ ! -d "$OUTPUT_FILE" ]; then
    echo "❌ --output must be a directory (got a file: $OUTPUT_FILE)"
    exit 1
  fi
  mkdir -p "$OUTPUT_FILE"

  echo "🔎 Extracting all attestations for $IMAGE@$DIGEST ..."
  REFERRERS=$(oras discover "$IMAGE@$DIGEST" --format json \
    | jq -r '.referrers[] | select(.artifactType=="application/vnd.dev.sigstore.bundle.v0.3+json") | .digest')

  idx=1
  for d in $REFERRERS; do
    layer_digest=$(oras manifest fetch "$IMAGE@$d" | jq -r '.layers[0].digest')
    bundle=$(mktemp)
    oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null
    raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d)

    ptype=$(echo "$raw" | jq -r '.predicateType')
    base=$(pretty_name "$ptype")

    file="$OUTPUT_FILE/${base}-${idx}.json"
    echo "$raw" | jq . > "$file"
    echo "💾 Attestation $idx ($ptype) written to $file"

    rm -f "$bundle"
    idx=$((idx+1))
  done
  exit 0
fi

# Otherwise: extract a specific type
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
  oras discover "$IMAGE@$DIGEST" --format json \
    | jq -r '.referrers[].annotations["dev.sigstore.bundle.predicateType"] // empty' \
    | sed '/^$/d' \
    | sort | uniq -c | sed 's/^/  /'
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
  local index="${2:-}"
  local bundle
  bundle=$(mktemp)

  # fetch manifest → get blob digest
  layer_digest=$(oras manifest fetch "$IMAGE@$ref_digest" | jq -r '.layers[0].digest')
  oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null

  raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d)

  local output=""
  if echo "$raw" | jq -e '.predicate.Data' >/dev/null 2>&1; then
    data=$(echo "$raw" | jq -r '.predicate.Data')
    if echo "$data" | jq empty >/dev/null 2>&1; then
      output=$(echo "$raw" | jq --argjson parsed "$data" '.predicate.Data=$parsed')
    else
      output=$(echo "$raw" | jq .)
    fi
  else
    output=$(echo "$raw" | jq .)
  fi

  if [ -n "$OUTPUT_FILE" ]; then
    if [ -n "$index" ]; then
      file="${OUTPUT_FILE%.json}-$index.json"
      echo "$output" > "$file"
      echo "💾 Attestation $index written to $file"
    else
      echo "$output" > "$OUTPUT_FILE"
      echo "💾 Attestation written to $OUTPUT_FILE"
    fi
  else
    echo "$output"
  fi

  rm -f "$bundle"
}

# Decide what to extract
if [ "$CHOICE" == "all" ]; then
  idx=1
  for d in "${DIGESTS[@]}"; do
    echo "----- Attestation $d -----"
    fetch_attestation "$d" "$idx"
    echo ""
    idx=$((idx+1))
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
