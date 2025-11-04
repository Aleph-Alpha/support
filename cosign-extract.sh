#!/usr/bin/env bash
set -euo pipefail

# Check shell compatibility
if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "Warning: This script was designed for bash but is running in: ${0##*/}" >&2
    echo "Some features may not work correctly in zsh or other shells." >&2
    echo "For best results, run with: bash $0 $*" >&2
    echo "" >&2
fi

show_help() {
  cat <<EOF
Usage:
  $0 --type TYPE --image IMAGE[:TAG] [--choice index|all] [--output FILE] [--verify] [--no-extraction|--predicate-only]
  $0 --image IMAGE[:TAG] --choice all --output DIR      # extract ALL types
  $0 --image IMAGE[:TAG] --list [--show-null]
  $0 --image IMAGE[:TAG] --inspect-null
  $0 --type TYPE --image IMAGE[:TAG] --verify --no-extraction  # verify only, no extraction
  $0 --type TYPE --image IMAGE[:TAG] --output FILE --predicate-only  # extract only predicate content

Options:
  --type TYPE                         Attestation type (slsa|cyclonedx|spdx|vuln|license|triage|custom)
  --image IMAGE                       Fully qualified image reference (required)
  --choice                            Which attestation to fetch: index, all
  --last                              Automatically select the most recent attestation if multiple exist
  --output PATH                       Output file (single type) or directory (all types)
  --list                              List available predicateTypes and counts
  --show-null                         Show entries missing predicateType in --list
  --inspect-null                      Inspect referrers missing predicateType
  --verify                            Verify attestations using cosign before extraction
  --no-extraction                     Skip extraction and content output (useful with --verify for verification-only)
  --predicate-only                    Extract only the predicate content, not the full attestation envelope (mutually exclusive with --no-extraction)
  --certificate-oidc-issuer ISSUER    OIDC issuer for verification (default: https://token.actions.githubusercontent.com)
  --certificate-identity-regexp REGEX Identity regexp for verification (default: Aleph Alpha workflows)
  -h, --help                          Show this help

Verification:
  When --verify is used, attestations are verified using cosign verify-attestation before extraction.
  Default verification uses GitHub Actions OIDC issuer and Aleph Alpha workflow identity patterns.
EOF
}

TYPE=""
IMAGE=""
CHOICE=""
OUTPUT_FILE=""
LIST_ONLY=false
SHOW_NULL=false
INSPECT_NULL=false
VERIFY=false
NO_EXTRACTION=false
PREDICATE_ONLY=false
USE_LAST=false
CERTIFICATE_OIDC_ISSUER="https://token.actions.githubusercontent.com"
CERTIFICATE_IDENTITY_REGEXP="https://github.com/Aleph-Alpha/shared-workflows/.github/workflows/(build-and-push|scan-and-reattest).yaml@.*"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type) TYPE="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --choice) CHOICE="$2"; shift 2 ;;
    --last) USE_LAST=true; shift ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    --list) LIST_ONLY=true; shift ;;
    --show-null) SHOW_NULL=true; shift ;;
    --inspect-null) INSPECT_NULL=true; shift ;;
    --verify) VERIFY=true; shift ;;
    --no-extraction) NO_EXTRACTION=true; shift ;;
    --predicate-only) PREDICATE_ONLY=true; shift ;;
    --certificate-oidc-issuer) CERTIFICATE_OIDC_ISSUER="$2"; shift 2 ;;
    --certificate-identity-regexp) CERTIFICATE_IDENTITY_REGEXP="$2"; shift 2 ;;
    -h|--help) show_help; exit 0 ;;
    *) echo "❌ Unknown option: $1"; show_help; exit 1 ;;
  esac
done

# Validate mutually exclusive options
if $PREDICATE_ONLY && $NO_EXTRACTION; then
  echo "❌ Conflicting options: --predicate-only and --no-extraction cannot be used together"
  echo "   --predicate-only extracts only the predicate content"
  echo "   --no-extraction skips all content extraction"
  exit 1
fi

if [[ -z "$IMAGE" ]]; then
  echo "❌ Missing required --image"
  show_help
  exit 1
fi

# Validate option combinations
if $NO_EXTRACTION && [ -n "$OUTPUT_FILE" ]; then
  echo "❌ --no-extraction and --output cannot be used together"
  exit 1
fi

if $NO_EXTRACTION && "$LIST_ONLY"; then
  echo "❌ --no-extraction and --list cannot be used together"
  exit 1
fi

if $NO_EXTRACTION && "$INSPECT_NULL"; then
  echo "❌ --no-extraction and --inspect-null cannot be used together"
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

# Verify attestation using cosign
verify_attestation() {
  local pred_type="$1"
  local image="$2"

  if ! $VERIFY; then
    return 0
  fi

  echo "🔐 Verifying attestation with cosign..."
  echo "   ↳ Type: $pred_type"
  echo "   ↳ OIDC Issuer: $CERTIFICATE_OIDC_ISSUER"
  echo "   ↳ Identity Regexp: $CERTIFICATE_IDENTITY_REGEXP"

  # Check if cosign is available
  if ! command -v cosign >/dev/null 2>&1; then
    echo "❌ cosign command not found. Please install cosign to use --verify option."
    echo "   Installation: https://docs.sigstore.dev/cosign/installation/"
    exit 1
  fi

  # Perform verification
  local temp_output
  temp_output=$(mktemp 2>/dev/null || mktemp -t cosign-extract)

  if cosign verify-attestation \
    --type "$pred_type" \
    --new-bundle-format \
    --certificate-oidc-issuer="$CERTIFICATE_OIDC_ISSUER" \
    --certificate-identity-regexp="$CERTIFICATE_IDENTITY_REGEXP" \
    "$image" > "$temp_output" 2>&1; then
    echo "✅ Attestation verification successful"
    rm -f "$temp_output"
    return 0
  else
    echo "❌ Attestation verification failed:"
    cat "$temp_output"
    rm -f "$temp_output"
    return 1
  fi
}

# Show helpful info about authentication
echo "ℹ️  Note: If you encounter authentication errors, ensure you're logged in to the registry:"
echo "   docker login <registry>"
echo ""

# Resolve tag -> digest
if command -v crane >/dev/null 2>&1; then
  if DIGEST=$(crane digest "$IMAGE" 2>/dev/null); then
    echo "ℹ️  Using image digest: $DIGEST"
  else
    echo "❌ Failed to resolve image digest with crane"
    exit 1
  fi
else
  echo "❌ crane command not found. Please install crane to resolve image digests."
  echo "   Installation: https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md"
  exit 1
fi

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
    bundle=$(mktemp 2>/dev/null || mktemp -t cosign-extract)
    oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null

    if jq -e '.dsseEnvelope.payload' "$bundle" >/dev/null 2>&1; then
      raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d 2>/dev/null || jq -r '.dsseEnvelope.payload' "$bundle" | base64 -D)
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

  # If verification is requested, collect all predicate types first
  if $VERIFY; then
    echo "🔐 Collecting predicate types for verification..."
    PRED_TYPES=()
    for d in $REFERRERS; do
      layer_digest=$(oras manifest fetch "$IMAGE@$d" | jq -r '.layers[0].digest')
      bundle=$(mktemp 2>/dev/null || mktemp -t cosign-extract)
      oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null
      raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d 2>/dev/null || jq -r '.dsseEnvelope.payload' "$bundle" | base64 -D)
      ptype=$(echo "$raw" | jq -r '.predicateType')
      rm -f "$bundle"

      # Add to array if not already present
      if [[ ! " ${PRED_TYPES[@]} " =~ " ${ptype} " ]]; then
        PRED_TYPES+=("$ptype")
      fi
    done

    # Verify each unique predicate type
    for ptype in "${PRED_TYPES[@]}"; do
      verify_attestation "$ptype" "$IMAGE@$DIGEST"
      if [ $? -ne 0 ]; then
        echo "❌ Verification failed for type $ptype, aborting extraction"
        exit 1
      fi
    done

    # If we only need verification and no extraction, we're done
    if $NO_EXTRACTION; then
      echo "✅ Verification complete. All ${#PRED_TYPES[@]} attestation types are valid."
      exit 0
    fi
  fi

  idx=1
  for d in $REFERRERS; do
    layer_digest=$(oras manifest fetch "$IMAGE@$d" | jq -r '.layers[0].digest')
    bundle=$(mktemp 2>/dev/null || mktemp -t cosign-extract)
    oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null
    raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d 2>/dev/null || jq -r '.dsseEnvelope.payload' "$bundle" | base64 -D)

    ptype=$(echo "$raw" | jq -r '.predicateType')
    base=$(pretty_name "$ptype")

    if $NO_EXTRACTION; then
      echo "✅ Attestation $idx ($ptype) found and verified (content extraction skipped)"
    else
      file="$OUTPUT_FILE/${base}-${idx}.json"
      echo "$raw" | jq . > "$file"
      echo "💾 Attestation $idx ($ptype) written to $file"
    fi

    rm -f "$bundle"
    idx=$((idx+1))
  done
  exit 0
fi

# Otherwise: extract a specific type
# First verify the attestation if requested
if $VERIFY; then
  verify_attestation "$PRED_TYPE" "$IMAGE@$DIGEST"
  if [ $? -ne 0 ]; then
    echo "❌ Verification failed, aborting extraction"
    exit 1
  fi

  # If we only need verification and no extraction, we're done
  if $NO_EXTRACTION; then
    echo "✅ Verification complete. Attestation exists and is valid."
    exit 0
  fi
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
  bundle=$(mktemp 2>/dev/null || mktemp -t cosign-extract)
  oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null
  raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d 2>/dev/null || jq -r '.dsseEnvelope.payload' "$bundle" | base64 -D)
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
  bundle=$(mktemp 2>/dev/null || mktemp -t cosign-extract)

  # fetch manifest → get blob digest
  layer_digest=$(oras manifest fetch "$IMAGE@$ref_digest" | jq -r '.layers[0].digest')
  oras blob fetch "$IMAGE@$layer_digest" --output "$bundle" >/dev/null

  raw=$(jq -r '.dsseEnvelope.payload' "$bundle" | base64 -d 2>/dev/null || jq -r '.dsseEnvelope.payload' "$bundle" | base64 -D)

  # Skip extraction if --no-extraction is used
  if $NO_EXTRACTION; then
    echo "✅ Attestation found and verified (content extraction skipped)"
    rm -f "$bundle"
    return 0
  fi

  local output=""

  # If --predicate-only is set, extract only the predicate content
  if $PREDICATE_ONLY; then
    output=$(echo "$raw" | jq '.predicate')
  # Otherwise, handle special cases and return full attestation
  elif echo "$raw" | jq -e '.predicate.Data' >/dev/null 2>&1; then
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
      if $USE_LAST; then
        # Automatically select the last (most recent) attestation
        CHOICE=${#DIGESTS[@]}
        echo "ℹ️  Automatically selecting most recent attestation [$CHOICE/${#DIGESTS[@]}]"
      else
        echo -n "Select attestation [1-${#DIGESTS[@]}]: "
        read -r CHOICE
      fi
    fi
    INDEX=$((CHOICE-1))
    if [ $INDEX -lt 0 ] || [ $INDEX -ge ${#DIGESTS[@]} ]; then
      echo "❌ Invalid choice. Pick 1..${#DIGESTS[@]} or 'all'."
      exit 1
    fi
    fetch_attestation "${DIGESTS[$INDEX]}"
  fi
fi
