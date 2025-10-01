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
  $0 --image IMAGE[:TAG] [--verify-options]
  $0 --image IMAGE[:TAG] --certificate-oidc-issuer ISSUER --certificate-identity-regexp REGEX
  $0 --image IMAGE[:TAG] --key KEY_FILE
  $0 --image IMAGE[:TAG] --keyless

Options:
  --image IMAGE                         Fully qualified image reference (required)
  --certificate-oidc-issuer ISSUER      OIDC issuer for keyless verification (default: https://token.actions.githubusercontent.com)
  --certificate-identity-regexp REGEX   Identity regexp for keyless verification (default: Aleph Alpha workflows)
  --certificate-identity IDENTITY       Exact certificate identity for keyless verification
  --key KEY_FILE                        Path to public key file for key-based verification
  --keyless                             Use keyless verification (default mode)
  --rekor-url URL                       Rekor transparency log URL (default: https://rekor.sigstore.dev)
  --output-signature FILE               Save signature to file
  --output-certificate FILE             Save certificate to file
  --output-level LEVEL                  Output verbosity: none, info (default), verbose
  --no-error                            Return exit code 0 even on verification failure
  -h, --help                            Show this help

Verification Modes:
  1. Keyless (default): Verify using OIDC identity and transparency log
  2. Key-based: Verify using a provided public key file
  3. Custom keyless: Verify with custom OIDC issuer and identity patterns

Examples:
  # Verify with default Aleph Alpha settings (keyless)
  $0 --image registry.example.com/myapp:latest

  # Verify with custom GitHub organization
  $0 --image registry.example.com/myapp:latest \\
    --certificate-identity-regexp "https://github.com/myorg/.*/.github/workflows/.*"

  # Verify with specific identity
  $0 --image registry.example.com/myapp:latest \\
    --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/build.yaml@refs/heads/main"

  # Verify with public key
  $0 --image registry.example.com/myapp:latest --key cosign.pub

  # Verbose output with signature extraction
  $0 --image registry.example.com/myapp:latest --output-level verbose \\
    --output-signature signature.sig --output-certificate cert.pem

  # Silent mode for automation (only exit code)
  $0 --image registry.example.com/myapp:latest --output-level none

  # Check if image is signed without failing (useful for discovery)
  $0 --image registry.example.com/myapp:latest --output-level none --no-error
EOF
}

IMAGE=""
CERTIFICATE_OIDC_ISSUER="https://token.actions.githubusercontent.com"
CERTIFICATE_IDENTITY_REGEXP="https://github.com/Aleph-Alpha/shared-workflows/.github/workflows/build-and-push.yaml@.*"
CERTIFICATE_IDENTITY=""
KEY_FILE=""
KEYLESS=true
REKOR_URL="https://rekor.sigstore.dev"
OUTPUT_SIGNATURE=""
OUTPUT_CERTIFICATE=""
OUTPUT_LEVEL="info"
NO_ERROR=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --certificate-oidc-issuer) CERTIFICATE_OIDC_ISSUER="$2"; shift 2 ;;
    --certificate-identity-regexp) CERTIFICATE_IDENTITY_REGEXP="$2"; shift 2 ;;
    --certificate-identity) CERTIFICATE_IDENTITY="$2"; shift 2 ;;
    --key) KEY_FILE="$2"; KEYLESS=false; shift 2 ;;
    --keyless) KEYLESS=true; shift ;;
    --rekor-url) REKOR_URL="$2"; shift 2 ;;
    --output-signature) OUTPUT_SIGNATURE="$2"; shift 2 ;;
    --output-certificate) OUTPUT_CERTIFICATE="$2"; shift 2 ;;
    --output-level) OUTPUT_LEVEL="$2"; shift 2 ;;
    --no-error) NO_ERROR=true; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) echo "❌ Unknown option: $1"; show_help; exit 1 ;;
  esac
done

if [[ -z "$IMAGE" ]]; then
  echo "❌ Missing required --image"
  show_help
  exit 1
fi

# Validate option combinations
if [[ -n "$KEY_FILE" && "$KEYLESS" == "true" ]]; then
  echo "❌ Cannot use both --key and --keyless options"
  exit 1
fi

if [[ -n "$KEY_FILE" && ! -f "$KEY_FILE" ]]; then
  echo "❌ Key file not found: $KEY_FILE"
  exit 1
fi

if [[ -n "$CERTIFICATE_IDENTITY" && -n "$CERTIFICATE_IDENTITY_REGEXP" ]]; then
  echo "❌ Cannot use both --certificate-identity and --certificate-identity-regexp"
  exit 1
fi

# Validate output level
case "$OUTPUT_LEVEL" in
  none|info|verbose) ;;
  *) echo "❌ Invalid output level: $OUTPUT_LEVEL (must be: none, info, verbose)"
     exit 1 ;;
esac

# Output functions for different verbosity levels
output() {
  case "$OUTPUT_LEVEL" in
    none) ;;
    info|verbose) echo "$@" ;;
  esac
}

output_verbose() {
  case "$OUTPUT_LEVEL" in
    none|info) ;;
    verbose) echo "$@" ;;
  esac
}

# Check if cosign is available
if ! command -v cosign >/dev/null 2>&1; then
  echo "❌ cosign command not found. Please install cosign."
  echo "   Installation: https://docs.sigstore.dev/cosign/installation/"
  exit 1
fi

# Show helpful info about authentication
output "ℹ️  Note: If you encounter authentication errors, ensure you're logged in to the registry:"
output "   docker login <registry>"
output ""

# Resolve tag -> digest for consistent verification
output "ℹ️  Resolving image reference..."
if command -v crane >/dev/null 2>&1; then
  if [[ "$OUTPUT_LEVEL" == "none" ]]; then
    # In silent mode, suppress crane stderr
    DIGEST=$(crane digest "$IMAGE" 2>/dev/null)
  else
    # In info/verbose mode, show crane errors
    DIGEST=$(crane digest "$IMAGE")
  fi

  if [[ -n "$DIGEST" ]]; then
    IMAGE_WITH_DIGEST="$IMAGE@$DIGEST"
    output "ℹ️  Using image digest: $DIGEST"
  else
    # If crane failed to get digest, fall back to tag reference
    IMAGE_WITH_DIGEST="$IMAGE"
    output "⚠️  Failed to resolve digest, using tag reference (less secure)"
  fi
else
  IMAGE_WITH_DIGEST="$IMAGE"
  output "⚠️  crane not found, using tag reference (less secure)"
fi

output "🔐 Verifying image signature for: $IMAGE_WITH_DIGEST"

# Build cosign verify command arguments
COSIGN_ARGS=()

if $KEYLESS; then
  output "   ↳ Mode: Keyless verification"
  output "   ↳ OIDC Issuer: $CERTIFICATE_OIDC_ISSUER"

  COSIGN_ARGS+=("--certificate-oidc-issuer=$CERTIFICATE_OIDC_ISSUER")

  if [[ -n "$CERTIFICATE_IDENTITY" ]]; then
    output "   ↳ Identity: $CERTIFICATE_IDENTITY"
    COSIGN_ARGS+=("--certificate-identity=$CERTIFICATE_IDENTITY")
  else
    output "   ↳ Identity Regexp: $CERTIFICATE_IDENTITY_REGEXP"
    COSIGN_ARGS+=("--certificate-identity-regexp=$CERTIFICATE_IDENTITY_REGEXP")
  fi

  COSIGN_ARGS+=("--rekor-url=$REKOR_URL")
else
  output "   ↳ Mode: Key-based verification"
  output "   ↳ Public Key: $KEY_FILE"
  COSIGN_ARGS+=("--key=$KEY_FILE")
fi

# Add output options
if [[ -n "$OUTPUT_SIGNATURE" ]]; then
  COSIGN_ARGS+=("--output-signature=$OUTPUT_SIGNATURE")
fi

if [[ -n "$OUTPUT_CERTIFICATE" ]]; then
  COSIGN_ARGS+=("--output-certificate=$OUTPUT_CERTIFICATE")
fi

# Add the image reference
COSIGN_ARGS+=("$IMAGE_WITH_DIGEST")

# Execute verification
output ""
output_verbose "🔍 Running: cosign verify ${COSIGN_ARGS[*]}"
output_verbose ""

TEMP_OUTPUT=$(mktemp)
if [[ "$OUTPUT_LEVEL" == "none" ]]; then
  # In silent mode, suppress all output including stderr
  if cosign verify "${COSIGN_ARGS[@]}" > "$TEMP_OUTPUT" 2>/dev/null; then
    VERIFY_SUCCESS=true
  else
    VERIFY_SUCCESS=false
  fi
else
  # In info/verbose mode, capture both stdout and stderr
  if cosign verify "${COSIGN_ARGS[@]}" > "$TEMP_OUTPUT" 2>&1; then
    VERIFY_SUCCESS=true
  else
    VERIFY_SUCCESS=false
  fi
fi

if $VERIFY_SUCCESS; then
  output "✅ Image signature verification successful!"

  output_verbose ""
  output_verbose "📋 Verification Details:"
  if [[ "$OUTPUT_LEVEL" == "verbose" ]]; then
    cat "$TEMP_OUTPUT"
  fi

  # Show output file locations
  if [[ -n "$OUTPUT_SIGNATURE" ]]; then
    output "💾 Signature saved to: $OUTPUT_SIGNATURE"
  fi

  if [[ -n "$OUTPUT_CERTIFICATE" ]]; then
    output "💾 Certificate saved to: $OUTPUT_CERTIFICATE"
  fi

  output ""
  output "🛡️  Image is cryptographically signed and verified!"

else
  # Only show error details if not in silent mode
  if [[ "$OUTPUT_LEVEL" != "none" ]]; then
    output "❌ Image signature verification failed!"
    output ""

    # Extract clean error message from cosign output
    ERROR_MSG=$(grep -E "^Error:|^error during command execution:" "$TEMP_OUTPUT" | head -1 | sed 's/^Error: //' | sed 's/^error during command execution: //')
    if [[ -z "$ERROR_MSG" ]]; then
      ERROR_MSG=$(head -1 "$TEMP_OUTPUT")
    fi

    output "📋 Error Details: $ERROR_MSG"
    output ""
    output "💡 Possible reasons:"
    output "   • Image is not signed"
    output "   • Wrong verification parameters (OIDC issuer, identity, key)"
    output "   • Signature was created with different signing method"
    output "   • Network issues accessing transparency log"
  fi

  rm -f "$TEMP_OUTPUT"
  if $NO_ERROR; then
    exit 0
  else
    exit 1
  fi
fi

rm -f "$TEMP_OUTPUT"
