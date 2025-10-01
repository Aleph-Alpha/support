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
  --verbose                             Show detailed verification output
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
  $0 --image registry.example.com/myapp:latest --verbose \\
    --output-signature signature.sig --output-certificate cert.pem
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
VERBOSE=false

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
    --verbose) VERBOSE=true; shift ;;
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

# Check if cosign is available
if ! command -v cosign >/dev/null 2>&1; then
  echo "❌ cosign command not found. Please install cosign."
  echo "   Installation: https://docs.sigstore.dev/cosign/installation/"
  exit 1
fi

# Resolve tag -> digest for consistent verification
echo "ℹ️  Resolving image reference..."
if command -v crane >/dev/null 2>&1; then
  if DIGEST=$(crane digest "$IMAGE" 2>/dev/null); then
    IMAGE_WITH_DIGEST="$IMAGE@$DIGEST"
    echo "ℹ️  Using image digest: $DIGEST"
  else
    IMAGE_WITH_DIGEST="$IMAGE"
    echo "⚠️  Failed to resolve digest, using tag reference (less secure)"
  fi
else
  IMAGE_WITH_DIGEST="$IMAGE"
  echo "⚠️  crane not found, using tag reference (less secure)"
fi

echo "🔐 Verifying image signature for: $IMAGE_WITH_DIGEST"

# Build cosign verify command arguments
COSIGN_ARGS=()

if $KEYLESS; then
  echo "   ↳ Mode: Keyless verification"
  echo "   ↳ OIDC Issuer: $CERTIFICATE_OIDC_ISSUER"

  COSIGN_ARGS+=("--certificate-oidc-issuer=$CERTIFICATE_OIDC_ISSUER")

  if [[ -n "$CERTIFICATE_IDENTITY" ]]; then
    echo "   ↳ Identity: $CERTIFICATE_IDENTITY"
    COSIGN_ARGS+=("--certificate-identity=$CERTIFICATE_IDENTITY")
  else
    echo "   ↳ Identity Regexp: $CERTIFICATE_IDENTITY_REGEXP"
    COSIGN_ARGS+=("--certificate-identity-regexp=$CERTIFICATE_IDENTITY_REGEXP")
  fi

  COSIGN_ARGS+=("--rekor-url=$REKOR_URL")
else
  echo "   ↳ Mode: Key-based verification"
  echo "   ↳ Public Key: $KEY_FILE"
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
echo ""
if $VERBOSE; then
  echo "🔍 Running: cosign verify ${COSIGN_ARGS[*]}"
  echo ""
fi

TEMP_OUTPUT=$(mktemp 2>/dev/null || mktemp -t cosign-verify)
if cosign verify "${COSIGN_ARGS[@]}" > "$TEMP_OUTPUT" 2>&1; then
  echo "✅ Image signature verification successful!"

  if $VERBOSE; then
    echo ""
    echo "📋 Verification Details:"
    cat "$TEMP_OUTPUT"
  fi

  # Show output file locations
  if [[ -n "$OUTPUT_SIGNATURE" ]]; then
    echo "💾 Signature saved to: $OUTPUT_SIGNATURE"
  fi

  if [[ -n "$OUTPUT_CERTIFICATE" ]]; then
    echo "💾 Certificate saved to: $OUTPUT_CERTIFICATE"
  fi

  echo ""
  echo "🛡️  Image is cryptographically signed and verified!"

else
  echo "❌ Image signature verification failed!"
  echo ""
  echo "📋 Error Details:"
  cat "$TEMP_OUTPUT"
  echo ""
  echo "💡 Possible reasons:"
  echo "   • Image is not signed"
  echo "   • Wrong verification parameters (OIDC issuer, identity, key)"
  echo "   • Signature was created with different signing method"
  echo "   • Network issues accessing transparency log"

  rm -f "$TEMP_OUTPUT"
  exit 1
fi

rm -f "$TEMP_OUTPUT"
