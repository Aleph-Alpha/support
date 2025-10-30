#!/usr/bin/env bash
set -euo pipefail

# Check shell compatibility
if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "Warning: This script was designed for bash but is running in: ${0##*/}" >&2
    echo "Some features may not work correctly in zsh or other shells." >&2
    echo "For best results, run with: bash $0 $*" >&2
    echo "" >&2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
  cat <<EOF
Chainguard Base Image Checker

This script verifies if a Docker image was built using a Chainguard base image
by checking signatures. It can be used as a standalone script or called from
other scripts.

Usage:
  $0 --image IMAGE [OPTIONS]

Required:
  --image IMAGE                         Docker image to inspect (can be local or remote)

Options:
  --chainguard-org ORG                  Chainguard organization name for production images (leave empty for starter images)
  --chainctl-token TOKEN                Chainguard chainctl token for production image verification
  --chainctl-identity ID                Chainguard identity ID for production image verification (alternative to token)
  --fail-on-mismatch                    Whether to fail if base image doesn't match pattern (default: true)
  --output-level LEVEL                  Output verbosity: none, info (default), verbose
  --no-error                            Return exit code 0 even on verification failure
  -h, --help                            Show this help

Verification Modes:
  1. Starter images: Uses GitHub Actions OIDC issuer (default)
  2. Production images: Uses Chainguard organization with chainctl authentication

Examples:
  # Check if image is based on Chainguard starter image
  $0 --image registry.example.com/myapp:latest

  # Check production image with organization
  $0 --image registry.example.com/myapp:latest --chainguard-org myorg --chainctl-token \$TOKEN

  # Check with identity instead of token
  $0 --image registry.example.com/myapp:latest --chainguard-org myorg --chainctl-identity \$IDENTITY

  # Silent mode for automation (only exit code)
  $0 --image registry.example.com/myapp:latest --output-level none

  # Check without failing on mismatch (useful for discovery)
  $0 --image registry.example.com/myapp:latest --no-error

Prerequisites:
  - docker (for local image inspection)
  - crane (for remote image inspection)
  - cosign (for signature verification)
  - jq (for JSON processing)
  - chainctl (for production image verification, if using --chainguard-org)

EOF
}

# Default configuration
IMAGE=""
CHAINGUARD_ORG=""
CHAINCTL_TOKEN=""
CHAINCTL_IDENTITY=""
FAIL_ON_MISMATCH=true
OUTPUT_LEVEL="info"
NO_ERROR=false

# Global variables for results
IS_CHAINGUARD=false
BASE_IMAGE=""
SIGNATURE_VERIFIED=false

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --image)
                IMAGE="$2"
                shift 2
                ;;
            --chainguard-org)
                CHAINGUARD_ORG="$2"
                shift 2
                ;;
            --chainctl-token)
                CHAINCTL_TOKEN="$2"
                shift 2
                ;;
            --chainctl-identity)
                CHAINCTL_IDENTITY="$2"
                shift 2
                ;;
            --fail-on-mismatch)
                FAIL_ON_MISMATCH=true
                shift
                ;;
            --no-fail-on-mismatch)
                FAIL_ON_MISMATCH=false
                shift
                ;;
            --output-level)
                OUTPUT_LEVEL="$2"
                shift 2
                ;;
            --no-error)
                NO_ERROR=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "❌ Unknown option: $1" >&2
                show_help
                exit 1
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$IMAGE" ]]; then
        echo "❌ Missing required argument: --image" >&2
        show_help
        exit 1
    fi

    # Validate that if chainguard-org is set, either token or identity is provided
    if [[ -n "$CHAINGUARD_ORG" ]]; then
        if [[ -z "$CHAINCTL_TOKEN" && -z "$CHAINCTL_IDENTITY" ]]; then
            echo "❌ Error: Either chainctl-token or chainctl-identity is required when chainguard-org is set" >&2
            exit 1
        fi
    fi

    # Validate output level
    case "$OUTPUT_LEVEL" in
        none|info|verbose) ;;
        *) echo "❌ Invalid output level: $OUTPUT_LEVEL (must be: none, info, verbose)" >&2
           exit 1 ;;
    esac
}

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

# Check prerequisites
check_prerequisites() {
    local missing_tools=()

    for tool in docker crane cosign jq; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    # Only check for chainctl if using production images (when org is provided)
    if [[ -n "$CHAINGUARD_ORG" ]]; then
        if ! command -v chainctl >/dev/null 2>&1; then
            missing_tools+=("chainctl")
        fi
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo "❌ Missing required tools: ${missing_tools[*]}" >&2
        echo "   Please install the missing tools and try again." >&2
        exit 1
    fi
}

# Function to extract base image from Docker inspect output
extract_base_from_docker_inspect() {
    local config_json="$1"

    # Try OCI standard labels first
    local base_name=$(echo "$config_json" | jq -r '.[0].Config.Labels["org.opencontainers.image.base.name"] // empty')
    if [[ -n "$base_name" && "$base_name" != "null" ]]; then
        echo "$base_name"
        return 0
    fi

    # Try base digest label
    local base_digest=$(echo "$config_json" | jq -r '.[0].Config.Labels["org.opencontainers.image.base.digest"] // empty')
    if [[ -n "$base_digest" && "$base_digest" != "null" ]]; then
        echo "$base_digest"
        return 0
    fi

    # Parse history for FROM statements
    local from_layer=$(echo "$config_json" | jq -r '.[0].History[]? | select(.created_by | contains("FROM")) | .created_by' | head -1)
    if [[ -n "$from_layer" && "$from_layer" != "null" ]]; then
        # Extract image name from FROM statement
        local base_img=$(echo "$from_layer" | sed -n 's/.*FROM[[:space:]]\+\([^[:space:]]*\).*/\1/p')
        if [[ -n "$base_img" ]]; then
            echo "$base_img"
            return 0
        fi
    fi

    # Fallback: check if there's a parent image
    local parent=$(echo "$config_json" | jq -r '.[0].Parent // empty')
    if [[ -n "$parent" && "$parent" != "null" ]]; then
        echo "$parent"
        return 0
    fi

    return 1
}

# Function to extract base image from crane config output
extract_base_from_crane_config() {
    local config_json="$1"

    # Try OCI standard labels first
    local base_name=$(echo "$config_json" | jq -r '.config.Labels["org.opencontainers.image.base.name"] // empty')
    if [[ -n "$base_name" && "$base_name" != "null" ]]; then
        echo "$base_name"
        return 0
    fi

    # Try base digest label
    local base_digest=$(echo "$config_json" | jq -r '.config.Labels["org.opencontainers.image.base.digest"] // empty')
    if [[ -n "$base_digest" && "$base_digest" != "null" ]]; then
        echo "$base_digest"
        return 0
    fi

    # Parse history for FROM statements
    local from_layer=$(echo "$config_json" | jq -r '.history[]? | select(.created_by | contains("FROM")) | .created_by' | head -1)
    if [[ -n "$from_layer" && "$from_layer" != "null" ]]; then
        # Extract image name from FROM statement
        local base_img=$(echo "$from_layer" | sed -n 's/.*FROM[[:space:]]\+\([^[:space:]]*\).*/\1/p')
        if [[ -n "$base_img" ]]; then
            echo "$base_img"
            return 0
        fi
    fi

    return 1
}

# Function to run command with timeout
run_with_timeout() {
    local timeout_seconds="$1"
    shift
    local cmd=("$@")

    if command -v timeout >/dev/null 2>&1; then
        # Linux/GNU timeout
        timeout "${timeout_seconds}s" "${cmd[@]}"
    elif command -v gtimeout >/dev/null 2>&1; then
        # macOS with GNU coreutils (brew install coreutils)
        gtimeout "${timeout_seconds}s" "${cmd[@]}"
    else
        # Fallback without timeout
        output_verbose "No timeout command available, running without timeout"
        "${cmd[@]}"
    fi
}

# Function to verify Chainguard signature
verify_chainguard_signature() {
    local image="$1"
    local org="$2"

    output_verbose "Verifying Chainguard signature for: $image"

    if [[ -n "$org" ]]; then
        # Production image verification
        output_verbose "Checking production image signature..."

        # Get service bindings from chainctl
        output_verbose "Getting service bindings for organization: $org"
        local catalog_syncer
        local apko_builder

        # Use timeout for chainctl commands
        if ! catalog_syncer=$(run_with_timeout 30 chainctl iam account-associations describe "$org" -o json 2>/dev/null | jq -r '.[].chainguard.service_bindings.CATALOG_SYNCER // empty'); then
            output_verbose "Error: Failed to get CATALOG_SYNCER for organization: $org"
            return 1
        fi

        if ! apko_builder=$(run_with_timeout 30 chainctl iam account-associations describe "$org" -o json 2>/dev/null | jq -r '.[].chainguard.service_bindings.APKO_BUILDER // empty'); then
            output_verbose "Error: Failed to get APKO_BUILDER for organization: $org"
            return 1
        fi

        if [[ -z "$catalog_syncer" || -z "$apko_builder" ]]; then
            output_verbose "Error: Could not retrieve service bindings for organization: $org"
            return 1
        fi

        output_verbose "Using service bindings - CATALOG_SYNCER: $catalog_syncer, APKO_BUILDER: $apko_builder"

        if run_with_timeout 60 cosign verify "$image" \
            --certificate-oidc-issuer=https://issuer.enforce.dev \
            --certificate-identity-regexp="https://issuer.enforce.dev/(${catalog_syncer}|${apko_builder})" \
            >/dev/null 2>&1; then
            output_verbose "✅ Production Chainguard signature verified"
            return 0
        fi
    else
        # Starter image verification - no authentication needed, just use public verification
        output_verbose "Checking starter image signature..."
        if run_with_timeout 60 cosign verify "$image" \
            --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
            --certificate-identity=https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main \
            >/dev/null 2>&1; then
            output_verbose "✅ Starter Chainguard signature verified"
            return 0
        fi
    fi

    output_verbose "❌ Chainguard signature verification failed"
    return 1
}

# Main function to check base image
check_base_image() {
    local image="$1"
    local chainguard_org="$2"
    local fail_on_mismatch="$3"

    output "Checking if base image is signed by Chainguard: $image"

    # First, try to extract base image information
    local base_image_found=false

    # Check if image exists locally first
    if docker image inspect "$image" >/dev/null 2>&1; then
        output_verbose "Image found locally, using docker inspect"
        local config_json
        if config_json=$(run_with_timeout 30 docker image inspect "$image" 2>/dev/null); then
            local extracted
            extracted=$(extract_base_from_docker_inspect "$config_json" || true)
            if [[ -n "$extracted" ]]; then
                BASE_IMAGE="$extracted"
                base_image_found=true
            fi
        else
            output_verbose "Failed to inspect local image with docker"
        fi
    else
        output_verbose "Image not found locally, using crane to fetch from remote"
        local config_json
        if config_json=$(run_with_timeout 60 crane config "$image" 2>/dev/null); then
            local extracted
            extracted=$(extract_base_from_crane_config "$config_json" || true)
            if [[ -n "$extracted" ]]; then
                BASE_IMAGE="$extracted"
                base_image_found=true
            fi
        else
            output_verbose "Failed to fetch image config with crane"
        fi
    fi

    if [[ "$base_image_found" == "true" ]]; then
        output "Detected base image: $BASE_IMAGE"

        # Verify Chainguard signature on the base image
        if verify_chainguard_signature "$BASE_IMAGE" "$chainguard_org"; then
            output "✅ Base image is signed by Chainguard"
            IS_CHAINGUARD=true
            SIGNATURE_VERIFIED=true
        else
            IS_CHAINGUARD=false
            SIGNATURE_VERIFIED=false

            if [[ "$fail_on_mismatch" == "true" ]]; then
                echo "Error: Base image '$BASE_IMAGE' is not signed by Chainguard" >&2
                return 1
            fi
        fi
    else
        output "Error: Could not determine base image from image metadata"
        IS_CHAINGUARD=false
        BASE_IMAGE="unknown"
        SIGNATURE_VERIFIED=false

        if [[ "$fail_on_mismatch" == "true" ]]; then
            return 1
        fi
    fi

    return 0
}

# Function to output results in a format suitable for other scripts
output_results() {
    # Only show detailed results if there's an error or in verbose mode
    if [[ "$OUTPUT_LEVEL" != "none" && ("$IS_CHAINGUARD" == "false" || "$OUTPUT_LEVEL" == "verbose") ]]; then
        echo ""
        echo "📋 Results:"
        echo "   Base Image: $BASE_IMAGE"
        echo "   Is Chainguard: $IS_CHAINGUARD"
        echo "   Signature Verified: $SIGNATURE_VERIFIED"
    fi

    # Output results in a format that can be sourced by other scripts
    # Only show these variables when output level is "none" (for automation)
    if [[ "$OUTPUT_LEVEL" == "none" ]]; then
        echo "IS_CHAINGUARD=$IS_CHAINGUARD"
        echo "BASE_IMAGE=\"$BASE_IMAGE\""
        echo "SIGNATURE_VERIFIED=$SIGNATURE_VERIFIED"
    fi
}

# Main execution
main() {
    # Parse arguments
    parse_args "$@"

    # Show configuration
    if [[ "$OUTPUT_LEVEL" != "none" ]]; then
        echo "🔍 Chainguard Base Image Checker"
        echo ""
        echo "⚙️  Configuration:"
        echo "   Image: $IMAGE"
        if [[ -n "$CHAINGUARD_ORG" ]]; then
            echo "   Chainguard Org: $CHAINGUARD_ORG"
            echo "   Mode: Production"
        else
            echo "   Mode: Starter"
        fi
        echo "   Fail on Mismatch: $FAIL_ON_MISMATCH"
        echo ""
    fi

    # Check prerequisites
    check_prerequisites

    # Check base image
    if check_base_image "$IMAGE" "$CHAINGUARD_ORG" "$FAIL_ON_MISMATCH"; then
        output_results
        if [[ "$NO_ERROR" == "true" ]]; then
            exit 0
        else
            exit 0
        fi
    else
        local exit_code=$?
        if [[ "$NO_ERROR" == "true" ]]; then
            # Don't reset BASE_IMAGE here - it was already set in check_base_image
            output_results
            exit 0
        else
            exit $exit_code
        fi
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being executed directly
    main "$@"
else
    # Script is being sourced, provide functions for other scripts to use
    # This allows other scripts to call the functions directly
    :
fi
