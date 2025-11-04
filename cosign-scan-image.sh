#!/bin/bash
set -e

# Cosign Image Scanner with Triage Support
# Scans a single container image with Trivy, applying cosign triage attestations to filter known vulnerabilities

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Show help
show_help() {
  cat <<EOF
Aleph Alpha - Single Image Scanner with Triage Support

This script scans a single container image by downloading its SBOM attestation
and scanning it with Trivy. It automatically applies cosign triage attestations
to filter out known and addressed vulnerabilities.

Usage:
  $0 --image IMAGE [OPTIONS]

Required:
  --image IMAGE                         Container image to scan (e.g., registry.io/org/image:tag)

Options:
  --output-dir DIR                      Output directory for reports (default: ./scan-results)
  --trivy-config FILE                   Custom Trivy configuration file (optional)
  --timeout TIMEOUT                     Timeout for individual operations in seconds (default: 300)
  --certificate-oidc-issuer ISSUER      OIDC issuer for cosign verification
  --certificate-identity-regexp REGEX   Identity regexp for cosign verification
  --verbose                             Enable verbose logging
  --dry-run                             Show what would be scanned without executing
  --format FORMAT                       Report format: table|json|sarif (default: table)
  --severity LEVEL                      Minimum severity level: LOW|MEDIUM|HIGH|CRITICAL (default: HIGH)
                                        Scans for this level and all higher severities
  --min-cve-level LEVEL                 Minimum CVE level to consider relevant: LOW|MEDIUM|HIGH|CRITICAL (default: HIGH)
  --no-triage                           Skip triage filtering and show all CVEs (ignore trivyignore)
  --show-cves                           Display detailed CVE list in output (default: true)
  --max-cves NUM                        Maximum number of CVEs to display in table (default: 20, 0 = all)
  --sbom-type TYPE                      SBOM type to extract: cyclonedx|spdx (default: cyclonedx)
  -h, --help                            Show this help

Examples:
  # Scan a specific image using its SBOM (default: HIGH and CRITICAL)
  $0 --image harbor.example.com/library/myapp:v1.0.0

  # Scan with MEDIUM severity and above (MEDIUM, HIGH, CRITICAL)
  $0 --image myregistry.io/app:latest --severity MEDIUM

  # Scan only CRITICAL vulnerabilities
  $0 --image myregistry.io/app:latest --severity CRITICAL

  # Scan with JSON output format
  $0 --image myimage:tag --format json --output-dir ./reports

  # Scan without triage filtering to see all CVEs
  $0 --image myimage:tag --no-triage

  # Show all CVEs (not just first 20)
  $0 --image myimage:tag --max-cves 0

  # Dry run to see what would be scanned
  $0 --image harbor.example.com/prod/api:1.2.3 --dry-run

Note:
  This scanner requires images to have SBOM attestations (CycloneDX or SPDX).
  It downloads the SBOM and scans it with Trivy instead of scanning the image directly.

Prerequisites:
  - trivy (for vulnerability scanning)
  - jq (for JSON processing)
  - cosign (for attestation verification)
  - docker (for registry accessibility checking)
  - crane (for image digest resolution)
  - cosign-extract.sh (for extracting triage attestations)
  - cosign-verify-image.sh (for verifying image signatures)

EOF
}

# Default configuration
IMAGE=""
OUTPUT_DIR="./scan-results"
TRIVY_CONFIG=""
TIMEOUT=300
CERTIFICATE_OIDC_ISSUER="https://token.actions.githubusercontent.com"
CERTIFICATE_IDENTITY_REGEXP="https://github.com/Aleph-Alpha/shared-workflows/.github/workflows/(build-and-push|scan-and-reattest).yaml@.*"
VERBOSE=false
DRY_RUN=false
FORMAT="table"
SEVERITY_LEVEL="HIGH"  # Minimum severity level (will be converted to list)
SEVERITY=""            # Actual severity list for Trivy (computed from SEVERITY_LEVEL)
MIN_CVE_LEVEL="HIGH"
NO_TRIAGE=false        # Skip triage filtering
SHOW_CVES=true         # Display CVE list in output
MAX_CVES=20            # Maximum CVEs to display (0 = all)
SBOM_TYPE="cyclonedx"  # SBOM type to extract (cyclonedx or spdx)

# Convert severity level to comma-separated list
# LOW includes: LOW, MEDIUM, HIGH, CRITICAL
# MEDIUM includes: MEDIUM, HIGH, CRITICAL
# HIGH includes: HIGH, CRITICAL
# CRITICAL includes: CRITICAL
convert_severity_level() {
    local level=$(echo "$1" | tr '[:lower:]' '[:upper:]')
    case "$level" in
        "CRITICAL")
            echo "CRITICAL"
            ;;
        "HIGH")
            echo "HIGH,CRITICAL"
            ;;
        "MEDIUM")
            echo "MEDIUM,HIGH,CRITICAL"
            ;;
        "LOW")
            echo "LOW,MEDIUM,HIGH,CRITICAL"
            ;;
        *)
            echo "HIGH,CRITICAL"  # Default fallback
            ;;
    esac
}

# Logging functions
log_verbose() {
    if $VERBOSE; then
        echo "[VERBOSE] $*" >&2
    fi
}

log_info() {
    echo "ℹ️  $*" >&2
}

log_step() {
    echo "📋 $*" >&2
}

log_result() {
    echo "   $*" >&2
}

log_warn() {
    echo "⚠️  $*" >&2
}

log_error() {
    echo "❌ $*" >&2
}

log_error_multiline() {
    local main_message="$1"
    shift
    echo "❌ $main_message" >&2
    for line in "$@"; do
        echo "   $line" >&2
    done
}

# Parse command line arguments
parse_args() {
    # Check for help first, regardless of position
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            show_help
            exit 0
        fi
    done

    while [[ $# -gt 0 ]]; do
        case $1 in
            --image)
                IMAGE="$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --trivy-config)
                TRIVY_CONFIG="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --certificate-oidc-issuer)
                CERTIFICATE_OIDC_ISSUER="$2"
                shift 2
                ;;
            --certificate-identity-regexp)
                CERTIFICATE_IDENTITY_REGEXP="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --format)
                FORMAT="$2"
                shift 2
                ;;
            --severity)
                SEVERITY_LEVEL="$2"
                shift 2
                ;;
            --min-cve-level)
                MIN_CVE_LEVEL="$2"
                shift 2
                ;;
            --no-triage)
                NO_TRIAGE=true
                shift
                ;;
            --show-cves)
                SHOW_CVES=true
                shift
                ;;
            --max-cves)
                MAX_CVES="$2"
                shift 2
                ;;
            --sbom-type)
                SBOM_TYPE="$2"
                shift 2
                ;;
            -h|--help)
                # Already handled above, but keep for consistency
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                show_help
                exit 1
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$IMAGE" ]]; then
        log_error "Missing required argument: --image"
        echo "" >&2
        show_help
        exit 1
    fi

    # Validate SBOM type
    case "$SBOM_TYPE" in
        cyclonedx|spdx) ;;
        *)
            log_error "Invalid SBOM type: $SBOM_TYPE. Must be: cyclonedx or spdx"
            exit 1
            ;;
    esac

    # Validate and normalize severity level (case-insensitive)
    SEVERITY_LEVEL=$(echo "$SEVERITY_LEVEL" | tr '[:lower:]' '[:upper:]')
    case "$SEVERITY_LEVEL" in
        LOW|MEDIUM|HIGH|CRITICAL) ;;
        *)
            log_error "Invalid severity level: $SEVERITY_LEVEL. Must be one of: LOW, MEDIUM, HIGH, CRITICAL"
            exit 1
            ;;
    esac

    # Convert severity level to comma-separated list
    SEVERITY=$(convert_severity_level "$SEVERITY_LEVEL")
    log_verbose "Severity level: $SEVERITY_LEVEL -> Trivy filter: $SEVERITY"
}

# Check prerequisites
check_prerequisites() {
    local missing_tools=()

    for tool in trivy jq cosign docker crane; do
        if ! command -v "$tool" &>/dev/null; then
            missing_tools+=("$tool")
        fi
    done

    # Check for required scripts
    local cosign_extract="$SCRIPT_DIR/cosign-extract.sh"
    local cosign_verify="$SCRIPT_DIR/cosign-verify-image.sh"

    if [[ ! -f "$cosign_extract" ]]; then
        log_error_multiline "Required script not found: cosign-extract.sh" \
            "Expected location: $cosign_extract"
        exit 1
    fi

    if [[ ! -f "$cosign_verify" ]]; then
        log_error_multiline "Required script not found: cosign-verify-image.sh" \
            "Expected location: $cosign_verify"
        exit 1
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
}

# Check if registry is accessible using docker
check_registry_accessible() {
    local image="$1"

    log_verbose "Checking registry accessibility for: $image"

    # Use docker manifest inspect which respects Docker's authentication
    if docker manifest inspect "$image" >/dev/null 2>&1; then
        log_verbose "Registry is accessible for: $image"
        return 0
    else
        log_error_multiline "Registry is not accessible for: $image" \
            "Please ensure you're logged in to the registry:" \
            "  docker login <registry>"
        return 1
    fi
}

# Run command with timeout
run_with_timeout() {
    local timeout_duration=$1
    shift

    if command -v timeout >/dev/null 2>&1; then
        # Linux/GNU timeout
        timeout "${timeout_seconds}s" "${cmd[@]}"
    elif command -v gtimeout >/dev/null 2>&1; then
        # macOS with GNU coreutils (brew install coreutils)
        gtimeout "${timeout_seconds}s" "${cmd[@]}"
    else
        # Fallback without timeout
        log_verbose "No timeout command available, running without timeout"
        "${cmd[@]}"
    fi
}

# Check if image is Cosign-signed and has SBOM/triage attestations
detect_attestation_type() {
    local image="$1"

    # Temporarily disable exit on error for this function
    set +e
    local verify_output
    local verify_exit_code

    log_verbose "Checking if image is Cosign-signed: $image"

    # Use the existing cosign-verify-image.sh script for verification
    local verify_script="$SCRIPT_DIR/cosign-verify-image.sh"
    if [[ ! -f "$verify_script" ]]; then
        log_error "cosign-verify-image.sh not found at: $verify_script"
        return 1
    fi

    # Run cosign verification using the dedicated script with timeout
    verify_output=$(run_with_timeout 60 "$verify_script" --image "$image" \
        --certificate-oidc-issuer "$CERTIFICATE_OIDC_ISSUER" \
        --certificate-identity-regexp "$CERTIFICATE_IDENTITY_REGEXP" \
        --output-level none 2>&1)
    verify_exit_code=$?

    # Log the results
    if [[ $verify_exit_code -eq 0 ]]; then
        log_verbose "cosign-verify-image.sh succeeded"
    else
        log_verbose "cosign-verify-image.sh failed with exit code: $verify_exit_code"
        log_verbose "cosign-verify-image.sh output: $verify_output"
    fi

    if [[ $verify_exit_code -eq 0 ]]; then
        log_verbose "Image is Cosign-signed, checking for SBOM and triage attestations"

        # Image is signed, check what attestations exist (using --list which is fast)
        local extract_output
        local extract_exit_code

        if extract_output=$("$SCRIPT_DIR/cosign-extract.sh" --image "$image" --list 2>&1); then
            extract_exit_code=0
        else
            extract_exit_code=$?
            log_verbose "cosign-extract.sh failed with exit code: $extract_exit_code"
            log_verbose "cosign-extract.sh output: $extract_output"
        fi

        if [[ $extract_exit_code -eq 0 ]]; then
            local has_sbom=false
            local has_triage=false

            # Check for SBOM (cyclonedx or spdx)
            if echo "$extract_output" | grep -qE "https://cyclonedx.org/bom|https://spdx.dev/Document"; then
                has_sbom=true
                log_verbose "Found SBOM attestation for $image"
            fi

            # Check for triage
            if echo "$extract_output" | grep -q "https://aleph-alpha.com/attestations/triage/v1"; then
                has_triage=true
                log_verbose "Found triage attestation for $image"
            fi

            # Return status based on what we found
            if [[ "$has_sbom" == "true" && "$has_triage" == "true" ]]; then
                echo "cosign-sbom-triage"
            elif [[ "$has_sbom" == "true" ]]; then
                echo "cosign-sbom"
            elif [[ "$has_triage" == "true" ]]; then
                echo "cosign-no-sbom"
            else
                echo "cosign-no-sbom"
            fi
        else
            log_verbose "Image is Cosign-signed but couldn't list attestations"
            echo "cosign-no-sbom"
        fi
    else
        log_verbose "Image is not Cosign-signed"
        echo "unsigned"
    fi

    # Re-enable exit on error
    set -e
}

# Download SBOM using cosign attestation
download_sbom() {
    local image="$1"
    local output_file="$2"

    log_verbose "Downloading SBOM attestation ($SBOM_TYPE) for: $image"

    # Use the existing cosign-extract.sh script
    local extract_script="$SCRIPT_DIR/cosign-extract.sh"
    log_verbose "Looking for cosign-extract.sh at: $extract_script"
    if [[ ! -f "$extract_script" ]]; then
        log_error_multiline "cosign-extract.sh not found at: $extract_script" \
            "Current working directory: $(pwd)" \
            "Script directory: $SCRIPT_DIR"
        return 1
    fi
    log_verbose "Found cosign-extract.sh script"

    # Extract SBOM attestation predicate (automatically select latest if multiple)
    # Use --predicate-only to extract just the SBOM content, not the attestation envelope
    if "$extract_script" --type "$SBOM_TYPE" --image "$image" --output "$output_file" --last --predicate-only >/dev/null 2>&1; then
        log_verbose "Successfully downloaded SBOM for: $image"

        # Verify the extracted SBOM is valid JSON
        if jq empty "$output_file" 2>/dev/null; then
            log_verbose "SBOM is valid JSON"
            return 0
        else
            log_error "Extracted SBOM is not valid JSON"
            if $VERBOSE; then
                log_verbose "SBOM content:"
                head -20 "$output_file" >&2
            fi
            rm -f "$output_file"
            return 1
        fi
    else
        log_verbose "Failed to download SBOM for: $image"
        return 1
    fi
}

# Download triage file using cosign attestation
download_cosign_triage() {
    local image="$1"
    local output_file="$2"

    log_verbose "Downloading cosign triage attestation for: $image"

    # Use the existing cosign-extract.sh script
    local extract_script="$SCRIPT_DIR/cosign-extract.sh"
    log_verbose "Looking for cosign-extract.sh at: $extract_script"
    if [[ ! -f "$extract_script" ]]; then
        log_error_multiline "cosign-extract.sh not found at: $extract_script" \
            "Current working directory: $(pwd)" \
            "Script directory: $SCRIPT_DIR"
        return 1
    fi
    log_verbose "Found cosign-extract.sh script"

    # Extract triage attestation (automatically select latest if multiple)
    # Note: We skip --verify here for performance since we already verified the image signature
    # in detect_attestation_type(). The image signature verification confirms the image is trusted.
    if "$extract_script" --type triage --image "$image" --output "$output_file" --last >/dev/null 2>&1; then

        log_verbose "Successfully downloaded cosign triage for: $image"
        return 0
    else
        log_verbose "Failed to download cosign triage for: $image"
        return 1
    fi
}

# Convert triage attestation to trivyignore format
convert_triage_to_trivyignore() {
    local triage_file="$1"
    local output_file="$2"

    log_verbose "Converting triage to trivyignore format"

    # Extract CVE IDs from triage attestation
    # Triage format: {"vulnerabilities": [{"id": "CVE-2021-1234", ...}, ...]}
    if ! jq -r '.vulnerabilities[]?.id // empty' "$triage_file" > "$output_file" 2>/dev/null; then
        log_verbose "No vulnerabilities found in triage file"
        return 1
    fi

    # Check if output file has content
    if [[ ! -s "$output_file" ]]; then
        log_verbose "No CVEs to ignore"
        return 1
    fi

    local cve_count=$(wc -l < "$output_file")
    log_verbose "Created trivyignore with $cve_count CVEs"
    return 0
}

# Run Trivy scan on SBOM file
run_trivy_scan() {
    local sbom_file="$1"
    local triage_file="$2"
    local output_file="$3"
    local scan_format="${4:-$FORMAT}"  # Use provided format or fall back to global $FORMAT

    log_verbose "Running Trivy scan on SBOM: $sbom_file"

    local trivy_args=(
        "sbom"
        "--format" "$scan_format"
        "--severity" "$SEVERITY"
        "--output" "$output_file"
    )

    # Add triage file if available (unless --no-triage is set)
    if [[ "$NO_TRIAGE" == "false" && -n "$triage_file" && -f "$triage_file" ]]; then
        # Convert triage attestation to Trivy ignore format
        local trivy_ignore_file="${triage_file%.json}.trivyignore"
        if convert_triage_to_trivyignore "$triage_file" "$trivy_ignore_file"; then
            trivy_args+=("--ignorefile" "$trivy_ignore_file")
            log_verbose "Using triage file: $trivy_ignore_file"
        else
            log_verbose "No CVEs to ignore in triage file, scanning all vulnerabilities"
        fi
    elif [[ "$NO_TRIAGE" == "true" ]]; then
        log_verbose "Skipping triage filtering (--no-triage flag set)"
    fi

    # Add custom config if specified
    if [[ -n "$TRIVY_CONFIG" && -f "$TRIVY_CONFIG" ]]; then
        trivy_args+=("--config" "$TRIVY_CONFIG")
    fi

    # Add timeout
    trivy_args+=("--timeout" "${TIMEOUT}s")

    # Add the SBOM file
    trivy_args+=("$sbom_file")

    # Run Trivy scan
    log_verbose "Running: trivy ${trivy_args[*]}"

    # Create a temporary file for stderr
    local stderr_file=$(mktemp)

    if trivy "${trivy_args[@]}" 2>"$stderr_file"; then
        log_verbose "Trivy SBOM scan completed"
        rm -f "$stderr_file"
        return 0
    else
        local exit_code=$?
        local error_details=()

        # Show error output for debugging
        if [[ -s "$stderr_file" ]]; then
            error_details+=("Trivy error output:")
            error_details+=("$(cat "$stderr_file")")
        fi

        # Additional debug info
        error_details+=("SBOM file: $sbom_file")
        if [[ -f "$sbom_file" ]]; then
            local file_size=$(stat -f%z "$sbom_file" 2>/dev/null || stat -c%s "$sbom_file" 2>/dev/null || echo "unknown")
            error_details+=("SBOM file exists, size: $file_size bytes")
            if $VERBOSE; then
                error_details+=("SBOM first few lines:")
                error_details+=("$(head -10 "$sbom_file")")
            fi
        else
            error_details+=("SBOM file does not exist!")
        fi

        log_error_multiline "Trivy SBOM scan failed (exit code: $exit_code)" "${error_details[@]}"

        rm -f "$stderr_file"
        return 1
    fi
}

# Analyze CVEs from scan results
analyze_cves() {
    local image="$1"
    local image_dir="$2"
    local triage_file="$3"

    log_verbose "Analyzing CVEs for: $image"

    # Always analyze from the JSON report (we always generate one)
    local trivy_report="$image_dir/trivy-report.json"

    if [[ ! -f "$trivy_report" ]]; then
        log_verbose "Trivy JSON report not found: $trivy_report"
        return 1
    fi

    # Count vulnerabilities by severity
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0

    # Extract CVE counts from Trivy JSON report
    if command -v jq &>/dev/null; then
        critical_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$trivy_report" 2>/dev/null || echo 0)
        high_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$trivy_report" 2>/dev/null || echo 0)
        medium_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM")] | length' "$trivy_report" 2>/dev/null || echo 0)
        low_count=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW")] | length' "$trivy_report" 2>/dev/null || echo 0)
    fi

    # Count triaged CVEs
    local triaged_count=0
    if [[ -n "$triage_file" && -f "$triage_file" ]]; then
        triaged_count=$(jq '.vulnerabilities | length' "$triage_file" 2>/dev/null || echo 0)
    fi

    # Save CVE details
    cat > "$image_dir/cve_details.json" <<EOF
{
  "image": "$image",
  "critical": $critical_count,
  "high": $high_count,
  "medium": $medium_count,
  "low": $low_count,
  "triaged": $triaged_count,
  "min_cve_level": "$MIN_CVE_LEVEL"
}
EOF

    log_verbose "CVE analysis saved to: $image_dir/cve_details.json"
}

# Scan the image
scan_image() {
    local image="$IMAGE"

    echo ""
    log_step "Starting SBOM-based scan"
    log_result "- Image: $image"
    log_result "- Method: Download SBOM and scan with Trivy"

    # Check registry accessibility
    log_verbose "Checking registry accessibility"
    if ! check_registry_accessible "$image"; then
        return 1
    fi
    log_result "- Registry: accessible"

    if $DRY_RUN; then
        echo ""
        log_info "[DRY RUN] Would scan image: $image"
        return 0
    fi

    # Create output directory
    local image_safe_name
    image_safe_name=$(echo "$image" | sed 's|[^A-Za-z0-9._-]|_|g')
    local image_dir="$OUTPUT_DIR/$image_safe_name"

    if ! mkdir -p "$image_dir"; then
        log_error "Failed to create directory: $image_dir"
        return 1
    fi

    log_verbose "Output directory: $image_dir"

    # Detect attestation type
    echo ""
    log_step "Verifying image signature"
    local attestation_type
    attestation_type=$(detect_attestation_type "$image")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to detect attestation type for: $image"
        return 1
    fi

    local sbom_file=""
    local sbom_downloaded=false
    local triage_file=""
    local triage_downloaded=false

    # Handle image based on signature status
    case "$attestation_type" in
        "cosign-sbom-triage")
            # Image is signed and has both SBOM and triage
            log_result "- Signature: ✅ verified"
            log_result "- SBOM attestation: found"
            log_result "- Triage attestation: found"

            # Download SBOM
            echo ""
            log_step "Downloading SBOM attestation"
            sbom_file="$image_dir/sbom.json"
            if download_sbom "$image" "$sbom_file"; then
                sbom_downloaded=true
                log_result "- SBOM downloaded: ✅"
            else
                log_error "Failed to download SBOM attestation"
                return 1
            fi

            # Only download triage if we're going to use it
            if [[ "$NO_TRIAGE" == "false" ]]; then
                echo ""
                log_step "Downloading triage attestation"
                triage_file="$image_dir/triage.json"
                if download_cosign_triage "$image" "$triage_file"; then
                    triage_downloaded=true
                    local triage_count=$(jq '.vulnerabilities | length' "$triage_file" 2>/dev/null || echo 0)
                    log_result "- CVEs triaged: $triage_count"
                else
                    log_warn "Failed to download triage attestation"
                    triage_file=""
                fi
            else
                log_result "- Triage download: skipped (--no-triage flag set)"
            fi
            ;;
        "cosign-sbom")
            # Image is signed and has SBOM but no triage
            log_result "- Signature: ✅ verified"
            log_result "- SBOM attestation: found"
            log_result "- Triage attestation: not found"

            # Download SBOM
            echo ""
            log_step "Downloading SBOM attestation"
            sbom_file="$image_dir/sbom.json"
            if download_sbom "$image" "$sbom_file"; then
                sbom_downloaded=true
                log_result "- SBOM downloaded: ✅"
            else
                log_error "Failed to download SBOM attestation"
                return 1
            fi
            ;;
        "cosign-no-sbom")
            # Image is signed but no SBOM
            log_result "- Signature: ✅ verified"
            log_result "- SBOM attestation: ❌ not found"
            log_error_multiline "Cannot scan image without SBOM attestation" \
                "This scanner requires an SBOM (CycloneDX or SPDX) to be attached to the image"
            return 1
            ;;
        "unsigned")
            # Image is not signed
            log_result "- Signature: ⚠️  not signed"
            log_error_multiline "Cannot scan unsigned image" \
                "This scanner requires a Cosign-signed image with SBOM attestation"
            return 1
            ;;
    esac

    # Verify we have an SBOM to scan
    if [[ ! -f "$sbom_file" ]]; then
        log_error "No SBOM file available for scanning"
        return 1
    fi

    # Run Trivy scan on SBOM
    echo ""
    log_step "Running vulnerability scan on SBOM"
    local scan_output="$image_dir/trivy-report.$FORMAT"

    # Always generate JSON for analysis (in addition to user's requested format)
    local json_output="$image_dir/trivy-report.json"
    if [[ "$FORMAT" != "json" ]]; then
        # Generate JSON first for analysis (explicitly pass "json" format)
        if ! run_trivy_scan "$sbom_file" "$triage_file" "$json_output" "json"; then
            log_error "Failed to generate JSON report for analysis"
            return 1
        fi
    fi

    # Generate the user's requested format
    if run_trivy_scan "$sbom_file" "$triage_file" "$scan_output" "$FORMAT"; then
        log_result "- Scan status: ✅ completed"
        log_result "- Report format: $FORMAT"
        log_result "- Severity filter: $SEVERITY_LEVEL and above"

        # Create metadata file
        cat > "$image_dir/metadata.json" <<EOF
{
  "image": "$image",
  "attestation_type": "$attestation_type",
  "sbom_downloaded": $sbom_downloaded,
  "sbom_type": "$SBOM_TYPE",
  "triage_downloaded": $triage_downloaded,
  "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")",
  "scan_format": "$FORMAT",
  "severity_filter": "$SEVERITY",
  "scan_method": "sbom"
}
EOF

        # Analyze CVEs for summary (uses the JSON report we generated)
        analyze_cves "$image" "$image_dir" "$triage_file"

        return 0
    else
        log_error "Scan failed for: $image"
        return 1
    fi
}

# Generate final summary table
generate_summary_table() {
    local image_dir="$1"
    local attestation_type="$2"

    {
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📊 SCAN SUMMARY"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        # Image info
        printf "%-20s %s\n" "Image:" "$IMAGE"
        printf "%-20s %s\n" "Scan Time:" "$(date '+%Y-%m-%d %H:%M:%S')"
        echo ""

        # Signature and attestation status
        case "$attestation_type" in
            "cosign-sbom-triage")
                printf "%-20s %s\n" "Signature:" "✅ Verified"
                printf "%-20s %s\n" "SBOM:" "✅ Downloaded"
                if [[ "$NO_TRIAGE" == "true" ]]; then
                    printf "%-20s %s\n" "Triage:" "⚠️  Skipped (--no-triage)"
                else
                    printf "%-20s %s\n" "Triage:" "✅ Applied"
                fi
                ;;
            "cosign-sbom")
                printf "%-20s %s\n" "Signature:" "✅ Verified"
                printf "%-20s %s\n" "SBOM:" "✅ Downloaded"
                printf "%-20s %s\n" "Triage:" "⚠️  Not available"
                ;;
            "cosign-no-sbom")
                printf "%-20s %s\n" "Signature:" "✅ Verified"
                printf "%-20s %s\n" "SBOM:" "❌ Not found"
                ;;
            "unsigned")
                printf "%-20s %s\n" "Signature:" "⚠️  Not signed"
                printf "%-20s %s\n" "SBOM:" "❌ N/A"
                ;;
        esac
        printf "%-20s %s\n" "Scan Method:" "SBOM-based"
        echo ""

        # CVE summary - only show filtered severities
        if [[ -f "$image_dir/cve_details.json" ]]; then
            local critical=$(jq -r '.critical' "$image_dir/cve_details.json")
            local high=$(jq -r '.high' "$image_dir/cve_details.json")
            local medium=$(jq -r '.medium' "$image_dir/cve_details.json")
            local low=$(jq -r '.low' "$image_dir/cve_details.json")
            local triaged=$(jq -r '.triaged' "$image_dir/cve_details.json")
            local total=$((critical + high + medium + low))

            echo "Vulnerabilities:"

            # Only show severity levels that match the filter
            if echo "$SEVERITY" | grep -qi "CRITICAL"; then
                printf "  🔴 Critical: %s\n" "$critical"
            fi

            if echo "$SEVERITY" | grep -qi "HIGH"; then
                printf "  🟠 High:     %s\n" "$high"
            fi

            if echo "$SEVERITY" | grep -qi "MEDIUM"; then
                printf "  🟡 Medium:   %s\n" "$medium"
            fi

            if echo "$SEVERITY" | grep -qi "LOW"; then
                printf "  🟢 Low:      %s\n" "$low"
            fi

            if [[ $triaged -gt 0 ]]; then
                printf "  📋 Triaged:  %s (filtered out)\n" "$triaged"
            fi

            # Show CVE details table if there are vulnerabilities and SHOW_CVES is true
            if [[ $total -gt 0 && "$SHOW_CVES" == "true" ]]; then
                echo ""
                echo "Details:"
                echo ""

                local json_report="$image_dir/trivy-report.json"
                if [[ -f "$json_report" ]]; then
                    # Create table data using column utility
                    local table_data="CVE ID|SEVERITY|PACKAGE|INSTALLED|FIXED|TITLE\n"

                    # Extract CVEs from JSON report and add to table data
                    local cve_data=$(jq -r '
                        [.Results[]?.Vulnerabilities[]? |
                        {
                            id: .VulnerabilityID,
                            severity: .Severity,
                            pkg: .PkgName,
                            installed: .InstalledVersion,
                            fixed: (.FixedVersion // "n/a"),
                            title: (.Title // .Description // "No description")[0:60]
                        }] |
                        sort_by(.severity) |
                        reverse |
                        .[] |
                        [.id, .severity, .pkg, .installed, .fixed, .title] |
                        @tsv
                    ' "$json_report" 2>/dev/null)

                    if [[ -n "$cve_data" ]]; then
                        # Process CVEs and add to table data
                        local count=0
                        while IFS=$'\t' read -r cve_id severity pkg installed fixed title; do
                            # Add severity emoji
                            local severity_display
                            case "$severity" in
                                CRITICAL) severity_display="🔴 CRIT" ;;
                                HIGH)     severity_display="🟠 HIGH" ;;
                                MEDIUM)   severity_display="🟡 MED" ;;
                                LOW)      severity_display="🟢 LOW" ;;
                                *)        severity_display="$severity" ;;
                            esac

                            # Truncate long fields
                            pkg=$(echo "$pkg" | cut -c1-20)
                            installed=$(echo "$installed" | cut -c1-15)
                            fixed=$(echo "$fixed" | cut -c1-15)
                            title=$(echo "$title" | cut -c1-30)

                            # Add row to table data
                            table_data+="$cve_id|$severity_display|$pkg|$installed|$fixed|$title\n"

                            ((count++))

                            # Check if we should limit the output
                            if [[ $MAX_CVES -gt 0 && $count -ge $MAX_CVES ]]; then
                                local remaining=$((total - count))
                                if [[ $remaining -gt 0 ]]; then
                                    table_data+="... and $remaining more (use --max-cves 0 to show all)|||||\n"
                                fi
                                break
                            fi
                        done <<< "$cve_data"

                        # Print table using column utility
                        echo -e "$table_data" | column -t -s '|'
                    fi
                fi
            fi
        fi

        echo ""
        echo "Output: $OUTPUT_DIR"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    } >&2
}

# Main function
main() {
    parse_args "$@"

    {
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔍 Aleph Alpha - Single Image Scanner"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
    } >&2

    log_step "Configuration"
    log_result "- Image: $IMAGE"
    log_result "- Output: $OUTPUT_DIR"
    log_result "- Format: $FORMAT"
    log_result "- Severity: $SEVERITY_LEVEL and above"
    if $NO_TRIAGE; then
        log_result "- Triage: ⚠️  DISABLED (--no-triage)"
    fi
    if $DRY_RUN; then
        log_result "- Mode: 🧪 DRY RUN"
    fi

    echo "" >&2
    log_step "Checking prerequisites"
    check_prerequisites
    log_result "- Tools: ✅ all available"

    # Create output directory
    if ! mkdir -p "$OUTPUT_DIR"; then
        log_error "Failed to create output directory: $OUTPUT_DIR"
        exit 1
    fi

    # Scan the image
    local scan_result=0
    local image_safe_name
    image_safe_name=$(echo "$IMAGE" | sed 's|[^A-Za-z0-9._-]|_|g')
    local image_dir="$OUTPUT_DIR/$image_safe_name"

    if scan_image; then
        scan_result=0

        # Read attestation type from metadata
        local attestation_type="unknown"
        if [[ -f "$image_dir/metadata.json" ]]; then
            attestation_type=$(jq -r '.attestation_type' "$image_dir/metadata.json")
        fi

        # Show final summary table
        if ! $DRY_RUN; then
            generate_summary_table "$image_dir" "$attestation_type"
        fi

        {
            echo ""
            echo "✅ Scan completed successfully"
            echo ""
        } >&2
    else
        scan_result=1
        {
            echo ""
            echo "❌ Scan failed"
            echo ""
        } >&2
    fi

    exit $scan_result
}

# Run main function
main "$@"
