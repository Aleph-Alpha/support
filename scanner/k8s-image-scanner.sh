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
Aleph Alpha - Signed Image Scanner (SBOM-based)

This script connects to Kubernetes, extracts Aleph Alpha signed images from a namespace,
downloads SBOM attestations, downloads cosign triage attestations, and runs Trivy
vulnerability scans on the SBOM with triage filtering applied to focus on unaddressed
security issues.

Usage:
  $0 [OPTIONS]

Options:
  --namespace NAMESPACE                 Kubernetes namespace to scan (default: pharia-ai)
  --ignore-file FILE                    File containing images to ignore (one per line)
  --output-dir DIR                      Output directory for reports (default: ./scan-results)
  --kubeconfig FILE                     Path to kubeconfig file (optional)
  --context CONTEXT                     Kubernetes context to use (optional)
  --trivy-config FILE                   Custom Trivy configuration file (optional)
  --parallel-scans NUM                  Number of parallel scans (default: 3)
  --timeout TIMEOUT                     Timeout for individual operations in seconds (default: 300)
  --certificate-oidc-issuer ISSUER      OIDC issuer for cosign verification
  --certificate-identity-regexp REGEX   Identity regexp for cosign verification
  --verbose                             Enable verbose logging
  --dry-run                             Show what would be scanned without executing
  --format FORMAT                       Report format: table|json|sarif (default: table)
  --severity SEVERITIES                 Comma-separated list of severities to include (default: LOW,MEDIUM,HIGH,CRITICAL)
  --min-cve-level LEVEL                 Minimum CVE level to consider relevant: LOW|MEDIUM|HIGH|CRITICAL (default: HIGH)
  --cache-dir DIR                       Cache directory (default: ~/.cache/k8s-image-scanner)
  --cache-ttl HOURS                     Cache TTL in hours (default: 24)
  --no-cache                            Disable caching entirely
  --clear-cache                         Clear cache before running
  --cache-stats                         Show cache statistics and exit
  --test-flow                           Only scan the first valid image (for testing)
  -h, --help                            Show this help

Examples:
  # Scan default namespace with default settings
  $0

  # Scan specific namespace with ignore file
  $0 --namespace production --ignore-file ./ignore-images.txt

  # Scan with custom output directory and parallel scans
  $0 --namespace staging --output-dir ./security-reports --parallel-scans 5

  # Dry run to see what would be scanned
  $0 --namespace production --dry-run

  # Scan with custom Trivy configuration
  $0 --trivy-config ./trivy.yaml --format json

Prerequisites:
  - kubectl (configured with access to target cluster)
  - trivy (for vulnerability scanning of SBOMs)
  - jq (for JSON processing)
  - cosign (for attestation verification)
  - podman (for registry accessibility checking)
  - cosign-extract.sh (for extracting SBOM and triage attestations)
  - cosign-verify-image.sh (for verifying image signatures)

EOF
}

# Default configuration
NAMESPACE="pharia-ai"
IGNORE_FILE=""
OUTPUT_DIR="./scan-results"
KUBECONFIG=""
CONTEXT=""
TRIVY_CONFIG=""
PARALLEL_SCANS=3
TIMEOUT=300
CERTIFICATE_OIDC_ISSUER="https://token.actions.githubusercontent.com"
CERTIFICATE_IDENTITY_REGEXP="https://github.com/Aleph-Alpha/shared-workflows/.github/workflows/(build-and-push|scan-and-reattest).yaml@.*"
VERBOSE=false
DRY_RUN=false
FORMAT="table"
SEVERITY="LOW,MEDIUM,HIGH,CRITICAL"
MIN_CVE_LEVEL="HIGH"  # Minimum CVE level to consider relevant (LOW, MEDIUM, HIGH, CRITICAL)
CACHE_DIR="${HOME}/.cache/k8s-image-scanner"
CACHE_TTL_HOURS=24
NO_CACHE=false
CLEAR_CACHE=false
CACHE_STATS=false
TEST_FLOW=false

# Global variables
TEMP_DIR=""
IGNORE_LIST=()
SCANNED_IMAGES=()
FAILED_SCANS=()
SUCCESSFUL_SCANS=()
TOTAL_IMAGES=0
SKIPPED_IMAGES=0
IGNORED_IMAGES=0
INACCESSIBLE_IMAGES=0
INACCESSIBLE_REGISTRIES=()  # Track registries that are not accessible
# CVE_ANALYSIS_RESULTS will be stored as files in temp directory

# Logging functions
log_info() {
    echo "$*" >&2
}

log_step() {
    echo "📋 $*" >&2
}

log_result() {
    echo "   - $*" >&2
}

log_warn() {
    echo "⚠️ $*" >&2
}

log_error() {
    echo "❌ $*" >&2
}

log_success() {
    echo "✅ $*" >&2
}

log_verbose() {
    if $VERBOSE; then
        echo "🔍 $*" >&2
    fi
}

# Cache functions
# Get image digest for cache key
get_image_digest() {
    local image="$1"
    local digest=""

    # Try to get digest using crane (preferred)
    if command -v crane >/dev/null 2>&1; then
        digest=$(crane digest "$image" 2>/dev/null || echo "")
    fi

    # Fallback to podman if crane not available
    if [[ -z "$digest" ]] && command -v podman >/dev/null 2>&1; then
        digest=$(podman inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null | cut -d'@' -f2 || echo "")
    fi

    echo "$digest"
}

# Get cache key (digest or sanitized image reference)
get_cache_key() {
    local image="$1"
    local digest
    digest=$(get_image_digest "$image")

    if [[ -n "$digest" ]]; then
        # Use digest as cache key (remove sha256: prefix for directory name)
        echo "${digest#sha256:}"
    else
        # Fallback to sanitized image reference
        echo "$image" | sed 's|[^A-Za-z0-9._-]|_|g' | sed 's|__*|_|g'
    fi
}

# Get cache directory for an image
get_cache_dir() {
    local image="$1"
    local cache_key
    cache_key=$(get_cache_key "$image")
    echo "$CACHE_DIR/$cache_key"
}

# Check if cache is enabled
is_cache_enabled() {
    if $NO_CACHE; then
        return 1
    fi
    return 0
}

# Check if cache file is valid (exists and within TTL)
is_cache_valid() {
    local cache_file="$1"
    local ttl_hours="${2:-$CACHE_TTL_HOURS}"

    if ! is_cache_enabled; then
        return 1
    fi

    if [[ ! -f "$cache_file" ]]; then
        return 1
    fi

    # Check file age
    local file_age_seconds
    local ttl_seconds=$((ttl_hours * 3600))

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS
        file_age_seconds=$(($(date +%s) - $(stat -f %m "$cache_file" 2>/dev/null || echo 0)))
    else
        # Linux
        file_age_seconds=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
    fi

    if [[ $file_age_seconds -lt $ttl_seconds ]]; then
        return 0  # Valid
    else
        log_verbose "Cache expired: $cache_file (age: ${file_age_seconds}s, TTL: ${ttl_seconds}s)"
        return 1  # Expired
    fi
}

# Get cached attestation type
get_cached_attestation_type() {
    local image="$1"
    local cache_dir
    local cache_file

    if ! is_cache_enabled; then
        return 1
    fi

    cache_dir=$(get_cache_dir "$image")
    cache_file="$cache_dir/attestation-type.json"

    if is_cache_valid "$cache_file"; then
        local cached_type
        cached_type=$(jq -r '.attestation_type' "$cache_file" 2>/dev/null || echo "")
        if [[ -n "$cached_type" && "$cached_type" != "null" ]]; then
            echo "$cached_type"
            log_verbose "Cache hit: attestation type for $image"
            return 0
        fi
    fi

    return 1
}

# Cache attestation type
cache_attestation_type() {
    local image="$1"
    local attestation_type="$2"
    local cache_dir
    local cache_file

    if ! is_cache_enabled; then
        return 0
    fi

    cache_dir=$(get_cache_dir "$image")
    mkdir -p "$cache_dir"
    cache_file="$cache_dir/attestation-type.json"

    local digest
    digest=$(get_image_digest "$image")

    cat > "$cache_file" <<EOF
{
  "cached_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")",
  "cache_version": "1.0",
  "image": "$image",
  "image_digest": "${digest:-}",
  "attestation_type": "$attestation_type",
  "ttl_hours": $CACHE_TTL_HOURS
}
EOF
    log_verbose "Cached attestation type for $image: $attestation_type"
}

# Get cached SBOM file
get_cached_sbom() {
    local image="$1"
    local sbom_type="${2:-cyclonedx}"
    local cache_dir
    local cache_file

    if ! is_cache_enabled; then
        return 1
    fi

    cache_dir=$(get_cache_dir "$image")
    cache_file="$cache_dir/sbom-${sbom_type}.json"

    if is_cache_valid "$cache_file"; then
        echo "$cache_file"
        log_verbose "Cache hit: SBOM ($sbom_type) for $image"
        return 0
    fi

    return 1
}

# Cache SBOM file
cache_sbom() {
    local image="$1"
    local sbom_file="$2"
    local sbom_type="${3:-cyclonedx}"
    local cache_dir
    local cache_file

    if ! is_cache_enabled || [[ ! -f "$sbom_file" ]]; then
        return 0
    fi

    cache_dir=$(get_cache_dir "$image")
    mkdir -p "$cache_dir"
    cache_file="$cache_dir/sbom-${sbom_type}.json"

    cp "$sbom_file" "$cache_file"
    log_verbose "Cached SBOM ($sbom_type) for $image"
}

# Get cached triage file
get_cached_triage() {
    local image="$1"
    local cache_dir
    local cache_file

    if ! is_cache_enabled; then
        return 1
    fi

    cache_dir=$(get_cache_dir "$image")
    cache_file="$cache_dir/triage.json"

    if is_cache_valid "$cache_file"; then
        echo "$cache_file"
        log_verbose "Cache hit: triage for $image"
        return 0
    fi

    return 1
}

# Cache triage file
cache_triage() {
    local image="$1"
    local triage_file="$2"
    local cache_dir
    local cache_file

    if ! is_cache_enabled || [[ ! -f "$triage_file" ]]; then
        return 0
    fi

    cache_dir=$(get_cache_dir "$image")
    mkdir -p "$cache_dir"
    cache_file="$cache_dir/triage.json"

    cp "$triage_file" "$cache_file"
    log_verbose "Cached triage for $image"
}

# Clear cache
clear_cache() {
    if [[ -d "$CACHE_DIR" ]]; then
        log_result "Clearing cache directory: $CACHE_DIR"
        rm -rf "$CACHE_DIR"
        mkdir -p "$CACHE_DIR"
        log_success "Cache cleared"
    fi
}

# Initialize cache
init_cache() {
    if $CLEAR_CACHE; then
        clear_cache
    fi

    if is_cache_enabled; then
        mkdir -p "$CACHE_DIR"
        log_verbose "Cache directory: $CACHE_DIR (TTL: ${CACHE_TTL_HOURS}h)"
    else
        log_verbose "Caching disabled"
    fi
}

# Cache statistics functions
# Calculate directory size in bytes
get_dir_size() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS
            du -sk "$dir" 2>/dev/null | awk '{print $1 * 1024}' || echo "0"
        else
            # Linux
            du -sb "$dir" 2>/dev/null | awk '{print $1}' || echo "0"
        fi
    else
        echo "0"
    fi
}

# Format bytes to human readable
format_bytes() {
    local bytes="$1"
    if [[ $bytes -ge 1073741824 ]]; then
        awk "BEGIN {printf \"%.2f GB\", $bytes / 1073741824}"
    elif [[ $bytes -ge 1048576 ]]; then
        awk "BEGIN {printf \"%.2f MB\", $bytes / 1048576}"
    elif [[ $bytes -ge 1024 ]]; then
        awk "BEGIN {printf \"%.2f KB\", $bytes / 1024}"
    else
        printf "%d B" "$bytes"
    fi
}

# Get cache age in hours
get_cache_age_hours() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "0"
        return
    fi

    local file_age_seconds
    if [[ "$(uname)" == "Darwin" ]]; then
        file_age_seconds=$(($(date +%s) - $(stat -f %m "$file" 2>/dev/null || echo 0)))
    else
        file_age_seconds=$(($(date +%s) - $(stat -c %Y "$file" 2>/dev/null || echo 0)))
    fi

    awk "BEGIN {printf \"%.1f\", $file_age_seconds / 3600}"
}

# Show cache statistics
show_cache_stats() {
    echo "📊 Cache Statistics"
    echo "==================="
    echo ""

    if [[ ! -d "$CACHE_DIR" ]]; then
        echo "Cache directory does not exist: $CACHE_DIR"
        echo "No cache statistics available."
        return 0
    fi

    # Cache directory info
    echo "Cache Configuration:"
    echo "  Directory: $CACHE_DIR"
    echo "  TTL: ${CACHE_TTL_HOURS} hours"
    echo ""

    # Count cached items
    local total_images=0
    local attestation_types=0
    local sbom_cyclonedx=0
    local sbom_spdx=0
    local triage_files=0
    local expired_items=0
    local valid_items=0

    # Calculate cache size
    local cache_size_bytes
    cache_size_bytes=$(get_dir_size "$CACHE_DIR")
    local cache_size_formatted
    cache_size_formatted=$(format_bytes "$cache_size_bytes")

    # Count items by type
    if [[ -d "$CACHE_DIR" ]]; then
        for cache_entry in "$CACHE_DIR"/*; do
            if [[ -d "$cache_entry" ]]; then
                ((total_images++))

                # Check attestation type
                if [[ -f "$cache_entry/attestation-type.json" ]]; then
                    if is_cache_valid "$cache_entry/attestation-type.json"; then
                        ((attestation_types++))
                        ((valid_items++))
                    else
                        ((expired_items++))
                    fi
                fi

                # Check SBOM files
                if [[ -f "$cache_entry/sbom-cyclonedx.json" ]]; then
                    if is_cache_valid "$cache_entry/sbom-cyclonedx.json"; then
                        ((sbom_cyclonedx++))
                        ((valid_items++))
                    else
                        ((expired_items++))
                    fi
                fi

                if [[ -f "$cache_entry/sbom-spdx.json" ]]; then
                    if is_cache_valid "$cache_entry/sbom-spdx.json"; then
                        ((sbom_spdx++))
                        ((valid_items++))
                    else
                        ((expired_items++))
                    fi
                fi

                # Check triage files
                if [[ -f "$cache_entry/triage.json" ]]; then
                    if is_cache_valid "$cache_entry/triage.json"; then
                        ((triage_files++))
                        ((valid_items++))
                    else
                        ((expired_items++))
                    fi
                fi
            fi
        done
    fi

    echo "Cache Size:"
    echo "  Total: $cache_size_formatted"
    echo "  Cached images: $total_images"
    echo ""

    echo "Cached Items:"
    echo "  Attestation types: $attestation_types"
    echo "  SBOM (CycloneDX): $sbom_cyclonedx"
    echo "  SBOM (SPDX): $sbom_spdx"
    echo "  Triage files: $triage_files"
    echo "  Total cached items: $valid_items"
    if [[ $expired_items -gt 0 ]]; then
        echo "  Expired items: $expired_items"
    fi
    echo ""

    # Show age distribution
    if [[ $total_images -gt 0 ]]; then
        local age_lt1h=0
        local age_1_12h=0
        local age_12_24h=0
        local age_expired=0

        for cache_entry in "$CACHE_DIR"/*; do
            if [[ -d "$cache_entry" ]]; then
                local oldest_age=0
                for cache_file in "$cache_entry"/*.json; do
                    if [[ -f "$cache_file" ]]; then
                        local age
                        age=$(get_cache_age_hours "$cache_file")
                        if awk "BEGIN {exit !($age > $oldest_age)}"; then
                            oldest_age=$age
                        fi
                    fi
                done

                if awk "BEGIN {exit !($oldest_age < 1)}"; then
                    ((age_lt1h++))
                elif awk "BEGIN {exit !($oldest_age < 12)}"; then
                    ((age_1_12h++))
                elif awk "BEGIN {exit !($oldest_age < $CACHE_TTL_HOURS)}"; then
                    ((age_12_24h++))
                else
                    ((age_expired++))
                fi
            fi
        done

        echo "Cache Age Distribution:"
        echo "  < 1 hour: $age_lt1h images"
        echo "  1-12 hours: $age_1_12h images"
        echo "  12-${CACHE_TTL_HOURS} hours: $age_12_24h images"
        if [[ $age_expired -gt 0 ]]; then
            echo "  Expired (>${CACHE_TTL_HOURS}h): $age_expired images"
        fi
        echo ""
    fi

    # Show top cached images by size
    if [[ $total_images -gt 0 ]]; then
        echo "Top Cached Images (by size):"
        # Create temporary file to store size/image pairs for sorting
        local temp_file
        temp_file=$(mktemp 2>/dev/null || mktemp -t cache-stats)

        for cache_entry in "$CACHE_DIR"/*; do
            if [[ -d "$cache_entry" ]]; then
                local entry_size
                entry_size=$(get_dir_size "$cache_entry")

                # Get image name from metadata if available
                local image_name="$(basename "$cache_entry")"
                if [[ -f "$cache_entry/attestation-type.json" ]]; then
                    local cached_image
                    cached_image=$(jq -r '.image // empty' "$cache_entry/attestation-type.json" 2>/dev/null || echo "")
                    if [[ -n "$cached_image" && "$cached_image" != "null" ]]; then
                        image_name="$cached_image"
                    fi
                fi

                local age
                age=$(get_cache_age_hours "$cache_entry/attestation-type.json" 2>/dev/null || echo "0")

                # Store: size|image_name|age for sorting
                printf "%d|%s|%s\n" "$entry_size" "$image_name" "$age" >> "$temp_file"
            fi
        done

        # Sort by size (descending) and show top 10
        local count=0
        while IFS='|' read -r entry_size image_name age; do
            local entry_size_formatted
            entry_size_formatted=$(format_bytes "$entry_size")
            printf "  %2d. %-60s %10s (cached %sh ago)\n" $((++count)) "$image_name" "$entry_size_formatted" "$age"
            if [[ $count -ge 10 ]]; then
                break
            fi
        done < <(sort -t'|' -k1 -rn "$temp_file" 2>/dev/null || sort -t'|' -k1 -rn "$temp_file")

        rm -f "$temp_file"

        if [[ $total_images -gt 10 ]]; then
            echo "  ... and $((total_images - 10)) more images"
        fi
    fi

    echo ""
    echo "💡 Tip: Use --clear-cache to clear expired entries, or --no-cache to disable caching"
}

# Execute command with timeout if available
# Usage: run_with_timeout <timeout_seconds> <command> [args...]
# Returns: command output in stdout, exit code in $?
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
        log_verbose "No timeout command available, running without timeout"
        "${cmd[@]}"
    fi
}

# Convert cosign triage attestation JSON to Trivy ignore format
convert_triage_to_trivyignore() {
    local triage_file="$1"
    local output_file="$2"

    log_verbose "Converting cosign triage attestation to Trivy ignore format: $triage_file -> $output_file"

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is required for triage file conversion but not found"
        return 1
    fi

    # Extract CVE IDs from the cosign triage attestation
    if jq -r '.predicate.trivy | keys[]' "$triage_file" > "$output_file" 2>/dev/null; then
        log_verbose "Successfully converted triage file with $(wc -l < "$output_file") CVEs"
        return 0
    else
        # Check if the triage file exists but has no CVE data
        if jq -e '.predicate.trivy' "$triage_file" >/dev/null 2>&1; then
            log_error "Failed to extract CVEs from triage file: $triage_file"
        else
            log_verbose "Triage file contains no CVEs to ignore (clean image): $triage_file"
        fi
        return 1
    fi
}

# Check if image is based on Chainguard base image
check_chainguard_base_image() {
    local image="$1"
    local output_file="$2"

    log_verbose "Checking Chainguard base image for: $image"

    # Use the verify-chainguard-base-image.sh script
    local verify_script="$SCRIPT_DIR/../verify-chainguard-base-image.sh"
    if [[ ! -f "$verify_script" ]]; then
        log_error "verify-chainguard-base-image.sh not found at: $verify_script"
        return 1
    fi

    # Run the verification script in silent mode and capture output
    local verify_output
    if verify_output=$("$verify_script" --image "$image" --output-level none --no-error 2>/dev/null); then
        # Parse the output to extract variables
        local is_chainguard="false"
        local base_image="unknown"
        local signature_verified="false"

        while IFS= read -r line; do
            if [[ "$line" =~ ^IS_CHAINGUARD=(.*)$ ]]; then
                is_chainguard="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^BASE_IMAGE=\"(.*)\"$ ]]; then
                base_image="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^SIGNATURE_VERIFIED=(.*)$ ]]; then
                signature_verified="${BASH_REMATCH[1]}"
            fi
        done <<< "$verify_output"

        # Save results to file
        cat > "$output_file" <<EOF
{
  "is_chainguard": $is_chainguard,
  "base_image": "$base_image",
  "signature_verified": $signature_verified
}
EOF
        log_verbose "Chainguard verification completed for: $image (is_chainguard: $is_chainguard)"
        return 0
    else
        log_verbose "Chainguard verification failed for: $image"
        # Create empty results
        cat > "$output_file" <<EOF
{
  "is_chainguard": false,
  "base_image": "unknown",
  "signature_verified": false
}
EOF
        return 1
    fi
}

# Analyze CVEs from Trivy JSON output and categorize them
analyze_cves() {
    local image="$1"
    local scan_dir="$2"
    local triage_file="$3"

    # Initialize counters
    local unaddressed_cves=0
    local addressed_cves=0
    local irrelevant_cves=0
    local has_triage_file="No"

    # Check if triage file exists
    if [[ -n "$triage_file" && -f "$triage_file" ]]; then
        has_triage_file="Yes"
    fi

    # Run Trivy scan to get JSON output for analysis
    local json_report="$scan_dir/trivy-analysis.json"
    local stderr_file=$(mktemp)

    log_verbose "Running Trivy analysis scan for CVE categorization: $image"

    # Run Trivy without ignore file to get all vulnerabilities
    if trivy image --format json --severity LOW,MEDIUM,HIGH,CRITICAL --output "$json_report" "$image" 2>"$stderr_file"; then
        log_verbose "Trivy analysis completed for: $image"

        # Get list of addressed CVEs from cosign triage file
        local addressed_cve_list=()
        local unaddressed_cve_list=()
        local irrelevant_cve_list=()

        if [[ "$has_triage_file" == "Yes" ]]; then
            # Cosign JSON format only - check if predicate.trivy exists
            if jq -e '.predicate.trivy' "$triage_file" >/dev/null 2>&1; then
                while IFS= read -r cve; do
                    [[ -n "$cve" ]] && addressed_cve_list+=("$cve")
                done < <(jq -r '.predicate.trivy | keys[]' "$triage_file" 2>/dev/null || true)
                addressed_cves=${#addressed_cve_list[@]}
                log_verbose "Extracted ${addressed_cves} CVEs from triage file"
            else
                log_verbose "Triage file exists but contains no CVEs to ignore (clean image)"
            fi
        fi

        # Analyze all CVEs from the JSON report
        if [[ -f "$json_report" ]]; then
            # Get severity level hierarchy for comparison
            local min_level_num
            case "$MIN_CVE_LEVEL" in
                LOW) min_level_num=1 ;;
                MEDIUM) min_level_num=2 ;;
                HIGH) min_level_num=3 ;;
                CRITICAL) min_level_num=4 ;;
            esac

            # Count CVEs by category
            while IFS= read -r line; do
                local cve_id severity
                cve_id=$(echo "$line" | jq -r '.VulnerabilityID // empty')
                severity=$(echo "$line" | jq -r '.Severity // empty')

                if [[ -n "$cve_id" && -n "$severity" ]]; then
                    # Convert severity to number for comparison
                    local severity_num
                    case "$severity" in
                        LOW) severity_num=1 ;;
                        MEDIUM) severity_num=2 ;;
                        HIGH) severity_num=3 ;;
                        CRITICAL) severity_num=4 ;;
                        *) severity_num=0 ;;
                    esac

                    # Check if CVE is in addressed list
                    local is_addressed=false
                    if [[ ${#addressed_cve_list[@]} -gt 0 ]]; then
                        for addressed_cve in "${addressed_cve_list[@]}"; do
                            if [[ "$cve_id" == "$addressed_cve" ]]; then
                                is_addressed=true
                                break
                            fi
                        done
                    fi

                    # Categorize CVE
                    if [[ $severity_num -ge $min_level_num ]]; then
                        if [[ "$is_addressed" == "true" ]]; then
                            # Already counted in addressed_cves
                            :
                        else
                            ((unaddressed_cves++))
                            unaddressed_cve_list+=("$cve_id")
                        fi
                    else
                        ((irrelevant_cves++))
                        irrelevant_cve_list+=("$cve_id")
                    fi
                fi
            done < <(jq -c '.Results[]?.Vulnerabilities[]? // empty' "$json_report" 2>/dev/null || true)
        fi

        # Clean up temporary files
        rm -f "$json_report" "$stderr_file"
    else
        log_verbose "Trivy analysis failed for: $image"
        if [[ -s "$stderr_file" ]]; then
            log_verbose "Trivy analysis error: $(cat "$stderr_file")"
        fi
        rm -f "$stderr_file"
    fi

    # Store results in scan directory for summary table
    local image_safe_name=$(echo "$image" | sed 's|[^A-Za-z0-9._-]|_|g')
    local results_file="$OUTPUT_DIR/$image_safe_name/cve_analysis.txt"
    local cve_details_file="$OUTPUT_DIR/$image_safe_name/cve_details.json"

    # Save basic counts for backward compatibility
    if echo "$unaddressed_cves|$addressed_cves|$irrelevant_cves|$has_triage_file" > "$results_file"; then
        log_verbose "CVE analysis results saved to: $results_file"
    else
        log_error "Failed to save CVE analysis results to: $results_file"
    fi

    # Save detailed CVE information as JSON
    # Handle empty arrays safely
    local unaddressed_json="[]"
    local addressed_json="[]"
    local irrelevant_json="[]"

    # Check if arrays exist and have content (for unbound variable safety)
    if [[ ${unaddressed_cve_list[@]+_} && ${#unaddressed_cve_list[@]} -gt 0 ]]; then
        unaddressed_json="[$(printf '"%s",' "${unaddressed_cve_list[@]}" | sed 's/,$//')]"
    fi

    if [[ ${addressed_cve_list[@]+_} && ${#addressed_cve_list[@]} -gt 0 ]]; then
        addressed_json="[$(printf '"%s",' "${addressed_cve_list[@]}" | sed 's/,$//')]"
    fi

    if [[ ${irrelevant_cve_list[@]+_} && ${#irrelevant_cve_list[@]} -gt 0 ]]; then
        irrelevant_json="[$(printf '"%s",' "${irrelevant_cve_list[@]}" | sed 's/,$//')]"
    fi

    # Check Chainguard base image
    local chainguard_file="$image_dir/chainguard_verification.json"
    check_chainguard_base_image "$image" "$chainguard_file"

    # Read Chainguard verification results
    local is_chainguard="false"
    local base_image="unknown"
    local signature_verified="false"
    if [[ -f "$chainguard_file" ]]; then
        is_chainguard=$(jq -r '.is_chainguard' "$chainguard_file" 2>/dev/null || echo "false")
        base_image=$(jq -r '.base_image' "$chainguard_file" 2>/dev/null || echo "unknown")
        signature_verified=$(jq -r '.signature_verified' "$chainguard_file" 2>/dev/null || echo "false")
    fi

    cat > "$cve_details_file" <<EOF
{
  "image": "$image",
  "unaddressed_cves": $unaddressed_cves,
  "addressed_cves": $addressed_cves,
  "irrelevant_cves": $irrelevant_cves,
  "has_triage_file": $(if [[ "$has_triage_file" == "Yes" ]]; then echo "true"; else echo "false"; fi),
  "unaddressed_cve_list": $unaddressed_json,
  "addressed_cve_list": $addressed_json,
  "irrelevant_cve_list": $irrelevant_json,
  "min_cve_level": "$MIN_CVE_LEVEL",
  "is_chainguard": $is_chainguard,
  "base_image": "$base_image",
  "signature_verified": $signature_verified
}
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace) NAMESPACE="$2"; shift 2 ;;
    --ignore-file) IGNORE_FILE="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --kubeconfig) KUBECONFIG="$2"; shift 2 ;;
    --context) CONTEXT="$2"; shift 2 ;;
    --trivy-config) TRIVY_CONFIG="$2"; shift 2 ;;
    --parallel-scans) PARALLEL_SCANS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --certificate-oidc-issuer) CERTIFICATE_OIDC_ISSUER="$2"; shift 2 ;;
    --certificate-identity-regexp) CERTIFICATE_IDENTITY_REGEXP="$2"; shift 2 ;;
    --verbose) VERBOSE=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --format) FORMAT="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --min-cve-level) MIN_CVE_LEVEL="$2"; shift 2 ;;
    --cache-dir) CACHE_DIR="$2"; shift 2 ;;
    --cache-ttl) CACHE_TTL_HOURS="$2"; shift 2 ;;
    --no-cache) NO_CACHE=true; shift ;;
    --clear-cache) CLEAR_CACHE=true; shift ;;
    --cache-stats) CACHE_STATS=true; shift ;;
    --test-flow) TEST_FLOW=true; shift ;;
    -h|--help) show_help; exit 0 ;;
    *) log_error "Unknown option: $1"; show_help; exit 1 ;;
  esac
done

# Validate format
case "$FORMAT" in
  table|json|sarif) ;;
  *) log_error "Invalid format: $FORMAT. Must be one of: table, json, sarif"; exit 1 ;;
esac

# Validate min-cve-level
case "$MIN_CVE_LEVEL" in
  LOW|MEDIUM|HIGH|CRITICAL) ;;
  *) log_error "Invalid min-cve-level: $MIN_CVE_LEVEL. Must be one of: LOW, MEDIUM, HIGH, CRITICAL"; exit 1 ;;
esac

# Check prerequisites
check_prerequisites() {
    echo "🔧 Checking prerequisites" >&2

    local missing_tools=()

    for tool in kubectl trivy jq cosign podman; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install the missing tools and try again."
        exit 1
    fi


    log_result "All required tools available"

    # Check for required cosign scripts
    local extract_script="$SCRIPT_DIR/../cosign-extract.sh"
    local verify_script="$SCRIPT_DIR/../cosign-verify-image.sh"

    if [[ ! -f "$extract_script" ]]; then
        log_error "cosign-extract.sh not found at: $extract_script"
        log_error "Current working directory: $(pwd)"
        log_error "Script directory: $SCRIPT_DIR"
        log_error "Please ensure cosign-extract.sh is in the parent directory of the scanner folder"
        exit 1
    fi
    log_result "cosign-extract.sh script found"

    if [[ ! -f "$verify_script" ]]; then
        log_error "cosign-verify-image.sh not found at: $verify_script"
        log_error "Current working directory: $(pwd)"
        log_error "Script directory: $SCRIPT_DIR"
        log_error "Please ensure cosign-verify-image.sh is in the parent directory of the scanner folder"
        exit 1
    fi
    log_result "cosign-verify-image.sh script found"
}

# Setup temporary directory
setup_temp_dir() {
    TEMP_DIR=$(mktemp -d)
    log_verbose "Created temporary directory: $TEMP_DIR"

    # Cleanup on exit
    log_verbose "Setting up cleanup trap for temporary directory: $TEMP_DIR"
    trap cleanup_temp_dir EXIT
}

cleanup_temp_dir() {
    # Disable exit on error for cleanup function
    set +e
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        log_verbose "Cleaning up temporary directory: $TEMP_DIR"
        # List contents for debugging
        log_verbose "Directory contents: $(ls -la "$TEMP_DIR" 2>/dev/null || echo 'cannot list')"
        # Try to remove the directory, but don't fail if we can't due to permissions
        if ! rm -rf "$TEMP_DIR" 2>/dev/null; then
            log_verbose "Could not remove temporary directory (permission denied): $TEMP_DIR"
            # Try to remove contents first, then the directory
            if ! rm -rf "$TEMP_DIR"/* 2>/dev/null; then
                log_verbose "Could not remove temporary directory contents: $TEMP_DIR"
            fi
            # Try to remove the directory again
            if ! rmdir "$TEMP_DIR" 2>/dev/null; then
                log_verbose "Could not remove temporary directory: $TEMP_DIR (will be cleaned up by system)"
            fi
        else
            log_verbose "Successfully cleaned up temporary directory: $TEMP_DIR"
        fi
    fi
    # Re-enable exit on error
    set -e
}

# Load ignore list from file
load_ignore_list() {
    if [[ -n "$IGNORE_FILE" && -f "$IGNORE_FILE" ]]; then
        echo "📂 Loading ignore patterns from: $IGNORE_FILE" >&2

        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip empty lines and comments
            if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
                IGNORE_LIST+=("$line")
            fi
        done < "$IGNORE_FILE"

        log_result "Loaded ${#IGNORE_LIST[@]} ignore patterns"
        if $VERBOSE; then
            for img in "${IGNORE_LIST[@]}"; do
                log_verbose "Pattern: $img"
            done
        fi
    fi
}

# Check if image should be ignored
should_ignore_image() {
    local image="$1"

    # Return false if IGNORE_LIST is empty
    if [[ ${#IGNORE_LIST[@]} -eq 0 ]]; then
        return 1
    fi

    for ignore_pattern in "${IGNORE_LIST[@]}"; do
        if [[ "$image" == *"$ignore_pattern"* ]]; then
            return 0
        fi
    done

    return 1
}

# Extract registry from image reference
extract_registry() {
    local image="$1"
    echo "$image" | sed -E 's|^([^/]+).*|\1|'
}

# Check if registry is accessible using docker
is_registry_accessible() {
    local registry="$1"
    local test_image="$2"  # The actual image we want to test

    # Check if we already know this registry is accessible
    if [[ ${#ACCESSIBLE_REGISTRIES[@]} -gt 0 ]]; then
        for accessible_reg in "${ACCESSIBLE_REGISTRIES[@]}"; do
            if [[ "$registry" == "$accessible_reg" ]]; then
                log_verbose "Registry already known to be accessible: $registry"
                return 0
            fi
        done
    fi

    # Check if we already know this registry is inaccessible
    if [[ ${#INACCESSIBLE_REGISTRIES[@]} -gt 0 ]]; then
        for inaccessible_reg in "${INACCESSIBLE_REGISTRIES[@]}"; do
            if [[ "$registry" == "$inaccessible_reg" ]]; then
                log_verbose "Registry already known to be inaccessible: $registry"
                return 1
            fi
        done
    fi

    # Check if registry is accessible using docker (which uses proper authentication)
    # We test with the actual image we want to scan
    log_verbose "Checking registry accessibility: $registry using image: $test_image"

    # Use docker manifest inspect which respects Docker's authentication
    if podman manifest inspect "$test_image" >/dev/null 2>&1; then
        log_verbose "Registry is accessible: $registry"
        # Add to accessible registries list
        ACCESSIBLE_REGISTRIES+=("$registry")
        return 0
    else
        log_verbose "Registry is not accessible: $registry"
        # Add to inaccessible registries list
        INACCESSIBLE_REGISTRIES+=("$registry")
        return 1
    fi
}

# Check if image should be skipped due to inaccessible registry
should_skip_inaccessible_registry() {
    local image="$1"
    local registry
    registry=$(extract_registry "$image")

    if ! is_registry_accessible "$registry" "$image"; then
        return 0  # Skip this image
    fi

    return 1  # Don't skip
}

# Setup kubectl context
setup_kubectl() {
    local kubectl_args=()

    if [[ -n "$KUBECONFIG" ]]; then
        kubectl_args+=(--kubeconfig="$KUBECONFIG")
    fi

    if [[ -n "$CONTEXT" ]]; then
        kubectl_args+=(--context="$CONTEXT")
    fi

    # Test kubectl connectivity with timeout
    echo "⚡ Testing Kubernetes connectivity (30s timeout)" >&2
    local connectivity_test_output

    # Test connectivity with timeout
    if connectivity_test_output=$(run_with_timeout 30 kubectl ${kubectl_args[@]+"${kubectl_args[@]}"} get namespace "$NAMESPACE" 2>&1); then
        log_verbose "Kubernetes connectivity test successful"
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            log_error "Kubernetes connectivity test timed out after 30 seconds"
            log_error "This usually indicates network issues or an unreachable cluster"
        else
            log_error "Cannot access namespace '$NAMESPACE' in Kubernetes cluster"
            log_error "kubectl output: $connectivity_test_output"
        fi
        log_error "Please check your kubeconfig, context, and namespace settings"
        log_error "You can test manually with: kubectl ${kubectl_args[@]+"${kubectl_args[@]}"} get namespace $NAMESPACE"
        exit 1
    fi

    log_result "Connected to cluster, namespace: $NAMESPACE"

    # Store kubectl args for later use
    echo ${kubectl_args[@]+"${kubectl_args[@]}"} > "$TEMP_DIR/kubectl_args"
}

# Extract images from Kubernetes namespace
extract_k8s_images() {
    local kubectl_args
    kubectl_args=$(cat "$TEMP_DIR/kubectl_args")

    echo "🔍 Discovering images in namespace: $NAMESPACE" >&2

    # Get all images from pods, deployments, daemonsets, statefulsets, jobs, cronjobs
    local images_file="$TEMP_DIR/all_images.txt"

    {
        # From running pods
        kubectl $kubectl_args get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{range .spec.initContainers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null || true

        # From deployments
        kubectl $kubectl_args get deployments -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}{range .spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null || true

        # From daemonsets
        kubectl $kubectl_args get daemonsets -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}{range .spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null || true

        # From statefulsets
        kubectl $kubectl_args get statefulsets -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}{range .spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null || true

        # From jobs
        kubectl $kubectl_args get jobs -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}{range .spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null || true

        # From cronjobs
        kubectl $kubectl_args get cronjobs -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.jobTemplate.spec.template.spec.containers[*]}{.image}{"\n"}{end}{range .spec.jobTemplate.spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null || true

    } | grep -v '^$' | sort -u > "$images_file"

    # Filter out ignored images
    local filtered_images=()
    log_verbose "📂 Processing images from file: $images_file"
    if [[ -f "$images_file" ]]; then
        log_verbose "Images file exists, processing $(wc -l < "$images_file") images"
    while IFS= read -r image || [[ -n "$image" ]]; do
        if [[ -n "$image" ]]; then
            if should_ignore_image "$image"; then
                log_verbose "🚫 Ignoring image: $image"
                ((IGNORED_IMAGES++))
                ((SKIPPED_IMAGES++))
                log_verbose "Updated IGNORED_IMAGES: $IGNORED_IMAGES, SKIPPED_IMAGES: $SKIPPED_IMAGES"
            elif should_skip_inaccessible_registry "$image"; then
                log_verbose "🚫 Skipping image from inaccessible registry: $image"
                ((INACCESSIBLE_IMAGES++))
                ((SKIPPED_IMAGES++))
                log_verbose "Updated INACCESSIBLE_IMAGES: $INACCESSIBLE_IMAGES, SKIPPED_IMAGES: $SKIPPED_IMAGES"
            else
                filtered_images+=("$image")
                log_verbose "Including image: $image"
            fi
        fi
    done < "$images_file"
    else
        log_error "Images file not found: $images_file"
        exit 1
    fi

    TOTAL_IMAGES=${#filtered_images[@]}

    if [[ $TOTAL_IMAGES -eq 0 ]]; then
        log_warn "No images found to scan in namespace: $NAMESPACE"
        if [[ $SKIPPED_IMAGES -gt 0 ]]; then
            if [[ $INACCESSIBLE_IMAGES -gt 0 && $IGNORED_IMAGES -gt 0 ]]; then
                log_info "   All $SKIPPED_IMAGES images were skipped:"
                log_info "    - $INACCESSIBLE_IMAGES images from inaccessible registries"
                log_info "    - $IGNORED_IMAGES images ignored by patterns"
                log_info "   Inaccessible registries:"
                for registry in "${INACCESSIBLE_REGISTRIES[@]}"; do
                    log_info "    - $registry"
                done
                log_info "   To access these registries, run: podman login <registry>"
                log_info "   Then try running the scanner again."
            elif [[ $INACCESSIBLE_IMAGES -gt 0 ]]; then
                log_info "   All $SKIPPED_IMAGES images were skipped due to inaccessible registries"
                log_info "   Inaccessible registries:"
                for registry in "${INACCESSIBLE_REGISTRIES[@]}"; do
                    log_info "     - $registry"
                done
                log_info "   To access these registries, run: podman login <registry>"
                log_info "   Then try running the scanner again."
            else
                log_info "   All $SKIPPED_IMAGES images were ignored by ignore patterns"
            fi
        else
            log_info "No images were found in the namespace"
        fi
        exit 0
    fi

    log_result "Found $TOTAL_IMAGES unique images to scan"

    # Show separate messages for ignored images vs inaccessible registries
    if [[ $IGNORED_IMAGES -gt 0 ]]; then
        log_result "🚫 Skipped $IGNORED_IMAGES ignored images"
    fi

    if [[ $INACCESSIBLE_IMAGES -gt 0 ]]; then
        log_warn "🚫 Inaccessible registries detected: ${INACCESSIBLE_REGISTRIES[*]}"
        log_warn "   Skipped $INACCESSIBLE_IMAGES images from these registries"
        log_warn "   To access these registries, run: podman login <registry>"
        log_warn "   Then try running the scanner again."
    fi

    # Save filtered images list
    log_verbose "Saving filtered images list to: $TEMP_DIR/images_to_scan.txt"
    if ! printf '%s\n' "${filtered_images[@]}" > "$TEMP_DIR/images_to_scan.txt"; then
        log_error "Failed to save images list to: $TEMP_DIR/images_to_scan.txt"
        return 1
    fi
    local line_count
    if line_count=$(wc -l < "$TEMP_DIR/images_to_scan.txt" 2>/dev/null); then
        log_verbose "Saved $line_count images to scan file"
    else
        log_verbose "Saved images to scan file (could not count lines)"
    fi

    if $VERBOSE; then
        log_verbose "Images to scan:"
        for img in "${filtered_images[@]}"; do
            log_verbose "  $img"
        done
    fi

    log_verbose "extract_k8s_images function completed successfully"
}

# Check if image is Cosign-signed and has triage attestations
detect_attestation_type() {
    local image="$1"
    local attestation_type=""

    # Check cache first
    if cached_type=$(get_cached_attestation_type "$image" 2>/dev/null); then
        echo "$cached_type"
        return 0
    fi

    # Temporarily disable exit on error for this function
    set +e
    local verify_output
    local verify_exit_code

    log_verbose "Checking if image is Cosign-signed: $image"

    # Use the existing cosign-verify-image.sh script for verification
    local verify_script="$SCRIPT_DIR/../cosign-verify-image.sh"
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

        if extract_output=$("$SCRIPT_DIR/../cosign-extract.sh" --image "$image" --list 2>&1); then
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
                attestation_type="cosign-sbom-triage"
            elif [[ "$has_sbom" == "true" ]]; then
                attestation_type="cosign-sbom"
            elif [[ "$has_triage" == "true" ]]; then
                attestation_type="cosign-no-sbom"
            else
                attestation_type="cosign-no-sbom"
            fi
        else
            log_verbose "Image is Cosign-signed but couldn't list attestations"
            attestation_type="cosign-no-sbom"
        fi
    else
        log_verbose "Image is not Cosign-signed"
        attestation_type="unsigned"
    fi

    # Cache the result
    cache_attestation_type "$image" "$attestation_type"

    echo "$attestation_type"

    # Re-enable exit on error
    set -e
}

# Download SBOM using cosign attestation
download_sbom() {
    local image="$1"
    local output_file="$2"
    local sbom_type="${3:-cyclonedx}"  # Default to cyclonedx

    # Check cache first
    local cached_sbom
    if cached_sbom=$(get_cached_sbom "$image" "$sbom_type" 2>/dev/null); then
        if cp "$cached_sbom" "$output_file" 2>/dev/null; then
            log_verbose "Using cached SBOM ($sbom_type) for: $image"
            return 0
        fi
    fi

    log_verbose "Downloading SBOM attestation ($sbom_type) for: $image"

    # Use the existing cosign-extract.sh script
    local extract_script="$SCRIPT_DIR/../cosign-extract.sh"
    log_verbose "Looking for cosign-extract.sh at: $extract_script"
    if [[ ! -f "$extract_script" ]]; then
        log_error "cosign-extract.sh not found at: $extract_script"
        log_error "Current working directory: $(pwd)"
        log_error "Script directory: $SCRIPT_DIR"
        return 1
    fi
    log_verbose "Found cosign-extract.sh script"

    # Extract SBOM attestation predicate (automatically select latest if multiple)
    # Use --predicate-only to extract just the SBOM content, not the attestation envelope
    if "$extract_script" --type "$sbom_type" --image "$image" --output "$output_file" --last --predicate-only >/dev/null 2>&1; then
        log_verbose "Successfully downloaded SBOM for: $image"

        # Verify the extracted SBOM is valid JSON
        if jq empty "$output_file" 2>/dev/null; then
            log_verbose "SBOM is valid JSON"
            # Cache the SBOM
            cache_sbom "$image" "$output_file" "$sbom_type"
            return 0
        else
            log_error "Extracted SBOM is not valid JSON"
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

    # Check cache first
    local cached_triage
    if cached_triage=$(get_cached_triage "$image" 2>/dev/null); then
        if cp "$cached_triage" "$output_file" 2>/dev/null; then
            log_verbose "Using cached triage for: $image"
            return 0
        fi
    fi

    log_verbose "Downloading cosign triage attestation for: $image"

    # Use the existing cosign-extract.sh script
    local extract_script="$SCRIPT_DIR/../cosign-extract.sh"
    log_verbose "Looking for cosign-extract.sh at: $extract_script"
    if [[ ! -f "$extract_script" ]]; then
        log_error "cosign-extract.sh not found at: $extract_script"
        log_error "Current working directory: $(pwd)"
        log_error "Script directory: $SCRIPT_DIR"
        return 1
    fi
    log_verbose "Found cosign-extract.sh script"

    # Extract triage attestation (automatically select latest if multiple)
    if "$extract_script" --type triage --image "$image" --output "$output_file" --last --verify \
        --certificate-oidc-issuer "$CERTIFICATE_OIDC_ISSUER" \
        --certificate-identity-regexp "$CERTIFICATE_IDENTITY_REGEXP" >/dev/null 2>&1; then

        log_verbose "Successfully downloaded cosign triage for: $image"
        # Cache the triage
        cache_triage "$image" "$output_file"
        return 0
    else
        log_verbose "Failed to download cosign triage for: $image"
        return 1
    fi
}

# Run Trivy scan on SBOM file
run_trivy_scan() {
    local sbom_file="$1"
    local triage_file="$2"
    local output_file="$3"

    log_verbose "Running Trivy scan on SBOM: $sbom_file"

    local trivy_args=(
        "sbom"
        "--format" "$FORMAT"
        "--severity" "$SEVERITY"
        "--output" "$output_file"
    )

    # Add triage file if available
    if [[ -n "$triage_file" && -f "$triage_file" ]]; then
        # Convert triage attestation to Trivy ignore format
        local trivy_ignore_file="${triage_file%.json}.trivyignore"
        if convert_triage_to_trivyignore "$triage_file" "$trivy_ignore_file"; then
            trivy_args+=("--ignorefile" "$trivy_ignore_file")
            log_verbose "Using triage file: $trivy_ignore_file"
        else
            log_verbose "No CVEs to ignore in triage file, scanning all vulnerabilities"
        fi
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
        log_verbose "Trivy SBOM scan failed"
        # Show error output for debugging
        if $VERBOSE && [[ -s "$stderr_file" ]]; then
            echo "Debug: Trivy error output:" >&2
            head -5 "$stderr_file" >&2
        fi
        rm -f "$stderr_file"
        return 1
    fi
}

# Process a single image
process_image() {
    # Disable exit on error for this function since it runs in background
    set +e

    local image="$1"
    local image_safe_name
    image_safe_name=$(echo "$image" | sed 's|[^A-Za-z0-9._-]|_|g')

    local image_dir="$OUTPUT_DIR/$image_safe_name"
    if ! mkdir -p "$image_dir"; then
        local error_msg="Failed to create directory: $image_dir"
        log_error "$error_msg"
        echo "$error_msg" > "$image_dir/error.txt" 2>/dev/null || true
        return 1
    fi

    log_verbose "Processing: $image"

    # Detect attestation type
    local attestation_type
    local detect_error_file
    detect_error_file=$(mktemp 2>/dev/null || mktemp -t detect-error)
    # Disable exit on error for this command substitution
    set +e
    attestation_type=$(detect_attestation_type "$image" 2>"$detect_error_file")
    local detect_exit_code=$?
    local detect_error_output=""
    if [[ -f "$detect_error_file" ]]; then
        detect_error_output=$(cat "$detect_error_file" 2>/dev/null || echo "")
        rm -f "$detect_error_file"
    fi
    set -e

    if [[ $detect_exit_code -ne 0 ]]; then
        local error_msg="Failed to detect attestation type for: $image (exit code: $detect_exit_code)"
        if [[ -n "$detect_error_output" ]]; then
            error_msg="$error_msg

Error details:
$detect_error_output"
        fi
        log_error "$error_msg"
        echo "$error_msg" > "$image_dir/error.txt" 2>/dev/null || true
        return 1
    fi
    log_verbose "Detected attestation type: $attestation_type"

    local sbom_file=""
    local sbom_downloaded=false
    local triage_file=""
    local triage_downloaded=false

    # Handle image based on signature status
    case "$attestation_type" in
        "cosign-sbom-triage")
            # Image is signed and has both SBOM and triage
            log_verbose "Image has SBOM and triage attestations"

            # Download SBOM
            sbom_file="$image_dir/sbom.json"
            local sbom_error_file
            sbom_error_file=$(mktemp 2>/dev/null || mktemp -t sbom-error)
            if download_sbom "$image" "$sbom_file" 2>"$sbom_error_file"; then
                sbom_downloaded=true
                log_verbose "Downloaded SBOM for: $image"
                rm -f "$sbom_error_file"
            else
                local sbom_error_output=""
                if [[ -f "$sbom_error_file" ]]; then
                    sbom_error_output=$(cat "$sbom_error_file" 2>/dev/null || echo "")
                fi
                rm -f "$sbom_error_file"
                local error_msg="Failed to download SBOM for: $image"
                if [[ -n "$sbom_error_output" ]]; then
                    error_msg="$error_msg

Error details:
$sbom_error_output"
                fi
                log_error "$error_msg"
                echo "$error_msg" > "$image_dir/error.txt" 2>/dev/null || true
                return 1
            fi

            # Download triage
            triage_file="$image_dir/triage.json"
            if download_cosign_triage "$image" "$triage_file"; then
                triage_downloaded=true
                log_verbose "Downloaded triage for: $image"
            else
                # Missing triage is not an error - it just means the image has no triage data
                triage_file=""
            fi
            ;;
        "cosign-sbom")
            # Image is signed and has SBOM but no triage
            log_verbose "Image has SBOM attestation (no triage)"

            # Download SBOM
            sbom_file="$image_dir/sbom.json"
            local sbom_error_file
            sbom_error_file=$(mktemp 2>/dev/null || mktemp -t sbom-error)
            if download_sbom "$image" "$sbom_file" 2>"$sbom_error_file"; then
                sbom_downloaded=true
                log_verbose "Downloaded SBOM for: $image"
                rm -f "$sbom_error_file"
            else
                local sbom_error_output=""
                if [[ -f "$sbom_error_file" ]]; then
                    sbom_error_output=$(cat "$sbom_error_file" 2>/dev/null || echo "")
                fi
                rm -f "$sbom_error_file"
                local error_msg="Failed to download SBOM for: $image"
                if [[ -n "$sbom_error_output" ]]; then
                    error_msg="$error_msg

Error details:
$sbom_error_output"
                fi
                log_error "$error_msg"
                echo "$error_msg" > "$image_dir/error.txt" 2>/dev/null || true
                return 1
            fi
            ;;
        "cosign-no-sbom")
            # Image is signed but no SBOM - skip scanning
            log_verbose "Image is signed but no SBOM attestation found, skipping: $image"
            if echo "skipped-no-sbom" > "$image_dir/skipped.txt"; then
                log_verbose "Created skip marker (no SBOM) for: $image"
            else
                log_error "Failed to create skip marker for: $image"
            fi
            return 0
            ;;
        "unsigned")
            # Image is not signed, skip scanning silently
            log_verbose "Image is not Cosign-signed, skipping: $image"
            # Create a marker file to indicate this image was skipped
            if echo "skipped" > "$image_dir/skipped.txt"; then
                log_verbose "Created skip marker for: $image"
            else
                log_error "Failed to create skip marker for: $image"
            fi
            return 0
            ;;
    esac

    # Verify we have an SBOM to scan
    if [[ ! -f "$sbom_file" ]]; then
        local error_msg="No SBOM file available for scanning: $image"
        log_error "$error_msg"
        echo "$error_msg" > "$image_dir/error.txt" 2>/dev/null || true
        return 1
    fi

    # Run Trivy scan on SBOM
    local scan_output="$image_dir/trivy-report.$FORMAT"
    local trivy_error_file
    trivy_error_file=$(mktemp 2>/dev/null || mktemp -t trivy-error)
    if run_trivy_scan "$sbom_file" "$triage_file" "$scan_output" 2>"$trivy_error_file"; then
        # Create metadata file to indicate successful scan
        cat > "$image_dir/metadata.json" <<EOF
{
  "image": "$image",
  "attestation_type": "$attestation_type",
  "sbom_downloaded": $sbom_downloaded,
  "triage_downloaded": $triage_downloaded,
  "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")",
  "scan_format": "$FORMAT",
  "severity_filter": "$SEVERITY",
  "scan_method": "sbom"
}
EOF
        # Analyze CVEs for summary table
        analyze_cves "$image" "$image_dir" "$triage_file"
        log_verbose "Scan completed for: $image"
        rm -f "$trivy_error_file"
    else
        local trivy_error_output=""
        if [[ -f "$trivy_error_file" ]]; then
            trivy_error_output=$(cat "$trivy_error_file" 2>/dev/null || echo "")
        fi
        rm -f "$trivy_error_file"
        local error_msg="Trivy scan failed for: $image"
        if [[ -n "$trivy_error_output" ]]; then
            error_msg="$error_msg

Error details:
$trivy_error_output"
        fi
        log_verbose "$error_msg"
        echo "$error_msg" > "$image_dir/error.txt" 2>/dev/null || true
        return 1
    fi

    # Re-enable exit on error
    set -e
}

# Process all images
process_all_images() {
    local images=()
    log_verbose "Reading images from: $TEMP_DIR/images_to_scan.txt"
    if [[ ! -f "$TEMP_DIR/images_to_scan.txt" ]]; then
        log_error "Images to scan file not found: $TEMP_DIR/images_to_scan.txt"
        return 1
    fi

    while IFS= read -r image; do
        if [[ -n "$image" ]]; then
            images+=("$image")
        fi
    done < "$TEMP_DIR/images_to_scan.txt"

    log_verbose "Loaded ${#images[@]} images to process"
    log_verbose "Array length: ${#images[@]}, First image: ${images[0]:-none}"

    if $DRY_RUN; then
        log_result "[DRY RUN] - Would process ${#images[@]} images:"
        for img in "${images[@]}"; do
            echo "     - $img" >&2
        done
        return 0
    fi

    # Test flow mode: process only the first valid image
    if $TEST_FLOW; then
        log_result "TEST FLOW: Processing only the first valid image"
        local processed=false
        # Disable exit on error for test flow since we want to continue trying images
        set +e
        for image in "${images[@]}"; do
            log_verbose "Testing image: $image"
            local progress_msg="🔄 Processing test image: $image"
            printf "\r%s" "$progress_msg" >&2
            # Call process_image (it re-enables exit on error at the end, so we disable it again)
            process_image "$image"
            # Re-disable exit on error (process_image re-enables it at the end)
            set +e

            # Check if this was a successful scan (not skipped)
            local image_safe_name
            image_safe_name=$(echo "$image" | sed 's|[^A-Za-z0-9._-]|_|g')
            local image_dir="$OUTPUT_DIR/$image_safe_name"
            if [[ -f "$image_dir/skipped.txt" ]]; then
                # Clear progress line using ANSI escape code (clear to end of line) or spaces
                if [[ -t 2 ]]; then
                    # Terminal supports ANSI codes
                    printf "\r\033[K" >&2
                else
                    # Fallback: clear with spaces (use large buffer to handle long image names)
                    printf "\r%*s\r" 200 "" >&2
                fi
                echo "" >&2  # New line
                log_verbose "Image was skipped, trying next image..."
                continue
            elif [[ -f "$image_dir/metadata.json" ]]; then
                # Clear progress line using ANSI escape code (clear to end of line) or spaces
                if [[ -t 2 ]]; then
                    # Terminal supports ANSI codes
                    printf "\r\033[K" >&2
                else
                    # Fallback: clear with spaces (use large buffer to handle long image names)
                    printf "\r%*s\r" 200 "" >&2
                fi
                echo "" >&2  # New line
                log_success "Test flow: Successfully processed first valid image: $image"
                processed=true
                break
            fi
        done
        # Re-enable exit on error
        set -e

        # Clear any remaining progress line (if not already cleared)
        if ! $processed; then
            if [[ -t 2 ]]; then
                # Terminal supports ANSI codes
                printf "\r\033[K" >&2
            else
                # Fallback: clear with spaces
                printf "\r%*s\r" 200 "" >&2
            fi
            echo "" >&2  # New line
            log_warn "Test flow: No valid image was successfully processed"
        fi

        printf "✅ Test flow completed\n" >&2
        log_info "Finalizing scan results..."
        collect_scan_results
        return 0
    fi

    # Process images in parallel
    local pids=()
    local count=0

    for image in "${images[@]}"; do
        # Wait if we've reached the parallel limit
        while [[ ${#pids[@]} -ge $PARALLEL_SCANS ]]; do
            local new_pids=()
            if [[ ${#pids[@]} -gt 0 ]]; then
                for pid in "${pids[@]}"; do
                    # Disable exit on error for kill command
                    set +e
                    if kill -0 "$pid" 2>/dev/null; then
                        new_pids+=("$pid")
                    fi
                    set -e
                done
            fi
            pids=()
            if [[ ${#new_pids[@]} -gt 0 ]]; then
                pids=("${new_pids[@]}")
            fi
            sleep 1
        done

        # Start processing in background
        log_verbose "Starting background process for: $image"
        process_image "$image" &
        local bg_pid=$!
        pids+=($bg_pid)
        log_verbose "Started background process with PID: $bg_pid"

        ((count++))
        # Update progress on the same line
        printf "\r🔄 Processing images: %d/%d" "$count" "${#images[@]}" >&2
    done

    # Clear the progress line and show completion
    printf "\r✅ Processing completed: %d/%d images\n" "${#images[@]}" "${#images[@]}" >&2
    log_info "Finalizing scan results..."

    # Wait for all remaining processes
    if [[ ${#pids[@]} -gt 0 ]]; then
        for pid in "${pids[@]}"; do
            # Disable exit on error temporarily for wait command
            set +e
            wait "$pid"
            local wait_exit_code=$?
            set -e
            if [[ $wait_exit_code -ne 0 ]]; then
                log_verbose "Background process $pid exited with code $wait_exit_code"
            fi
        done
    fi

    # Collect results by checking what was actually created
    log_verbose "Collecting scan results"
    collect_scan_results
    log_verbose "Scan results collection completed"

    # Show final results
    if [[ ${#SUCCESSFUL_SCANS[@]} -gt 0 ]]; then
        log_result "✅ ${#SUCCESSFUL_SCANS[@]} successful scans"
    fi

    if [[ ${#FAILED_SCANS[@]} -gt 0 ]]; then
        log_result "❌ ${#FAILED_SCANS[@]} failed scans"
    fi

    if [[ ${#SKIPPED_SCANS[@]} -gt 0 ]]; then
        log_result "⏭️  ${#SKIPPED_SCANS[@]} skipped scans (unsigned images)"
    fi

    log_result "Completed processing all images"
}

# Collect scan results from output directories
collect_scan_results() {
    log_verbose "Collecting scan results..."

    # Reset arrays
    SUCCESSFUL_SCANS=()
    FAILED_SCANS=()
    SKIPPED_SCANS=()

    # Read the list of images that were supposed to be scanned
    log_verbose "Reading images from: $TEMP_DIR/images_to_scan.txt"
    if [[ ! -f "$TEMP_DIR/images_to_scan.txt" ]]; then
        log_error "Images to scan file not found during result collection: $TEMP_DIR/images_to_scan.txt"
        return 1
    fi

    while IFS= read -r image; do
        if [[ -z "$image" ]]; then
            continue
        fi
        local image_safe_name
        image_safe_name=$(echo "$image" | sed 's|[^A-Za-z0-9._-]|_|g')
        local image_dir="$OUTPUT_DIR/$image_safe_name"

        # Skip images that were never processed (no directory exists)
        # This happens in test-flow mode where we stop after the first valid image
        if [[ ! -d "$image_dir" ]]; then
            if $TEST_FLOW; then
                log_verbose "⏭️  Not processed (test-flow): $(basename "$image")"
            else
                # In normal mode, if directory doesn't exist, it's a failure
                # Try to create the directory and save an error message
                if mkdir -p "$image_dir" 2>/dev/null; then
                    echo "Image processing failed before any output was generated. This usually indicates a critical error during initialization." > "$image_dir/error.txt" 2>/dev/null || true
                fi
                FAILED_SCANS+=("$image")
                log_verbose "❌ Failed (no output): $(basename "$image")"
            fi
            continue
        fi

        # Check if image was skipped (unsigned)
        if [[ -f "$image_dir/skipped.txt" ]]; then
            SKIPPED_SCANS+=("$image")
            log_verbose "⏭️  Skipped: $(basename "$image")"
        # Check if scan completed successfully (trivy report exists and metadata exists)
        elif [[ -f "$image_dir/metadata.json" && -f "$image_dir/trivy-report.$FORMAT" ]]; then
            SUCCESSFUL_SCANS+=("$image")
            log_verbose "✅ Successful: $(basename "$image")"
        else
            # Only mark as failed if directory exists (image was actually attempted)
            FAILED_SCANS+=("$image")
            local error_file="$image_dir/error.txt"
            if [[ -f "$error_file" ]]; then
                log_verbose "❌ Failed: $(basename "$image") (error details in $error_file)"
            else
                log_verbose "❌ Failed: $(basename "$image") (no error details available)"
            fi
        fi
    done < "$TEMP_DIR/images_to_scan.txt"

    # Ensure arrays are defined before accessing them
    SUCCESSFUL_SCANS=(${SUCCESSFUL_SCANS[@]:-})
    FAILED_SCANS=(${FAILED_SCANS[@]:-})
    SKIPPED_SCANS=(${SKIPPED_SCANS[@]:-})

    log_verbose "Collected ${#SUCCESSFUL_SCANS[@]} successful, ${#FAILED_SCANS[@]} failed, and ${#SKIPPED_SCANS[@]} skipped scans"
}

# Generate final report
generate_final_report() {
    local report_file="$OUTPUT_DIR/scan-summary.json"

    local successful_count=0
    local failed_count=0
    local skipped_count=0

    # Ensure arrays are defined before accessing them
    SUCCESSFUL_SCANS=(${SUCCESSFUL_SCANS[@]:-})
    FAILED_SCANS=(${FAILED_SCANS[@]:-})
    SKIPPED_SCANS=(${SKIPPED_SCANS[@]:-})

    # Safe array length calculation
    if [[ ${#SUCCESSFUL_SCANS[@]} -gt 0 ]]; then
        successful_count=${#SUCCESSFUL_SCANS[@]}
    fi

    if [[ ${#FAILED_SCANS[@]} -gt 0 ]]; then
        failed_count=${#FAILED_SCANS[@]}
    fi

    if [[ ${#SKIPPED_SCANS[@]} -gt 0 ]]; then
        skipped_count=${#SKIPPED_SCANS[@]}
    fi

    local total_processed=$((successful_count + failed_count + skipped_count))

    # Create summary report
    cat > "$report_file" <<EOF
{
  "scan_summary": {
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ")",
    "namespace": "$NAMESPACE",
    "total_images_found": $TOTAL_IMAGES,
    "images_skipped": $SKIPPED_IMAGES,
    "images_processed": $total_processed,
    "successful_scans": $successful_count,
    "failed_scans": $failed_count,
    "skipped_scans": $skipped_count,
    "format": "$FORMAT",
    "severity_filter": "$SEVERITY"
  },
  "successful_scans": [
$(if [[ ${#SUCCESSFUL_SCANS[@]} -gt 0 ]]; then
    for i in "${!SUCCESSFUL_SCANS[@]}"; do
        if [[ $i -eq $((${#SUCCESSFUL_SCANS[@]} - 1)) ]]; then
            printf '    "%s"\n' "${SUCCESSFUL_SCANS[$i]}"
        else
            printf '    "%s",\n' "${SUCCESSFUL_SCANS[$i]}"
        fi
    done
fi)
  ],
  "failed_scans": [
$(if [[ ${#FAILED_SCANS[@]} -gt 0 ]]; then
    for i in "${!FAILED_SCANS[@]}"; do
        local failed_image="${FAILED_SCANS[$i]}"
        local image_safe_name
        image_safe_name=$(echo "$failed_image" | sed 's|[^A-Za-z0-9._-]|_|g')
        local image_dir="$OUTPUT_DIR/$image_safe_name"
        local error_file="$image_dir/error.txt"
        local error_details=""
        if [[ -f "$error_file" ]]; then
            # Read error file and escape JSON special characters
            error_details=$(cat "$error_file" 2>/dev/null | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g' || echo "")
        fi
        if [[ $i -eq $((${#FAILED_SCANS[@]} - 1)) ]]; then
            if [[ -n "$error_details" ]]; then
                printf '    {\n      "image": "%s",\n      "error": "%s"\n    }\n' "$failed_image" "$error_details"
            else
                printf '    {\n      "image": "%s",\n      "error": "No error details available"\n    }\n' "$failed_image"
            fi
        else
            if [[ -n "$error_details" ]]; then
                printf '    {\n      "image": "%s",\n      "error": "%s"\n    },\n' "$failed_image" "$error_details"
            else
                printf '    {\n      "image": "%s",\n      "error": "No error details available"\n    },\n' "$failed_image"
            fi
        fi
    done
fi)
  ],
  "skipped_scans": [
$(if [[ ${#SKIPPED_SCANS[@]} -gt 0 ]]; then
    for i in "${!SKIPPED_SCANS[@]}"; do
        if [[ $i -eq $((${#SKIPPED_SCANS[@]} - 1)) ]]; then
            printf '    "%s"\n' "${SKIPPED_SCANS[$i]}"
        else
            printf '    "%s",\n' "${SKIPPED_SCANS[$i]}"
        fi
    done
fi)
  ],
  "cve_analysis": [
$(# Collect detailed CVE analysis from individual scan directories
if [[ -d "$OUTPUT_DIR" ]]; then
    local first=true
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            if [[ "$first" == "true" ]]; then
                first=false
            else
                printf ",\n"
            fi
            printf "    "
            cat "$file" | jq -c .
        fi
    done < <(find "$OUTPUT_DIR" -name "cve_details.json" -print0 2>/dev/null)
fi)
  ]
}
EOF

    log_result "Report saved: $report_file"

    # Print summary to console
    echo ""
    echo "📊 SCAN SUMMARY"
    echo "==============="
    echo "Namespace: $NAMESPACE"
    echo "Total images found: $TOTAL_IMAGES"
    echo "🚫 Images skipped (ignored): $SKIPPED_IMAGES"
    echo "Images processed: $total_processed"
    echo "Successful scans: $successful_count"
    echo "Failed scans: $failed_count"
    echo "Skipped scans: $skipped_count (unsigned images)"
    echo ""
    echo "📁 Reports saved to: $OUTPUT_DIR"

    if [[ $failed_count -gt 0 && ${#FAILED_SCANS[@]} -gt 0 ]]; then
        echo ""
        echo "❌ Failed scans:"
        for img in "${FAILED_SCANS[@]}"; do
            echo "  - $img"
        done
    fi
}

# Generate CVE summary table
generate_cve_summary_table() {
    echo ""
    echo "🔍 CVE ANALYSIS SUMMARY"
    echo "======================="

    # Read data from the JSON report instead of recalculating
    local json_file="$OUTPUT_DIR/scan-summary.json"
    if [[ ! -f "$json_file" ]]; then
        echo "No scan summary available."
        return
    fi

    # Extract minimum CVE level and display it
    local min_cve_level=$(jq -r '.cve_analysis[0].min_cve_level // "HIGH"' "$json_file")
    echo "Minimum CVE Level: $min_cve_level (levels below this are considered irrelevant)"
    echo ""

    # Check if we have CVE analysis data
    local cve_count=$(jq '.cve_analysis | length' "$json_file")
    if [[ "$cve_count" == "0" ]]; then
        echo "No CVE analysis data available."
        return
    fi

    # Create table data using column utility
    local table_data="Image|Unaddressed CVEs|Addressed CVEs|Irrelevant CVEs|Triage File|Chainguard Base\n"

    # Read data from JSON and build table
    while IFS= read -r line; do
        local image=$(echo "$line" | jq -r '.image')
        local unaddressed=$(echo "$line" | jq -r '.unaddressed_cves')
        local addressed=$(echo "$line" | jq -r '.addressed_cves')
        local irrelevant=$(echo "$line" | jq -r '.irrelevant_cves')
        local has_triage=$(echo "$line" | jq -r '.has_triage_file')
        local is_chainguard=$(echo "$line" | jq -r '.is_chainguard')
        local base_image=$(echo "$line" | jq -r '.base_image')

        # Extract just image name and version (last component)
        local image_name=$(echo "$image" | sed 's|.*/||')

        # Add color coding for unaddressed CVEs
        local unaddressed_display="$unaddressed"
        if [[ $unaddressed -gt 0 ]]; then
            unaddressed_display="🔴 $unaddressed"
        else
            unaddressed_display="✅ $unaddressed"
        fi

        # Add color coding for triage file status
        local triage_display="➖ No"
        if [[ "$has_triage" == "true" ]]; then
            triage_display="✅ Yes"
        fi

        # Add color coding for Chainguard base image status (use grey minus for No)
        local chainguard_display="➖ No"
        if [[ "$is_chainguard" == "true" ]]; then
            # Check if it's a public Chainguard image (starts with cgr.dev/chainguard)
            if echo "$base_image" | grep -q "^cgr.dev/chainguard"; then
                chainguard_display="✅ Yes (public)"
            else
                chainguard_display="✅ Yes"
            fi
        fi

        # Add row to table data
        table_data+="$image_name|$unaddressed_display|$addressed|$irrelevant|$triage_display|$chainguard_display\n"

    done < <(jq -c '.cve_analysis[]' "$json_file")

    # Print table sorted alphabetically by Image (keep header at top)
    echo -e "$table_data" | {
        IFS= read -r header
        echo "$header"
        sort -t '|' -k1,1
    } | column -t -s '|'

    # Print summary statistics (calculated from JSON)
    local total_unaddressed=$(jq '[.cve_analysis[].unaddressed_cves] | add' "$json_file")
    local total_addressed=$(jq '[.cve_analysis[].addressed_cves] | add' "$json_file")
    local total_irrelevant=$(jq '[.cve_analysis[].irrelevant_cves] | add' "$json_file")
    local images_with_triage=$(jq '[.cve_analysis[] | select(.has_triage_file == true)] | length' "$json_file")
    local images_with_chainguard=$(jq '[.cve_analysis[] | select(.is_chainguard == true)] | length' "$json_file")
    local total_images=$(jq '.cve_analysis | length' "$json_file")

    echo ""
    echo "📈 SUMMARY STATISTICS"
    echo "===================="
    echo "Total unaddressed CVEs (≥$min_cve_level): $total_unaddressed"
    echo "Total addressed CVEs: $total_addressed"
    echo "Total irrelevant CVEs (<$min_cve_level): $total_irrelevant"
    echo "Images with triage files: $images_with_triage/$total_images"
    echo "Images with Chainguard base: $images_with_chainguard/$total_images"

    if [[ $total_unaddressed -eq 0 ]]; then
        echo "🎉 All relevant CVEs have been addressed!"
    else
        echo "⚠️  $total_unaddressed unaddressed CVEs need attention"
    fi
}


# Main execution
main() {
    # Handle cache statistics request
    if $CACHE_STATS; then
        init_cache
        show_cache_stats
        exit 0
    fi

    echo "🚀 Aleph Alpha - Signed Image Scanner" >&2
    echo >&2
    echo "⚙️ Selected options:" >&2
    log_result "Namespace: $NAMESPACE"
    log_result "Output directory: $OUTPUT_DIR"

    # Cache configuration
    if $NO_CACHE; then
        log_result "Cache: Disabled"
    else
        log_result "Cache: Enabled (dir: $CACHE_DIR, TTL: ${CACHE_TTL_HOURS}h)"
    fi

    if $DRY_RUN; then
        log_result "Mode: DRY RUN (no actual scanning)"
    fi

    if $TEST_FLOW; then
        log_result "Mode: TEST FLOW (only first valid image)"
    fi

    # Setup
    check_prerequisites
    setup_temp_dir
    init_cache
    load_ignore_list
    setup_kubectl

    # Initialize arrays to prevent undefined variable errors
    SUCCESSFUL_SCANS=()
    FAILED_SCANS=()
    SKIPPED_SCANS=()
    INACCESSIBLE_REGISTRIES=()
    ACCESSIBLE_REGISTRIES=()

    # Initialize counters
    IGNORED_IMAGES=0
    INACCESSIBLE_IMAGES=0

    # Create output directory (only if not dry-run)
    if ! $DRY_RUN; then
        # Clean existing results
        if [[ -d "$OUTPUT_DIR" ]]; then
            log_result "Cleaning existing results in: $OUTPUT_DIR"
            rm -rf "$OUTPUT_DIR"
        fi
        mkdir -p "$OUTPUT_DIR"
    fi

    # Extract and process images
    log_step "Starting image extraction and processing"
    extract_k8s_images
    log_step "Image extraction completed, starting image processing"
    log_verbose "About to call process_all_images function"
    process_all_images
    log_verbose "process_all_images function completed"
    log_step "Image processing completed"

    # Generate final report and CVE summary
    if ! $DRY_RUN; then
        log_step "Generating final report"
        # Generate final report first (creates JSON with CVE data)
        generate_final_report
        log_step "Generating CVE summary table"
        # Generate CVE summary table from JSON data
        generate_cve_summary_table
    fi

    log_success "Kubernetes image scanning completed!"
    log_verbose "Script execution finished successfully, cleanup will be handled by trap"
}

# Run main function
log_verbose "Starting main function execution"
main "$@"
log_verbose "Main function completed, script should exit normally"
