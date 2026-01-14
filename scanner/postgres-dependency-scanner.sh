#!/usr/bin/env bash
set -euo pipefail

# Postgres Dependency Scanner
# This script analyzes SBOMs from k8s-image-scanner.sh results to identify images with Postgres dependencies
# It also orchestrates the complete analysis workflow including repository discovery and dependency analysis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
  cat <<EOF
Postgres Dependency Scanner

This script analyzes SBOM files from k8s-image-scanner.sh scan results to identify
images that contain Postgres-related packages or dependencies.

Usage:
  $0 [OPTIONS]

Options:
  --scan-results-dir DIR        Directory containing scan results (default: ../scan-results/k8s-images relative to script)
  --output FILE                 Output file for results (default: ../scan-results/postgres-analysis/postgres-images.json, written to scan-results directory)
  --format FORMAT               Output format: json|table|list (default: json)
  --verbose                     Enable verbose logging
  --no-trivy                    Disable Trivy scanning for images without SBOMs (default: enabled)
  --trivy-timeout SECONDS       Timeout for Trivy scans (default: 300)
  --full-analysis               Run complete analysis workflow: SBOM analysis + repository discovery + dependency analysis (default: enabled)
  --no-repo-analysis            Skip repository discovery and dependency analysis (only analyze SBOMs)
  -h, --help                    Show this help

Examples:
  # Analyze existing scan results
  $0

  # Analyze with table output
  $0 --format table

  # Disable Trivy scanning (only analyze images with SBOMs)
  $0 --no-trivy

EOF
}

# Default configuration (relative to script directory)
SCAN_RESULTS_DIR="../scan-results/k8s-images"
OUTPUT_FILE="../scan-results/postgres-analysis/postgres-images.json"
FORMAT="json"
VERBOSE=false
USE_TRIVY=true  # Default: use Trivy to scan images without SBOMs
TRIVY_TIMEOUT=300
FULL_ANALYSIS=true  # Default: run complete analysis workflow

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --scan-results-dir)
      SCAN_RESULTS_DIR="$2"
      shift 2
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --format)
      FORMAT="$2"
      shift 2
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --no-trivy)
      USE_TRIVY=false
      shift
      ;;
    --trivy-timeout)
      TRIVY_TIMEOUT="$2"
      shift 2
      ;;
    --full-analysis)
      FULL_ANALYSIS=true
      shift
      ;;
    --no-repo-analysis)
      FULL_ANALYSIS=false
      shift
      ;;
    -h|--help)
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

log_verbose() {
  if $VERBOSE; then
    echo "[VERBOSE] $*" >&2
  fi
}

log_info() {
  echo "[INFO] $*" >&2
}

log_error() {
  echo "[ERROR] $*" >&2
}

# Print step header with visual separator
print_step_header() {
  local step_num="$1"
  local step_title="$2"
  local step_desc="$3"
  
  echo "" >&2
  echo "╔══════════════════════════════════════════════════════════════════════════════╗" >&2
  printf "║ STEP %s: %-65s ║\n" "$step_num" "$step_title" >&2
  echo "╠══════════════════════════════════════════════════════════════════════════════╣" >&2
  if [[ -n "$step_desc" ]]; then
    printf "║ %-76s ║\n" "$step_desc" >&2
    echo "╚══════════════════════════════════════════════════════════════════════════════╝" >&2
  else
    echo "╚══════════════════════════════════════════════════════════════════════════════╝" >&2
  fi
  echo "" >&2
}

# Print step summary
print_step_summary() {
  local summary_title="$1"
  shift
  local summary_items=("$@")
  
  log_info "📋 $summary_title:"
  for item in "${summary_items[@]}"; do
    log_info "   • $item"
  done
  echo "" >&2
}

# Postgres-related package patterns to search for
# These cover common Postgres packages across different ecosystems
declare -a POSTGRES_PATTERNS=(
  "postgresql"
  "postgres"
  "psycopg"
  "psycopg2"
  "psycopg3"
  "pg"
  "libpq"
  "postgresql-client"
  "postgres-client"
  "pg_dump"
  "pg_restore"
  "postgresql-server"
  "postgresql-contrib"
  "postgresql-dev"
  "postgresql-devel"
  "libpq-dev"
  "libpq5"
  "node-postgres"
  "pg-promise"
  "sequelize"
  "typeorm"
  "prisma"
  "diesel"
  "sqlx"
  "gorm"
  "activerecord"
  "sqlalchemy"
  "asyncpg"
  "tortoise-orm"
)

# Check if a package name matches Postgres patterns
is_postgres_package() {
  local package_name="$1"
  local package_lower="${package_name,,}"  # Convert to lowercase
  
  for pattern in "${POSTGRES_PATTERNS[@]}"; do
    if [[ "$package_lower" == *"${pattern,,}"* ]]; then
      return 0
    fi
  done
  
  return 1
}

# Analyze CycloneDX SBOM
analyze_cyclonedx_sbom() {
  local sbom_file="$1"
  local image="$2"
  local postgres_packages=()
  
  if [[ ! -f "$sbom_file" ]]; then
    return 1
  fi
  
  # Check if valid JSON
  if ! jq empty "$sbom_file" 2>/dev/null; then
    log_verbose "Invalid JSON in SBOM: $sbom_file"
    return 1
  fi
  
  # Extract components from CycloneDX format
  # CycloneDX has components array with name, purl, etc.
  local components
  if ! components=$(jq -r '.components[]? | "\(.name)|\(.purl // "")|\(.type // "")"' "$sbom_file" 2>/dev/null); then
    log_verbose "No components found in CycloneDX SBOM: $sbom_file"
    return 1
  fi
  
  while IFS='|' read -r name purl type; do
    if [[ -z "$name" ]]; then
      continue
    fi
    
    # Check package name
    if is_postgres_package "$name"; then
      postgres_packages+=("$name")
      log_verbose "Found Postgres package in $image: $name"
    fi
    
    # Check PURL (Package URL) for Postgres references
    if [[ -n "$purl" ]] && is_postgres_package "$purl"; then
      postgres_packages+=("$purl")
      log_verbose "Found Postgres package in $image (PURL): $purl"
    fi
  done <<< "$components"
  
  # Also check dependencies
  local dependencies
  if dependencies=$(jq -r '.dependencies[]?.ref // empty' "$sbom_file" 2>/dev/null); then
    while read -r dep_ref; do
      if [[ -n "$dep_ref" ]] && is_postgres_package "$dep_ref"; then
        postgres_packages+=("$dep_ref")
        log_verbose "Found Postgres dependency in $image: $dep_ref"
      fi
    done <<< "$dependencies"
  fi
  
  # Return unique packages
  if [[ ${#postgres_packages[@]} -gt 0 ]]; then
    printf '%s\n' "${postgres_packages[@]}" | sort -u | tr '\n' '|'
    return 0
  fi
  
  return 1
}

# Analyze SPDX SBOM
analyze_spdx_sbom() {
  local sbom_file="$1"
  local image="$2"
  local postgres_packages=()
  
  if [[ ! -f "$sbom_file" ]]; then
    return 1
  fi
  
  # Check if valid JSON
  if ! jq empty "$sbom_file" 2>/dev/null; then
    log_verbose "Invalid JSON in SBOM: $sbom_file"
    return 1
  fi
  
  # Extract packages from SPDX format
  # SPDX has packages array with name, externalRefs, etc.
  local packages
  if ! packages=$(jq -r '.packages[]? | "\(.name)|\(.externalRefs[]?.referenceLocator // "")"' "$sbom_file" 2>/dev/null); then
    log_verbose "No packages found in SPDX SBOM: $sbom_file"
    return 1
  fi
  
  while IFS='|' read -r name ref; do
    if [[ -z "$name" ]]; then
      continue
    fi
    
    # Check package name
    if is_postgres_package "$name"; then
      postgres_packages+=("$name")
      log_verbose "Found Postgres package in $image: $name"
    fi
    
    # Check external reference
    if [[ -n "$ref" ]] && is_postgres_package "$ref"; then
      postgres_packages+=("$ref")
      log_verbose "Found Postgres package in $image (ref): $ref"
    fi
  done <<< "$packages"
  
  # Return unique packages
  if [[ ${#postgres_packages[@]} -gt 0 ]]; then
    printf '%s\n' "${postgres_packages[@]}" | sort -u | tr '\n' '|'
    return 0
  fi
  
  return 1
}

# Analyze SBOM file (auto-detect format)
analyze_sbom() {
  local sbom_file="$1"
  local image="$2"
  local packages=""
  
  if [[ ! -f "$sbom_file" ]]; then
    return 1
  fi
  
  # Detect SBOM format
  if jq -e '.bomFormat // .spdxVersion' "$sbom_file" >/dev/null 2>&1; then
    # Check for CycloneDX
    if jq -e '.bomFormat' "$sbom_file" >/dev/null 2>&1; then
      log_verbose "Detected CycloneDX format: $sbom_file"
      packages=$(analyze_cyclonedx_sbom "$sbom_file" "$image")
    # Check for SPDX
    elif jq -e '.spdxVersion' "$sbom_file" >/dev/null 2>&1; then
      log_verbose "Detected SPDX format: $sbom_file"
      packages=$(analyze_spdx_sbom "$sbom_file" "$image")
    else
      log_verbose "Unknown SBOM format: $sbom_file"
      return 1
    fi
  else
    log_verbose "Invalid SBOM format: $sbom_file"
    return 1
  fi
  
  if [[ -n "$packages" ]]; then
    echo "$packages"
    return 0
  fi
  
  return 1
}

# Show spinner while command runs in background
show_spinner() {
  local pid=$1
  local message="$2"
  local spin='-\|/'
  local i=0
  
  while kill -0 "$pid" 2>/dev/null; do
    i=$(((i + 1) % 4))
    printf "\r%s %s" "$message" "${spin:$i:1}" >&2
    sleep 0.1
  done
  printf "\r%*s\r" 100 "" >&2  # Clear the spinner line
}

# Use Trivy to scan image for Postgres (fallback for images without SBOMs)
scan_image_with_trivy() {
  local image="$1"
  local postgres_packages=()
  
  if ! command -v trivy &> /dev/null; then
    log_error "Trivy not found. Install Trivy to use --use-trivy option"
    return 1
  fi
  
  log_verbose "Scanning image with Trivy: $image"
  
  # Use Trivy to get installed packages
  # Run in background and show spinner
  local trivy_output
  local temp_file
  temp_file=$(mktemp)
  
  # Start Trivy in background
  (timeout "$TRIVY_TIMEOUT" trivy image --format json --timeout "${TRIVY_TIMEOUT}s" "$image" 2>/dev/null > "$temp_file") &
  local trivy_pid=$!
  
  # Show spinner while Trivy runs
  show_spinner "$trivy_pid" "[INFO] Scanning with Trivy..."
  
  # Wait for process and get exit code
  wait "$trivy_pid"
  local trivy_exit=$?
  
  if [[ $trivy_exit -eq 0 ]] && [[ -s "$temp_file" ]]; then
    trivy_output=$(cat "$temp_file")
    rm -f "$temp_file"
  else
    log_verbose "Trivy scan failed for: $image"
    rm -f "$temp_file"
    return 1
  fi
  
  # Extract package names from Trivy JSON output
  local packages
  if packages=$(echo "$trivy_output" | jq -r '.Results[]?.Packages[]?.Name // empty' 2>/dev/null); then
    while read -r pkg_name; do
      if [[ -n "$pkg_name" ]] && is_postgres_package "$pkg_name"; then
        postgres_packages+=("$pkg_name")
        log_verbose "Found Postgres package via Trivy in $image: $pkg_name"
      fi
    done <<< "$packages"
  fi
  
  # Return unique packages
  if [[ ${#postgres_packages[@]} -gt 0 ]]; then
    printf '%s\n' "${postgres_packages[@]}" | sort -u | tr '\n' '|'
    return 0
  fi
  
  return 1
}

# Write incremental results to temporary file
write_incremental_results() {
  local temp_file="$1"
  local current="$2"
  local total="$3"
  local postgres_count="$4"
  local without_sbom_count="$5"
  shift 5
  # Handle empty array case - if no arguments left, array is empty
  local postgres_entries=()
  if [[ $# -gt 0 ]]; then
    postgres_entries=("$@")
  fi
  
  # Calculate percentage
  local percent=0
  if [[ $total -gt 0 ]]; then
    percent=$(awk -v c="$current" -v t="$total" 'BEGIN {printf "%.1f", (c / t) * 100}')
  fi
  
  {
    echo "{"
    echo "  \"status\": \"in_progress\","
    echo "  \"progress\": {"
    echo "    \"current\": $current,"
    echo "    \"total\": $total,"
    echo "    \"percent\": $percent"
    echo "  },"
    echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"images_with_postgres\": $postgres_count,"
    echo "  \"images_without_sbom\": $without_sbom_count,"
    echo "  \"images\": ["
    local first=true
    if [[ ${#postgres_entries[@]} -gt 0 ]]; then
      for entry in "${postgres_entries[@]}"; do
        if [[ -n "$entry" ]]; then
          IFS='|' read -r image pkg_list <<< "$entry"
          if [[ "$first" == "true" ]]; then
            first=false
          else
            echo ","
          fi
          echo -n "    {"
          echo -n "\"image\": \"$image\","
          echo -n "\"packages\": ["
          IFS=' ' read -ra pkgs <<< "$pkg_list"
          local pkg_first=true
          for pkg in "${pkgs[@]}"; do
            if [[ -n "$pkg" ]]; then
              if [[ "$pkg_first" == "true" ]]; then
                pkg_first=false
              else
                echo -n ", "
              fi
              echo -n "\"$pkg\""
            fi
          done
          echo -n "]"
          echo -n "}"
        fi
      done
    fi
    echo ""
    echo "  ]"
    echo "}"
  } > "$temp_file"
}

# Main analysis function
main() {
  local scan_dir
  
  # Resolve scan results directory (relative to script directory if not absolute)
  if [[ -z "$SCAN_RESULTS_DIR" ]]; then
    # Default: scan-results in parent directory of script
    scan_dir="$(cd "$SCRIPT_DIR/../scan-results" && pwd)"
  elif [[ "$SCAN_RESULTS_DIR" == /* ]]; then
    # Absolute path
    scan_dir="$SCAN_RESULTS_DIR"
  else
    # Relative path - resolve from script directory
    scan_dir="$(cd "$SCRIPT_DIR/$SCAN_RESULTS_DIR" && pwd)"
  fi
  
  if [[ ! -d "$scan_dir" ]]; then
    log_error "Scan results directory not found: $scan_dir"
    log_error "Expected location: $SCRIPT_DIR/../scan-results"
    exit 1
  fi
  
  log_info "Analyzing scan results in: $scan_dir"
  echo "" >&2
  
  # Resolve output file path
  local output_path
  if [[ "$OUTPUT_FILE" == /* ]]; then
    # Absolute path
    output_path="$OUTPUT_FILE"
  elif [[ "$OUTPUT_FILE" == ../* ]]; then
    # Relative path starting with ../ - resolve relative to script directory
    local rel_dir
    rel_dir="$(dirname "$OUTPUT_FILE")"
    local filename
    filename="$(basename "$OUTPUT_FILE")"
    # Resolve directory part (may not exist yet)
    if [[ -d "$SCRIPT_DIR/$rel_dir" ]]; then
      output_path="$(cd "$SCRIPT_DIR/$rel_dir" && pwd)/$filename"
    else
      # Directory doesn't exist yet, construct absolute path
      output_path="$(cd "$SCRIPT_DIR" && pwd)/$rel_dir/$filename"
    fi
  else
    # Relative path - resolve relative to scan results directory
    local rel_dir
    rel_dir="$(dirname "$OUTPUT_FILE")"
    local filename
    filename="$(basename "$OUTPUT_FILE")"
    # Resolve directory part (may not exist yet)
    if [[ -d "$scan_dir/$rel_dir" ]]; then
      output_path="$(cd "$scan_dir/$rel_dir" && pwd)/$filename"
    else
      # Directory doesn't exist yet, construct absolute path
      output_path="$(cd "$scan_dir" && pwd)/$rel_dir/$filename"
    fi
  fi
  
  # STEP 1: SBOM Analysis
  print_step_header "1" "SBOM Analysis" "Analyzing SBOM files to identify images with PostgreSQL dependencies"
  
  # Check if output file already exists
  local skip_sbom_analysis=false
  if [[ -f "$output_path" ]]; then
    log_info "✓ Output file already exists: $output_path"
    log_info "  Skipping SBOM analysis step"
    skip_sbom_analysis=true
    
    # Show summary from existing file if possible
    if command -v jq &>/dev/null; then
      local total_images_in_file
      total_images_in_file=$(jq '.images | length' "$output_path" 2>/dev/null || echo "0")
      if [[ "$total_images_in_file" != "0" ]]; then
        print_step_summary "Summary from existing file" \
          "Images with Postgres: $total_images_in_file"
      fi
    fi
    echo "" >&2
  else
    # Print step summary before starting
    print_step_summary "SBOM Analysis Summary" \
      "Input: Scan results directory ($scan_dir)" \
      "Output: $output_path" \
      "Process: Analyze SBOM files for PostgreSQL packages" \
      "Fallback: Use Trivy for images without SBOMs (if enabled)"
    
    # Skip SBOM analysis if output already exists
    if [[ "$skip_sbom_analysis" == "true" ]]; then
      # Continue to complete analysis workflow if enabled
      # (the workflow check happens later in the function)
      :
    else
      # Ensure output directory exists
      local output_dir
      output_dir="$(dirname "$output_path")"
      if [[ ! -d "$output_dir" ]]; then
        log_info "Creating output directory: $output_dir"
        mkdir -p "$output_dir"
      fi
      
      # Create temporary file for incremental results
      local temp_output_file="${output_path}.tmp"
      local start_time
      start_time=$(date +%s)
      
      # Results storage
      declare -a images_with_postgres=()
      declare -a images_without_sbom=()
      local total_images=0
      local images_analyzed=0
      
      # Count total images first for progress display
      while IFS= read -r -d '' image_dir; do
        total_images=$((total_images + 1))
      done < <(find "$scan_dir" -mindepth 1 -maxdepth 1 -type d -print0)
      
      if [[ $total_images -eq 0 ]]; then
        log_error "No image directories found in: $scan_dir"
        exit 1
      fi
      
      log_info "Found $total_images images to analyze (from scan result directories)"
      log_info ""
      log_info "Note: The SBOM analysis above only processes images with scan directories."
      log_info "      The repository discovery step will process ALL images from scan-summary.json."
      log_info ""
      
      # Process each image directory
      local current_image=0
      while IFS= read -r -d '' image_dir; do
        current_image=$((current_image + 1))
        
        # Extract image name from directory
        # Directory format: registry_domain_path_image_tag -> registry/domain/path/image:tag
        local image_name
        local dir_name
        dir_name=$(basename "$image_dir")
        # The last underscore-separated segment is typically the tag
        # Convert all underscores to slashes, then convert the last slash to a colon
        image_name=$(echo "$dir_name" | sed 's|_|/|g' | sed 's|\(.*\)/\([^/]*\)$|\1:\2|')
        
        # Show progress
        printf "[INFO] Processing: [%d/%d] %s\n" "$current_image" "$total_images" "$image_name" >&2
        log_verbose "Processing: $image_name (from dir: $dir_name)"
        
        # Check for SBOM file
        local sbom_file="$image_dir/sbom.json"
        local packages=""
        
        if [[ -f "$sbom_file" ]]; then
          log_verbose "Found SBOM: $sbom_file"
          if packages=$(analyze_sbom "$sbom_file" "$image_name"); then
            images_analyzed=$((images_analyzed + 1))
            # Convert packages string back to array
            IFS='|' read -ra pkg_array <<< "$packages"
            images_with_postgres+=("$image_name|${pkg_array[*]}")
            printf "       ✓ Found Postgres packages\n" >&2
            # Write incremental result
            if [[ ${#images_with_postgres[@]} -gt 0 ]]; then
              write_incremental_results "$temp_output_file" "$current_image" "$total_images" "${#images_with_postgres[@]}" "${#images_without_sbom[@]}" "${images_with_postgres[@]}"
            else
              write_incremental_results "$temp_output_file" "$current_image" "$total_images" "${#images_with_postgres[@]}" "${#images_without_sbom[@]}"
            fi
          else
            log_verbose "No Postgres packages found in: $image_name"
          fi
        else
          log_verbose "No SBOM found for: $image_name"
          images_without_sbom+=("$image_name")
          
          # Try Trivy if enabled
          if $USE_TRIVY; then
            if packages=$(scan_image_with_trivy "$image_name"); then
              images_analyzed=$((images_analyzed + 1))
              IFS='|' read -ra pkg_array <<< "$packages"
              images_with_postgres+=("$image_name|${pkg_array[*]}")
              printf "       ✓ Found Postgres packages (via Trivy)\n" >&2
              # Write incremental result
              if [[ ${#images_with_postgres[@]} -gt 0 ]]; then
                write_incremental_results "$temp_output_file" "$current_image" "$total_images" "${#images_with_postgres[@]}" "${#images_without_sbom[@]}" "${images_with_postgres[@]}"
              else
                write_incremental_results "$temp_output_file" "$current_image" "$total_images" "${#images_with_postgres[@]}" "${#images_without_sbom[@]}"
              fi
            else
              # No Postgres found via Trivy
              log_verbose "No Postgres packages found via Trivy in: $image_name"
            fi
          fi
          # Update temp file even if no Postgres found (to show progress)
          if [[ ${#images_with_postgres[@]} -gt 0 ]]; then
            write_incremental_results "$temp_output_file" "$current_image" "$total_images" "${#images_with_postgres[@]}" "${#images_without_sbom[@]}" "${images_with_postgres[@]}"
          else
            write_incremental_results "$temp_output_file" "$current_image" "$total_images" "${#images_with_postgres[@]}" "${#images_without_sbom[@]}"
          fi
        fi
      done < <(find "$scan_dir" -mindepth 1 -maxdepth 1 -type d -print0)
      
      # Generate final output
      echo "" >&2
      log_info "Analysis complete:"
      log_info "  Total images: $total_images"
      log_info "  Images with Postgres: ${#images_with_postgres[@]}"
      log_info "  Images without SBOM: ${#images_without_sbom[@]}"
      log_info "  Temporary results: $temp_output_file"
      
        case "$FORMAT" in
          json)
            {
              echo "{"
              echo "  \"analysis_timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
              echo "  \"total_images\": $total_images,"
              echo "  \"images_with_postgres\": ${#images_with_postgres[@]},"
              echo "  \"images_without_sbom\": ${#images_without_sbom[@]},"
              echo "  \"images\": ["
              local first=true
              if [[ ${#images_with_postgres[@]} -gt 0 ]]; then
                for entry in "${images_with_postgres[@]}"; do
                  IFS='|' read -r image pkg_list <<< "$entry"
                  if [[ "$first" == "true" ]]; then
                    first=false
                  else
                    echo ","
                  fi
                  echo -n "    {"
                  echo -n "\"image\": \"$image\","
                  echo -n "\"packages\": ["
                  IFS=' ' read -ra pkgs <<< "$pkg_list"
                  local pkg_first=true
                  for pkg in "${pkgs[@]}"; do
                    if [[ -n "$pkg" ]]; then
                      if [[ "$pkg_first" == "true" ]]; then
                        pkg_first=false
                      else
                        echo -n ", "
                      fi
                      echo -n "\"$pkg\""
                    fi
                  done
                  echo -n "]"
                  echo -n "}"
                done
              fi
              echo ""
              echo "  ],"
              echo "  \"images_without_sbom\": ["
              first=true
              if [[ ${#images_without_sbom[@]} -gt 0 ]]; then
                for image in "${images_without_sbom[@]}"; do
                  if [[ "$first" == "true" ]]; then
                    first=false
                  else
                    echo ","
                  fi
                  echo -n "    \"$image\""
                done
              fi
              echo ""
              echo "  ]"
              echo "}"
            } > "$output_path"
            # Remove temporary file now that final output is written
            rm -f "$temp_output_file"
            log_info "Results written to: $output_path"
            ;;
          table)
            {
              echo "Images Using Postgres:"
              echo "======================"
              echo ""
              printf "%-60s %s\n" "IMAGE" "POSTGRES PACKAGES"
              printf "%-60s %s\n" "-----" "-----------------"
              if [[ ${#images_with_postgres[@]} -gt 0 ]]; then
                for entry in "${images_with_postgres[@]}"; do
                  IFS='|' read -r image pkg_list <<< "$entry"
                  printf "%-60s %s\n" "$image" "$pkg_list"
                done
              else
                echo "(none)"
              fi
              echo ""
              echo "Images Without SBOM (${#images_without_sbom[@]}):"
              echo "=========================================="
              if [[ ${#images_without_sbom[@]} -gt 0 ]]; then
                for image in "${images_without_sbom[@]}"; do
                  echo "  - $image"
                done
              else
                echo "  (none)"
              fi
            } > "$output_path"
            # Remove temporary file now that final output is written
            rm -f "$temp_output_file"
            log_info "Results written to: $output_path"
            ;;
          list)
            {
              if [[ ${#images_with_postgres[@]} -gt 0 ]]; then
                for entry in "${images_with_postgres[@]}"; do
                  IFS='|' read -r image pkg_list <<< "$entry"
                  echo "$image"
                done
              fi
            } > "$output_path"
            # Remove temporary file now that final output is written
            rm -f "$temp_output_file"
            log_info "Results written to: $output_path"
            ;;
        esac
      fi  # End of skip_sbom_analysis else block
    fi  # End of if [[ -f "$output_path" ]] else block
  
  # Run full analysis workflow if enabled
  if $FULL_ANALYSIS; then
    # Setup paths for complete analysis workflow
    # Note: scan_dir already points to k8s-images directory
    local scan_summary_file="$scan_dir/scan-summary.json"
    # postgres-analysis is in the parent directory (scan-results), not inside k8s-images
    local postgres_analysis_dir="$(dirname "$scan_dir")/postgres-analysis"
    local image_source_analysis_file="$postgres_analysis_dir/image-source-analysis.json"
    local generate_script="$SCRIPT_DIR/postgres-dependency-scanner/generate-image-source-analysis.py"
    local analyze_script="$SCRIPT_DIR/postgres-dependency-scanner/analyze-postgres-dependencies.py"
    
    # Create postgres-analysis directory if it doesn't exist
    mkdir -p "$postgres_analysis_dir"
    
    # Ensure generate script is executable
    if [[ -f "$generate_script" ]]; then
      chmod +x "$generate_script" 2>/dev/null || true
    fi
    
    # Ensure analyze script is executable
    if [[ -f "$analyze_script" ]]; then
      chmod +x "$analyze_script" 2>/dev/null || true
    fi
    
    # Check if scan-summary.json exists
    if [[ ! -f "$scan_summary_file" ]]; then
      log_error "scan-summary.json not found: $scan_summary_file"
      log_error "Skipping repository discovery and dependency analysis"
      log_info "Run k8s-image-scanner.sh first to generate scan-summary.json"
      return 0
    fi
    
    # STEP 2: Repository Discovery
    print_step_header "2" "Repository Discovery" "Discovering source repositories for images with PostgreSQL dependencies"
    
    print_step_summary "Repository Discovery Summary" \
      "Input: scan-summary.json ($scan_summary_file)" \
      "Output: image-source-analysis.json ($image_source_analysis_file)" \
      "Process: Match images to their source repositories" \
      "Note: Processes ALL images from scan-summary.json (not just those with scan directories)"
    
    # Check if image-source-analysis.json already exists
    if [[ -f "$image_source_analysis_file" ]]; then
      log_info "✓ image-source-analysis.json already exists: $image_source_analysis_file"
      log_info "  Skipping repository discovery step"
      echo "" >&2
      
      # Show summary from existing file
      if command -v jq &>/dev/null; then
        local total_processed
        local found_count
        local not_found_count
        
        total_processed=$(jq '.results | length' "$image_source_analysis_file" 2>/dev/null || echo "0")
        found_count=$(jq '[.results[] | select(.status == "found")] | length' "$image_source_analysis_file" 2>/dev/null || echo "0")
        not_found_count=$(jq '[.results[] | select(.status == "not_found")] | length' "$image_source_analysis_file" 2>/dev/null || echo "0")
        
        if [[ "$total_processed" != "0" ]]; then
          print_step_summary "Summary from existing file" \
            "Total images processed: $total_processed" \
            "Repositories found: $found_count" \
            "Repositories not found: $not_found_count"
        fi
      fi
    elif [[ ! -f "$generate_script" ]]; then
      log_error "generate-image-source-analysis.py not found: $generate_script"
      log_error "Skipping repository discovery"
    else
      # Count images in scan-summary.json for reporting
      if [[ -f "$scan_summary_file" ]] && command -v jq &>/dev/null; then
        local total_in_summary
        local successful_count
        local failed_count
        local skipped_count
        
        total_in_summary=$(jq '[.successful_scans[], .failed_scans[], .skipped_scans[]] | length' "$scan_summary_file" 2>/dev/null || echo "0")
        successful_count=$(jq '.successful_scans | length' "$scan_summary_file" 2>/dev/null || echo "0")
        failed_count=$(jq '.failed_scans | length' "$scan_summary_file" 2>/dev/null || echo "0")
        skipped_count=$(jq '.skipped_scans | length' "$scan_summary_file" 2>/dev/null || echo "0")
        
        if [[ "$total_in_summary" != "0" ]]; then
          log_info "  Images in scan-summary.json: $total_in_summary total"
          log_info "    - Successful: $successful_count"
          log_info "    - Failed: $failed_count"
          log_info "    - Skipped: $skipped_count"
        fi
      fi
      local verbose_flag=""
      if $VERBOSE; then
        verbose_flag="--verbose"
      fi
      
      log_info "  Running: python3 $generate_script --scan-summary $scan_summary_file --output $image_source_analysis_file"
      log_info ""
      
      # Run the script with live output (unbuffered for real-time progress)
      python3 -u "$generate_script" \
        --scan-summary "$scan_summary_file" \
        --output "$image_source_analysis_file" \
        $verbose_flag
      local script_exit_code=$?
      
      log_info ""
      
      if [[ $script_exit_code -eq 0 ]]; then
        log_info ""
        log_info "✓ Successfully generated: $image_source_analysis_file"
        
        # Show summary from the generated file if it exists
        if [[ -f "$image_source_analysis_file" ]] && command -v jq &>/dev/null; then
          local total_processed
          local found_count
          local not_found_count
          
          total_processed=$(jq '.results | length' "$image_source_analysis_file" 2>/dev/null || echo "0")
          found_count=$(jq '[.results[] | select(.status == "found")] | length' "$image_source_analysis_file" 2>/dev/null || echo "0")
          not_found_count=$(jq '[.results[] | select(.status == "not_found")] | length' "$image_source_analysis_file" 2>/dev/null || echo "0")
          
          if [[ "$total_processed" != "0" ]]; then
            log_info "  Summary:"
            log_info "    - Total images processed: $total_processed"
            log_info "    - Repositories found: $found_count"
            log_info "    - Repositories not found: $not_found_count"
          fi
        fi
      else
        local exit_code=$?
        log_error ""
        log_error "Failed to generate image-source-analysis.json (exit code: $exit_code)"
        log_error "Skipping dependency analysis"
        return 1
      fi
    fi
    
    # STEP 3: Dependency Analysis
    print_step_header "3" "Dependency Analysis" "Analyzing PostgreSQL dependencies in source repositories"
    
    local postgres_dependency_analysis_file="$postgres_analysis_dir/postgres-dependency-analysis.json"
    
    print_step_summary "Dependency Analysis Summary" \
      "Input: image-source-analysis.json ($image_source_analysis_file)" \
      "Output: postgres-dependency-analysis.json ($postgres_dependency_analysis_file)" \
      "Process: Scan repositories for PostgreSQL dependencies and migration effort"
    
    # Check if postgres-dependency-analysis.json already exists
    if [[ -f "$postgres_dependency_analysis_file" ]]; then
      log_info "✓ postgres-dependency-analysis.json already exists: $postgres_dependency_analysis_file"
      log_info "  Skipping dependency analysis step"
      echo "" >&2
      
      # Show summary from existing file if possible
      if command -v jq &>/dev/null; then
        local total_projects
        total_projects=$(jq '.projects | length' "$postgres_dependency_analysis_file" 2>/dev/null || echo "0")
        if [[ "$total_projects" != "0" ]]; then
          print_step_summary "Summary from existing file" \
            "Total projects analyzed: $total_projects"
        fi
      fi
    elif [[ ! -f "$analyze_script" ]]; then
      log_error "analyze-postgres-dependencies.py not found: $analyze_script"
      log_error "Skipping dependency analysis"
    elif [[ ! -f "$image_source_analysis_file" ]]; then
      log_error "image-source-analysis.json not found: $image_source_analysis_file"
      log_error "Skipping dependency analysis"
    else
      # Run the script from its directory
      local original_dir
      original_dir="$(pwd)"
      cd "$(dirname "$analyze_script")" || exit 1
      
      log_info "  Running: python3 $(basename "$analyze_script")"
      log_info "  Working directory: $(pwd)"
      log_info "  Input file: $image_source_analysis_file"
      log_info "  Output file: $postgres_dependency_analysis_file"
      log_info ""
      
      # Run the script with live output (unbuffered for real-time progress)
      python3 -u "$analyze_script"
      local script_exit_code=$?
      
      log_info ""
      
      if [[ $script_exit_code -eq 0 ]]; then
        log_info ""
        log_info "✓ Successfully generated postgres-dependency-analysis.json"
        log_info "  Location: $postgres_dependency_analysis_file"
      else
        log_error ""
        log_error "Failed to analyze PostgreSQL dependencies (exit code: $script_exit_code)"
        if [[ -n "$script_output" ]]; then
          log_error "Script output:"
          echo "$script_output" | while IFS= read -r line; do
            log_error "  $line"
          done
        fi
        cd "$original_dir" || exit 1
        return 1
      fi
      
      cd "$original_dir" || exit 1
    fi
    
    echo "" >&2
    echo "╔══════════════════════════════════════════════════════════════════════════════╗" >&2
    echo "║ ✓ COMPLETE ANALYSIS WORKFLOW FINISHED                                        ║" >&2
    echo "╚══════════════════════════════════════════════════════════════════════════════╝" >&2
    echo "" >&2
    print_step_summary "Generated Files" \
      "SBOM Analysis: $output_path" \
      "Repository Discovery: $image_source_analysis_file" \
      "Dependency Analysis: $postgres_dependency_analysis_file"
  else
    log_info ""
    log_info "Skipping repository discovery and dependency analysis (--no-repo-analysis)"
  fi
}

main "$@"

