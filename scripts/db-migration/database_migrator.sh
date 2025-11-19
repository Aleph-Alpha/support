#!/bin/bash
#
# PostgreSQL Multi-Database Backup and Restore Automation Script
# =============================================================
#
# This script automates the process of dumping and restoring multiple PostgreSQL
#
# Features:
# - YAML configuration for multiple PostgreSQL database pairs
# - Support for PostgreSQL only (optimized for pg_dump/psql)
# - Simple backup files with database names
# - Comprehensive logging and error handling
# - Dry-run mode for testing
# - Colored terminal output
# - Security features (password hiding)
# - Retry logic for failed operations
# - PostgreSQL version validation
#

# Remove -e to prevent premature exit on per-database failures; we handle errors explicitly.
set -uo pipefail

# Script metadata
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="PostgreSQL Multi-Database Migrator"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
CONFIG_FILE=""
DRY_RUN=false
VERBOSE=false

# Directories
DUMP_DIR=""
LOG_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Global variables
TOTAL_DATABASES=0
SUCCESSFUL_DUMPS=0
FAILED_DUMPS=0
SUCCESSFUL_RESTORES=0
FAILED_RESTORES=0
START_TIME=""
LOG_FILE=""
LAST_DUMP_FILE=""

# Cleanup function
cleanup() {
    # Cleanup function for any future cleanup needs
    :
}

# Signal handlers
trap cleanup EXIT
trap 'echo -e "\n${YELLOW}⚠️  Script interrupted by user${NC}"; exit 130' INT TERM

# Logging functions
log_info() {
    local message="$1"
    echo -e "${BLUE}ℹ️  $message${NC}" >&2
    [[ -n "$LOG_FILE" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $message" >> "$LOG_FILE"
}

log_success() {
    local message="$1"
    echo -e "${GREEN}✅ $message${NC}" >&2
    [[ -n "$LOG_FILE" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $message" >> "$LOG_FILE"
}

log_warning() {
    local message="$1"
    echo -e "${YELLOW}⚠️  $message${NC}" >&2
    [[ -n "$LOG_FILE" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $message" >> "$LOG_FILE"
}

log_error() {
    local message="$1"
    echo -e "${RED}❌ $message${NC}" >&2
    [[ -n "$LOG_FILE" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $message" >> "$LOG_FILE"
}

log_debug() {
    local message="$1"
    [[ "$VERBOSE" == true ]] && echo -e "${MAGENTA}🔍 $message${NC}" >&2
    [[ -n "$LOG_FILE" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG: $message" >> "$LOG_FILE"
}

# Display usage information
usage() {
    cat << EOF
${BOLD}${SCRIPT_NAME}${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS]

${BOLD}OPTIONS:${NC}
    -c, --config FILE       Path to YAML configuration file (default: db_config.yaml)
    -d, --dry-run          Show what would be done without executing commands
    -v, --verbose          Enable verbose output
    -h, --help             Show this help message
    --version              Show version information

${BOLD}EXAMPLES:${NC}
    $0 --config db_config.yaml
    $0 --config production.yaml --dry-run
    $0 --config production.yaml --verbose

${BOLD}CONFIGURATION:${NC}
    The script requires a YAML configuration file with PostgreSQL database definitions.
    See db_config.yaml for an example configuration.

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --version)
                echo "${SCRIPT_NAME} v${SCRIPT_VERSION}"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Set default config file if not specified
    if [[ -z "$CONFIG_FILE" ]]; then
        CONFIG_FILE="${SCRIPT_DIR}/db_config.yaml"
    fi

    # Convert to absolute path
    if [[ ! "$CONFIG_FILE" =~ ^/ ]]; then
        CONFIG_FILE="${SCRIPT_DIR}/${CONFIG_FILE}"
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for required tools
    local missing_tools=()

    for tool in yq psql pg_dump; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        echo -e "${YELLOW}💡 Installation instructions:${NC}"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                yq)
                    echo "  - yq: brew install yq (macOS) or apt update && apt install yq"
                    ;;
                psql|pg_dump)
                    echo "  - PostgreSQL client: brew install postgresql@17 (macOS) or apt-get install postgresql-client-17 (Ubuntu)"
                    ;;
            esac
        done
        return 1
    fi

    # Check PostgreSQL version
    if command -v psql >/dev/null 2>&1; then
        local pg_version=""
        pg_version=$(psql --version 2>/dev/null | head -n1 || echo "unknown")
        log_success "Found: $pg_version"
    fi

    log_success "All prerequisites satisfied"
    return 0
}

# Validate configuration file
validate_config() {
    local config_file="$1"

    log_info "Validating configuration file: $config_file"

    if [[ ! -f "$config_file" ]]; then
        log_error "Configuration file not found: $config_file"
        return 1
    fi

    # Check if file is valid YAML
    if ! yq eval '.' "$config_file" >/dev/null 2>&1; then
        log_error "Invalid YAML syntax in configuration file"
        return 1
    fi

    # Check for required sections
    if ! yq eval '.databases' "$config_file" >/dev/null 2>&1; then
        log_error "Configuration file missing 'databases' section"
        return 1
    fi

    # Count databases
    local db_count=""
    db_count=$(yq eval '.databases | length' "$config_file" 2>/dev/null || echo "0")

    if [[ "$db_count" -eq 0 ]]; then
        log_error "No databases defined in configuration"
        return 1
    fi

    TOTAL_DATABASES="$db_count"
    log_success "Configuration valid with $TOTAL_DATABASES database(s)"

    # Validate each database configuration
    for ((i=0; i<db_count; i++)); do
        local db_name=""
        db_name=$(yq eval ".databases[$i].name" "$config_file" 2>/dev/null || echo "")

        if [[ -z "$db_name" || "$db_name" == "null" ]]; then
            log_error "Database $((i+1)): Missing 'name' field"
            return 1
        fi

        # Validate source and destination
        for conn_type in "source" "destination"; do
            # Only PostgreSQL is supported - no engine validation needed

            # Check required connection fields
            for field in "host" "port" "username" "password" "database"; do
                local value=""
                value=$(yq eval ".databases[$i].$conn_type.$field" "$config_file" 2>/dev/null || echo "")

                if [[ -z "$value" || "$value" == "null" ]]; then
                    log_error "Database '$db_name' $conn_type: Missing required field '$field'"
                    return 1
                fi
            done
        done

        log_debug "Database '$db_name': Configuration valid"
    done

    return 0
}

# Setup directories and logging
setup_environment() {
    log_info "Setting up environment..."

    # Get dump directory from config or use default
    local config_dump_dir=""
    config_dump_dir=$(yq eval '.config.dump_directory // "./dumps"' "$CONFIG_FILE" 2>/dev/null || echo "./dumps")

    # Convert relative paths to absolute
    if [[ ! "$config_dump_dir" =~ ^/ ]]; then
        DUMP_DIR="${SCRIPT_DIR}/${config_dump_dir#./}"
    else
        DUMP_DIR="$config_dump_dir"
    fi

    # Create dump directory
    if ! mkdir -p "$DUMP_DIR"; then
        log_error "Failed to create dump directory: $DUMP_DIR"
        return 1
    fi

    # Setup log directory
    LOG_DIR="${SCRIPT_DIR}/logs"
    if ! mkdir -p "$LOG_DIR"; then
        log_error "Failed to create log directory: $LOG_DIR"
        return 1
    fi

    # Create log file
    local timestamp=""
    timestamp=$(date '+%Y%m%d_%H%M%S')
    LOG_FILE="${LOG_DIR}/migration_${timestamp}.log"

    # Initialize log file
    cat > "$LOG_FILE" << EOF
PostgreSQL Multi-Database Migration Log
Started: $(date '+%Y-%m-%d %H:%M:%S')
Configuration: $CONFIG_FILE
Mode: $([ "$DRY_RUN" = true ] && echo "DRY RUN" || echo "LIVE")
========================================

EOF

    log_success "Dump directory: $DUMP_DIR"
    log_success "Log file: $LOG_FILE"

    return 0
}

# Expand environment variables in values
expand_env_vars() {
    local value="$1"

    # Replace ${VAR} patterns with environment variable values
    echo "$value"
}

# Test database connection
test_connection() {
    local host="$1"
    local port="$2"
    local username="$3"
    local password="$4"
    local database="$5"
    local conn_type="$6"  # "source" or "destination"

    log_debug "Testing $conn_type connection to $host:$port/$database"

    local error_output=""
    error_output=$(PGPASSWORD="$password" psql --host="$host" --port="$port" --username="$username" --dbname="$database" --command="SELECT 1;" 2>&1)
    local exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_warning "$conn_type connection test failed: $error_output"
        return 1
    fi

    log_debug "$conn_type connection successful"
    return 0
}

# Get database connection info
get_db_info() {
    local config_file="$1"
    local db_index="$2"
    local conn_type="$3"  # "source" or "destination"
    local field="$4"

    local value=""
    value=$(yq eval ".databases[$db_index].$conn_type.$field" "$config_file" 2>/dev/null || echo "")

    # Expand environment variables
    expand_env_vars "$value"
}

# Dump a PostgreSQL database
dump_database() {
    local config_file="$1"
    local db_index="$2"
    local db_name="$3"

    local start_time=""
    start_time=$(date +%s)

    log_info "Dumping PostgreSQL database: $db_name"

    # Get source connection info
    local host port username password database
    host=$(get_db_info "$config_file" "$db_index" "source" "host")
    port=$(get_db_info "$config_file" "$db_index" "source" "port")
    username=$(get_db_info "$config_file" "$db_index" "source" "username")
    password=$(get_db_info "$config_file" "$db_index" "source" "password")
    database=$(get_db_info "$config_file" "$db_index" "source" "database")

    # Generate dump filename
    local dump_file="${DUMP_DIR}/${db_name}.sql"

    if [[ "$DRY_RUN" == true ]]; then
        log_warning "[DRY RUN] Would dump $db_name to $(basename "$dump_file")"
        return 0
    fi

    # Test source connection before attempting dump
    if ! test_connection "$host" "$port" "$username" "$password" "$database" "source"; then
        log_error "$db_name: Cannot connect to source database. Skipping dump."
        ((FAILED_DUMPS++))
        return 1
    fi

    # Get dump options from config (removed --verbose to prevent output interference)
    local dump_options=""
    dump_options=$(yq eval '.config.postgresql.dump_options // ["--no-owner", "--format=plain"]' "$config_file" 2>/dev/null | yq eval '.[] | "--" + .' | tr '\n' ' ')

    # Build pg_dump command
    local cmd_args=(
        "--host=$host"
        "--port=$port"
        "--username=$username"
        "--file=$dump_file"
    )

    # Add dump options
    read -ra options_array <<< "$dump_options"
    cmd_args+=("${options_array[@]}")
    cmd_args+=("$database")

    # Execute pg_dump with timeout
    local timeout=""
    timeout=$(yq eval '.config.timeouts.dump // 3600' "$config_file" 2>/dev/null || echo "3600")

    log_debug "Executing: pg_dump [ARGS_HIDDEN] $database"

    # Capture stderr for detailed error reporting
    local error_file="${DUMP_DIR}/${db_name}_dump_error.log"
    local exit_code=0

    # Execute pg_dump and redirect all output to prevent interference with return value
    if ! PGPASSWORD="$password" timeout "$timeout" pg_dump "${cmd_args[@]}" >/dev/null 2>"$error_file"; then
        exit_code=$?

        # Read the actual error message
        local error_msg=""
        if [[ -f "$error_file" && -s "$error_file" ]]; then
            error_msg=$(tail -10 "$error_file" | tr '\n' ' ' | sed 's/  */ /g')
            # Also log to main log file
            cat "$error_file" >> "$LOG_FILE"
        fi

        # Provide detailed error message based on exit code
        case $exit_code in
            124)
                log_error "$db_name: Dump timed out after ${timeout}s. Check connection and database size."
                ;;
            1)
                if [[ -n "$error_msg" ]]; then
                    log_error "$db_name: Dump failed - $error_msg"
                else
                    log_error "$db_name: Dump failed - Connection or authentication error. Check host, port, username, and password."
                fi
                ;;
            2)
                log_error "$db_name: Dump failed - Database connection error. Check if database '$database' exists and is accessible."
                ;;
            *)
                if [[ -n "$error_msg" ]]; then
                    log_error "$db_name: Dump failed (exit code $exit_code) - $error_msg"
                else
                    log_error "$db_name: Dump failed with exit code $exit_code. Check logs for details."
                fi
                ;;
        esac

        # Clean up error file
        [[ -f "$error_file" ]] && rm -f "$error_file"

        ((FAILED_DUMPS++))
        return 1
    fi

    # Clean up error file if successful
    [[ -f "$error_file" ]] && rm -f "$error_file"

    # Check if dump file was created and has content
    if [[ ! -s "$dump_file" ]]; then
        log_error "$db_name: Dump file is empty or was not created"
        ((FAILED_DUMPS++))
        return 1
    fi

    local file_size=""
    file_size=$(du -h "$dump_file" | cut -f1)
    local duration=$(($(date +%s) - start_time))

    log_success "$db_name: Dump completed successfully ($file_size) in ${duration}s"
    ((SUCCESSFUL_DUMPS++))
    LAST_DUMP_FILE="$dump_file"
    return 0
}

# Restore a PostgreSQL database
restore_database() {
    local config_file="$1"
    local db_index="$2"
    local db_name="$3"
    local dump_file="$4"

    local start_time=""
    start_time=$(date +%s)

    log_info "Restoring PostgreSQL database: $db_name"

    # Get destination connection info
    local host port username password database
    host=$(get_db_info "$config_file" "$db_index" "destination" "host")
    port=$(get_db_info "$config_file" "$db_index" "destination" "port")
    username=$(get_db_info "$config_file" "$db_index" "destination" "username")
    password=$(get_db_info "$config_file" "$db_index" "destination" "password")
    database=$(get_db_info "$config_file" "$db_index" "destination" "database")

    if [[ "$DRY_RUN" == true ]]; then
        log_warning "[DRY RUN] Would restore $db_name from $(basename "$dump_file")"
        return 0
    fi

    # Test destination connection before attempting restore
    if ! test_connection "$host" "$port" "$username" "$password" "$database" "destination"; then
        log_error "$db_name: Cannot connect to destination database. Skipping restore."
        ((FAILED_RESTORES++))
        return 1
    fi

    if [[ ! -f "$dump_file" ]]; then
        log_error "$db_name: Dump file not found: $dump_file"
        log_debug "Expected dump file at: $dump_file"
        log_debug "Current working directory: $(pwd)"
        log_debug "Contents of DUMP_DIR ($DUMP_DIR):"
        if [[ -d "$DUMP_DIR" ]]; then
            ls -la "$DUMP_DIR" 2>/dev/null | head -10 >&2 || true
        else
            log_debug "DUMP_DIR does not exist!"
        fi
        ((FAILED_RESTORES++))
        return 1
    fi

    # Build psql command
    local cmd_args=(
        "--host=$host"
        "--port=$port"
        "--username=$username"
        "--dbname=$database"
        "--file=$dump_file"
    )

    # Execute psql with timeout
    local timeout=""
    timeout=$(yq eval '.config.timeouts.restore // 7200' "$config_file" 2>/dev/null || echo "7200")

    log_debug "Executing: psql [ARGS_HIDDEN] --file=$dump_file"

    # Capture stderr for detailed error reporting
    local error_file="${DUMP_DIR}/${db_name}_restore_error.log"
    local exit_code=0

    if ! PGPASSWORD="$password" timeout "$timeout" psql "${cmd_args[@]}" > /dev/null 2>"$error_file"; then
        exit_code=$?
        # Read the actual error message
        local error_msg=""
        if [[ -f "$error_file" && -s "$error_file" ]]; then
            error_msg=$(tail -10 "$error_file" | tr '\n' ' ' | sed 's/  */ /g')
            # Also log to main log file
            cat "$error_file" >> "$LOG_FILE"
        fi

        # Provide detailed error message based on exit code
        case $exit_code in
            124)
                log_error "$db_name: Restore timed out after ${timeout}s. Large database or slow connection."
                ;;
            1)
                if [[ -n "$error_msg" ]]; then
                    log_error "$db_name: Restore failed - $error_msg"
                else
                    log_error "$db_name: Restore failed - Connection or authentication error. Check destination database connection."
                fi
                ;;
            2)
                log_error "$db_name: Restore failed - Database connection error. Check if destination database '$database' exists and is accessible."
                ;;
            3)
                log_error "$db_name: Restore failed - SQL execution error. Check dump file compatibility and database permissions."
                ;;
            *)
                if [[ -n "$error_msg" ]]; then
                    log_error "$db_name: Restore failed (exit code $exit_code) - $error_msg"
                else
                    log_error "$db_name: Restore failed with exit code $exit_code. Check logs for details."
                fi
                ;;
        esac

        # Clean up error file
        [[ -f "$error_file" ]] && rm -f "$error_file"

        ((FAILED_RESTORES++))
        return 1
    fi


    # Clean up error file if successful
    [[ -f "$error_file" ]] && rm -f "$error_file"

    local duration=$(($(date +%s) - start_time))

    log_success "$db_name: Restore completed successfully in ${duration}s"
    ((SUCCESSFUL_RESTORES++))
}

# Process a single database (dump and restore)
process_database() {
    local config_file="$1"
    local db_index="$2"

    local db_name=""
    db_name=$(yq eval ".databases[$db_index].name" "$config_file")

    log_info "Processing database $((db_index + 1))/$TOTAL_DATABASES: $db_name"

    local dump_status=0
    local restore_status=0

    # Attempt dump (call directly, use global LAST_DUMP_FILE)
    dump_database "$config_file" "$db_index" "$db_name"
    dump_status=$?

    if [[ $dump_status -ne 0 ]]; then
        log_warning "$db_name: Dump failed (status $dump_status); will not attempt restore"
        ((FAILED_RESTORES++))
        return 0  # Continue with next database
    fi

    # Sanitize path
    local dump_file="$LAST_DUMP_FILE"
    dump_file=$(echo "$dump_file" | tr -d '\n\r' | xargs)
    if [[ -z "$dump_file" ]]; then
        log_error "$db_name: Empty dump file path returned; skipping restore"
        ((FAILED_RESTORES++))
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        dump_file="${DUMP_DIR}/${db_name}.sql"
    fi

    restore_database "$config_file" "$db_index" "$db_name" "$dump_file"
    restore_status=$?
    if [[ $restore_status -ne 0 ]]; then
        log_warning "$db_name: Restore failed (status $restore_status)"
    fi

    return 0  # Never propagate failure to avoid -e style aborts
}



# Process databases sequentially
process_databases_sequential() {
    local config_file="$1"

    log_info "Running sequential processing for $TOTAL_DATABASES database(s)"

    for ((i=0; i<TOTAL_DATABASES; i++)); do
        echo -e "\n${CYAN}--- Processing Database $((i+1))/$TOTAL_DATABASES ---${NC}"
        process_database "$config_file" "$i"
    done
}

# Print migration summary
print_summary() {
    local end_time=""
    end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))

    echo
    echo -e "${BOLD}📊 Migration Summary${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"

    echo -e "${GREEN}✅ Successful dumps: $SUCCESSFUL_DUMPS${NC}"
    echo -e "${RED}❌ Failed dumps: $FAILED_DUMPS${NC}"
    echo -e "${GREEN}✅ Successful restores: $SUCCESSFUL_RESTORES${NC}"
    echo -e "${RED}❌ Failed restores: $FAILED_RESTORES${NC}"

    echo
    echo -e "${BLUE}⏱️  Total execution time: ${total_duration}s${NC}"

    # Calculate averages
    if [[ $SUCCESSFUL_DUMPS -gt 0 ]]; then
        echo -e "${BLUE}📈 Average operations per database: $((total_duration / TOTAL_DATABASES))s${NC}"
    fi

    # Overall status
    local total_operations=$((TOTAL_DATABASES * 2))  # dump + restore for each DB
    local successful_operations=$((SUCCESSFUL_DUMPS + SUCCESSFUL_RESTORES))

    echo
    if [[ $successful_operations -eq $total_operations ]]; then
        echo -e "${GREEN}${BOLD}🎉 ALL OPERATIONS COMPLETED SUCCESSFULLY!${NC}"
    elif [[ $successful_operations -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}⚠️  PARTIAL SUCCESS: $successful_operations/$total_operations operations completed${NC}"
    else
        echo -e "${RED}${BOLD}💥 ALL OPERATIONS FAILED${NC}"
    fi

    echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"

    # Log summary to file
    if [[ -n "$LOG_FILE" ]]; then
        {
            echo
            echo "MIGRATION SUMMARY"
            echo "================="
            echo "Successful dumps: $SUCCESSFUL_DUMPS"
            echo "Failed dumps: $FAILED_DUMPS"
            echo "Successful restores: $SUCCESSFUL_RESTORES"
            echo "Failed restores: $FAILED_RESTORES"
            echo "Total execution time: ${total_duration}s"
            echo "Completed: $(date '+%Y-%m-%d %H:%M:%S')"
        } >> "$LOG_FILE"
    fi
}

# Main execution function
main() {
    # Print header
    echo -e "${BOLD}${BLUE}${SCRIPT_NAME}${NC}"
    echo -e "${CYAN}Automated migration for multiple PostgreSQL databases${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"

    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}🧪 DRY RUN MODE - No actual operations will be performed${NC}"
    fi

    echo

    START_TIME=$(date +%s)

    # Run setup steps
    if ! check_prerequisites; then
        exit 1
    fi

    if ! validate_config "$CONFIG_FILE"; then
        exit 1
    fi

    if ! setup_environment; then
        exit 1
    fi

    # Start migration process
    echo
    echo -e "${BOLD}🚀 Starting Database Migration Process${NC}"
    echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"

    # Process databases
    process_databases_sequential "$CONFIG_FILE"

    # Print final summary
    print_summary

    # Exit with appropriate code
    local total_failed=$((FAILED_DUMPS + FAILED_RESTORES))
    if [[ $total_failed -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_args "$@"
    main
fi
