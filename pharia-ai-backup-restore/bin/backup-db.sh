#!/bin/bash

###############################################################################
# PostgreSQL Multi-Database Backup Script
# Backs up multiple PostgreSQL databases from configuration
###############################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/config.yaml}"
TIMESTAMP=$(date +%Y-%m-%d_%H%M)

# Load common library
source "$SCRIPT_DIR/../lib/common.sh"

###############################################################################
# Backup Functions
###############################################################################

backup_database() {
    local db_name=$1
    local db_host=$2
    local db_port=$3
    local db_user=$4
    local db_pass=$5

    local backup_file="${BACKUP_DIR}/${db_name}_${TIMESTAMP}.sql"

    echo "Starting backup of database: $db_name"

    # Set password for pg_dump
    export PGPASSWORD="$db_pass"

    # Perform backup in plain format
    if pg_dump -h "$db_host" -p "$db_port" -U "$db_user" -d "$db_name" --no-owner > "$backup_file" 2>&1; then
        local file_size=$(du -h "$backup_file" | cut -f1)
        echo -e "${GREEN}SUCCESS: Backup completed for $db_name (Size: $file_size)${NC}"
        echo "$backup_file" >> "${BACKUP_DIR}/.backup_success_${TIMESTAMP}"
    else
        echo -e "${RED}ERROR: Backup failed for $db_name${NC}"
        rm -f "$backup_file"
        unset PGPASSWORD
        return 1
    fi

    # Unset password
    unset PGPASSWORD
    return 0
}

###############################################################################
# Main Script
###############################################################################

main() {
    print_header "PostgreSQL Multi-Database Backup Script"

    # Load configuration
    load_config "$CONFIG_FILE"

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    echo "=========================================="
    echo "Starting backup process"
    echo "Config file: $CONFIG_FILE"
    echo "Backup directory: $BACKUP_DIR"
    echo "Timestamp: $TIMESTAMP"
    echo "=========================================="

    # Check for required tools
    check_command "pg_dump" "Please install PostgreSQL client tools." || exit 1

    # Get database count
    local db_count=$(get_database_count "$CONFIG_FILE")
    echo "Found $db_count database(s) to backup"

    if [ "$db_count" -eq 0 ]; then
        echo -e "${RED}ERROR: No databases configured${NC}"
        exit 1
    fi

    # Backup databases sequentially
    local success_count=0
    local failed_count=0

    for ((i=0; i<$db_count; i++)); do
        # Get database info
        get_database_info "$CONFIG_FILE" "$i"

        # Validate database info
        if [ -z "$DB_NAME" ] || [ "$DB_NAME" == "null" ]; then
            echo -e "${YELLOW}WARNING: Skipping invalid database entry at index $i${NC}"
            continue
        fi

        # Backup database
        if backup_database "$DB_NAME" "$DB_HOST" "$DB_PORT" "$DB_USER" "$DB_PASS"; then
            success_count=$((success_count + 1))
        else
            failed_count=$((failed_count + 1))
        fi
    done

    # Print summary
    if print_summary "$success_count" "$failed_count" "Backup process"; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
