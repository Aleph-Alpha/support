#!/bin/bash

###############################################################################
# PostgreSQL Multi-Database Restore Script
# Restores PostgreSQL databases from backups
###############################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/config.yaml}"
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)

# Load common library
source "$SCRIPT_DIR/../lib/common.sh"

###############################################################################
# Restore Functions
###############################################################################

find_latest_backup() {
    local db_name=$1

    # Find the most recent backup file for this database
    local latest=$(ls -t "${BACKUP_DIR}/${db_name}"_*.sql 2>/dev/null | head -1)

    if [ -z "$latest" ]; then
        return 1
    fi

    echo "$latest"
    return 0
}

list_backups() {
    local db_name=$1

    echo ""
    echo "Available backups for $db_name:"
    echo "----------------------------------------"

    local backups=$(ls -t "${BACKUP_DIR}/${db_name}"_*.sql 2>/dev/null)

    if [ -z "$backups" ]; then
        echo "No backups found for $db_name"
        return 1
    fi

    local count=1
    while IFS= read -r backup; do
        local size=$(du -h "$backup" | cut -f1)
        local date=$(echo "$backup" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{4}')
        echo "$count) $(basename "$backup") (Size: $size, Date: $date)"
        ((count++))
    done <<< "$backups"

    echo ""
    return 0
}

restore_database() {
    local db_name=$1
    local db_host=$2
    local db_port=$3
    local db_user=$4
    local db_pass=$5
    local backup_file=$6

    echo "Starting restore of database: $db_name from $(basename "$backup_file")"

    # Validate backup file exists
    if [ ! -f "$backup_file" ]; then
        echo -e "${RED}ERROR: Backup file not found: $backup_file${NC}"
        return 1
    fi

    # Set password for psql
    export PGPASSWORD="$db_pass"

    # Restore from backup
    echo "Restoring data to $db_name..."
    if psql -h "$db_host" -p "$db_port" -U "$db_user" -d "$db_name" -f "$backup_file" > /dev/null 2>&1; then
        echo -e "${GREEN}SUCCESS: Restore completed for $db_name${NC}"
        unset PGPASSWORD
        return 0
    else
        echo -e "${RED}ERROR: Restore failed for $db_name${NC}"
        unset PGPASSWORD
        return 1
    fi
}

###############################################################################
# Usage/Help Functions
###############################################################################

show_usage() {
    cat << EOF
PostgreSQL Multi-Database Restore Script

Usage: $0 [OPTIONS] [DATABASE_NAME|all]

Options:
    -h, --help              Show this help message
    -f, --file FILE         Specify backup file to restore (for single database)
    -l, --list DATABASE     List available backups for a database
    -c, --config FILE       Specify config file (default: config.yaml)

Arguments:
    DATABASE_NAME           Name of the database to restore (must match config)
    all                     Restore all databases from their latest backups

Examples:
    # Restore a specific database from latest backup
    $0 myapp_db

    # Restore a specific database from a specific backup file
    $0 -f database-backups/myapp_db_2025-12-21_1430.sql myapp_db

    # List available backups for a database
    $0 -l myapp_db

    # Restore all databases from their latest backups
    $0 all

EOF
}

###############################################################################
# Main Script
###############################################################################

main() {
    local target_db=""
    local backup_file=""
    local list_mode=false
    local list_db=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -f|--file)
                backup_file="$2"
                shift 2
                ;;
            -l|--list)
                list_mode=true
                list_db="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -*)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                target_db="$1"
                shift
                ;;
        esac
    done

    print_header "PostgreSQL Multi-Database Restore Script"

    # Load configuration
    load_config "$CONFIG_FILE"

    # Handle list mode
    if [ "$list_mode" == true ]; then
        if [ -z "$list_db" ]; then
            echo "ERROR: Please specify a database name to list backups"
            exit 1
        fi

        list_backups "$list_db"
        exit $?
    fi

    # Check if target database is specified
    if [ -z "$target_db" ]; then
        echo "ERROR: Please specify a database name or 'all'"
        echo ""
        show_usage
        exit 1
    fi

    echo "=========================================="
    echo "Starting restore process"
    echo "Config file: $CONFIG_FILE"
    echo "Target: $target_db"
    echo "Timestamp: $TIMESTAMP"
    echo "=========================================="

    # Check for required tools
    check_command "psql" "Please install PostgreSQL client tools." || exit 1

    local success_count=0
    local failed_count=0

    # Restore all databases or specific one
    if [ "$target_db" == "all" ]; then
        echo "Restoring all databases from latest backups"

        local db_count=$(get_database_count "$CONFIG_FILE")

        for ((i=0; i<db_count; i++)); do
            get_database_info "$CONFIG_FILE" "$i"

            if [ -z "$DB_NAME" ] || [ "$DB_NAME" == "null" ]; then
                echo -e "${YELLOW}WARNING: Skipping invalid database entry at index $i${NC}"
                continue
            fi

            # Find latest backup
            local latest_backup=$(find_latest_backup "$DB_NAME")
            if [ $? -ne 0 ]; then
                echo -e "${RED}ERROR: No backup found for $DB_NAME${NC}"
                failed_count=$((failed_count + 1))
                continue
            fi

            # Restore database
            if restore_database "$DB_NAME" "$DB_HOST" "$DB_PORT" "$DB_USER" "$DB_PASS" "$latest_backup"; then
                success_count=$((success_count + 1))
            else
                failed_count=$((failed_count + 1))
            fi
        done

    else
        # Restore specific database
        if ! get_database_info_by_name "$CONFIG_FILE" "$target_db"; then
            echo -e "${RED}ERROR: Database '$target_db' not found in config file${NC}"
            exit 1
        fi

        # Determine backup file
        if [ -z "$backup_file" ]; then
            backup_file=$(find_latest_backup "$target_db")
            if [ $? -ne 0 ]; then
                echo -e "${RED}ERROR: No backup found for $target_db${NC}"
                echo "Use -l option to list available backups"
                exit 1
            fi
            echo "Using latest backup: $(basename "$backup_file")"
        fi

        # Restore the database
        if restore_database "$DB_NAME" "$DB_HOST" "$DB_PORT" "$DB_USER" "$DB_PASS" "$backup_file"; then
            success_count=1
        else
            failed_count=1
        fi
    fi

    # Print summary
    if print_summary "$success_count" "$failed_count" "Restore process"; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
