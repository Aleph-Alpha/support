#!/bin/bash

###############################################################################
# Pharia AI Backup/Restore Unified CLI
# Main wrapper script for all backup and restore operations
###############################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load common library for colors
source "$SCRIPT_DIR/../lib/common.sh"

###############################################################################
# Help Functions
###############################################################################

show_help() {
    cat << 'EOF'
Pharia AI Backup & Restore CLI

Usage: pharia-backup.sh <resource> <action> [options]

Resources:
    db          Database operations
    secrets     Kubernetes secrets operations

Actions:
    backup      Create a backup
    restore     Restore from a backup

Examples:
    # Database operations
    pharia-backup.sh db backup                    # Backup all databases
    pharia-backup.sh db restore mydb              # Restore specific database
    pharia-backup.sh db restore all               # Restore all databases
    pharia-backup.sh db restore -l mydb           # List backups for database

    # Secrets operations
    pharia-backup.sh secrets backup               # Backup secrets
    pharia-backup.sh secrets backup production    # Backup from namespace
    pharia-backup.sh secrets restore --latest     # Restore from latest backup
    pharia-backup.sh secrets restore -l           # List available backups

Getting help:
    pharia-backup.sh --help                       # Show this help
    pharia-backup.sh db --help                    # Database help
    pharia-backup.sh secrets --help               # Secrets help

For more detailed help on each script:
    ./bin/backup-db.sh --help
    ./bin/restore-db.sh --help
    ./bin/backup-secrets.sh --help
    ./bin/restore-secrets.sh --help

EOF
}

show_db_help() {
    cat << 'EOF'
Database Backup & Restore

Usage: pharia-backup.sh db <action> [options]

Actions:
    backup              Backup all databases from config
    restore <name>      Restore specific database (or 'all')
    restore -l <name>   List available backups for database
    restore -f <file>   Restore from specific backup file

Examples:
    pharia-backup.sh db backup
    pharia-backup.sh db restore mydb
    pharia-backup.sh db restore all
    pharia-backup.sh db restore -l mydb
    pharia-backup.sh db restore -f database-backups/mydb_2025-12-22_1430.sql mydb

For full options, run:
    ./bin/backup-db.sh --help
    ./bin/restore-db.sh --help

EOF
}

show_secrets_help() {
    cat << 'EOF'
Kubernetes Secrets Backup & Restore

Usage: pharia-backup.sh secrets <action> [options]

Actions:
    backup [namespace]      Backup secrets from namespace (default: pharia-ai)
    restore [options]       Restore secrets from backup

Restore Options:
    -l, --list              List available backups
    --latest                Use latest backup
    -n, --namespace NAME    Target namespace (default: pharia-ai)
    -f, --force             Force overwrite existing secrets
    <backup_dir>            Specific backup directory to restore

Examples:
    pharia-backup.sh secrets backup
    pharia-backup.sh secrets backup production
    pharia-backup.sh secrets restore --latest
    pharia-backup.sh secrets restore -l
    pharia-backup.sh secrets restore secrets-backups/secrets_2025-12-22_115835
    pharia-backup.sh secrets restore --latest -n production -f

For full options, run:
    ./bin/backup-secrets.sh --help
    ./bin/restore-secrets.sh --help

EOF
}

###############################################################################
# Main Script
###############################################################################

main() {
    # Check for no arguments or help flag
    if [ $# -eq 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
        show_help
        exit 0
    fi

    local resource=$1
    shift

    case $resource in
        db|database)
            # Check for help or no action
            if [ $# -eq 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
                show_db_help
                exit 0
            fi

            local action=$1
            shift

            case $action in
                backup)
                    exec "$SCRIPT_DIR/backup-db.sh" "$@"
                    ;;
                restore)
                    exec "$SCRIPT_DIR/restore-db.sh" "$@"
                    ;;
                *)
                    echo -e "${RED}ERROR: Unknown database action: $action${NC}"
                    echo "Valid actions: backup, restore"
                    echo "Run 'pharia-backup.sh db --help' for more information"
                    exit 1
                    ;;
            esac
            ;;

        secrets|secret)
            # Check for help or no action
            if [ $# -eq 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
                show_secrets_help
                exit 0
            fi

            local action=$1
            shift

            case $action in
                backup)
                    exec "$SCRIPT_DIR/backup-secrets.sh" "$@"
                    ;;
                restore)
                    exec "$SCRIPT_DIR/restore-secrets.sh" "$@"
                    ;;
                *)
                    echo -e "${RED}ERROR: Unknown secrets action: $action${NC}"
                    echo "Valid actions: backup, restore"
                    echo "Run 'pharia-backup.sh secrets --help' for more information"
                    exit 1
                    ;;
            esac
            ;;

        *)
            echo -e "${RED}ERROR: Unknown resource: $resource${NC}"
            echo "Valid resources: db, secrets"
            echo "Run 'pharia-backup.sh --help' for more information"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
