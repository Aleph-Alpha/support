#!/bin/bash

###############################################################################
# Common Library for Pharia AI Backup/Restore Scripts
# Shared functions, utilities, and YAML parsing
###############################################################################

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

###############################################################################
# Utility Functions
###############################################################################

# Check if a command exists
check_command() {
    local cmd=$1
    local error_msg=$2

    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}ERROR: $cmd not found. $error_msg${NC}"
        return 1
    fi
    return 0
}

# Print a formatted header
print_header() {
    local title=$1
    echo "=========================================="
    echo "$title"
    echo "=========================================="
    echo ""
}

# Print a summary of operations
print_summary() {
    local success_count=$1
    local failed_count=$2
    local operation=$3

    echo "=========================================="
    echo "$operation completed"
    echo "Successful: $success_count"
    echo "Failed: $failed_count"
    echo "=========================================="

    if [ "$failed_count" -eq 0 ]; then
        echo -e "${GREEN}SUCCESS: All operations completed successfully!${NC}"
        return 0
    else
        echo -e "${RED}ERROR: Some operations failed${NC}"
        return 1
    fi
}

###############################################################################
# YAML Parser Functions
###############################################################################

# Parse YAML configuration using yq (preferred method)
parse_yaml_with_yq() {
    local config_file=$1

    if ! command -v yq &> /dev/null; then
        return 1
    fi

    # Get settings
    BACKUP_DIR=$(yq eval '.backup_dir // "./database-backups"' "$config_file")

    # Get number of databases
    local db_count=$(yq eval '.databases | length' "$config_file")

    if [ "$db_count" == "0" ] || [ "$db_count" == "null" ]; then
        echo -e "${RED}ERROR: No databases found in config file${NC}"
        exit 1
    fi

    return 0
}

# Fallback YAML parser using grep/sed (when yq is not available)
parse_yaml_fallback() {
    local config_file=$1

    echo -e "${YELLOW}yq not found, using fallback YAML parser${NC}"

    # Extract backup_dir with default
    BACKUP_DIR=$(grep -E "^backup_dir:" "$config_file" | sed 's/backup_dir:[[:space:]]*//' | tr -d '"' 2>/dev/null)

    # Use default if not found
    if [ -z "$BACKUP_DIR" ]; then
        BACKUP_DIR="./database-backups"
    fi

    # Validate databases section exists
    if ! grep -q "^databases:" "$config_file"; then
        echo -e "${RED}ERROR: No 'databases:' section found in config file${NC}"
        exit 1
    fi
}

# Get the count of databases in config
get_database_count() {
    local config_file=$1

    if command -v yq &> /dev/null; then
        yq eval '.databases | length' "$config_file"
    else
        # Count database entries (lines with '- name:')
        grep -c "^[[:space:]]*- name:" "$config_file" 2>/dev/null || echo "0"
    fi
}

# Get database information by index
get_database_info() {
    local config_file=$1
    local index=$2

    if command -v yq &> /dev/null; then
        DB_NAME=$(yq eval ".databases[$index].name" "$config_file")
        DB_HOST=$(yq eval ".databases[$index].host" "$config_file")
        DB_PORT=$(yq eval ".databases[$index].port" "$config_file")
        DB_USER=$(yq eval ".databases[$index].user" "$config_file")
        DB_PASS=$(yq eval ".databases[$index].password" "$config_file")
    else
        # Fallback: extract database block for the given index
        local db_block=$(awk -v idx="$((index+1))" '
            /^[[:space:]]*- name:/ { i++; if (i == idx) { flag=1 } else if (i > idx) { exit } }
            flag { print }
        ' "$config_file")

        DB_NAME=$(echo "$db_block" | grep "name:" | head -1 | sed 's/.*name:[[:space:]]*//' | tr -d '"')
        DB_HOST=$(echo "$db_block" | grep "host:" | sed 's/.*host:[[:space:]]*//' | tr -d '"')
        DB_PORT=$(echo "$db_block" | grep "port:" | sed 's/.*port:[[:space:]]*//' | tr -d '"')
        DB_USER=$(echo "$db_block" | grep "user:" | sed 's/.*user:[[:space:]]*//' | tr -d '"')
        DB_PASS=$(echo "$db_block" | grep "password:" | sed 's/.*password:[[:space:]]*//' | tr -d '"')
    fi
}

# Get database information by name
get_database_info_by_name() {
    local config_file=$1
    local target_name=$2
    local db_count=$(get_database_count "$config_file")

    for ((i=0; i<db_count; i++)); do
        get_database_info "$config_file" "$i"
        if [ "$DB_NAME" == "$target_name" ]; then
            return 0
        fi
    done

    return 1
}

# Load configuration file
load_config() {
    local config_file=$1

    if [ ! -f "$config_file" ]; then
        echo -e "${RED}ERROR: Config file not found: $config_file${NC}"
        echo "Please copy config.yaml.example to config.yaml and configure it."
        exit 1
    fi

    # Parse YAML configuration
    if ! parse_yaml_with_yq "$config_file"; then
        parse_yaml_fallback "$config_file"
    fi
}
